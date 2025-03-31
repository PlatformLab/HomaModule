#!/usr/bin/python3

# SPDX-License-Identifier: BSD-2-Clause

"""
This script is used to copy information from the Homa GitHub repo to
a Linux kernel repo, removing information that doesn't belong in the
official kernel version (such as calls to tt_record).

Usage: strip.py file file file ... destdir

Each of the files will be read, stripped as appropriate, and copied to a
file by the same name in destdir. If there is only a single file and no
destdir, then the stripped file is printed on standard output.

The following code is removed automatically:
  * Calls to timetracing, such as tt_record*
  * Blocks conditionalized on '#ifdef __UNIT_TEST__'
  * UNIT_LOG and UNIT_HOOK statements
  * INC_METRIC statements
  * IF_NO_STRIP statements

Additional stripping is controlled by #ifdefs. The #ifdefs allow the
code to be used in three ways:
* Normal compilation in a development environment: includes unit testing
  and timetracing support, nothing is stripped. The code is compiled as
  is.
* Upstreaming: source files are run through this program, which produces
  a statically-stripped version.
* Compile-time stripping: the code is compiled as is, but "__STRIP__=y" is
  set on the make command line (both for compiling Homa and for unit testing).
  This omits almost all of the information that must be omitted for
  upstreaming, but retains a few debugging facilities like timetracing.

Here are details about the #ifdefs used for stripping:

* This entire block will be removed in the stripped version, but it will
  be compiled in normal mode:
    #ifndef __STRIP__ /* See strip.py */
    ...
    #endif /* See strip.py */

* This entire block will be removed in the stripped version, but it will
  be compiled in both normal mode and with compile-time stripping.
    #ifndef __UPSTREAM__ /* See strip.py */
    ...
    #endif /* See strip.py */

* The #if and #endif statements will be removed, leaving just the code
  in between. The code will be compiled in compile-time stripping mode
    #ifdef __STRIP__ /* See strip.py */
    ...
    #endif /* See strip.py */

* Everything will be removed except the code between #else and #endif.
  During normal mode the #ifndef block will be compiled; under compile-time
  stripping the #else block will be compiled.
    #ifndef __STRIP__ /* See strip.py */
    ...
    #else /* See strip.py */
    ...
    #endif /* See strip.py */
"""

from collections import defaultdict
from glob import glob
from optparse import OptionParser
import math
import os
from pathlib import Path
import re
import string
import sys

exit_code = 0

def remove_close(line):
    """
    Given a line of text containing a '}', remove the '}' and any
    following white space. If there is no '}', returns the original line.
    """
    i = line.rfind('}')
    if i < 0:
        return line
    for j in range(i+1, len(line), 1):
        if line[j] != ' ':
            break
    return line[0:i] + line [j:]

def remove_open(line):
    """
    Given a line of text containing a '{', remove the '{' and any
    preceding white space. If there is no '{', returns the original line.
    """
    i = line.rfind('{')
    if i < 0:
        return line
    j = -1
    for j in range(i-1, -1, -1):
        if line[j] != ' ':
            break
    return line[0:j+1] + line [i+1:]

def leading_space(line):
    """
    Return the number of characters of leading space in a line (a tab counts
    as 8 spaces).
    """

    count = 0
    for c in line:
        if c == ' ':
            count += 1
        elif c == '\t':
            count += 8
        else:
            break
    return count

def last_non_blank(s):
    """
    Return the last non-blank character in s, or None if there is no
    non-blank character in s.
    """
    s2 = s.rstrip()
    if s2:
        return s2[-1]
    return None

def blank_next_ok(line):
    """
    Given a line, return True if it is OK for this line to be followed by
    a blank line. False means that if the next line to be output is blank,
    it should be dropped.
    """
    s = line.strip()
    if s == '':
        return False
    if s.endswith('{') or s.endswith('*/'):
        return False
    return True

def scan(file):
    """
    Read a file, remove information that shouldn't appear in the Linux kernel
    version, and return an array of lines representing the stripped file.
    file:     Pathname of file to read
    """

    global exit_code

    # True means the current line ends in the middle of a /* ... */ comment
    in_comment = False

    # True means we're in the middle of a multi-line statement that
    # should be skipped (drop until a semicolon is seen).
    skip_statement = False

    # Values of 0 or 1 mean we're in the middle of a group of lines labeled
    # with '#ifndef __STRIP__' or "#ifdef __STRIP__". 0 means we're including
    # lines, 1 means we're stripping them. None means we're not in such a
    # group.
    in_labeled_skip = None

    # Used to strip out unit testing code. Value is one of:
    # None:    We're not in the middle of an '#ifdef __UNIT_TEST__'
    # 'if':    An '#idfdef __UNIT_TEST__" has been seen, but the
    #          corresponding #else or #endif has not been seen yet
    # 'else':  We are in the middle of an '#else' clause for an
    #          '#ifdef __UNIT_TEST__'
    in_unit = None

    # Used to strip out conditional code based on version
    # None:    We're not in the middle of an '#if LINUX_VERSION_CODE'
    # 'if':    An '#if LINUX_VERSION_CODE" has been seen, but not the
    #          corresponding #else or #endif (code should be stripped)
    # 'else':  We are in the middle of an '#else' clause for an
    #          '#if LINUX_VERSION_CODE' (this code should remain)
    in_version = None

    # Array of lines containing the stripped version of the file
    slines = []

    # Index in slines of the most recent line ending with a '{', or None
    # if none. Only valid for innermost blocks (those with no nested blocks).
    open_index = None

    # Number of statements that have been seen since the last '{': used to
    # eliminate curly braces around blocks that end up with only a single
    # statement. Set to a number > 1 if there isn't an "interesting"
    # current block.
    statements_in_block = 100

    # True means lines were automatically deleted in the current block;
    # at the end of the block, see if curly braces are no longer needed.
    check_braces = False

    # Used when deleted statements like tt_record are surrounded on both
    # sides by empty lines; the second empty line will be deleted.
    delete_empty_line = False

    line_num = 0

    f = open(file)
    for line in f:
        line_num += 1

        # pline is used for parsing; it is modified to remove
        # uninteresting information such as whitespace.
        pline = line.strip()

        if pline.startswith('//') and not 'SPDX-License' in pline:
            # Strip // comment lines: these are used only for commenting
            # out debugging code.
            continue

        # Extract the part of the line that is *not* in a /*...*/ comment
        # (assume at most one comment per line).
        cstart = pline.find('/*')
        cend = pline.find('*/')
        if cstart >= 0:
            if cend >= 0:
                non_comment = pline[0:cstart] + pline[cend+2:]
                in_comment = False
            else:
                non_comment = pline[0:cstart]
                in_comment = True
        elif cend >= 0:
                non_comment = pline[cend+2:]
                in_comment = False
        elif in_comment:
            non_comment = ''
        else:
            non_comment = pline
        non_comment = non_comment.strip()

        # Strip groups of lines labeled with '#ifndef __STRIP__' or
        # '#ifndef __UPSTREAM__'. Note: don't do brace elimination here:
        # this gives greater control to the __STRIP__ code.
        if in_labeled_skip != None:
            if line.startswith('#endif /* See strip.py */'):
                in_labeled_skip = None
                continue
            elif line.startswith('#else /* See strip.py */'):
                in_labeled_skip = 0
                continue
            if in_labeled_skip == 1:
                continue
        if line.startswith('#ifndef __STRIP__ /* See strip.py */') or (
                line.startswith('#ifndef __UPSTREAM__ /* See strip.py */')):
            if not blank_next_ok(slines[-1]):
                delete_empty_line = True
            in_labeled_skip = 1
            check_braces = True
            continue
        if line.startswith('#ifdef __STRIP__ /* See strip.py */') :
            if not blank_next_ok(slines[-1]):
                slines.pop()
            in_labeled_skip = 0
            check_braces = True
            continue

        # Strip tt_freeze() statements.
        if pline == 'tt_freeze();':
            check_braces = True
            if not blank_next_ok(slines[-1]):
                delete_empty_line = True
            continue

        if skip_statement:
            if pline[-1] == ';':
                skip_statement = False
            check_braces = True
            continue

        # Strip tt_record, INC_METRIC, and IF_NO_STRIP statements.
        match = re.match('(//[ \t]*)?tt_record[1-4]?[(]', pline)
        if not match:
            match = re.match('(//[ \t]*)?INC_METRIC[(]', pline)
        if not match:
            match = re.match('(//[ \t]*)?IF_NO_STRIP[(]', pline)
        if match:
            # If this is the only statement in its block, delete the
            # outer block statement (if, while, etc.). Don't delete case
            # statements.
            if not match.group(1):
                indent = leading_space(line)
                for i in range(len(slines)-1, -1, -1):
                    prev = slines[i]
                    prev_indent = leading_space(prev)
                    if last_non_blank(prev) == '{':
                        break
                    if prev_indent == 0:
                        # Label or method start; no need to continue further
                        break
                    if leading_space(prev) < indent:
                        if not prev.lstrip().startswith('case'):
                            slines = slines[:i]
                        break

            if pline[-1] != ';':
                  skip_statement = True
            if not blank_next_ok(slines[-1]):
                delete_empty_line = True
            check_braces = True
            continue

        # Strip UNIT_LOG and UNIT_HOOK statements.
        if (pline.startswith('UNIT_LOG(') or pline.startswith('UNIT_HOOK(')):
            if pline[-1] != ';':
                  skip_statement = True
            if not blank_next_ok(slines[-1]):
                delete_empty_line = True
            check_braces = True
            continue

        # Strip #include "homa_strip.h" statements.
        if pline.startswith('#include "homa_strip.h"'):
            if not blank_next_ok(slines[-1]):
                delete_empty_line = True
            continue

        # Strip '#ifdef __UNIT_TEST__' blocks (keep #else clauses)
        if in_unit:
            if line.startswith('#endif /* __UNIT_TEST__ */'):
                in_unit = None
                continue
            if line.startswith('#else /* __UNIT_TEST__ */'):
                in_unit = 'else'
                continue
            if in_unit == 'if':
                continue
        elif line.startswith('#ifdef __UNIT_TEST__'):
            in_unit = 'if'
            if not blank_next_ok(slines[-1]):
                delete_empty_line = True
            continue
        elif line.startswith('#ifndef __UNIT_TEST__'):
            in_unit = 'else'
            if not blank_next_ok(slines[-1]):
                delete_empty_line = True
            continue

        # Strip 'if LINUX_VERSION_CODE' blocks (keep #else clauses)
        if in_version:
            if line.startswith('#endif'):
                in_version = None
                continue
            if line.startswith('#else'):
                in_version = 'else'
                continue
            if in_version == 'if':
                continue
        elif line.startswith('#if LINUX_VERSION_CODE'):
            in_version = 'if'
            if not blank_next_ok(slines[-1]):
                delete_empty_line = True
            continue

        if not pline:
            if not line.isspace() or not delete_empty_line:
                slines.append(line)
            delete_empty_line = False
            continue
        delete_empty_line = False

        # Remove braces for blocks that now have only a single statement
        if pline == '}' or pline.startswith('} else'):
            if check_braces:
                check_braces = False
                if open_index != None:
                    if statements_in_block == 0:
                        print('%s:%d: stripping creates empty block' %
                                (file, line_num), file=sys.stderr)
                        exit_code = 1
                    if statements_in_block == 1:
                        slines[open_index] = remove_open(slines[open_index])
                        line = remove_close(line)
                        if not line.strip():
                            open_index = None
                            continue
                    open_index = None
        if pline[-1] == '{' and line[0] != '{':
            statements_in_block = 0
            open_index = len(slines)
            check_braces = False

        # Count statements
        if non_comment and non_comment[-1] == ';':
            statements_in_block += 1

        # The current line needs to be retained in the output.
        slines.append(line)
    f.close()
    return slines

if __name__ == '__main__':
    f = sys.stdin
    if len(sys.argv) < 2:
        print('Usage: strip.py [--alt] file [file ... destdir]', file=sys.stderr)
        exit(1)
    if len(sys.argv) == 2:
        for line in scan(sys.argv[1]):
            print(line, end='')
    else:
        for file in sys.argv[1:-1]:
            dst_file = '%s/%s' % (sys.argv[-1], file)
            print('Stripping %s into %s' % (file, dst_file))
            slines = scan(file)
            dst = open(dst_file, 'w')
            for line in slines:
                print(line, end='', file=dst)
            dst.close()
    sys.exit(exit_code)