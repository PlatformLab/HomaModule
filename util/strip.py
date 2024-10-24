#!/usr/bin/python3

# SPDX-License-Identifier: BSD-2-Clause

"""
This script is used to copy information from the Homa GitHub repo to
a Linux kernel repo, removing information that doesn't belong in the
official kernel version (primarily calls to tt_record).

Usage: strip.py [--alt] file file file ... destdir

Each of the files will be read, stripped as appropriate, and copied to a
file by the same name in destdir. If there is only a single file and no
destdir, then the stripped file is printed on standard output.

In some cases, such as calls to tt_record*, information is removed
automatically. In other cases, it is controlled with #if statments in
the following ways:

* This entire block will be removed in the stripped version:
    #if 1 /* See strip.py */
    ...
    #endif /* See strip.py */

* The #if and #endif statements will be removed, leaving just the code
  in between:
    #if 0 /* See strip.py */
    ...
    #endif /* See strip.py */

* Everything will be removed except the code between #else and #endif:
    #if 1 /* See strip.py */
    ...
    #else /* See strip.py */
    ...
    #endif /* See strip.py */

* It is also possible to strip using "alt" mode, with lines like this:
    #if 1 /* See strip.py --alt */
    #if 0 /* See strip.py --alt */
  If the --alt option was not specified then these lines are handled as
  if "--alt" wasn't present in the comments. However, if the --alt option
  was specified then these lines are ignored.

If the --alt option is specified, it means the output is intended for
testing outside the Linux kernel. In this case, the lines
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

def scan(file, alt_mode):
    """
    Read a file, remove information that shouldn't appear in the Linux kernel
    version, and return an array of lines representing the stripped file.
    file:     Pathname of file to read
    alt_mode: True means the --alt option was specified
    """

    global exit_code

    # True means we're in the middle of a '/* ... */' comment
    in_comment = False

    # True means we're in the middle of a statement that should be skipped.
    in_statement = False

    # Values of 0 or 1 mean we're in the middle of a group of lines labeled
    # with '#if /* GitHubOnly */'. 0 means we're including lines, 1 means
    # we're stripping them. None means we're not in such a group.
    in_labeled_skip = None

    # True means we're in the middle of an '#ifdef __UNIT_TEST__'
    in_unit = False

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
        # uninteresting information such as comments and whitespace.
        pline = line.rstrip()

        # Handle comments.
        if in_comment:
            index = pline.find('*/')
            if index < 0:
                slines.append(line)
                continue
            pline = pline[index+2:]
            in_comment = False
        index = pline.find('/*')
        if index >= 0:
            index2 = pline.find('*/', index+2)
            if index2 >= 0:
                pline = pline[0:index] + pline[index2+2:]
            else:
                pline = pline[0:index]
                in_comment = True
        index = pline.find('//')
        if index >= 0:
                pline = pline[0:index]

        pline = pline.strip()

        # Strip groups of lines labeled with special '#if'
        if in_labeled_skip != None:
            if line.startswith('#endif /* See strip.py */'):
                in_labeled_skip = None
                check_braces = False
                continue
            elif line.startswith('#else /* See strip.py */'):
                in_labeled_skip = 0
                continue
            if in_labeled_skip == 1:
                continue
        if line.startswith('#if 1 /* See strip.py */') or (
                line.startswith('#if 1 /* See strip.py --alt */')
                and not alt_mode):
            if slines[-1].strip() == '':
                slines.pop()
            in_labeled_skip = 1
            check_braces = False
            continue
        if line.startswith('#if 0 /* See strip.py */')or (
                line.startswith('#if 0 /* See strip.py --alt */')
                and not alt_mode):
            if slines[-1].strip() == '':
                slines.pop()
            in_labeled_skip = 0
            check_braces = False
            continue

        # Strip tt_freeze() statements.
        if pline == 'tt_freeze();':
            check_braces = True
            if slines[-1].strip() == '':
                delete_empty_line = True
            continue

        # Strip tt_record statements.
        if in_statement:
            if pline[-1] == ';':
                in_statement = False
            check_braces = True
            continue
        if re.match('tt_record[1-4]?[(]', pline):
            # If this is the only statement in its block, delete the
            # outer block statement (if, while, etc.).
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
                    if prev.lstrip().startswith('case'):
                        print('%s:%d: \'case\' before tt_record; don\'t know how to handle'
                                % (file, i), file=sys.stderr)
                        exit_code = 1
                        break
                    slines = slines[:i]
                    break

            if pline[-1] != ';':
                  in_statement = True
            if slines[-1].strip() == '':
                delete_empty_line = True
            check_braces = True
            continue

        if not pline:
            if not line.isspace() or not delete_empty_line:
                slines.append(line)
            delete_empty_line = False
            continue
        delete_empty_line = False

        # Remove braces for blocks that now have only a single statement
        if pline[0] == '}':
            if check_braces:
                check_braces = False;
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

        # Count statements
        if pline[-1] == ';':
            statements_in_block += 1

        # The current line needs to be retained in the output.
        slines.append(line)
    f.close()
    return slines

if __name__ == '__main__':
    f = sys.stdin
    alt_mode = False;
    if (len(sys.argv) >= 2) and (sys.argv[1] == '--alt'):
        alt_mode = True;
        del sys.argv[1]
    if len(sys.argv) < 2:
        print('Usage: strip.py [--alt] file [file ... destdir]', file=sys.stderr)
        exit(1)
    if len(sys.argv) == 2:
        for line in scan(sys.argv[1], alt_mode):
            print(line, end='')
    else:
        for file in sys.argv[1:-1]:
            dst_file = '%s/%s' % (sys.argv[-1], file)
            print('Stripping %s into %s' % (file, dst_file))
            slines = scan(file, alt_mode)
            dst = open(dst_file, 'w')
            for line in slines:
                print(line, end='', file=dst)
            dst.close()
    sys.exit(exit_code)