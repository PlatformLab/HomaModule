#!/usr/bin/env python

"""
Reads lines and extracts the first floating-point number to appear on
each line; prints both the individual values and the average of them.
Usage: avg.py [file]
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

if len(sys.argv) == 2:
    f = open(sys.argv[1])
elif len(sys.argv) == 1:
    f = sys.stdin
else:
    print("Usage: %s [tt_file]" % (sys.argv[0]))
    sys.exit(1)

values = []

for line in f:
    match = re.match('.*?[^0-9]([0-9]+[.][0-9]+)', line)
    if match:
        print('Found field %s' % (match.group(1)))
        values.append(float(match.group(1)))
    else:
        print('Line didn\'t match: %s' % (line))

if len(values):
    print('Average: %.3f' % (sum(values)/len(values)))
else:
    print('No lines matched')