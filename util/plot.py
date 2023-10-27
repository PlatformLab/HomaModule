#!/usr/bin/python3

# Copyright (c) 2023 Homa Developers
#
# SPDX-License-Identifier: BSD-1-Clause

# This file provides a library of functions for generating plots.

import matplotlib
import matplotlib.pyplot as plt
import os
from pathlib import Path
import re
import string
import sys

from cperf import *

# Standard colors for plotting
color_green =      '#00B000'
color_blue =       '#1759BB'
color_red =        '#d62728'
tcp_color =      '#00B000'
tcp_color2 =     '#5BD15B'
tcp_color3 =     '#96E296'
homa_color =     '#1759BB'
homa_color2 =    '#6099EE'
homa_color3 =    '#A6C6F6'
dctcp_color =    '#7A4412'
dctcp_color2 =   '#CB701D'
dctcp_color3 =   '#EAA668'
unloaded_color = '#d62728'

matplotlib.rc('mathtext', default='regular')

# Dictionary containing all data that has been read from files so far.
# Keys are file names, values are dictionaries of columns for that file,
# in which keys are column names and values are lists of the values
# in that column.
file_data = {}

def __read_file(file):
    """
    Read a file and add its contents to the file_data variable. If the
    file has already been read, then this function does nothing.

    file:   Path name of the file to read. Lines starting with '#' are
            considered comments and ignored, as are blank lines. Of the
            non-blank non-comment lines, the first contains space-separated
            column names, and the others contain data for those columns.
    """
    global file_data

    if file in file_data:
        return
    columns = {}
    names = None
    f = open(file)
    for line in f:
        fields = line.strip().split()
        if len(fields) == 0:
            continue
        if fields[0].startswith('#'):
            continue
        if not names:
            names = fields
            for n in names:
                if n in columns:
                    print('Duplicate column name %s in %s' % (file, n),
                            file=sys.stderr())
                columns[n] = []
        else:
            if len(fields) != len(names):
                print('Bad line in %s: %s (expected %d columns, got %d)'
                        % (file, line.rstrip(), len(columns), len(fields)),
                        file=sys.stderr)
                continue
            for i in range(0, len(names)):
                try:
                    value = float(fields[i])
                except ValueError:
                    value = fields[i]
                columns[names[i]].append(value)
    f.close()
    file_data[file] = columns

def get_column(file, column):
    """
    Return a list containing the values of a given column in a given file.

    file:    Path name of the file containing the desired column.
    column:  Name of the column within that file.
    """

    __read_file(file)
    if not column in file_data[file]:
        raise Exception('Column %s doesn\'t exist in %s' % (column, name))
    return file_data[file][column]

def get_column_names(file):
    """
    Returns a list containing the names of all of the columns in file.
    """

    __read_file(file)
    return file_data[file].keys()

def get_numbers(file):
    """
    Scans all of the column names in file for numbers and returns a
    sorted list of all the unique numbers found.
    """

    numbers = set()
    for name in get_column_names(file):
        match = re.match('[^0-9]*([0-9]+)', name)
        if match:
            numbers.add(int(match.group(1)))
    return sorted(list(numbers))

def max_value(file, columns):
    """
    Returns the largest value in a set of columns.

    columns:   A list of column names.
    """

    overall_max = None
    for column in columns:
        col_max = max(get_column(file, column))
        if (overall_max == None) or (col_max > overall_max):
            overall_max = col_max
    return overall_max

def node_name(file):
    """
    Given the name of a trace file, return a shorter name that can be
    used (e.g. in titles) to identify the node represented by the file.
    """
    name = Path(file).stem
    i = name.rfind('_')
    if i != -1:
        name = name[i+1:]
    return name

def start_plot(max_x, max_y, title="", x_label="", y_label="", size=10,
       figsize=[6,4]):
    """
    Create a basic pyplot graph without plotting any data. Returns the
    Axes object for the plot.

    max_x:             Maximum x-coordinate
    max_y:             Maximum y-coordinate
    title:             Title for the plot; empty means no title
    x_label:           Label for x-axis
    y_label:           Label for y-axis
    size:              Size to use for fonts
    figsize:           Dimensions of plot
    """

    fig = plt.figure(figsize=figsize)
    ax = fig.add_subplot(111)
    if title != '':
        ax.set_title(title, size=size)
    ax.set_xlim(0, max_x)
    ax.set_ylim(1, max_y)
    if x_label:
        ax.set_xlabel(x_label, size=size)
    if y_label:
        ax.set_ylabel(y_label, size=size)
    return ax

def plot_colors(file):
    """
    Generates a test plot that shows the standard colors defined above.

    file: Name of PDF file in which to write the plot.
    """

    ax = start_plot(200, 100, title='Standard Colors')
    ax.plot([0, 200], [65, 65], color=color_green,    label='color_green')
    ax.plot([0, 200], [60, 60], color=color_blue,     label='color_blue')
    ax.plot([0, 200], [55, 55], color=color_red,      label='color_red')
    ax.plot([0, 200], [50, 50], color=tcp_color,      label='tcp_color')
    ax.plot([0, 200], [45, 45], color=tcp_color2,     label='tcp_color2')
    ax.plot([0, 200], [40, 40], color=tcp_color3,     label='tcp_color3')
    ax.plot([0, 200], [35, 35], color=homa_color,     label='homa_color')
    ax.plot([0, 200], [30, 30], color=homa_color2,    label='homa_color2')
    ax.plot([0, 200], [25, 25], color=homa_color3,    label='homa_color3')
    ax.plot([0, 200], [20, 20], color=dctcp_color,    label='dctcp_color')
    ax.plot([0, 200], [15, 15], color=dctcp_color2,   label='dctcp_color2')
    ax.plot([0, 200], [10, 10], color=dctcp_color3,   label='dctcp_color3')
    ax.plot([0, 200], [5, 5],   color=unloaded_color, label='unloaded_color')
    ax.legend(loc='upper right', prop={'size': 9})
    plt.tight_layout()
    plt.savefig(file)