# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+
"""Regression tests for the timetrace-line regexes in util/.

These document the W605 fix (invalid escape sequences in regex string
literals -> raw strings) and pin down the behaviour that must stay
unchanged. Run standalone:

    python -W error::SyntaxWarning -m pytest util/tests/test_trace_line.py

There is no new CI wiring; this file is included as executable
documentation of the fix.
"""

import ast
import re
import warnings
from pathlib import Path

import pytest

UTIL = Path(__file__).resolve().parent.parent

# The canonical trace-line prefix regex, shared by rpcid.py / smi.py /
# tput.py / tthoma.py after the fix.
PREFIX = re.compile(r' *([-0-9.]+) us .* \[C([0-9]+)\]')

# Table-driven cases: positive, boundary, negative, corner.
PREFIX_CASES = [
    {
        "description": "positive: typical line, extracts timestamp and core",
        "line": "  123.5 us (+ 2.0 us) [C07] homa_data_pkt invoked",
        "expected": ("123.5", "07"),
    },
    {
        "description": "boundary: negative relative timestamp is accepted",
        "line": "  -0.5 us stuff [C00] first event",
        "expected": ("-0.5", "00"),
    },
    {
        "description": "corner: multi-digit core id",
        "line": "0 us x [C128] y",
        "expected": ("0", "128"),
    },
    {
        "description": "negative: literal brackets required, none present",
        "line": "  123.5 us no core marker here",
        "expected": None,
    },
    {
        "description": "negative: '[C..]' must be literal, not a char class",
        "line": "  123.5 us .* CX",
        "expected": None,
    },
]


@pytest.mark.parametrize("case", PREFIX_CASES, ids=lambda c: c["description"])
def test_prefix_regex(case):
    m = PREFIX.match(case["line"])
    if case["expected"] is None:
        assert m is None
    else:
        assert m is not None
        assert m.groups() == case["expected"]


# Every util/*.py that carried a W605 finding must now compile without any
# SyntaxWarning about invalid escape sequences. Compiling the source with
# warnings promoted to errors is the pytest form of the ruff W605 gate.
FIXED_SOURCES = [
    "rpcid.py",
    "smi.py",
    "tput.py",
    "tthoma.py",
    "ttmerge.py",
    "ttsyslog.py",
]


@pytest.mark.parametrize("name", FIXED_SOURCES)
def test_no_invalid_escape_sequences(name):
    src = (UTIL / name).read_text()
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        # Raises SyntaxWarning (-> error) if any invalid escape remains.
        compile(ast.parse(src, filename=name), name, "exec")
