#!/usr/bin/python3

# SPDX-License-Identifier: BSD-2-Clause

"""
This script is used to make a copy of homa_impl.h that seletively omits
certain function definitions, depending on which patch in a patch series
is being generated.

Usage: strip_decl.py src dst patch

Src gives the file to read, dst names the file to (over)write, and patch
identifies the specific patch that is being generated (it must be one
of the initial values in a sublist of symbols below).
"""

from collections import defaultdict
from glob import glob
import math
import os
import re
import string
import sys

# Each list element is a list containing a patch name followed by any number
# of line prefixes. The lists are in patch order: a line will be excluded
# from the output file it starts with one of the prefixes for a patch *after*
# the one specified on the command line. The "none" patch includes no symbols,
# "all" includes all symbols.
symbols = [
    ['none'],
    ['outgoing',
        'int      homa_fill_data_interleaved(',
        'int      homa_message_out_fill(',
        'void     homa_message_out_init(',
        'struct sk_buff *homa_tx_data_pkt_alloc(',
        'int      homa_xmit_control(',
        'int      __homa_xmit_control(',
        'void     homa_xmit_data(',
        'void     __homa_xmit_data(',
        'void     homa_xmit_unknown('
    ],
    ['utils',
        'void     homa_destroy(',
        'int      homa_init(',
        'void     homa_spin('
    ],
    ['incoming',
        'void     homa_ack_pkt(',
        'void     homa_add_packet(',
        'int      homa_copy_to_user(',
        'void     homa_data_pkt(',
        'void     homa_dispatch_pkts(',
        'struct homa_gap *homa_gap_alloc(',
        'void     homa_gap_retry(',
        'int      homa_message_in_init(',
        'void     homa_need_ack_pkt(',
        'void     homa_resend_data(',
        'void     homa_resend_pkt(',
        'void     homa_rpc_handoff(',
        'void     homa_rpc_unknown_pkt(',
        'int      homa_wait_private(',
        'struct homa_rpc *homa_wait_shared('
	],
    ['timer',
        'void     homa_timer(',
	    'void     homa_timer_check_rpc(',
        'int      homa_timer_main('
    ],
    ['plumbing',
        'int      homa_bind(',
        'void     homa_close(',
        'int      homa_err_handler_v4(',
        'int      homa_err_handler_v6(',
        'int      homa_getsockopt(',
        'int      homa_hash(',
        'enum hrtimer_restart homa_hrtimer(',
        'int      homa_ioctl(',
        'int      homa_load(',
        'int      homa_net_init(',
        'void     homa_net_exit(',
        '__poll_t homa_poll(',
        'int      homa_recvmsg(',
        'int      homa_sendmsg(',
        'int      homa_setsockopt(',
        'int      homa_shutdown(',
        'int      homa_softirq(',
        'void     homa_unhash(',
        'void     homa_unload('
    ],
    ['all']
]


if len(sys.argv) != 4:
    print('Usage: strip_decl.py src dst patch')
    exit(1)

src = open(sys.argv[1])
dst = open(sys.argv[2], 'w')
patch_name = sys.argv[3]
skipping_to_semi = False
prev_line_empty = False
for line in src:
    if skipping_to_semi:
        if line.endswith(';\n'):
            skipping_to_semi = False
        continue

    found_patch = False
    omit = False
    for patch in symbols:
        if found_patch:
            for prefix in patch[1:]:
                if line.startswith(prefix):
                    omit = True
                    break
            if omit:
                break
        if patch_name == patch[0]:
            found_patch = True
    if omit:
        if not line.endswith(';\n'):
            skipping_to_semi = True
    else:
        if line == '\n':
            prev_line_empty = True
        else:
            if prev_line_empty:
                print('', file=dst,)
            print(line, file=dst, end='')
            prev_line_empty = False

dst.close()
src.close()