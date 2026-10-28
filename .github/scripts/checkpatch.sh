#!/bin/bash

# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

# Usage: .github/scripts/checkpatch.sh <base> <linux> [stripped]
#
# Run checkpatch on the change from commit <base> to the working tree, in the
# same way as the netdev patch checks (NIPA). <linux> is a Linux source tree;
# its scripts/checkpatch.pl is used. Run this from the top of the repository.
#
# Without "stripped", check the module sources as they are (CHECK_SRCS in the
# Makefile, as "make checkpatch"). With "stripped", check the files that go
# upstream, after util/strip.py (as "make checkpatch-net-next"). util/ and
# test/ are not checked. The main branch has checkpatch findings of its own,
# so only the change is checked.
#
# The exit status is 1 if checkpatch reports an error, and 0 otherwise:
# warnings and checks do not fail, as in NIPA.

set -e

if [ $# -lt 2 ] || [ $# -gt 3 ] || [ "${3:-stripped}" != stripped ]; then
	echo "Usage: $0 <base> <linux> [stripped]" >&2
	exit 2
fi
base=$1
linux=$2
stripped=$3
work=$(mktemp -d)
trap 'rm -rf $work' EXIT

# Put into directory $2 the code of tree $1 that checkpatch must see.
prepare_tree() {
	local tree=$1 out=$2 srcs

	if [ -n "$stripped" ]; then
		# "make net-next" writes the stripped files into a Linux source
		# tree: the module into net/homa and homa.h into
		# include/uapi/linux.
		mkdir -p $out/net $out/include/uapi/linux
		make -s -C $tree net-next LINUX_SRC_DIR=$out HOMA_TARGET=$out/net/homa
	else
		# "make print-CHECK_SRCS" prints "CHECK_SRCS = <files>".
		srcs=$(make -s -C $tree print-CHECK_SRCS | sed 's/^CHECK_SRCS = //')
		mkdir -p $out
		(cd $tree && cp $srcs $out/)
	fi
}

# Check the diff in file $1 with the options of NIPA
# (tests/patch/checkpatch/checkpatch.sh). The diff is not in a Linux tree and
# has no commit message: hence --no-tree, --no-signoff and COMMIT_MESSAGE, and
# NIPA's ignored types for commit messages are left out.
run_checkpatch() {
	local diff=$1 result=$work/checkpatch.out

	# checkpatch exits with 1 for warnings and checks too, so its exit
	# status is not used; the result is read below.
	$linux/scripts/checkpatch.pl --strict --codespell --max-line-length=80 \
		--no-tree --no-signoff --color=never \
		--ignore=COMMIT_MESSAGE,MACRO_ARG_REUSE,ALLOC_SIZEOF_STRUCT,CAMELCASE,FILE_PATH_CHANGES \
		$diff > $result || true

	# In GitHub Actions, a line that starts with "::warning::" shows as an
	# annotation, so add it to warnings and checks there.
	if [ -n "$GITHUB_ACTIONS" ]; then
		sed -E 's/^(WARNING|CHECK):/::warning::&/' $result
	else
		cat $result
	fi

	if grep -q '^ERROR:' $result; then
		echo "checkpatch found errors."
		return 1
	fi
}

# Prepare this tree first, so that a util/strip.py failure always shows.
prepare_tree . $work/head

if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
	echo "Base commit '$base' is not in this repository: checkpatch skipped."
	exit 0
fi
mkdir $work/base-src
git archive $base | tar -x -C $work/base-src
prepare_tree $work/base-src $work/base

cd $work
# diff exits with 1 when the trees differ, which is the normal case.
diff -ruN base head > change.diff || true
if [ ! -s change.diff ]; then
	echo "The change does not touch checked code: checkpatch skipped."
	exit 0
fi
run_checkpatch change.diff
