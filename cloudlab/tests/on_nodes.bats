#!/usr/bin/env bats

# SPDX-License-Identifier: BSD-1-Clause
#
# Regression tests for cloudlab/bin/on_nodes.
#
# These document the SC2068 fix: the remote command and its arguments
# must be forwarded to ssh with their word boundaries intact, which
# requires "$@" (quoted) rather than a bare $@. With an unquoted $@ an
# argument containing spaces or glob characters is re-split / expanded by
# the loop's word splitting before ssh ever sees it.
#
# Run:  nix shell nixpkgs#bats -c bats cloudlab/tests/on_nodes.bats
#
# No new CI is wired; this file is included as executable documentation.

setup() {
    ON_NODES="${BATS_TEST_DIRNAME}/../bin/on_nodes"

    # Stub PATH with a fake ssh that records exactly the argv it receives,
    # one argument per line, so tests can assert on argument boundaries.
    STUB_DIR="$(mktemp -d)"
    ARGV_LOG="${STUB_DIR}/argv.log"
    cat > "${STUB_DIR}/ssh" <<EOF
#!/usr/bin/env bash
: > "${ARGV_LOG}"
for a in "\$@"; do
    printf '%s\n' "\$a" >> "${ARGV_LOG}"
done
EOF
    chmod +x "${STUB_DIR}/ssh"
    PATH="${STUB_DIR}:${PATH}"
}

teardown() {
    rm -rf "${STUB_DIR}"
}

# Argument count that ssh saw, minus the leading `-4 nodeN` (2 args).
forwarded_count() {
    echo $(( $(wc -l < "${ARGV_LOG}") - 2 ))
}

@test "usage error when fewer than 3 args" {
    run "$ON_NODES" 1
    [ "$status" -eq 1 ]
    [[ "$output" == Usage:* ]]
}

@test "simple command is forwarded verbatim" {
    run "$ON_NODES" 1 1 echo hello
    [ "$status" -eq 0 ]
    # ssh argv: -4 node1 echo hello
    run cat "${ARGV_LOG}"
    [ "${lines[0]}" = "-4" ]
    [ "${lines[1]}" = "node1" ]
    [ "${lines[2]}" = "echo" ]
    [ "${lines[3]}" = "hello" ]
}

@test "argument containing spaces stays a single argument" {
    "$ON_NODES" 1 1 echo "one two three"
    # 2 forwarded args: 'echo' and 'one two three' (NOT split into 4).
    [ "$(forwarded_count)" -eq 2 ]
    run cat "${ARGV_LOG}"
    [ "${lines[3]}" = "one two three" ]
}

@test "argument with a glob char is not expanded by on_nodes" {
    "$ON_NODES" 1 1 ls '*.c'
    [ "$(forwarded_count)" -eq 2 ]
    run cat "${ARGV_LOG}"
    [ "${lines[3]}" = "*.c" ]
}

@test "empty-string argument is preserved as one argument" {
    "$ON_NODES" 1 1 echo ""
    # 'echo' + one empty arg = 2 forwarded args.
    [ "$(forwarded_count)" -eq 2 ]
}
