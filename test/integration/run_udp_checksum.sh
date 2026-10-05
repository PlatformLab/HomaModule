#!/usr/bin/env bash
# Inject valid, invalid, and computed-zero UDP checksums and verify
# Homa tunnel receive behavior using temporary namespaces and packet captures.

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ARTIFACT_DIR=${ARTIFACT_DIR:-"$SCRIPT_DIR/artifacts/checksum-$(date -u +%Y%m%dT%H%M%SZ)-$$"}
NS_CLIENT="homa-csum-client-$$"
NS_SERVER="homa-csum-server-$$"
CLIENT_IF="hcc$$"
SERVER_IF="hcs$$"
TRACE=/sys/kernel/tracing
BACKGROUND_PIDS=()
TRACE_OWNED=0
LAST_PID=""
RESULTS_FILE="$ARTIFACT_DIR/results.tsv"

fail()
{
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

register_pid()
{
	BACKGROUND_PIDS+=("$1")
}

stop_pid()
{
	local pid=$1
	local signal=${2:-TERM}

	if kill -0 "$pid" 2>/dev/null; then
		kill -s "$signal" "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
}

cleanup()
{
	local pid

	for pid in "${BACKGROUND_PIDS[@]}"; do
		stop_pid "$pid"
	done
	if (( TRACE_OWNED )); then
		printf '0\n' > "$TRACE/tracing_on"
		printf 'nop\n' > "$TRACE/current_tracer"
		printf '\n' > "$TRACE/set_ftrace_filter"
		printf '\n' > "$TRACE/trace"
		printf '1\n' > "$TRACE/tracing_on"
	fi
	ip netns del "$NS_CLIENT" 2>/dev/null || true
	ip netns del "$NS_SERVER" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_for_pattern()
{
	local file=$1
	local pattern=$2
	local deadline=$((SECONDS + 10))

	until grep -q "$pattern" "$file" 2>/dev/null; do
		(( SECONDS < deadline )) || return 1
	done
}

start_capture()
{
	local output=$1
	local log="$output.log"

	ip netns exec "$NS_SERVER" tcpdump --immediate-mode -Q in -U -n \
		-i "$SERVER_IF" -w "$output" "udp port 54321" \
		> "$log" 2>&1 &
	LAST_PID=$!
	register_pid "$LAST_PID"
	wait_for_pattern "$log" "listening on" || fail "tcpdump did not start"
}

wait_for_capture()
{
	local capture=$1
	local deadline=$((SECONDS + 10))

	until tcpdump -n -c 1 -r "$capture" >/dev/null 2>&1; do
		(( SECONDS < deadline )) || return 1
	done
}

run_case()
{
	local family=$1
	local validity=$2
	local expected_callbacks=$3
	local source_ip destination_ip family_name checksum_arg=""
	local capture="$ARTIFACT_DIR/ipv${family}-${validity}.pcap"
	local capture_pid callback_count expected_valid

	if [[ "$family" == 4 ]]; then
		source_ip=10.205.0.1
		destination_ip=10.205.0.2
		family_name=ipv4
	else
		source_ip=fd00:205::1
		destination_ip=fd00:205::2
		family_name=ipv6
	fi
	if [[ "$validity" == invalid ]]; then
		checksum_arg=--invalid
		expected_valid=0
	elif [[ "$validity" == zero ]]; then
		checksum_arg=--zero-checksum
		expected_valid=1
	else
		expected_valid=1
	fi

	start_capture "$capture"
	capture_pid=$LAST_PID
	printf '0\n' > "$TRACE/tracing_on"
	printf '\n' > "$TRACE/trace"
	printf '1\n' > "$TRACE/tracing_on"
	ip netns exec "$NS_CLIENT" python3 "$SCRIPT_DIR/inject_udp_checksum.py" \
		--interface "$CLIENT_IF" --family "$family" \
		--source-ip "$source_ip" --destination-ip "$destination_ip" \
		--source-mac "$CLIENT_MAC" --destination-mac "$SERVER_MAC" \
		$checksum_arg
	wait_for_capture "$capture" || fail "$family_name $validity frame not captured"
	printf '0\n' > "$TRACE/tracing_on"
	stop_pid "$capture_pid" INT
	callback_count=$(grep -c 'homa_hijack_udp_encap_rcv' "$TRACE/trace" || true)
	[[ "$callback_count" == "$expected_callbacks" ]] ||
		fail "$family_name $validity frame invoked Homa $callback_count times; expected $expected_callbacks"
	python3 - "$SCRIPT_DIR" "$capture" "$family_name" "$expected_valid" \
		"$validity" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
import verify_udp_pcap

packets = []
for _, frame in verify_udp_pcap.read_pcap(sys.argv[2]):
    parsed = verify_udp_pcap.parse_udp(frame)
    if parsed is not None:
        packets.append(parsed)
if len(packets) != 1:
    raise SystemExit("expected one captured UDP packet, found %d" % len(packets))
packet = packets[0]
if packet["family"] != sys.argv[3]:
    raise SystemExit("captured the wrong address family")
expected_valid = bool(int(sys.argv[4]))
if packet["checksum_valid"] != expected_valid:
    raise SystemExit("captured checksum validity did not match the test case")
if packet["checksum"] == 0:
    raise SystemExit("test packet used a zero UDP checksum")
if sys.argv[5] == "zero" and packet["checksum"] != 0xFFFF:
	raise SystemExit("computed-zero checksum was not transmitted as 0xffff")
PY
	printf '%s\tpass\tcaptured once; Homa callbacks=%s\n' \
		"$family_name-$validity" "$callback_count" >> "$RESULTS_FILE"
}

[[ $EUID -eq 0 ]] || fail "run as root"
for command in ip sysctl tcpdump python3; do
	command -v "$command" >/dev/null 2>&1 ||
		fail "required command not found: $command"
done
[[ -d /proc/sys/net/homa ]] || fail "the Homa module is not loaded"
[[ -w "$TRACE/current_tracer" ]] || fail "ftrace is unavailable"
[[ $(cat "$TRACE/current_tracer") == nop ]] || fail "ftrace is already in use"
[[ $(cat "$TRACE/function_profile_enabled") == 0 ]] ||
	fail "ftrace function profiling is already in use"
grep -q '^homa_hijack_udp_encap_rcv' "$TRACE/available_filter_functions" ||
	fail "homa_hijack_udp_encap_rcv is unavailable to ftrace"

mkdir -p "$ARTIFACT_DIR"
: > "$RESULTS_FILE"
ip netns add "$NS_CLIENT"
ip netns add "$NS_SERVER"
ip link add "$CLIENT_IF" type veth peer name "$SERVER_IF"
ip link set "$CLIENT_IF" netns "$NS_CLIENT"
ip link set "$SERVER_IF" netns "$NS_SERVER"
ip -n "$NS_CLIENT" link set lo up
ip -n "$NS_SERVER" link set lo up
ip -n "$NS_CLIENT" addr add 10.205.0.1/24 dev "$CLIENT_IF"
ip -n "$NS_SERVER" addr add 10.205.0.2/24 dev "$SERVER_IF"
ip -n "$NS_CLIENT" addr add fd00:205::1/64 dev "$CLIENT_IF" nodad
ip -n "$NS_SERVER" addr add fd00:205::2/64 dev "$SERVER_IF" nodad
ip netns exec "$NS_CLIENT" sysctl -q -w \
	"net.ipv6.conf.$CLIENT_IF.accept_dad=0"
ip netns exec "$NS_SERVER" sysctl -q -w \
	"net.ipv6.conf.$SERVER_IF.accept_dad=0"
ip -n "$NS_CLIENT" link set "$CLIENT_IF" up
ip -n "$NS_SERVER" link set "$SERVER_IF" up
ip netns exec "$NS_SERVER" sysctl -q -w net.homa.hijack_udp=1
CLIENT_MAC=$(ip netns exec "$NS_CLIENT" cat "/sys/class/net/$CLIENT_IF/address")
SERVER_MAC=$(ip netns exec "$NS_SERVER" cat "/sys/class/net/$SERVER_IF/address")

printf '0\n' > "$TRACE/tracing_on"
printf '\n' > "$TRACE/trace"
printf 'homa_hijack_udp_encap_rcv\n' > "$TRACE/set_ftrace_filter"
printf 'function\n' > "$TRACE/current_tracer"
TRACE_OWNED=1

run_case 4 valid 1
run_case 4 invalid 0
run_case 4 zero 1
run_case 6 valid 1
run_case 6 invalid 0
run_case 6 zero 1

printf 'PASS: invalid IPv4/IPv6 UDP checksums were dropped before Homa\n'
printf 'Artifacts: %s\n' "$ARTIFACT_DIR"