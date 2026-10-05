#!/usr/bin/env bash
# Verify native/UDP Homa transport isolation in both directions,
# including mismatch rejection and matching-transport baseline RPCs.

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
UTIL_DIR="$ROOT_DIR/util"
ARTIFACT_DIR=${ARTIFACT_DIR:-"$SCRIPT_DIR/artifacts/isolation-$(date -u +%Y%m%dT%H%M%SZ)-$$"}
NS_CLIENT="homa-iso-client-$$"
NS_SERVER="homa-iso-server-$$"
CLIENT_IF="hic$$"
SERVER_IF="his$$"
BACKGROUND_PIDS=()
LAST_PID=""

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
	ip netns del "$NS_CLIENT" 2>/dev/null || true
	ip netns del "$NS_SERVER" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

metric_value()
{
	awk '$1 == "unknown_packet_types" {sum += $2} END {print sum + 0}' \
		/proc/net/homa_metrics
}

set_udp()
{
	ip netns exec "$1" sysctl -q -w "net.homa.hijack_udp=$2"
}

start_server()
{
	local output=$1

	ip netns exec "$NS_SERVER" "$UTIL_DIR/server" --port 4000 --verbose \
		> "$output" 2>&1 &
	LAST_PID=$!
	register_pid "$LAST_PID"
}

invoke()
{
	local output=$1

	timeout 20 ip netns exec "$NS_CLIENT" "$UTIL_DIR/homa_test" \
		10.206.0.2:4000 --count 1 --length 100 udp > "$output" 2>&1 &&
		grep -q "Bandwidth at median" "$output"
}

wait_one_second()
{
	local deadline=$((SECONDS + 1))

	while (( SECONDS < deadline )); do
		:
	done
}

[[ $EUID -eq 0 ]] || fail "run as root"
for command in ip sysctl python3 timeout make awk; do
	command -v "$command" >/dev/null 2>&1 ||
		fail "required command not found: $command"
done
[[ -d /proc/sys/net/homa ]] || fail "the Homa module is not loaded"

mkdir -p "$ARTIFACT_DIR"
make -C "$UTIL_DIR" homa_test server
ip netns add "$NS_CLIENT"
ip netns add "$NS_SERVER"
ip link add "$CLIENT_IF" type veth peer name "$SERVER_IF"
ip link set "$CLIENT_IF" netns "$NS_CLIENT"
ip link set "$SERVER_IF" netns "$NS_SERVER"
ip -n "$NS_CLIENT" link set lo up
ip -n "$NS_SERVER" link set lo up
ip -n "$NS_CLIENT" addr add 10.206.0.1/24 dev "$CLIENT_IF"
ip -n "$NS_SERVER" addr add 10.206.0.2/24 dev "$SERVER_IF"
ip -n "$NS_CLIENT" link set "$CLIENT_IF" up
ip -n "$NS_SERVER" link set "$SERVER_IF" up
set_udp "$NS_CLIENT" 0
set_udp "$NS_SERVER" 0

# A socket selected while UDP is disabled must reject a valid packet that
# arrives later through the UDP tunnel.
start_server "$ARTIFACT_DIR/native-server.log"
native_server=$LAST_PID
invoke "$ARTIFACT_DIR/native-baseline.log" ||
	fail "native-selected server did not pass its baseline RPC"
set_udp "$NS_SERVER" 1
before=$(metric_value)
server_lines=$(wc -l < "$ARTIFACT_DIR/native-server.log")
client_mac=$(ip netns exec "$NS_CLIENT" cat "/sys/class/net/$CLIENT_IF/address")
server_mac=$(ip netns exec "$NS_SERVER" cat "/sys/class/net/$SERVER_IF/address")
ip netns exec "$NS_CLIENT" python3 "$SCRIPT_DIR/inject_udp_checksum.py" \
	--interface "$CLIENT_IF" --family 4 \
	--source-ip 10.206.0.1 --destination-ip 10.206.0.2 \
	--source-mac "$client_mac" --destination-mac "$server_mac" --data
wait_one_second
after=$(metric_value)
[[ "$after" == $((before + 1)) ]] ||
	fail "UDP-to-native mismatch changed metric from $before to $after"
[[ $(wc -l < "$ARTIFACT_DIR/native-server.log") == "$server_lines" ]] ||
	fail "UDP-to-native mismatch reached the native application"
stop_pid "$native_server"

# A socket selected while UDP is enabled must reject native Homa traffic.
set_udp "$NS_CLIENT" 1
start_server "$ARTIFACT_DIR/udp-server.log"
udp_server=$LAST_PID
invoke "$ARTIFACT_DIR/udp-baseline.log" ||
	fail "UDP-selected server did not pass its baseline RPC"
set_udp "$NS_CLIENT" 0
before=$(metric_value)
server_lines=$(wc -l < "$ARTIFACT_DIR/udp-server.log")
timeout 3 ip netns exec "$NS_CLIENT" "$UTIL_DIR/homa_test" \
	10.206.0.2:4000 --count 1 --length 100 udp \
	> "$ARTIFACT_DIR/native-mismatch.log" 2>&1 || true
wait_one_second
after=$(metric_value)
(( after > before )) ||
	fail "native-to-UDP mismatch did not increment unknown_packet_types"
[[ $(wc -l < "$ARTIFACT_DIR/udp-server.log") == "$server_lines" ]] ||
	fail "native-to-UDP mismatch reached the UDP application"
if grep -q "Bandwidth at median" "$ARTIFACT_DIR/native-mismatch.log"; then
	fail "native-to-UDP mismatch received a response"
fi
stop_pid "$udp_server"

printf 'PASS: live native/UDP transport isolation in both directions\n'
printf 'Artifacts: %s\n' "$ARTIFACT_DIR"
