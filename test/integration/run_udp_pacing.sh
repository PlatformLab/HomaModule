#!/usr/bin/env bash
# Compare native Homa throughput with UDP tunnel traffic and verify
# pacing on a 100 Mbit/s link using packet captures and qdisc statistics.

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
UTIL_DIR="$ROOT_DIR/util"
ARTIFACT_DIR=${ARTIFACT_DIR:-"$SCRIPT_DIR/artifacts/pacing-$(date -u +%Y%m%dT%H%M%SZ)-$$"}
NS_CLIENT="homa-pace-client-$$"
NS_SERVER="homa-pace-server-$$"
CLIENT_IF="hpc$$"
SERVER_IF="hps$$"
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

wait_for_pattern()
{
	local file=$1
	local pattern=$2
	local deadline=$((SECONDS + 10))

	until grep -q "$pattern" "$file" 2>/dev/null; do
		(( SECONDS < deadline )) || return 1
	done
}

start_server()
{
	local port=$1
	local log=$2

	ip netns exec "$NS_SERVER" "$UTIL_DIR/server" --port "$port" \
		--validate --verbose > "$ARTIFACT_DIR/$log" 2>&1 &
	LAST_PID=$!
	register_pid "$LAST_PID"
}

start_capture()
{
	local pcap=$1
	local filter=$2
	local log="${pcap%.pcap}.capture.log"

	ip netns exec "$NS_SERVER" tcpdump --immediate-mode -Q in -U -n \
		-i "$SERVER_IF" -w "$pcap" "$filter" > "$log" 2>&1 &
	LAST_PID=$!
	register_pid "$LAST_PID"
	wait_for_pattern "$log" "listening on" || fail "tcpdump did not become ready"
}

run_stream()
{
	local port=$1
	local log=$2

	timeout 15 ip netns exec "$NS_CLIENT" "$UTIL_DIR/homa_test" \
		"10.208.0.2:$port" --count 1 --length 1000000 stream \
		> "$ARTIFACT_DIR/$log" 2>&1 || fail "stream workload failed"
	grep -q "Homa throughput" "$ARTIFACT_DIR/$log" ||
		fail "stream workload did not report throughput"
}

[[ $EUID -eq 0 ]] || fail "run as root"
for command in ip sysctl tcpdump ethtool tc python3 timeout make date; do
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
ip -n "$NS_CLIENT" addr add 10.208.0.1/24 dev "$CLIENT_IF"
ip -n "$NS_SERVER" addr add 10.208.0.2/24 dev "$SERVER_IF"
ip -n "$NS_CLIENT" link set "$CLIENT_IF" up
ip -n "$NS_SERVER" link set "$SERVER_IF" up
ip netns exec "$NS_CLIENT" ethtool -K "$CLIENT_IF" tx off \
	> "$ARTIFACT_DIR/client-offload.log" 2>&1
ip netns exec "$NS_SERVER" ethtool -K "$SERVER_IF" tx off \
	> "$ARTIFACT_DIR/server-offload.log" 2>&1
for endpoint in "$NS_CLIENT:$CLIENT_IF" "$NS_SERVER:$SERVER_IF"; do
	namespace=${endpoint%%:*}
	interface=${endpoint#*:}
	ip netns exec "$namespace" tc qdisc add dev "$interface" root \
		netem limit 20000 rate 100mbit
	ip netns exec "$namespace" tc -s qdisc show dev "$interface"
done > "$ARTIFACT_DIR/qdisc.txt"

ip netns exec "$NS_CLIENT" sysctl -q -w net.homa.hijack_udp=0
ip netns exec "$NS_SERVER" sysctl -q -w net.homa.hijack_udp=0
start_server 4300 server-native.log
native_server=$LAST_PID
start_capture "$ARTIFACT_DIR/native-baseline.pcap" "ip proto 146"
native_capture=$LAST_PID
run_stream 4300 native-stream.log
stop_pid "$native_capture" INT
stop_pid "$native_server"
native_gbps=$(awk '/Homa throughput/ {print $(NF-1)}' \
	"$ARTIFACT_DIR/native-stream.log")
python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= 0.00875 else 1)' \
	"$native_gbps" || fail "native baseline was below 70 Mbit/s"

ip netns exec "$NS_CLIENT" sysctl -q -w net.homa.hijack_udp=1
ip netns exec "$NS_SERVER" sysctl -q -w net.homa.hijack_udp=1
start_server 4301 server-udp-stream.log
udp_stream_server=$LAST_PID
start_capture "$ARTIFACT_DIR/udp-stream.pcap" "udp port 54321"
udp_capture=$LAST_PID
run_stream 4301 udp-stream.log
stop_pid "$udp_capture" INT
stop_pid "$udp_stream_server"
python3 "$SCRIPT_DIR/verify_udp_pacing.py" \
	"$ARTIFACT_DIR/udp-stream.pcap" | tee "$ARTIFACT_DIR/pacing.json"
cat > "$ARTIFACT_DIR/srpt.json" <<'EOF'
{"reason":"veth reports fixed 10 Gbit/s speed; Homa qdisc minimum is 5%, and its bulk RPC made no progress at that setting","status":"incomplete"}
EOF
printf 'PASS: UDP pacing checks completed\n'
printf 'INCOMPLETE: SRPT requires a rate-configurable Homa-qdisc device\n'
printf 'Artifacts: %s\n' "$ARTIFACT_DIR"
