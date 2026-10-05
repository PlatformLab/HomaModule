#!/usr/bin/env bash
# Drop a UDP tunnel packet once and verify RPC recovery, retransmitted
# DATA, and Homa control packet classes from captured traffic.

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
UTIL_DIR="$ROOT_DIR/util"
ARTIFACT_DIR=${ARTIFACT_DIR:-"$SCRIPT_DIR/artifacts/retransmit-$(date -u +%Y%m%dT%H%M%SZ)-$$"}
NS_CLIENT="homa-retx-client-$$"
NS_SERVER="homa-retx-server-$$"
CLIENT_IF="hrc$$"
SERVER_IF="hrs$$"
BACKGROUND_PIDS=()
LAST_PID=""
RULE_ACTIVE=0

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

remove_drop_rule()
{
	if (( RULE_ACTIVE )); then
		ip netns exec "$NS_CLIENT" iptables -D OUTPUT -p udp \
			--dport 54321 -m statistic --mode nth --every 100000 \
			--packet 2 -j DROP 2>/dev/null || true
		RULE_ACTIVE=0
	fi
}

cleanup()
{
	local pid

	remove_drop_rule
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

[[ $EUID -eq 0 ]] || fail "run as root"
for command in ip sysctl tcpdump ethtool iptables python3 timeout make; do
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
ip -n "$NS_CLIENT" addr add 10.207.0.1/24 dev "$CLIENT_IF"
ip -n "$NS_SERVER" addr add 10.207.0.2/24 dev "$SERVER_IF"
ip -n "$NS_CLIENT" link set "$CLIENT_IF" up
ip -n "$NS_SERVER" link set "$SERVER_IF" up
ip netns exec "$NS_CLIENT" ethtool -K "$CLIENT_IF" tx off \
	> "$ARTIFACT_DIR/client-offload.log" 2>&1
ip netns exec "$NS_SERVER" ethtool -K "$SERVER_IF" tx off \
	> "$ARTIFACT_DIR/server-offload.log" 2>&1
ip netns exec "$NS_CLIENT" sysctl -q -w net.homa.hijack_udp=1
ip netns exec "$NS_SERVER" sysctl -q -w net.homa.hijack_udp=1

ip netns exec "$NS_SERVER" "$UTIL_DIR/server" --port 4200 \
	--validate --verbose > "$ARTIFACT_DIR/server.log" 2>&1 &
server_pid=$!
register_pid "$server_pid"

ip netns exec "$NS_CLIENT" tcpdump --immediate-mode -U -n -i "$CLIENT_IF" -w \
	"$ARTIFACT_DIR/retransmit.pcap" "udp port 54321" \
	> "$ARTIFACT_DIR/tcpdump.log" 2>&1 &
capture_pid=$!
register_pid "$capture_pid"
wait_for_pattern "$ARTIFACT_DIR/tcpdump.log" "listening on" ||
	fail "tcpdump did not become ready"

ip netns exec "$NS_CLIENT" iptables -I OUTPUT 1 -p udp --dport 54321 \
	-m statistic --mode nth --every 100000 --packet 2 -j DROP
RULE_ACTIVE=1
timeout 30 ip netns exec "$NS_CLIENT" "$UTIL_DIR/homa_test" \
	10.207.0.2:4200 --count 1 --length 65536 udp \
	> "$ARTIFACT_DIR/client.log" 2>&1 || fail "retransmission RPC failed"
grep -q "Bandwidth at median" "$ARTIFACT_DIR/client.log" ||
	fail "retransmission RPC did not complete"
ip netns exec "$NS_CLIENT" iptables -L OUTPUT 1 -v -n -x \
	> "$ARTIFACT_DIR/drop-rule.log"
dropped=$(awk 'NR == 1 {print $1}' "$ARTIFACT_DIR/drop-rule.log")
[[ "$dropped" == 1 ]] || fail "drop rule matched $dropped packets instead of 1"
remove_drop_rule

client_mac=$(ip netns exec "$NS_CLIENT" \
	cat "/sys/class/net/$CLIENT_IF/address")
server_mac=$(ip netns exec "$NS_SERVER" \
	cat "/sys/class/net/$SERVER_IF/address")
timeout 10 ip netns exec "$NS_CLIENT" tcpdump --immediate-mode -U -n \
	-i "$CLIENT_IF" -c 2 \
	'udp dst port 54321 and (udp[19] = 0x13 or udp[19] = 0x18)' \
	> "$ARTIFACT_DIR/control-responses.log" 2>&1 &
control_capture_pid=$!
register_pid "$control_capture_pid"
wait_for_pattern "$ARTIFACT_DIR/control-responses.log" "listening on" ||
	fail "control-response capture did not become ready"
for control in resend need-ack; do
	ip netns exec "$NS_CLIENT" python3 "$SCRIPT_DIR/inject_udp_checksum.py" \
		--interface "$CLIENT_IF" --family 4 \
		--source-ip 10.207.0.1 --destination-ip 10.207.0.2 \
		--source-mac "$client_mac" --destination-mac "$server_mac" \
		--homa-source-port 4100 --homa-destination-port 4200 \
		"--$control"
done
wait "$control_capture_pid" ||
	fail "did not observe RPC_UNKNOWN and ACK control responses"

stop_pid "$capture_pid" INT
stop_pid "$server_pid"

python3 "$SCRIPT_DIR/verify_udp_retransmit.py" \
	"$ARTIFACT_DIR/retransmit.pcap" | tee "$ARTIFACT_DIR/retransmit.json"
printf 'PASS: one dropped DATA datagram was retransmitted successfully\n'
printf 'Artifacts: %s\n' "$ARTIFACT_DIR"
