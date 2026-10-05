#!/usr/bin/env bash
# Exercise routed IPv4/IPv6 path-MTU discovery and tiny-MTU rejection
# for Homa-over-UDP RPCs in temporary network namespaces.

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
UTIL_DIR="$ROOT_DIR/util"
ARTIFACT_DIR=${ARTIFACT_DIR:-"$SCRIPT_DIR/artifacts/pmtu-$(date -u +%Y%m%dT%H%M%SZ)-$$"}
NS_CLIENT="homa-pmtu-client-$$"
NS_ROUTER="homa-pmtu-router-$$"
NS_SERVER="homa-pmtu-server-$$"
CLIENT_IF="pmc$$"
ROUTER_CLIENT_IF="pmrc$$"
ROUTER_SERVER_IF="pmrs$$"
SERVER_IF="pms$$"
BACKGROUND_PIDS=()
LAST_PID=""

log()
{
	printf '%s\n' "$*"
}

fail()
{
	log "FAIL: $*"
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
	ip netns del "$NS_ROUTER" 2>/dev/null || true
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
	local namespace=$1
	local interface=$2
	local output=$3
	local filter=$4
	local capture_log="$output.log"

	ip netns exec "$namespace" tcpdump --immediate-mode -U -n -i "$interface" \
		-w "$output" "$filter" > "$capture_log" 2>&1 &
	LAST_PID=$!
	register_pid "$LAST_PID"
	wait_for_pattern "$capture_log" "listening on" ||
		fail "tcpdump did not become ready on $namespace/$interface"
}

run_followup()
{
	local family=$1
	local target=$2
	local port=$3
	local output=$4
	local family_args=()
	local attempt

	if [[ "$family" == ipv6 ]]; then
		family_args+=(--ipv6)
	fi
	for attempt in 1 2 3 4 5; do
		if timeout 20 ip netns exec "$NS_CLIENT" "$UTIL_DIR/homa_test" \
			"$target:$port" "${family_args[@]}" --count 1 --length 8192 udp \
			> "$output" 2>&1 && grep -q "Bandwidth at median" "$output"; then
			return 0
		fi
	done
	return 1
}

verify_maximum_length()
{
	local capture=$1
	local summary=$2

	python3 "$SCRIPT_DIR/verify_udp_pcap.py" --json "$capture" > "$summary"
	python3 - "$summary" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as input_file:
    summary = json.load(input_file)
if summary["max_outer_length"] > 1280:
    raise SystemExit("post-PMTU packet exceeded 1280 bytes: %d" %
                     summary["max_outer_length"])
PY
}

run_family()
{
	local family=$1
	local target=$2
	local port=$3
	local icmp_filter=$4
	local icmp_pattern=$5
	local family_args=()
	local pre_capture="$ARTIFACT_DIR/$family-before-pmtu.pcap"
	local post_capture="$ARTIFACT_DIR/$family-after-pmtu.pcap"
	local first_log="$ARTIFACT_DIR/$family-first-rpc.log"
	local followup_log="$ARTIFACT_DIR/$family-followup-rpc.log"
	local summary="$ARTIFACT_DIR/$family-after-pmtu.json"
	local pre_capture_pid
	local post_capture_pid

	if [[ "$family" == ipv6 ]]; then
		family_args+=(--ipv6)
	fi
	start_capture "$NS_CLIENT" "$CLIENT_IF" "$pre_capture" \
		"udp port 54321 or $icmp_filter"
	pre_capture_pid=$LAST_PID
	timeout 20 ip netns exec "$NS_CLIENT" "$UTIL_DIR/homa_test" \
		"$target:$port" "${family_args[@]}" --count 1 --length 8192 udp \
		> "$first_log" 2>&1 || true
	stop_pid "$pre_capture_pid" INT
	grep -qi "Message too long" "$first_log" ||
		fail "$family current RPC did not report EMSGSIZE"
	tcpdump -nn -r "$pre_capture" "$icmp_filter" 2>/dev/null |
		grep -qi "$icmp_pattern" ||
		fail "$family PMTU ICMP error was not captured"

	start_capture "$NS_SERVER" "$SERVER_IF" "$post_capture" \
		"udp port 54321"
	post_capture_pid=$LAST_PID
	run_followup "$family" "$target" "$port" "$followup_log" ||
		fail "$family follow-up RPC did not succeed after PMTU update"
	stop_pid "$post_capture_pid" INT
	verify_maximum_length "$post_capture" "$summary"
	log "PASS: $family PMTU error, RPC abort, and reduced geometry"
}

run_tiny_mtu()
{
	local capture="$ARTIFACT_DIR/ipv4-tiny-mtu.pcap"
	local client_log="$ARTIFACT_DIR/ipv4-tiny-mtu.log"
	local capture_pid
	local packet_count

	ip -n "$NS_CLIENT" route add 10.204.2.3/32 via 10.204.1.1 mtu lock 80
	start_capture "$NS_SERVER" "$SERVER_IF" "$capture" "udp port 54321"
	capture_pid=$LAST_PID
	timeout 20 ip netns exec "$NS_CLIENT" "$UTIL_DIR/homa_test" \
		10.204.2.3:4100 --count 1 --length 100 udp > "$client_log" 2>&1 || true
	stop_pid "$capture_pid" INT
	grep -qi "Message too long" "$client_log" ||
		fail "tiny-MTU IPv4 RPC did not report EMSGSIZE"
	packet_count=$(tcpdump -nn -r "$capture" "udp port 54321" \
		2>/dev/null | wc -l)
	[[ "$packet_count" == 0 ]] ||
		fail "tiny-MTU IPv4 RPC emitted $packet_count UDP packets"
	log "PASS: tiny IPv4 route MTU returned EMSGSIZE without transmission"
}

[[ $EUID -eq 0 ]] || fail "run as root"
for command in ip sysctl tcpdump ethtool python3 timeout make; do
	command -v "$command" >/dev/null 2>&1 ||
		fail "required command not found: $command"
done
[[ -d /proc/sys/net/homa ]] || fail "the Homa module is not loaded"
mkdir -p "$ARTIFACT_DIR"
make -C "$UTIL_DIR" homa_test server

ip netns add "$NS_CLIENT"
ip netns add "$NS_ROUTER"
ip netns add "$NS_SERVER"
ip link add "$CLIENT_IF" type veth peer name "$ROUTER_CLIENT_IF"
ip link add "$ROUTER_SERVER_IF" type veth peer name "$SERVER_IF"
ip link set "$CLIENT_IF" netns "$NS_CLIENT"
ip link set "$ROUTER_CLIENT_IF" netns "$NS_ROUTER"
ip link set "$ROUTER_SERVER_IF" netns "$NS_ROUTER"
ip link set "$SERVER_IF" netns "$NS_SERVER"

for namespace in "$NS_CLIENT" "$NS_ROUTER" "$NS_SERVER"; do
	ip -n "$namespace" link set lo up
done
ip -n "$NS_CLIENT" addr add 10.204.1.2/24 dev "$CLIENT_IF"
ip -n "$NS_ROUTER" addr add 10.204.1.1/24 dev "$ROUTER_CLIENT_IF"
ip -n "$NS_ROUTER" addr add 10.204.2.1/24 dev "$ROUTER_SERVER_IF"
ip -n "$NS_SERVER" addr add 10.204.2.2/24 dev "$SERVER_IF"
ip -n "$NS_SERVER" addr add 10.204.2.3/24 dev "$SERVER_IF"
ip -n "$NS_CLIENT" addr add fd00:204:1::2/64 dev "$CLIENT_IF" nodad
ip -n "$NS_ROUTER" addr add fd00:204:1::1/64 dev "$ROUTER_CLIENT_IF" nodad
ip -n "$NS_ROUTER" addr add fd00:204:2::1/64 dev "$ROUTER_SERVER_IF" nodad
ip -n "$NS_SERVER" addr add fd00:204:2::2/64 dev "$SERVER_IF" nodad
ip netns exec "$NS_CLIENT" sysctl -q -w \
	"net.ipv6.conf.$CLIENT_IF.accept_dad=0"
ip netns exec "$NS_ROUTER" sysctl -q -w \
	"net.ipv6.conf.$ROUTER_CLIENT_IF.accept_dad=0"
ip netns exec "$NS_ROUTER" sysctl -q -w \
	"net.ipv6.conf.$ROUTER_SERVER_IF.accept_dad=0"
ip netns exec "$NS_SERVER" sysctl -q -w \
	"net.ipv6.conf.$SERVER_IF.accept_dad=0"
ip -n "$NS_CLIENT" link set "$CLIENT_IF" up
ip -n "$NS_ROUTER" link set "$ROUTER_CLIENT_IF" up
ip -n "$NS_ROUTER" link set "$ROUTER_SERVER_IF" mtu 1280 up
ip -n "$NS_SERVER" link set "$SERVER_IF" mtu 1280 up
ip netns exec "$NS_CLIENT" ethtool -K "$CLIENT_IF" tx off \
	> "$ARTIFACT_DIR/offload-disable-client.log" 2>&1
ip netns exec "$NS_SERVER" ethtool -K "$SERVER_IF" tx off \
	> "$ARTIFACT_DIR/offload-disable-server.log" 2>&1
ip -n "$NS_CLIENT" route add 10.204.2.0/24 via 10.204.1.1
ip -n "$NS_SERVER" route add 10.204.1.0/24 via 10.204.2.1
ip -n "$NS_CLIENT" -6 route add fd00:204:2::/64 via fd00:204:1::1
ip -n "$NS_SERVER" -6 route add fd00:204:1::/64 via fd00:204:2::1
ip netns exec "$NS_ROUTER" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$NS_ROUTER" sysctl -q -w net.ipv6.conf.all.forwarding=1
ip netns exec "$NS_CLIENT" sysctl -q -w net.homa.hijack_udp=1
ip netns exec "$NS_SERVER" sysctl -q -w net.homa.hijack_udp=1

ip netns exec "$NS_SERVER" "$UTIL_DIR/server" --port 4100 \
	--validate --verbose > "$ARTIFACT_DIR/server-v4.log" 2>&1 &
register_pid "$!"
ip netns exec "$NS_SERVER" "$UTIL_DIR/server" --ipv6 --port 4101 \
	--validate --verbose > "$ARTIFACT_DIR/server-v6.log" 2>&1 &
register_pid "$!"

run_family ipv4 10.204.2.2 4100 icmp "need to frag"
run_family ipv6 "[fd00:204:2::2]" 4101 icmp6 "packet too big"
run_tiny_mtu

log "PASS: UDP tunnel PMTU integration checks completed"
log "Artifacts: $ARTIFACT_DIR"
