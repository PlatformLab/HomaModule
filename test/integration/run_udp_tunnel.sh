#!/usr/bin/env bash
# Exercise UDP tunnel setup, IPv4/IPv6 RPCs, checksum offload, lifecycle
# stress, namespace teardown, and native Homa fallback in temporary namespaces.

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
UTIL_DIR="$ROOT_DIR/util"
ARTIFACT_BASE=${ARTIFACT_DIR:-"$SCRIPT_DIR/artifacts"}
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)-$$
ARTIFACT_DIR="$ARTIFACT_BASE/$RUN_ID"
NS_CLIENT="homa-udp-client-$$"
NS_SERVER="homa-udp-server-$$"
VETH_CLIENT="huc$$"
VETH_SERVER="hus$$"
SERVER_BIN="$UTIL_DIR/server"
CLIENT_BIN="$UTIL_DIR/homa_test"
BACKGROUND_PIDS=()
LAST_PID=""
MODE=${MODE:-development}
STRESS_ITERATIONS=${STRESS_ITERATIONS:-1}
STRESS_WORKERS=${STRESS_WORKERS:-8}
RESULTS_FILE="$ARTIFACT_DIR/results.tsv"
RUN_FAILED=0
CLEANUP_STARTED=0
KERNEL_LOG_BASELINE_LINES=0

log()
{
	printf '%s\n' "$*"
}

fail()
{
	record_result harness fail "$*"
	log "FAIL: $*"
	exit 1
}

record_result()
{
	local scenario=$1
	local status=$2
	local detail=$3

	printf '%s\t%s\t%s\n' "$scenario" "$status" "$detail" \
		>> "$RESULTS_FILE"
	if [[ "$status" == fail ||
	      ("$MODE" == signoff && "$status" != pass) ]]; then
		RUN_FAILED=1
	fi
}

write_summary()
{
	python3 - "$RESULTS_FILE" "$ARTIFACT_DIR/results.json" \
		"$(uname -r)" "$MODE" "$ARTIFACT_DIR" <<'PY'
import json
import sys

results_path, output_path, kernel, mode, artifacts = sys.argv[1:]
results = []
with open(results_path, encoding="utf-8") as input_file:
    for line in input_file:
        scenario, status, detail = line.rstrip("\n").split("\t", 2)
        results.append({
            "scenario": scenario,
            "status": status,
            "detail": detail,
        })
summary = {
    "artifacts": artifacts,
    "kernel": kernel,
    "mode": mode,
    "results": results,
}
with open(output_path, "w", encoding="utf-8") as output_file:
    json.dump(summary, output_file, indent=2, sort_keys=True)
    output_file.write("\n")
PY
}

require_command()
{
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

register_pid()
{
	BACKGROUND_PIDS+=("$1")
}

remove_pid()
{
	local target=$1
	local remaining=()
	local pid

	for pid in "${BACKGROUND_PIDS[@]}"; do
		if [[ "$pid" != "$target" ]]; then
			remaining+=("$pid")
		fi
	done
	BACKGROUND_PIDS=("${remaining[@]}")
}

stop_pid()
{
	local pid=$1
	local signal=${2:-TERM}

	if kill -0 "$pid" 2>/dev/null; then
		kill -s "$signal" "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	remove_pid "$pid"
}

cleanup()
{
	local pid
	local diagnostics="$ARTIFACT_DIR/kernel-diagnostics.log"
	local leaked_namespaces

	if (( CLEANUP_STARTED )); then
		return
	fi
	CLEANUP_STARTED=1

	for pid in "${BACKGROUND_PIDS[@]}"; do
		if kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
		fi
	done
	for pid in "${BACKGROUND_PIDS[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
	ip netns del "$NS_CLIENT" 2>/dev/null || true
	ip netns del "$NS_SERVER" 2>/dev/null || true
	leaked_namespaces=$(ip netns list 2>/dev/null | grep -Ec \
		"^($NS_CLIENT|$NS_SERVER)( |$)" || true)
	if (( leaked_namespaces )); then
		record_result cleanup fail "test namespaces remain after cleanup"
	else
		record_result cleanup pass "processes and test namespaces removed"
	fi

	dmesg > "$ARTIFACT_DIR/kernel-after.log" 2>/dev/null || true
	tail -n +$((KERNEL_LOG_BASELINE_LINES + 1)) \
		"$ARTIFACT_DIR/kernel-after.log" > "$ARTIFACT_DIR/kernel-new.log"
	if grep -Ei 'BUG:|WARNING:|KASAN:|use-after-free|double-free|refcount|lockdep|RCU.*stall|soft lockup|hung task|kernel oops' \
		"$ARTIFACT_DIR/kernel-new.log" > "$diagnostics"; then
		record_result kernel-diagnostics fail \
			"new kernel warning found; see kernel-diagnostics.log"
	else
		record_result kernel-diagnostics pass "no new kernel warnings"
	fi
	write_summary
}
trap cleanup EXIT INT TERM

wait_for_pattern()
{
	local file=$1
	local pattern=$2
	local deadline=$((SECONDS + 10))

	until grep -q "$pattern" "$file" 2>/dev/null; do
		if (( SECONDS >= deadline )); then
			return 1
		fi
	done
}

set_udp()
{
	local namespace=$1
	local value=$2

	ip netns exec "$namespace" sysctl -q -w \
		net.homa.hijack_udp="$value"
}

udp_value()
{
	ip netns exec "$1" cat /proc/sys/net/homa/hijack_udp
}

wait_for_udp_port_pair()
{
	local namespace=$1
	local timeout_ms=$2

	ip netns exec "$namespace" python3 - "$timeout_ms" <<'PY'
import socket
import sys
import time

deadline = time.monotonic() + int(sys.argv[1]) / 1000
while True:
    sockets = []
    try:
        sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock4.bind(("0.0.0.0", 54321))
        sockets.append(sock4)
        sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock6.bind(("::", 54321))
        sockets.append(sock6)
        break
    except OSError:
        for active_socket in sockets:
            active_socket.close()
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.005)
for active_socket in sockets:
    active_socket.close()
PY
}

trace_release_disable()
{
	local namespace=$1
	local trace=/sys/kernel/tracing
	local count

	if [[ ! -w "$trace/current_tracer" ]] ||
	   ! grep -q '^udp_tunnel_sock_release' \
		"$trace/available_filter_functions" 2>/dev/null ||
	   [[ $(cat "$trace/current_tracer") != nop ]] ||
	   [[ $(cat "$trace/function_profile_enabled") != 0 ]] ||
	   [[ -n $(grep -v '^####' "$trace/set_ftrace_filter" 2>/dev/null) ]]; then
		record_result release-count incomplete \
			"ftrace is unavailable or already in use"
		set_udp "$namespace" 0
		return
	fi

	printf '0\n' > "$trace/tracing_on"
	printf '\n' > "$trace/trace"
	printf 'udp_tunnel_sock_release\n' > "$trace/set_ftrace_filter"
	printf 'function\n' > "$trace/current_tracer"
	printf '1\n' > "$trace/tracing_on"
	set_udp "$namespace" 0
	printf '0\n' > "$trace/tracing_on"
	count=$(grep -c 'udp_tunnel_sock_release' "$trace/trace" || true)
	printf 'nop\n' > "$trace/current_tracer"
	printf '\n' > "$trace/set_ftrace_filter"
	printf '\n' > "$trace/trace"
	printf '1\n' > "$trace/tracing_on"

	if [[ "$count" != 2 ]]; then
		fail "expected two udp_tunnel_sock_release calls, observed $count"
	fi
	record_result release-count pass "two tunnel sockets released"
}

start_server()
{
	local namespace=$1
	local log_name=$2
	shift 2

	ip netns exec "$namespace" "$SERVER_BIN" "$@" \
		> "$ARTIFACT_DIR/$log_name" 2>&1 &
	LAST_PID=$!
	register_pid "$LAST_PID"
}

run_invoke()
{
	local namespace=$1
	local target=$2
	local length=$3
	local log_name=$4
	shift 4
	local attempt

	for attempt in 1 2 3 4 5; do
		if timeout 20 ip netns exec "$namespace" "$CLIENT_BIN" \
				"$target" "$@" --count 1 --length "$length" udp \
				> "$ARTIFACT_DIR/$log_name" 2>&1 &&
			grep -q "Bandwidth at median" "$ARTIFACT_DIR/$log_name"; then
			return 0
		fi
	done
	return 1
}

start_capture()
{
	local namespace=$1
	local interface=$2
	local pcap=$3
	local filter=$4
	local capture_log="${pcap%.pcap}.capture.log"

	: > "$capture_log"
	ip netns exec "$namespace" tcpdump --immediate-mode -Q in -U -n \
		-i "$interface" \
		-w "$pcap" "$filter" > "$capture_log" 2>&1 &
	LAST_PID=$!
	register_pid "$LAST_PID"
	wait_for_pattern "$capture_log" "listening on" ||
		fail "tcpdump did not become ready"
}

create_namespaces()
{
	ip netns add "$NS_CLIENT"
	ip netns add "$NS_SERVER"
	ip link add "$VETH_CLIENT" type veth peer name "$VETH_SERVER"
	ip link set "$VETH_CLIENT" netns "$NS_CLIENT"
	ip link set "$VETH_SERVER" netns "$NS_SERVER"
	ip -n "$NS_CLIENT" link set lo up
	ip -n "$NS_SERVER" link set lo up
	ip -n "$NS_CLIENT" addr add 10.203.0.1/24 dev "$VETH_CLIENT"
	ip -n "$NS_SERVER" addr add 10.203.0.2/24 dev "$VETH_SERVER"
	ip -n "$NS_CLIENT" addr add fd00:203::1/64 dev "$VETH_CLIENT"
	ip -n "$NS_SERVER" addr add fd00:203::2/64 dev "$VETH_SERVER"
	ip -n "$NS_CLIENT" link set "$VETH_CLIENT" up
	ip -n "$NS_SERVER" link set "$VETH_SERVER" up
}

mkdir -p "$ARTIFACT_DIR"
: > "$RESULTS_FILE"

[[ $EUID -eq 0 ]] || fail "run as root"
for command in ip sysctl tcpdump ethtool python3 timeout make tc; do
	require_command "$command"
done
[[ -d /proc/sys/net/homa ]] || fail "the Homa module is not loaded"

dmesg > "$ARTIFACT_DIR/kernel-before.log" 2>/dev/null || true
KERNEL_LOG_BASELINE_LINES=$(wc -l < "$ARTIFACT_DIR/kernel-before.log")
{
	printf 'run_id=%s\n' "$RUN_ID"
	printf 'mode=%s\n' "$MODE"
	printf 'uname=%s\n' "$(uname -a)"
	printf 'module_srcversion=%s\n' \
		"$(cat /sys/module/homa/srcversion 2>/dev/null || echo unavailable)"
	printf 'built_srcversion=%s\n' \
		"$(modinfo -F srcversion "$ROOT_DIR/homa.ko" 2>/dev/null || echo unavailable)"
	printf 'built_sha256=%s\n' \
		"$(sha256sum "$ROOT_DIR/homa.ko" 2>/dev/null | awk '{print $1}' || echo unavailable)"
	printf 'hijack_udp=%s\n' "$(cat /proc/sys/net/homa/hijack_udp)"
	grep -E '^CONFIG_(INET|IPV6|NET_UDP_TUNNEL|KASAN|LOCKDEP)=' \
		"/boot/config-$(uname -r)" 2>/dev/null || true
} > "$ARTIFACT_DIR/environment.txt"

loaded_srcversion=$(cat /sys/module/homa/srcversion 2>/dev/null || true)
built_srcversion=$(modinfo -F srcversion "$ROOT_DIR/homa.ko" 2>/dev/null || true)
if [[ -n "$loaded_srcversion" && "$loaded_srcversion" == "$built_srcversion" ]]; then
	record_result module-identity pass \
		"loaded and built srcversion $loaded_srcversion"
else
	fail "loaded module srcversion does not match $ROOT_DIR/homa.ko"
fi
make -C "$UTIL_DIR" homa_test server

kernel_release=$(uname -r)
if [[ "$kernel_release" != 6.17* ]]; then
	log "WARNING: running on $kernel_release; final V1 sign-off requires Linux 6.17"
	record_result environment incomplete \
		"Linux $kernel_release is regression-only; sign-off requires 6.17"
else
	record_result environment pass "Linux 6.17 target kernel"
fi

create_namespaces

[[ $(udp_value "$NS_CLIENT") == 0 ]] || fail "client namespace did not start disabled"
[[ $(udp_value "$NS_SERVER") == 0 ]] || fail "server namespace did not start disabled"

ip netns exec "$NS_CLIENT" python3 -c \
	'import signal, socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 54321)); signal.pause()' &
port_holder=$!
register_pid "$port_holder"
deadline=$((SECONDS + 10))
until ip netns exec "$NS_CLIENT" grep -q ':D431 ' /proc/net/udp; do
	(( SECONDS < deadline )) || fail "UDP port-conflict process did not bind"
done
if set_udp "$NS_CLIENT" 1 2> "$ARTIFACT_DIR/port-collision.log"; then
	fail "UDP hijack enabled despite a port 54321 collision"
fi
stop_pid "$port_holder"

set_udp "$NS_CLIENT" 1
[[ $(udp_value "$NS_SERVER") == 0 ]] || fail "UDP sysctl leaked across namespaces"
trace_release_disable "$NS_CLIENT"
wait_for_udp_port_pair "$NS_CLIENT" 0 ||
	fail "idle disable did not release IPv4/IPv6 port 54321 synchronously"
record_result idle-release pass "IPv4/IPv6 port 54321 reusable immediately"
set_udp "$NS_CLIENT" 1
set_udp "$NS_SERVER" 1

start_server "$NS_SERVER" server-v4.log --port 4000 --validate --verbose
server_v4=$LAST_PID
if ip netns exec "$NS_CLIENT" ethtool -K "$VETH_CLIENT" tx off \
		> "$ARTIFACT_DIR/offload-disable-client.log" 2>&1 &&
	ip netns exec "$NS_SERVER" ethtool -K "$VETH_SERVER" tx off \
		> "$ARTIFACT_DIR/offload-disable-server.log" 2>&1; then
	offload_off_pcap="$ARTIFACT_DIR/udp-ipv4-offload-off.pcap"
	ip netns exec "$NS_CLIENT" ethtool -k "$VETH_CLIENT" \
		> "$ARTIFACT_DIR/offload-off-features.log"
	start_capture "$NS_SERVER" "$VETH_SERVER" "$offload_off_pcap" \
		"udp port 54321"
	offload_capture_pid=$LAST_PID
	run_invoke "$NS_CLIENT" 10.203.0.2:4000 100 ipv4-small.log ||
		fail "IPv4 UDP request/response failed with TX offload disabled"
	run_invoke "$NS_CLIENT" 10.203.0.2:4000 8192 ipv4-large.log ||
		fail "above-MTU IPv4 UDP request/response failed with TX offload disabled"
	run_invoke "$NS_CLIENT" 10.203.0.2:4000 4096 offload-disabled.log ||
		fail "UDP request/response failed with TX offload disabled"
	stop_pid "$offload_capture_pid" INT
	python3 "$SCRIPT_DIR/verify_udp_pcap.py" "$offload_off_pcap" \
		> "$ARTIFACT_DIR/pcap-ipv4-offload-off.log"
	python3 "$SCRIPT_DIR/verify_udp_pcap.py" --json "$offload_off_pcap" \
		> "$ARTIFACT_DIR/pcap-ipv4-offload-off.json"
	record_result checksum-offload-off pass \
		"receiver-side IPv4 fallback checksums validated"
else
	fail "veth TX checksum offload cannot be disabled"
fi

udp_pcap="$ARTIFACT_DIR/udp-ipv4-offload-on.pcap"
ip netns exec "$NS_CLIENT" ethtool -K "$VETH_CLIENT" tx on \
	> "$ARTIFACT_DIR/offload-enable-client.log" 2>&1 || true
ip netns exec "$NS_SERVER" ethtool -K "$VETH_SERVER" tx on \
	> "$ARTIFACT_DIR/offload-enable-server.log" 2>&1 || true
ip netns exec "$NS_CLIENT" ethtool -k "$VETH_CLIENT" \
	> "$ARTIFACT_DIR/offload-on-features.log"
start_capture "$NS_SERVER" "$VETH_SERVER" "$udp_pcap" "udp port 54321"
capture_pid=$LAST_PID
run_invoke "$NS_CLIENT" 10.203.0.2:4000 4096 offload-enabled.log ||
	fail "IPv4 UDP request/response failed with TX offload enabled"
stop_pid "$capture_pid" INT
python3 "$SCRIPT_DIR/verify_udp_pcap.py" --allow-partial-checksum \
	"$udp_pcap" \
	> "$ARTIFACT_DIR/pcap-ipv4-offload-on.log"
python3 "$SCRIPT_DIR/verify_udp_pcap.py" --allow-partial-checksum --json \
	"$udp_pcap" \
	> "$ARTIFACT_DIR/pcap-ipv4-offload-on.json"
record_result checksum-offload-on incomplete \
	"veth preserved valid partial checksum seeds; physical wire completion is required"

start_server "$NS_CLIENT" server-v6.log --ipv6 --port 4001 --validate --verbose
server_v6=$LAST_PID
ipv6_pcap="$ARTIFACT_DIR/udp-ipv6-loopback.pcap"
start_capture "$NS_CLIENT" lo "$ipv6_pcap" "udp port 54321"
ipv6_capture_pid=$LAST_PID
run_invoke "$NS_CLIENT" localhost:4001 8192 ipv6-large.log --ipv6 ||
	fail "IPv6 UDP request/response failed"
stop_pid "$ipv6_capture_pid" INT
python3 "$SCRIPT_DIR/verify_udp_pcap.py" --allow-partial-checksum \
	"$ipv6_pcap" \
	> "$ARTIFACT_DIR/pcap-ipv6.log"
python3 "$SCRIPT_DIR/verify_udp_pcap.py" --allow-partial-checksum --json \
	"$ipv6_pcap" \
	> "$ARTIFACT_DIR/pcap-ipv6.json"
python3 "$SCRIPT_DIR/verify_transport_pcap.py" --expect udp --json \
	"$udp_pcap" \
	> "$ARTIFACT_DIR/transport-udp-ipv4.json"
python3 "$SCRIPT_DIR/verify_transport_pcap.py" --expect udp --json \
	"$ipv6_pcap" \
	> "$ARTIFACT_DIR/transport-udp-ipv6.json"
record_result ipv6-traffic incomplete \
	"IPv6 loopback traffic passed with valid partial checksum seeds; physical wire completion is required"

for iteration in $(seq 1 "$STRESS_ITERATIONS"); do
	race_pids=()
	for index in $(seq 1 "$STRESS_WORKERS"); do
		timeout 20 ip netns exec "$NS_CLIENT" "$CLIENT_BIN" \
			10.203.0.2:4000 --count 1 --length 65536 udp \
			> "$ARTIFACT_DIR/race-$iteration-$index.log" 2>&1 &
		race_pids+=("$!")
	done
	set_udp "$NS_CLIENT" 0
	set_udp "$NS_SERVER" 0
	for pid in "${race_pids[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
	wait_for_udp_port_pair "$NS_CLIENT" 350 ||
		fail "client UDP tunnel sockets not released within 350 ms"
	wait_for_udp_port_pair "$NS_SERVER" 350 ||
		fail "server UDP tunnel sockets not released within 350 ms"
	set_udp "$NS_CLIENT" 1
	set_udp "$NS_SERVER" 1
done
run_invoke "$NS_CLIENT" 10.203.0.2:4000 4096 reenabled.log ||
	fail "UDP request/response failed after disable/re-enable stress"
record_result lifecycle pass \
	"$STRESS_ITERATIONS iterations with $STRESS_WORKERS workers"

stop_pid "$server_v4"
stop_pid "$server_v6"
set_udp "$NS_CLIENT" 0
set_udp "$NS_SERVER" 0
start_server "$NS_SERVER" server-native.log --port 4002 --validate --verbose
server_native=$LAST_PID
native_pcap="$ARTIFACT_DIR/native.pcap"
start_capture "$NS_SERVER" "$VETH_SERVER" "$native_pcap" \
	"ip proto 146 or ip6 proto 146"
native_capture_pid=$LAST_PID
run_invoke "$NS_CLIENT" 10.203.0.2:4002 4096 native.log ||
	fail "native Homa regression failed"
stop_pid "$native_capture_pid" INT
stop_pid "$server_native"
python3 "$SCRIPT_DIR/verify_transport_pcap.py" --expect native --json \
	"$native_pcap" \
	> "$ARTIFACT_DIR/transport-native.json"

set_udp "$NS_CLIENT" 1
set_udp "$NS_SERVER" 1
ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_CLIENT" root \
	netem delay 100ms
ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_SERVER" root \
	netem delay 100ms
start_server "$NS_SERVER" server-teardown.log --port 4003 --validate --verbose
teardown_server=$LAST_PID
teardown_pids=()
for index in $(seq 1 "$STRESS_WORKERS"); do
	timeout 20 ip netns exec "$NS_CLIENT" "$CLIENT_BIN" \
		10.203.0.2:4003 --count 1 --length 1000000 udp \
		> "$ARTIFACT_DIR/teardown-$index.log" 2>&1 &
	teardown_pids+=("$!")
	register_pid "$!"
done
deadline=$((SECONDS + 10))
until ip netns exec "$NS_CLIENT" tc -s qdisc show dev "$VETH_CLIENT" |
		grep -Eq 'Sent [1-9][0-9]* bytes [1-9][0-9]* pkt'; do
	(( SECONDS < deadline )) || fail "teardown traffic did not reach the qdisc"
done
ip netns del "$NS_CLIENT"
ip netns del "$NS_SERVER"
for pid in "${teardown_pids[@]}"; do
	stop_pid "$pid"
done
stop_pid "$teardown_server"
if ip netns list | grep -Eq "^($NS_CLIENT|$NS_SERVER)( |$)"; then
	fail "namespace name remained after active teardown"
fi
create_namespaces
[[ $(udp_value "$NS_CLIENT") == 0 ]] ||
	fail "recreated client namespace inherited UDP enablement"
[[ $(udp_value "$NS_SERVER") == 0 ]] ||
	fail "recreated server namespace inherited UDP enablement"
set_udp "$NS_CLIENT" 1
set_udp "$NS_SERVER" 1
start_server "$NS_SERVER" server-after-teardown.log \
	--port 4004 --validate --verbose
server_after_teardown=$LAST_PID
run_invoke "$NS_CLIENT" 10.203.0.2:4004 4096 after-teardown.log ||
	fail "UDP request/response failed after active namespace teardown"
stop_pid "$server_after_teardown"
record_result namespace-teardown pass \
	"active namespaces deleted and recreated; UDP RPC succeeded after reuse"

log "PASS: UDP tunnel integration checks completed"
log "Artifacts: $ARTIFACT_DIR"
record_result integration pass "UDP and native regression checks completed"
cleanup
trap - EXIT INT TERM
exit "$RUN_FAILED"