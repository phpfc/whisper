#!/usr/bin/env bash
#
# natlab.sh - NAT lab for whisper. Linux only, needs root.
#
# Simulates real NAT behaviour with network namespaces and iptables, runs two
# whisper peers through each scenario and checks that they connect, or that
# they fail with the expected explanation. Prints `PASS <scenario>` or
# `FAIL <scenario>: <reason>` (followed by both peers' full output) and exits
# non-zero if any scenario fails.
#
#   cargo build --release --bins --examples && sudo scripts/natlab.sh
#   sudo scripts/natlab.sh symmetric-cone        # only the named scenarios
#
# Topology, rebuilt from scratch for every scenario so that no conntrack state
# leaks from one scenario into the next (namespace names carry a "wl-" prefix,
# so `inet` below is the namespace `wl-inet`):
#
#            inet: bridge br-wan, 203.0.113.0/24
#            203.0.113.1  STUN :3478 + DHT bootstrap (5 nodes)
#            203.0.113.2  STUN :3478 (a second IP, for the NAT type probe)
#                  |                            |
#          wan0 203.0.113.10            wan0 203.0.113.20
#            ra  (MASQUERADE)             rb  (MASQUERADE)
#          lan0 10.0.1.1/24             lan0 10.0.2.1/24
#             |           |                  |
#     a1 10.0.1.2   a2 10.0.1.3        b1 10.0.2.2
#
# A "cone" router masquerades with the kernel's default behaviour (the source
# port is kept when possible, so every destination sees the same mapping). A
# "symmetric" router adds --random-fully, which picks a new random source port
# for every destination.
#
# Environment:
#   WHISPER_BIN, STUN_RESPONDER_BIN, DHT_BOOTSTRAP_BIN  binaries to use
#                                  (default: target/release/ and .../examples/)
#   NATLAB_KEEP=1                  keep the logs directory even if all passed
#   NATLAB_TRACE=1                 trace every command (set -x)

set -Eeuo pipefail
if [[ -n ${NATLAB_TRACE:-} ]]; then
  set -x
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHISPER_BIN="${WHISPER_BIN:-$ROOT/target/release/whisper}"
STUN_BIN="${STUN_RESPONDER_BIN:-$ROOT/target/release/examples/stun_responder}"
DHT_BIN="${DHT_BOOTSTRAP_BIN:-$ROOT/target/release/examples/dht_bootstrap}"

NS_PREFIX=wl
NAMESPACES=(inet ra rb a1 a2 b1)
SCENARIO_NAMES=(cone-cone same-lan symmetric-cone symmetric-symmetric)

INET_IP1=203.0.113.1
INET_IP2=203.0.113.2
RA_WAN_IP=203.0.113.10
RB_WAN_IP=203.0.113.20
STUN_PORT=3478
DHT_NODES=5
STUN_SERVERS="$INET_IP1:$STUN_PORT,$INET_IP2:$STUN_PORT"

PEER_TIMEOUT=90      # hard limit for each peer, seconds
FAIL_MAX_SECONDS=70  # a scenario that must fail has to do so within this
CODE_WAIT=60         # how long the creator gets to write the session code
SERVICE_WAIT=20      # how long the STUN responders and DHT nodes get to start

SELECTED=()          # scenario names given on the command line (none = all)
WORK=""              # logs directory
SCEN_DIR=""          # logs of the scenario being run
BG_PIDS=()           # background processes of the scenario being run
SPAWNED_PID=""
BOOTSTRAP=""         # WHISPER_DHT_BOOTSTRAP value: the nodes dht_bootstrap printed
PROBLEMS=()          # why the scenario being run failed
EARLY_FAILURE=""
CREATOR_RC=-1
JOINER_RC=-1
JOINER_SECS=0
PASSED=0
FAILED=0

# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

log() { printf '[natlab %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
phase() { printf '\n==> %s\n' "$*"; }

# A problem with the lab itself, not a verdict on whisper: stop everything.
die() {
  printf 'natlab: error: %s\n' "$*" >&2
  exit 2
}

# Runs a command and stops the whole run if it fails. `set -e` is not enough:
# it is off inside anything called from an `if` or `||`.
must() {
  local rc=0
  "$@" || rc=$?
  if ((rc != 0)); then
    die "command failed (exit $rc): $*"
  fi
}

ns_of() { printf '%s-%s' "$NS_PREFIX" "$1"; }

# in_ns <name> <command...>: runs the command inside a lab namespace.
in_ns() {
  local name=$1
  shift
  ip netns exec "$(ns_of "$name")" "$@"
}

selected() {
  local name=$1 want
  if ((${#SELECTED[@]} == 0)); then
    return 0
  fi
  for want in "${SELECTED[@]}"; do
    if [[ $want == "$name" ]]; then
      return 0
    fi
  done
  return 1
}

has_line() { (($(wc -l <"$1") >= 1)); }

show_file() {
  printf -- '--- %s ---\n' "$1"
  if [[ -s $2 ]]; then
    cat -- "$2"
  else
    echo '(empty)'
  fi
}

# --------------------------------------------------------------------------
# Teardown. Idempotent: safe to call with nothing built, and from the EXIT trap.
# --------------------------------------------------------------------------

kill_namespace_processes() {
  local ns=$1 pids
  # A process may fork between the listing and the kill, so look again.
  for _ in 1 2 3; do
    pids=$(ip netns pids "$ns" 2>/dev/null || true)
    if [[ -z $pids ]]; then
      return 0
    fi
    # shellcheck disable=SC2086 # one pid per word
    kill -9 $pids 2>/dev/null || true
    sleep 0.1
  done
}

teardown_topology() {
  local name pid
  for name in "${NAMESPACES[@]}"; do
    # A process keeps its namespace alive after `ip netns del`.
    kill_namespace_processes "$(ns_of "$name")"
  done
  if ((${#BG_PIDS[@]} > 0)); then
    for pid in "${BG_PIDS[@]}"; do
      { wait "$pid"; } 2>/dev/null || true
    done
  fi
  BG_PIDS=()
  # Deleting a namespace takes its bridges and veth ends with it. Nothing is
  # ever created in the root namespace.
  for name in "${NAMESPACES[@]}"; do
    ip netns del "$(ns_of "$name")" 2>/dev/null || true
  done
}

cleanup() {
  local rc=$?
  trap - EXIT ERR INT TERM
  teardown_topology
  if [[ -n $WORK && -d $WORK ]]; then
    if [[ -n ${NATLAB_KEEP:-} ]] || ((FAILED > 0 || rc != 0)); then
      echo "natlab: logs kept in $WORK"
    else
      rm -rf "$WORK"
    fi
  fi
  exit "$rc"
}

# --------------------------------------------------------------------------
# Environment check
# --------------------------------------------------------------------------

preflight() {
  phase "Checking the environment"
  [[ $(uname -s) == Linux ]] || die "the NAT lab needs Linux (network namespaces and iptables)"
  [[ $EUID -eq 0 ]] || die "run it as root: sudo scripts/natlab.sh"

  local cmd bin mod
  for cmd in ip iptables sysctl timeout mktemp wc; do
    command -v "$cmd" >/dev/null || die "'$cmd' not found in PATH"
  done
  for bin in "$WHISPER_BIN" "$STUN_BIN" "$DHT_BIN"; do
    [[ -x $bin ]] || die "$bin not found; build it with: cargo build --release --bins --examples"
  done

  # Best effort: on most systems iptables loads these on demand.
  for mod in veth bridge nf_conntrack nf_nat iptable_nat xt_MASQUERADE xt_conntrack; do
    modprobe -q "$mod" 2>/dev/null || true
  done

  log "kernel: $(uname -r)"
  log "$(ip -V 2>&1 | head -n 1)"
  log "$(iptables --version 2>&1 | head -n 1)"
  log "whisper:         $WHISPER_BIN"
  log "stun_responder:  $STUN_BIN"
  log "dht_bootstrap:   $DHT_BIN"
}

# --------------------------------------------------------------------------
# Topology
# --------------------------------------------------------------------------

# add_router <name> <wan ip> <lan ip> <cone|symmetric>
add_router() {
  local r=$1 wan_ip=$2 lan_ip=$3 mode=$4
  # i-<r> stays in inet (a port of the bridge), wan0 goes to the router.
  must ip link add "i-$r" netns "$(ns_of inet)" type veth peer name wan0 netns "$(ns_of "$r")"
  must in_ns inet ip link set "i-$r" master br-wan
  must in_ns inet ip link set "i-$r" up
  must in_ns "$r" ip addr add "$wan_ip/24" dev wan0
  must in_ns "$r" ip link set wan0 up
  # The LAN side is a bridge too, so that several hosts can share it.
  must in_ns "$r" ip link add lan0 type bridge
  must in_ns "$r" ip addr add "$lan_ip/24" dev lan0
  must in_ns "$r" ip link set lan0 up
  must in_ns "$r" sysctl -qw net.ipv4.ip_forward=1

  # Like a home router, drop whatever arrives from the WAN that no outgoing
  # packet asked for. Without it, a peer's first probe (sent before our own
  # outgoing probe opened the hole) would create a conntrack entry here, and
  # that entry would stop the router from keeping our source port for the
  # outgoing flow to that peer: hole punching would break for a reason no
  # real NAT has. Replies to translated flows are un-NATed in PREROUTING and
  # never reach INPUT, so this does not touch them.
  must in_ns "$r" iptables -A INPUT -i wan0 -m conntrack --ctstate NEW -j DROP

  local masq=(-t nat -A POSTROUTING -o wan0 -j MASQUERADE)
  case $mode in
    cone) ;;
    symmetric) masq+=(--random-fully) ;;
    *) die "unknown NAT mode '$mode'" ;;
  esac
  must in_ns "$r" iptables "${masq[@]}"
}

# add_host <name> <router> <ip> <gateway>
add_host() {
  local h=$1 r=$2 ip=$3 gw=$4
  must ip link add "lan-$h" netns "$(ns_of "$r")" type veth peer name eth0 netns "$(ns_of "$h")"
  must in_ns "$r" ip link set "lan-$h" master lan0
  must in_ns "$r" ip link set "lan-$h" up
  must in_ns "$h" ip addr add "$ip/24" dev eth0
  must in_ns "$h" ip link set eth0 up
  # whisper finds its primary IPv4 by connecting to 8.8.8.8, which needs a
  # default route (nothing is sent).
  must in_ns "$h" ip route add default via "$gw"
}

build_topology() {
  local ra_mode=$1 rb_mode=$2 name
  log "building the topology (ra: $ra_mode NAT, rb: $rb_mode NAT)"
  for name in "${NAMESPACES[@]}"; do
    must ip netns add "$(ns_of "$name")"
    # No IPv6 anywhere: no IPv6 candidate may offer a way around the NAT. Set
    # before the interfaces exist so that they inherit it.
    if [[ -d /proc/sys/net/ipv6 ]]; then
      must in_ns "$name" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
    fi
    must in_ns "$name" ip link set lo up
  done

  # inet: one bridge stands for the Internet; the routers' WAN ports join it.
  must in_ns inet ip link add br-wan type bridge
  must in_ns inet ip addr add "$INET_IP1/24" dev br-wan
  must in_ns inet ip addr add "$INET_IP2/24" dev br-wan
  must in_ns inet ip link set br-wan up

  add_router ra "$RA_WAN_IP" 10.0.1.1 "$ra_mode"
  add_router rb "$RB_WAN_IP" 10.0.2.1 "$rb_mode"
  add_host a1 ra 10.0.1.2 10.0.1.1
  add_host a2 ra 10.0.1.3 10.0.1.1
  add_host b1 rb 10.0.2.2 10.0.2.1
}

check_reachability() {
  if ! command -v ping >/dev/null; then
    log "ping not found: skipping the reachability check"
    return 0
  fi
  log "checking that the routers and the hosts reach inet (hosts through their NAT)"
  local from to
  for from in ra rb; do
    if ! in_ns "$from" ping -c3 -W1 -i 0.2 -n "$INET_IP1" >/dev/null 2>&1; then
      dump_network
      die "$from cannot reach $INET_IP1: the topology is broken"
    fi
  done
  for from in a1 a2 b1; do
    for to in "$INET_IP1" "$INET_IP2"; do
      if ! in_ns "$from" ping -c3 -W1 -i 0.2 -n "$to" >/dev/null 2>&1; then
        dump_network
        die "$from cannot reach $to: the topology is broken"
      fi
    done
  done
}

# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------

# spawn <label> <namespace> <command...>: runs the command in the background
# inside a namespace, its output going to $SCEN_DIR/<label>.out and .err. The
# pid is left in SPAWNED_PID (and kept for the teardown).
spawn() {
  local label=$1 name=$2
  shift 2
  ip netns exec "$(ns_of "$name")" "$@" \
    </dev/null >"$SCEN_DIR/$label.out" 2>"$SCEN_DIR/$label.err" &
  SPAWNED_PID=$!
  BG_PIDS+=("$SPAWNED_PID")
}

# wait_for_line <label> <pid> <seconds>: waits until <label>.out has a complete
# line; stops the run if the process dies first or never gets there.
wait_for_line() {
  local label=$1 pid=$2 secs=$3
  local file="$SCEN_DIR/$label.out" deadline=$((SECONDS + secs))
  until has_line "$file"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      show_file "$label stdout" "$file"
      show_file "$label stderr" "$SCEN_DIR/$label.err"
      die "$label exited before it was ready"
    fi
    if ((SECONDS >= deadline)); then
      show_file "$label stdout" "$file"
      show_file "$label stderr" "$SCEN_DIR/$label.err"
      die "$label was not ready after ${secs}s"
    fi
    sleep 0.1
  done
}

start_services() {
  log "starting the STUN responders and the DHT bootstrap nodes in inet"
  local stun1_pid stun2_pid dht_pid
  spawn stun1 inet "$STUN_BIN" "$INET_IP1:$STUN_PORT"
  stun1_pid=$SPAWNED_PID
  spawn stun2 inet "$STUN_BIN" "$INET_IP2:$STUN_PORT"
  stun2_pid=$SPAWNED_PID
  spawn dht inet "$DHT_BIN" "$INET_IP1" "$DHT_NODES"
  dht_pid=$SPAWNED_PID
  # Nobody waits for the services and the teardown kills them: without this
  # bash reports each "Killed" in the log.
  disown "$stun1_pid" "$stun2_pid" "$dht_pid" 2>/dev/null || true

  wait_for_line stun1 "$stun1_pid" "$SERVICE_WAIT"
  wait_for_line stun2 "$stun2_pid" "$SERVICE_WAIT"
  wait_for_line dht "$dht_pid" "$SERVICE_WAIT"

  # The first line dht_bootstrap prints is the list WHISPER_DHT_BOOTSTRAP takes.
  BOOTSTRAP=$(head -n 1 "$SCEN_DIR/dht.out")
  local list_re='^[0-9.]+:[0-9]+(,[0-9.]+:[0-9]+)*$'
  [[ $BOOTSTRAP =~ $list_re ]] || die "dht_bootstrap printed '$BOOTSTRAP', not a list of ip:port"
  log "DHT bootstrap: $BOOTSTRAP"
  log "STUN servers:  $STUN_SERVERS"
}

# execute_peers <creator host> <joiner host>: starts the creator, waits for its
# code, starts the joiner and waits for both. Leaves the exit codes in
# CREATOR_RC and JOINER_RC and the joiner's run time in JOINER_SECS, or sets
# EARLY_FAILURE if the creator never got as far as writing its code.
execute_peers() {
  local creator=$1 joiner=$2
  local code_file="$SCEN_DIR/code" creator_pid joiner_pid code started deadline
  EARLY_FAILURE=""
  CREATOR_RC=-1
  JOINER_RC=-1
  JOINER_SECS=0

  local peer_env=(
    env
    "WHISPER_STUN_SERVERS=$STUN_SERVERS"
    "WHISPER_DHT_BOOTSTRAP=$BOOTSTRAP"
    WHISPER_TEST_EXIT_ON_CONNECT=1
    RUST_BACKTRACE=1
  )

  log "starting the creator on $creator (alice)"
  spawn creator "$creator" "${peer_env[@]}" "WHISPER_TEST_CODE_FILE=$code_file" \
    timeout -k 5 "$PEER_TIMEOUT" "$WHISPER_BIN" create -u alice
  creator_pid=$SPAWNED_PID

  deadline=$((SECONDS + CODE_WAIT))
  until [[ -s $code_file ]]; do
    if ! kill -0 "$creator_pid" 2>/dev/null; then
      CREATOR_RC=0
      wait "$creator_pid" || CREATOR_RC=$?
      EARLY_FAILURE="the creator exited with $CREATOR_RC before it wrote the session code"
      return 0
    fi
    if ((SECONDS >= deadline)); then
      EARLY_FAILURE="the creator did not write the session code within ${CODE_WAIT}s"
      return 0
    fi
    sleep 0.2
  done
  code=$(<"$code_file")
  log "session code: $code"

  log "starting the joiner on $joiner (bob)"
  started=$SECONDS
  spawn joiner "$joiner" "${peer_env[@]}" \
    timeout -k 5 "$PEER_TIMEOUT" "$WHISPER_BIN" join "$code" -u bob
  joiner_pid=$SPAWNED_PID

  JOINER_RC=0
  wait "$joiner_pid" || JOINER_RC=$?
  JOINER_SECS=$((SECONDS - started))
  CREATOR_RC=0
  wait "$creator_pid" || CREATOR_RC=$?
  log "creator exited with $CREATOR_RC, joiner with $JOINER_RC after ${JOINER_SECS}s"
}

# --------------------------------------------------------------------------
# Checks. Each adds to PROBLEMS whatever diverges from the expectation.
# --------------------------------------------------------------------------

# expect_connected <label> <exit code> <stdout file> <paths regex>
expect_connected() {
  local label=$1 rc=$2 out=$3 paths=$4
  if ((rc != 0)); then
    PROBLEMS+=("the $label exited with $rc (expected 0)")
  elif ! grep -qE "^CONNECTED via ($paths)\$" "$out"; then
    PROBLEMS+=("the $label did not print 'CONNECTED via ($paths)'")
  fi
}

# check_connected <creator paths regex> <joiner paths regex>
check_connected() {
  expect_connected creator "$CREATOR_RC" "$SCEN_DIR/creator.out" "$1"
  expect_connected joiner "$JOINER_RC" "$SCEN_DIR/joiner.out" "$2"
}

# check_no_path <text>...: the joiner must fail with exit code 1, in time, and
# print each of the texts (fixed strings).
check_no_path() {
  local text
  if ((JOINER_RC != 1)); then
    PROBLEMS+=("the joiner exited with $JOINER_RC (expected 1)")
  fi
  if ((JOINER_SECS > FAIL_MAX_SECONDS)); then
    PROBLEMS+=("the joiner took ${JOINER_SECS}s to fail (expected at most ${FAIL_MAX_SECONDS}s)")
  fi
  for text in "$@"; do
    if ! grep -qF -- "$text" "$SCEN_DIR/joiner.out" "$SCEN_DIR/joiner.err"; then
      PROBLEMS+=("the joiner's output does not contain '$text'")
    fi
  done
}

# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

dump_network() {
  local name
  for name in "${NAMESPACES[@]}"; do
    printf -- '--- %s: addresses and routes ---\n' "$name"
    in_ns "$name" ip -br addr || true
    in_ns "$name" ip route || true
  done
  for name in ra rb; do
    printf -- '--- %s: iptables ---\n' "$name"
    in_ns "$name" iptables -S || true
    in_ns "$name" iptables -t nat -S || true
    printf -- '--- %s: conntrack ---\n' "$name"
    in_ns "$name" cat /proc/net/nf_conntrack 2>/dev/null || echo '(not available)'
  done
}

dump_logs() {
  local label
  for label in creator joiner stun1 stun2 dht; do
    if [[ -e $SCEN_DIR/$label.out || -e $SCEN_DIR/$label.err ]]; then
      show_file "$label stdout" "$SCEN_DIR/$label.out"
      show_file "$label stderr" "$SCEN_DIR/$label.err"
    fi
  done
}

# conclude <scenario>: prints the verdict; the logs too, if it failed.
conclude() {
  local name=$1 reason="" problem
  if ((${#PROBLEMS[@]} == 0)); then
    echo "PASS $name"
    PASSED=$((PASSED + 1))
    return 0
  fi
  for problem in "${PROBLEMS[@]}"; do
    reason+="${reason:+; }$problem"
  done
  echo "FAIL $name: $reason"
  FAILED=$((FAILED + 1))
  printf '\n----- %s: output of both peers and of the lab services -----\n' "$name"
  dump_logs
  printf '\n----- %s: network state -----\n' "$name"
  dump_network
  printf '\n----- end of %s -----\n' "$name"
}

# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

# scenario <name> <creator> <joiner> <ra mode> <rb mode> <check> [check args...]
scenario() {
  local name=$1 creator=$2 joiner=$3 ra_mode=$4 rb_mode=$5 check=$6
  shift 6
  if ! selected "$name"; then
    return 0
  fi

  SCEN_DIR="$WORK/$name"
  mkdir -p "$SCEN_DIR"
  phase "Scenario $name: $creator creates, $joiner joins (ra: $ra_mode NAT, rb: $rb_mode NAT)"

  teardown_topology # whatever an earlier run left behind
  build_topology "$ra_mode" "$rb_mode"
  start_services
  check_reachability
  execute_peers "$creator" "$joiner"

  PROBLEMS=()
  if [[ -n $EARLY_FAILURE ]]; then
    PROBLEMS+=("$EARLY_FAILURE")
  else
    "$check" "$@"
  fi
  conclude "$name"

  teardown_topology # fresh conntrack state for the next scenario
}

run_scenarios() {
  # name                  creator joiner  ra         rb         expectation
  scenario cone-cone            a1 b1 cone      cone      check_connected 'reflexive|peer-reflexive' 'reflexive|peer-reflexive'
  scenario same-lan             a1 a2 cone      cone      check_connected 'lan|peer-reflexive' 'lan'
  scenario symmetric-cone       a1 b1 symmetric cone      check_no_path 'No direct path' 'Other peer: symmetric NAT'
  scenario symmetric-symmetric  a1 b1 symmetric symmetric check_no_path 'No direct path' 'symmetric NAT'
}

usage() {
  echo "usage: sudo scripts/natlab.sh [scenario...]"
  echo "scenarios: ${SCENARIO_NAMES[*]}"
}

main() {
  local arg known name
  for arg in "$@"; do
    if [[ $arg == -h || $arg == --help ]]; then
      usage
      return 0
    fi
    known=0
    for name in "${SCENARIO_NAMES[@]}"; do
      if [[ $arg == "$name" ]]; then
        known=1
      fi
    done
    if ((known == 0)); then
      usage >&2
      die "unknown scenario '$arg'"
    fi
    SELECTED+=("$arg")
  done

  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'printf "natlab: unexpected failure at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

  preflight
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/natlab.XXXXXX")
  log "logs directory: $WORK"

  run_scenarios

  # Each verdict was printed as its scenario ended: only the counts here.
  phase "Summary"
  echo "$PASSED passed, $FAILED failed"
  if ((PASSED + FAILED == 0)); then
    die "no scenario ran"
  fi
  if ((FAILED > 0)); then
    exit 1
  fi
}

main "$@"
