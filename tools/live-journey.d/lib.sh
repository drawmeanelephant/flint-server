# lib.sh — shared helpers for live-journey scenarios.
#
# Sourced by every scenario. Requires (exported by the runner):
#   FLINTD        path to the flintd binary
#   FLINT         path to the flint client binary
#   SCENARIO_DIR  fresh scratch dir for this scenario
#
# Scenario protocol (exit codes):
#   0   PASS
#   42  KNOWN issue reproduced   (call lj_known)
#   *   FAIL — new finding       (call lj_fail, or any unhandled error)
#
# Scenarios print structured marker lines the runner harvests:
#   STEP: <desc>            progress markers
#   EXPECTED: <text>        what the spec/contract says
#   ACTUAL: <text>          what happened
#   KNOWN_ISSUE: <ref>      e.g. "#9" (with lj_known)
#   FINDING_REPO: <repo>    flint-server (default) | flint-client

set -uo pipefail

LJ_FINDING_REPO="${LJ_FINDING_REPO:-flint-server}"

lj_step() { echo "STEP: $*"; }

lj_repo() { LJ_FINDING_REPO="$1"; echo "FINDING_REPO: $1"; }

lj_fail() {
  echo "EXPECTED: $1"
  echo "ACTUAL: $2"
  echo "FINDING_REPO: $LJ_FINDING_REPO"
  exit 1
}

lj_known() {
  echo "KNOWN_ISSUE: $1"
  echo "EXPECTED: $2"
  echo "ACTUAL: $3"
  echo "FINDING_REPO: $LJ_FINDING_REPO"
  exit 42
}

# --- client runner ---------------------------------------------------------
# lj_flint <args...>: run the client, never trip on nonzero exit.
# Results in LJ_LAST_STATUS / LJ_LAST_OUT / LJ_LAST_ERR.
lj_flint() {
  LJ_LAST_OUT="$SCENARIO_DIR/last.out"
  LJ_LAST_ERR="$SCENARIO_DIR/last.err"
  "$FLINT" "$@" >"$LJ_LAST_OUT" 2>"$LJ_LAST_ERR"
  LJ_LAST_STATUS=$?
  return 0
}

# lj_flint_t <seconds> <args...>: same, under a timeout.
lj_flint_t() {
  local t="$1"; shift
  LJ_LAST_OUT="$SCENARIO_DIR/last.out"
  LJ_LAST_ERR="$SCENARIO_DIR/last.err"
  timeout "$t" "$FLINT" "$@" >"$LJ_LAST_OUT" 2>"$LJ_LAST_ERR"
  LJ_LAST_STATUS=$?
  return 0
}

lj_expect_ok() { # lj_expect_ok <regex> — match a stdout line, exit 0 status
  local pat="$1"
  if [[ $LJ_LAST_STATUS -ne 0 ]]; then
    lj_fail "exit 0 with /$pat/" "exit $LJ_LAST_STATUS; stderr: $(tail -1 "$LJ_LAST_ERR")"
  fi
  grep -Eq "$pat" "$LJ_LAST_OUT" \
    || lj_fail "stdout matching /$pat/" "stdout: $(tail -n 1 "$LJ_LAST_OUT"); stderr: $(tail -n 1 "$LJ_LAST_ERR")"
}

lj_expect_refuse() { # lj_expect_refuse <name> — refuse line (client prints to stdout)
  local name="$1"
  if [[ $LJ_LAST_STATUS -eq 0 ]]; then
    lj_fail "refusal $name (exit nonzero)" "exit 0; stdout: $(tail -1 "$LJ_LAST_OUT")"
  fi
  grep -qh "refuse $name" "$LJ_LAST_OUT" "$LJ_LAST_ERR" 2>/dev/null \
    || lj_fail "refusal $name" "stdout: $(tail -1 "$LJ_LAST_OUT"); stderr: $(tail -1 "$LJ_LAST_ERR")"
}

# --- server lifecycle ------------------------------------------------------
lj_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

lj_start_flintd() { # lj_start_flintd <store> [extra serve args...]
  local store="$1"; shift
  LJ_PORT="$(lj_free_port)"
  LJ_REMOTE="tcp://127.0.0.1:$LJ_PORT"
  "$FLINTD" serve --store="$store" --listen="127.0.0.1:$LJ_PORT" "$@" \
    >"$SCENARIO_DIR/flintd.out" 2>"$SCENARIO_DIR/flintd.err" &
  LJ_FLINTD_PID=$!
  local i
  for i in $(seq 1 50); do
    grep -q "flintd: listening" "$SCENARIO_DIR/flintd.err" && return 0
    kill -0 "$LJ_FLINTD_PID" 2>/dev/null || {
      echo "flintd exited early:"; cat "$SCENARIO_DIR/flintd.err"
      exit 1
    }
    sleep 0.1
  done
  echo "flintd never reported listening"; cat "$SCENARIO_DIR/flintd.err"
  exit 1
}

lj_stop_flintd() {
  if [[ -n "${LJ_FLINTD_PID:-}" ]]; then
    kill "$LJ_FLINTD_PID" 2>/dev/null
    wait "$LJ_FLINTD_PID" 2>/dev/null
    LJ_FLINTD_PID=""
  fi
}

lj_flintd_alive() {
  kill -0 "$LJ_FLINTD_PID" 2>/dev/null
}

# --- fixtures --------------------------------------------------------------
# A pair of atoms so two clients can edit disjoint declarations.
lj_seed_src() { # lj_seed_src <dir>
  mkdir -p "$1"
  cat >"$1/main.zig" <<'EOF'
pub const alpha: u32 = 1;
pub const beta: u32 = 10;
EOF
}

lj_set_atom() { # lj_set_atom <dir> <alpha|beta> <value>
  local f="$1/main.zig" other
  case "$2" in
    alpha) other="pub const beta: u32 = $(grep -oP 'beta: u32 = \K[0-9]+' "$f");";
           printf 'pub const alpha: u32 = %s;\n%s\n' "$3" "$other" >"$f" ;;
    beta)  other="pub const alpha: u32 = $(grep -oP 'alpha: u32 = \K[0-9]+' "$f");";
           printf '%s\npub const beta: u32 = %s;\n' "$other" "$3" >"$f" ;;
  esac
}

lj_keygen_pub() { # lj_keygen_pub <store> <name> → prints 64-hex pubkey
  local out
  out="$("$FLINT" keygen --store="$1" --name="$2" 2>&1)" \
    || { echo "keygen failed: $out" >&2; exit 1; }
  echo "$out" | grep -oE '[0-9a-f]{64}' | head -1
}

# --- raw socket helpers ----------------------------------------------------
lj_tcp_send() { # lj_tcp_send <port> <payload> — send bytes + \n, print any reply
  python3 - "$1" "$2" <<'PY'
import socket, sys
port, payload = int(sys.argv[1]), sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(payload.encode() + b"\n")
s.settimeout(2)
try:
    print(s.recv(65536).decode(errors="replace").strip())
except (socket.timeout, ConnectionResetError):
    print("<no reply>")
s.close()
PY
}

lj_tcp_hold() { # lj_tcp_hold <port> — open an idle connection, backgrounded
  python3 - "$1" <<'PY' &
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
time.sleep(3600)
PY
  LJ_HOLD_PID=$!
}
