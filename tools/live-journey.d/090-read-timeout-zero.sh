#!/usr/bin/env bash
# 090-read-timeout-zero: --read-timeout=0 must not silently re-open the #9
# starvation footgun. Acceptable behaviors: flintd refuses 0 as a usage
# error, or 0 is documented AND the deadline still protects other clients.
# Current behavior: 0 disables the deadline and --help says nothing.
set -uo pipefail
source "$LJ_LIB"

D="$SCENARIO_DIR"; A="$D/a"
lj_seed_src "$A/src"

lj_step "A has a commit ready to push"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=c1; lj_expect_ok "commit ok"

lj_step "flintd serve --read-timeout=0"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
PORT="$(lj_free_port)"
"$FLINTD" serve --store="$D/server" --listen="127.0.0.1:$PORT" --read-timeout=0 \
  >"$D/flintd.out" 2>"$D/flintd.err" &
FPID=$!
sleep 0.7

if ! kill -0 "$FPID" 2>/dev/null; then
  # Refusing 0 outright is an acceptable fix.
  if grep -q "refuse usage" "$D/flintd.err"; then
    lj_step "flintd refuses --read-timeout=0 as usage (acceptable)"
    exit 0
  fi
  lj_fail "flintd running or clean usage refusal" "exited: $(cat "$D/flintd.err")"
fi

lj_step "idle connection holds; push must still complete within 8s"
lj_tcp_hold "$PORT"
sleep 0.5
lj_flint_t 8 push --store="$A" --remote="tcp://127.0.0.1:$PORT"
kill "${LJ_HOLD_PID:-}" 2>/dev/null
kill "$FPID" 2>/dev/null

if [[ $LJ_LAST_STATUS -eq 124 ]]; then
  lj_fail "--read-timeout=0 rejected as usage, or deadline still bounds idle peers" \
    "0 silently disables the deadline: push starved 8s behind an idle connection (undocumented #9 re-open)"
fi
lj_expect_ok "flint: push ok"
lj_step "done"
