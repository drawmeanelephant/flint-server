#!/usr/bin/env bash
# 140-push-stream-exists-hint: pushing a fresh local stream whose name is
# taken on the server (different stream id) refuses stream_exists — but
# bare: no stream named, no available-streams hint (contrast the #37 fix,
# which annotated stream_missing via list). Enhancement-grade UX.
set -uo pipefail
source "$LJ_LIB"
lj_repo flint-client

D="$SCENARIO_DIR"; A="$D/a"; C="$D/c"
lj_seed_src "$A/src"
lj_seed_src "$C/src"

lj_step "server seeded with stream 'main' (A pushes)"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=c1; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"; lj_expect_ok "push ok"

lj_step "fresh client C inits its own 'main' (different id), commits, pushes"
lj_flint init --store="$C" --name=main --src="$C/src"; lj_expect_ok "init ok"
lj_keygen_pub "$C" c >/dev/null
lj_flint add --store="$C"; lj_expect_ok "add files=1"
lj_flint commit --store="$C" -m=c1; lj_expect_ok "commit ok"
lj_flint push --store="$C" --remote="$LJ_REMOTE"
lj_expect_refuse stream_exists

lj_step "refusal should name the collision"
if ! grep -qiE "main|available|did you mean|name" "$LJ_LAST_OUT" "$LJ_LAST_ERR" 2>/dev/null; then
  lj_fail "stream_exists refusal names the stream / available streams (via list)" \
    "bare 'flint: refuse stream_exists' — no hint which stream name collided"
fi
lj_stop_flintd
lj_step "done"
