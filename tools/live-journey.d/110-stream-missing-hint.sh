#!/usr/bin/env bash
# 110-stream-missing-hint: clone/pull of a nonexistent stream refuses
# stream_missing — correctly — but bare. The protocol has 'list'; the
# client could name the streams that DO exist. Enhancement-grade UX.
set -uo pipefail
source "$LJ_LIB"
lj_repo flint-client

D="$SCENARIO_DIR"; A="$D/a"; B="$D/b"
lj_seed_src "$A/src"
mkdir -p "$B/src"

lj_step "server seeded with stream 'main'"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=c1; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"; lj_expect_ok "push ok"

lj_step "clone a nonexistent stream"
lj_flint clone --store="$B" "$LJ_REMOTE" --stream=nope --name=main --src="$B/src"
lj_expect_refuse stream_missing

lj_step "refusal should say what the remote DOES have"
if ! grep -qi "main" "$LJ_LAST_OUT" || ! grep -qiE "available|did you mean|streams" "$LJ_LAST_OUT" "$LJ_LAST_ERR" 2>/dev/null; then
  lj_fail "stream_missing refusal includes available stream names (via list)" \
    "bare 'flint: refuse stream_missing' — no hint that only 'main' exists"
fi
lj_stop_flintd
lj_step "done"
