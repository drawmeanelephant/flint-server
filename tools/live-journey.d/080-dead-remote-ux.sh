#!/usr/bin/env bash
# 080-dead-remote-ux: pushing to an unreachable remote must produce a
# friendly flint error line, not a raw Zig error name.
# KNOWN ISSUE #31 (flint-client). Flips to PASS once the fix lands.
set -uo pipefail
source "$LJ_LIB"
lj_repo flint-client

D="$SCENARIO_DIR"; A="$D/a"
lj_seed_src "$A/src"

lj_step "A has a commit; nothing listens on the remote port"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=c1; lj_expect_ok "commit ok"

PORT="$(lj_free_port)"
lj_step "push to tcp://127.0.0.1:$PORT (closed)"
lj_flint_t 15 push --store="$A" --remote="tcp://127.0.0.1:$PORT"
[[ $LJ_LAST_STATUS -ne 0 ]] || lj_fail "push to a dead remote fails nonzero" "exit 0"

# Client prints diagnostics to stdout (observed); check both streams.
err="$(cat "$LJ_LAST_OUT" "$LJ_LAST_ERR")"
if echo "$err" | grep -Eq 'error [A-Z][A-Za-z]+'; then
  lj_known "#31" "a friendly refusal naming the remote and the cause" \
    "$(echo "$err" | tail -1)"
fi
echo "$err" | grep -q "flint:" \
  || lj_fail "a flint-prefixed error line" "$(echo "$err" | tail -1)"

lj_step "done"
