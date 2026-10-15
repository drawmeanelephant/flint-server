#!/usr/bin/env bash
# 130-stale-head-hint: a divergent push refuses stale_head — correctly —
# but bare. The remote moved; the refusal should say so and point at the
# recovery (pull / pull --reset / fork). Enhancement-grade UX, same class
# as flint-client#36's stream_missing hint. Spec: client spec §1 (wire
# refusals print as 'flint: refuse <name>'; the fork_needed recovery
# journey is documented, stale_head is not).
set -uo pipefail
source "$LJ_LIB"
lj_repo flint-client

D="$SCENARIO_DIR"; A="$D/a"; B="$D/b"
lj_seed_src "$A/src"
mkdir -p "$B/src"

lj_step "server seeded with stream 'main' (A pushes c1)"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=c1; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"; lj_expect_ok "push ok"

lj_step "B clones, commits, pushes (remote head advances)"
lj_flint clone --store="$B" "$LJ_REMOTE" --stream=main --name=main --src="$B/src"; lj_expect_ok "clone ok"
lj_keygen_pub "$B" b >/dev/null
lj_seed_src "$B/src"
lj_set_atom "$B/src" alpha 2
lj_flint add --store="$B"; lj_expect_ok "modified=1"
lj_flint commit --store="$B" -m=b1; lj_expect_ok "commit ok"
lj_flint push --store="$B" --remote="$LJ_REMOTE"; lj_expect_ok "push ok"

lj_step "A commits locally without pulling, pushes — divergent"
lj_set_atom "$A/src" alpha 9
lj_flint add --store="$A"; lj_expect_ok "modified=1"
lj_flint commit --store="$A" -m=a2; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"
lj_expect_refuse stale_head

lj_step "refusal should hint at the recovery"
if ! grep -qiE "pull|reset|fork|remote|behind|ahead|diverg" "$LJ_LAST_OUT" "$LJ_LAST_ERR" 2>/dev/null; then
  lj_fail "stale_head refusal hints at recovery (pull/fork)" \
    "bare 'flint: refuse stale_head' — no hint that the remote advanced"
fi
lj_stop_flintd
lj_step "done"
