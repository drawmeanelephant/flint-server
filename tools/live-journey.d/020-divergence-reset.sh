#!/usr/bin/env bash
# 020-divergence-reset: the spec §4 recovery journey —
# stale_head → fork_needed → fork → pull --reset → merge → push.
set -uo pipefail
source "$LJ_LIB"

D="$SCENARIO_DIR"; A="$D/a"; B="$D/b"
lj_seed_src "$A/src"
mkdir -p "$B/src"

lj_step "server up"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server"

lj_step "A: base commit + push"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=base; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"; lj_expect_ok "push ok stream=main changes=1"

lj_step "B: clone"
lj_flint clone --store="$B" "$LJ_REMOTE" --stream=main --name=main --src="$B/src"
lj_expect_ok "clone ok stream=main changes=1"
lj_keygen_pub "$B" b >/dev/null
lj_seed_src "$B/src"   # clone replays atoms; source arrives out-of-band

lj_step "diverge: A edits alpha (stays local), B edits beta and pushes"
lj_set_atom "$A/src" alpha 2
lj_flint add --store="$A"; lj_expect_ok "modified=1"
lj_flint commit --store="$A" -m=a2; lj_expect_ok "commit ok"
lj_set_atom "$B/src" beta 20
lj_flint add --store="$B"; lj_expect_ok "modified=1"
lj_flint commit --store="$B" -m=b2; lj_expect_ok "commit ok"
lj_flint push --store="$B" --remote="$LJ_REMOTE"; lj_expect_ok "push ok stream=main changes=1"

lj_step "A: push must refuse stale_head"
lj_flint push --store="$A" --remote="$LJ_REMOTE"
lj_expect_refuse stale_head

lj_step "A: plain pull must refuse fork_needed"
lj_flint pull --store="$A" --remote="$LJ_REMOTE"
lj_expect_refuse fork_needed

lj_step "A: fork → pull --reset → merge → push (spec recovery)"
lj_flint fork --store="$A" main aside
lj_expect_ok "flint: fork ok stream=aside"
lj_flint pull --store="$A" --remote="$LJ_REMOTE" --reset
lj_expect_ok "flint: pull reset stream=main changes=1"
lj_flint merge --store="$A" aside
lj_expect_ok "flint: merge ok conflicts=0"
lj_flint push --store="$A" --remote="$LJ_REMOTE"
lj_expect_ok "flint: push ok"

lj_step "B: pull the merged head; both sides verify --all"
lj_flint pull --store="$B" --remote="$LJ_REMOTE"
lj_expect_ok "flint: pull ok"
lj_flint verify --store="$A" --all; lj_expect_ok "sig: verified"
lj_flint verify --store="$B" --all; lj_expect_ok "sig: verified"

lj_stop_flintd
lj_step "done"
