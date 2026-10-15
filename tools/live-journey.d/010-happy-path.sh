#!/usr/bin/env bash
# 010-happy-path: two clients, one server. clone/edit/push/pull/verify.
# Spec legs: sync journey (server spec §5), client verbs (client spec §1).
set -uo pipefail
source "$LJ_LIB"

D="$SCENARIO_DIR"; A="$D/a"; B="$D/b"
lj_seed_src "$A/src"
mkdir -p "$B/src"

lj_step "server: init + serve"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server"

lj_step "A: init + keygen"
lj_flint init --store="$A" --name=main --src="$A/src"
lj_expect_ok "flint: init ok ws=main stream=main"
PUB_A="$(lj_keygen_pub "$A" a)"
[[ -n "$PUB_A" ]] || lj_fail "keygen prints a 64-hex pubkey" "no hex in output"

lj_step "A: add + commit + push"
lj_flint add --store="$A"
lj_expect_ok "flint: add files=1 new=2"
lj_flint commit --store="$A" -m=c1
lj_expect_ok "flint: commit ok id=.* parent=none"
lj_flint push --store="$A" --remote="$LJ_REMOTE"
lj_expect_ok "flint: push ok stream=main changes=1"

lj_step "B: clone"
lj_flint clone --store="$B" "$LJ_REMOTE" --stream=main --name=main --src="$B/src"
lj_expect_ok "flint: clone ok stream=main changes=1"

lj_step "B: seed source (clone does not materialize files), edit, commit, push"
lj_keygen_pub "$B" b >/dev/null
lj_seed_src "$B/src"
lj_set_atom "$B/src" alpha 2
lj_flint add --store="$B"
lj_expect_ok "modified=1"
lj_flint commit --store="$B" -m=b1
lj_expect_ok "flint: commit ok"
lj_flint push --store="$B" --remote="$LJ_REMOTE"
lj_expect_ok "flint: push ok stream=main changes=1"

lj_step "A: pull"
lj_flint pull --store="$A" --remote="$LJ_REMOTE"
lj_expect_ok "flint: pull ok stream=main changes=1"

lj_step "A and B verify --all"
lj_flint verify --store="$A" --all
lj_expect_ok "sig: verified"
lj_flint verify --store="$B" --all
lj_expect_ok "sig: verified"

lj_step "server store loads read-only in the client (portability leg)"
lj_flint verify --store="$D/server" --all
lj_expect_ok "sig: verified"

lj_stop_flintd
lj_step "done"
