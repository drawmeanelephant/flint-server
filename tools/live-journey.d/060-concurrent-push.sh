#!/usr/bin/env bash
# 060-concurrent-push: two clients race; exactly one wins, the loser gets
# stale_head and recovers via fork → pull --reset → merge → push.
# Spec: server spec §3.3 (concurrency).
set -uo pipefail
source "$LJ_LIB"

D="$SCENARIO_DIR"; A="$D/a"; B="$D/b"
lj_seed_src "$A/src"
mkdir -p "$B/src"

lj_step "server up; A pushes base; B clones"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=base; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"; lj_expect_ok "push ok stream=main changes=1"
lj_flint clone --store="$B" "$LJ_REMOTE" --stream=main --name=main --src="$B/src"
lj_expect_ok "clone ok stream=main changes=1"
lj_keygen_pub "$B" b >/dev/null
lj_seed_src "$B/src"   # clone replays atoms; source arrives out-of-band

lj_step "both commit locally (disjoint atoms)"
lj_set_atom "$A/src" alpha 2
lj_flint add --store="$A"; lj_expect_ok "modified=1"
lj_flint commit --store="$A" -m=a2; lj_expect_ok "commit ok"
lj_set_atom "$B/src" beta 20
lj_flint add --store="$B"; lj_expect_ok "modified=1"
lj_flint commit --store="$B" -m=b2; lj_expect_ok "commit ok"

lj_step "race the pushes: exactly one ok, one stale_head"
"$FLINT" push --store="$A" --remote="$LJ_REMOTE" >"$D/pushA.out" 2>"$D/pushA.err" &
PA=$!
"$FLINT" push --store="$B" --remote="$LJ_REMOTE" >"$D/pushB.out" 2>"$D/pushB.err" &
PB=$!
wait "$PA"; SA=$?
wait "$PB"; SB=$?
# Client prints both success and refusal lines to stdout (observed).
ok_count=$(grep -l "push ok" "$D/pushA.out" "$D/pushB.out" 2>/dev/null | wc -l)
stale_count=$(grep -l "refuse stale_head" "$D/pushA.out" "$D/pushB.out" "$D/pushA.err" "$D/pushB.err" 2>/dev/null | wc -l)
if [[ $ok_count -ne 1 || $stale_count -ne 1 ]]; then
  lj_fail "exactly one 'push ok' and one 'refuse stale_head'" \
    "ok=$ok_count stale=$stale_count (A exit $SA: $(tail -n 1 "$D/pushA.out" "$D/pushA.err"); B exit $SB: $(tail -n 1 "$D/pushB.out" "$D/pushB.err"))"
fi

lj_step "loser recovers via fork → pull --reset → merge → push"
if grep -q "refuse stale_head" "$D/pushA.out" "$D/pushA.err" 2>/dev/null; then L="$A"; W="$B"; else L="$B"; W="$A"; fi
lj_flint fork --store="$L" main aside; lj_expect_ok "fork ok"
lj_flint pull --store="$L" --remote="$LJ_REMOTE" --reset; lj_expect_ok "pull reset"
lj_flint merge --store="$L" aside; lj_expect_ok "merge ok conflicts=0"
lj_flint push --store="$L" --remote="$LJ_REMOTE"; lj_expect_ok "push ok"

lj_step "winner pulls; both verify --all"
lj_flint pull --store="$W" --remote="$LJ_REMOTE"; lj_expect_ok "pull ok"
lj_flint verify --store="$A" --all; lj_expect_ok "sig: verified"
lj_flint verify --store="$B" --all; lj_expect_ok "sig: verified"

lj_stop_flintd
lj_step "done"
