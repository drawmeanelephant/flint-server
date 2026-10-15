#!/usr/bin/env bash
# 030-reclone: re-clone is a fast-forward only; divergence refuses fork_needed.
# Spec: client spec §1 clone — "Never silently overwrites a stream that
# already exists locally."
set -uo pipefail
source "$LJ_LIB"

D="$SCENARIO_DIR"; A="$D/a"; B="$D/b"; C="$D/c"
lj_seed_src "$A/src"
mkdir -p "$B/src" "$C/src"

lj_step "server up"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server"

lj_step "A: two commits pushed"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=c1; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"; lj_expect_ok "push ok stream=main changes=1"
lj_set_atom "$A/src" alpha 2
lj_flint add --store="$A"; lj_expect_ok "modified=1"
lj_flint commit --store="$A" -m=c2; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"; lj_expect_ok "push ok stream=main changes=1"

lj_step "B: clone (2 changes)"
lj_flint clone --store="$B" "$LJ_REMOTE" --stream=main --name=main --src="$B/src"
lj_expect_ok "clone ok stream=main changes=2"

lj_step "A: third commit pushed"
lj_set_atom "$A/src" beta 30
lj_flint add --store="$A"; lj_expect_ok "modified=1"
lj_flint commit --store="$A" -m=c3; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"; lj_expect_ok "push ok"

lj_step "B: re-clone (new ws name) fast-forwards, never rewrites the log"
mkdir -p "$B/src2"
lj_flint clone --store="$B" "$LJ_REMOTE" --stream=main --name=b2 --src="$B/src2"
lj_expect_ok "flint: clone ok stream=main changes=3"

lj_step "C: clone, seed source, local-only commit; A pushes a divergent sibling"
lj_flint clone --store="$C" "$LJ_REMOTE" --stream=main --name=main --src="$C/src"
lj_expect_ok "clone ok stream=main changes=3"
lj_keygen_pub "$C" c >/dev/null
# Clone replays atoms but does not materialize source; seed C's src with the
# stream's head state (alpha=2, beta=30 after A's c1..c3).
printf 'pub const alpha: u32 = 2;\npub const beta: u32 = 30;\n' >"$C/src/main.zig"
lj_set_atom "$C/src" alpha 9
lj_flint add --store="$C"; lj_expect_ok "modified=1"
lj_flint commit --store="$C" -m=c-local; lj_expect_ok "commit ok"
lj_set_atom "$A/src" beta 40
lj_flint add --store="$A"; lj_expect_ok "modified=1"
lj_flint commit --store="$A" -m=c4; lj_expect_ok "commit ok"
lj_flint push --store="$A" --remote="$LJ_REMOTE"; lj_expect_ok "push ok"

lj_step "C: re-clone over diverged stream must refuse fork_needed"
mkdir -p "$C/src2"
lj_flint clone --store="$C" "$LJ_REMOTE" --stream=main --name=c2 --src="$C/src2"
lj_expect_refuse fork_needed

lj_stop_flintd
lj_step "done"
