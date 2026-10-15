#!/usr/bin/env bash
# 120-merge-conflict-recovery: a conflicted merge must have a recovery path.
# Spec: client spec §1 (merge row) — conflicts print one line per conflict
# plus 'flint: merge conflicts=<n>' (exit 2); nothing documents or
# implements a recovery. Today: merge writes ws/<ws>/MERGE.json and exits 2,
# but no verb consumes it — commit during a merge produces a plain change
# (merged:null) and leaves MERGE.json in place, merge refuses stage_dirty
# so a staged resolution can't be re-merged, and there is no abort. The
# only escape is making your side byte-match the other side, which yields
# an empty ops=0 merge commit. Acceptable fix: commit during a merge
# completes it (clears MERGE.json; re-merge reports up to date), or an
# explicit merge --continue/--abort verb pair lands (update this scenario
# to drive those).
set -uo pipefail
source "$LJ_LIB"
lj_repo flint-client

D="$SCENARIO_DIR"; A="$D/a"
lj_seed_src "$A/src"

lj_step "base commit, fork feature, divergent edits"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=base; lj_expect_ok "commit ok"
lj_flint fork --store="$A" main feature; lj_expect_ok "fork ok"
lj_flint init --store="$A" --name=feat --src="$A/src" --stream=feature; lj_expect_ok "init ok"
lj_set_atom "$A/src" alpha 3
lj_flint add --store="$A" --ws=feat; lj_expect_ok "modified=1"
lj_flint commit --store="$A" --ws=feat -m=f1; lj_expect_ok "commit ok"
lj_set_atom "$A/src" alpha 2
lj_flint add --store="$A" --ws=main; lj_expect_ok "modified=1"
lj_flint commit --store="$A" --ws=main -m=m1; lj_expect_ok "commit ok"

lj_step "merge feature into main: conflict on alpha"
lj_flint merge --store="$A" feature --ws=main
if [[ $LJ_LAST_STATUS -ne 2 ]] || ! grep -q "merge conflicts=1" "$LJ_LAST_OUT" "$LJ_LAST_ERR" 2>/dev/null; then
  lj_fail "merge reports the conflict (exit 2, conflicts=1)" \
    "rc=$LJ_LAST_STATUS out=$(tail -1 "$LJ_LAST_OUT")"
fi
[[ -f "$A/ws/main/MERGE.json" ]] || lj_fail "conflicted merge writes MERGE.json" "MERGE.json absent"

lj_step "resolve in src, stage it, commit — the recovery"
lj_set_atom "$A/src" alpha 5
lj_flint add --store="$A" --ws=main; lj_expect_ok "modified=1"
lj_flint commit --store="$A" --ws=main -m=resolve; lj_expect_ok "commit ok"

lj_step "the merge must now be complete"
if [[ -f "$A/ws/main/MERGE.json" ]]; then
  lj_fail "commit during a merge completes it (MERGE.json cleared)" \
    "MERGE.json still present after commit; the conflicted merge is a dead end (no verb consumes MERGE.json, merge refuses stage_dirty, no abort)"
fi
lj_flint merge --store="$A" feature --ws=main
lj_expect_ok "merge up to date"
lj_step "done"
