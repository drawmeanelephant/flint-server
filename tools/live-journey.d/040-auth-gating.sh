#!/usr/bin/env bash
# 040-auth-gating: --auth-key challenge + --allow-author gate.
# Spec: server spec §3.2 (auth), §2.3 (refusals).
set -uo pipefail
source "$LJ_LIB"

D="$SCENARIO_DIR"; A="$D/a"; B="$D/b"
lj_seed_src "$A/src"
mkdir -p "$B/src"

# Auth fixture keys are generated per run — never hardcode a 64-hex literal
# here; secret scanners cannot tell a fixture from a real key.
KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
WRONG="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
printf '%s\n' "$KEY" >"$D/auth.key"
printf '%s\n' "$WRONG" >"$D/wrong.key"

lj_step "A: init + keygen + commit (author identity established)"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
PUB_A="$(lj_keygen_pub "$A" a)"
[[ -n "$PUB_A" ]] || lj_fail "keygen prints pubkey" "no hex"
printf '%s\n' "$PUB_A" >"$D/allow.txt"
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=c1; lj_expect_ok "commit ok"

lj_step "server with --auth-key and --allow-author (A's key only)"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server" --auth-key="$D/auth.key" --allow-author="$D/allow.txt"

lj_step "push without a key refuses auth_required"
lj_flint push --store="$A" --remote="$LJ_REMOTE"
lj_expect_refuse auth_required

lj_step "push with the wrong key refuses auth_failed"
lj_flint push --store="$A" --remote="$LJ_REMOTE" --auth-key="$D/wrong.key"
lj_expect_refuse auth_failed

lj_step "push with the right key and allowed author succeeds"
lj_flint push --store="$A" --remote="$LJ_REMOTE" --auth-key="$D/auth.key"
lj_expect_ok "flint: push ok stream=main changes=1"

lj_step "B clones with the key (read side of the gate)"
lj_flint clone --store="$B" "$LJ_REMOTE" --stream=main --name=main --src="$B/src" --auth-key="$D/auth.key"
lj_expect_ok "clone ok stream=main changes=1"

lj_step "B pushes as a non-allowlisted author → author_not_allowed"
lj_keygen_pub "$B" b >/dev/null
lj_seed_src "$B/src"   # clone replays atoms; source arrives out-of-band
lj_set_atom "$B/src" alpha 2
lj_flint add --store="$B"; lj_expect_ok "modified=1"
lj_flint commit --store="$B" -m=b1; lj_expect_ok "commit ok"
lj_flint push --store="$B" --remote="$LJ_REMOTE" --auth-key="$D/auth.key"
lj_expect_refuse author_not_allowed

lj_stop_flintd
lj_step "done"
