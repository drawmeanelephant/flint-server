#!/usr/bin/env bash
# 100-auth-key-refusal-name: a malformed --auth-key file is not a usage
# error — the command line was fine, the secret file is malformed. The
# contractual vocabulary has secret_malformed for exactly this (client
# spec §1); flintd currently refuses 'usage' with exit 2.
set -uo pipefail
source "$LJ_LIB"

D="$SCENARIO_DIR"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"

lj_step "serve with a garbage --auth-key file"
printf 'not-hex-at-all\n' >"$D/bad.key"
out="$("$FLINTD" serve --store="$D/server" --listen=127.0.0.1:1 --auth-key="$D/bad.key" 2>&1)"
rc=$?

[[ $rc -ne 0 ]] || lj_fail "nonzero exit on malformed key file" "exit 0"
echo "observed: rc=$rc out=$out"
echo "$out" | grep -q "refuse secret_malformed" \
  || lj_fail "refusal 'secret_malformed' (rc 1) for a malformed key file" \
    "got rc=$rc '$out' — 'usage' blames the operator's command line, not the file"
lj_step "done"
