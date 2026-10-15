#!/usr/bin/env bash
# 050-idle-starvation: an idle TCP connection must not starve other clients
# beyond the read deadline. Serial accept is by design (server spec §3.3);
# issue #9 was fixed by bounding idle sessions with --read-timeout (default
# 60s). This scenario sets --read-timeout=2 and requires a real push to
# complete within 8s. A timeout now is a regression → new finding.
set -uo pipefail
source "$LJ_LIB"
lj_repo flint-server

D="$SCENARIO_DIR"; A="$D/a"
lj_seed_src "$A/src"

lj_step "server up with --read-timeout=2; A has a commit ready to push"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server" --read-timeout=2
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=c1; lj_expect_ok "commit ok"

lj_step "an idle connection opens and says nothing"
lj_tcp_hold "$LJ_PORT"
sleep 0.5

lj_step "a real client must be served once the deadline drops the idle peer"
lj_flint_t 8 push --store="$A" --remote="$LJ_REMOTE"
kill "${LJ_HOLD_PID:-}" 2>/dev/null

if [[ $LJ_LAST_STATUS -eq 124 ]]; then
  lj_fail "push served within 8s (read-timeout=2 should drop the idle peer)" \
    "push timed out after 8s behind an idle connection (regression of #9)"
fi
lj_flintd_alive || lj_fail "server survives an idle connection" "flintd exited"
lj_expect_ok "flint: push ok"

if grep -q "idle_timeout" "$SCENARIO_DIR/flintd.err"; then
  lj_step "server logged the idle_timeout drop"
fi

lj_stop_flintd
lj_step "done"
