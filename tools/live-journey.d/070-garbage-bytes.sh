#!/usr/bin/env bash
# 070-garbage-bytes: the server must shrug off malformed input and keep
# serving real clients. Records responses for the finding log either way.
set -uo pipefail
source "$LJ_LIB"

D="$SCENARIO_DIR"; A="$D/a"
lj_seed_src "$A/src"

lj_step "server up; A has a commit ready"
"$FLINTD" init --store="$D/server" >/dev/null 2>&1 || lj_fail "flintd init ok" "init refused"
lj_start_flintd "$D/server"
lj_flint init --store="$A" --name=main --src="$A/src"; lj_expect_ok "init ok"
lj_keygen_pub "$A" a >/dev/null
lj_flint add --store="$A"; lj_expect_ok "add files=1"
lj_flint commit --store="$A" -m=c1; lj_expect_ok "commit ok"

lj_step "garbage line (not JSON)"
reply="$(lj_tcp_send "$LJ_PORT" "this is not json")"
echo "reply: $reply"

lj_step "wrong protocol version"
reply="$(lj_tcp_send "$LJ_PORT" '{"op":"hello","seq":1,"proto":"FLINT-SYNC/9"}')"
echo "reply: $reply"
echo "$reply" | grep -q "proto_version" \
  || lj_fail "proto_version refusal on mismatched hello" "$reply"

lj_step "unknown op"
reply="$(lj_tcp_send "$LJ_PORT" '{"op":"definitely-not-an-op","seq":1}')"
echo "reply: $reply"

lj_step "1 MiB of bytes with no newline (framing abuse)"
python3 - "$LJ_PORT" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(b"A" * (1024 * 1024))
s.settimeout(2)
try:
    print("reply:", s.recv(65536).decode(errors="replace").strip())
except (socket.timeout, ConnectionResetError):
    print("reply: <closed/no reply>")
s.close()
PY

lj_step "server still alive and serving real clients"
lj_flintd_alive || lj_fail "server survives garbage input" "flintd exited during garbage legs"
lj_flint_t 15 push --store="$A" --remote="$LJ_REMOTE"
lj_expect_ok "flint: push ok"

lj_stop_flintd
lj_step "done"
