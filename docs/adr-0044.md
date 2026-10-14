# ADR 0044: Agent control channel v1 — an outside agent drives a running VirelaiOS

- Date: 2026-10-11
- Status: **Accepted** — landed on `t3/complete-issue-2145`; `go-agentd`
  is 8/8 green on the reference host (observed 2026-10-12).
- Milestone: **M98**. Mission card #2145. This ADR is the card
  body: scope, acceptance, gates and `Touches`.

> The first, deliberately small step toward an agent-native OS. A host-side
> agent connects to a running guest, authenticates, and calls six verbs. It
> can list processes, read and write files in one sandbox directory, run one
> GOSH line and read back what it printed, and see which windows exist. Think
> of an MCP tool server, not a remote desktop and not an in-OS agent.

## Mission

Ship `AGENTD.ELF`, a Go EL0 daemon that serves newline-delimited JSON on the
guest's TCP listener behind an HMAC-SHA256 challenge. Also ship
`tools/agentctl/agentctl.py`, a stdlib-only host client that is both the
reference client and the gate harness, plus one class-B spec (`go-agentd`)
that proves every verb red and green. No kernel, runner, boot or Zig change.
The boot default does not move.

## Grounding (observed in tree `212eb777`, 2026-10-11)

- **Inbound TCP exists, one connection system-wide.** `vi.Listen(port)`
  (`user/go/vi/conn.go:155-172`) passive-opens through slot 30. The kernel
  TCP is a process-wide singleton (`conn.go:16-19`). ADR 0037 §S3 records
  that while one process holds it, no other guest process can use TCP, and
  that guest loopback does not exist. Precedents: GOSSHD, GOHTTPD, the seat's
  RFB server.
- **The host reaches it only through the runner's hermetic `--net`.**
  ADR 0037 §S4/D5 records that a Mac opening a socket directly to the guest
  is a negative, and that there is no NAT port-forward.
  `--net-tcp-connect <ip>:<port>` + `--net-tcp-connect-stream <exe>`
  (`host/vm-runner/Sources/VMRunner/main.swift:1320-1358`, `5615-5679`)
  launches a host executable whose stdin/stdout are the TCP byte stream and
  whose stderr reaches runner output. It prints `NET-TCP-STREAM: probe
  exited status=N`. Bounds: 16 KiB pending TX (`:780`), 4 MiB RX (`:783`).
  `live-rfb.spec` is the working precedent, including
  `--net-tcp-connect-intruder`, which tests refusal of a second SYN.
- **Auth precedent.** ADR 0024 D6/D7 define the `VIRELAIOS-AUTH/1` HMAC
  challenge. GOSH's verifier is `user/go/shlib/netauth.go`, its in-tree
  SHA-256/HMAC is `user/go/shlib/hmac.go`. `crypto/sha256` does **not**
  build under `GOOS=virelai` (`hmac.go:1-6`).
- **Secrets.** `SECRETS.TXT` can only be read through `sys_secret_get`
  (`vi.SecretList`, `user/go/vi/trust.go:79`). Entries can be app-bound:
  `key<TAB>uid<TAB>value<TAB>apps`, served only to an image that
  `OWNERS.TXT` marks as `uid_system`-owned (ADR 0024 D8, M97g #2083).
  `live-ssh-server.spec` stages exactly this for GOSSHD.
- **Processes.** `vi.Procs` returns 40-byte rows: pid, state
  1/2/3 = created/running/exited, exit_status, 16-byte name
  (`user/go/vi/ipc.go:26-127`). Any EL0 process can already read the table.
- **Running GOSH headless.** `GOSH.ELF -c LINE` runs one line and exits with
  its status (`user/go/sh/main.go:25-28`). GOSSHD captures output with
  `LINE > file`, then `vi.Wait` + `vi.ReadFileAll`
  (`user/go/sshd/main.go:267-292`). The GOSH grammar has `|`, `>`, `>>`,
  `<`, `&` and `#` comments, and **no `;`** (`user/go/shlib/parse.go:44-81`).
  Argv is limited to 8 × 255 bytes (`vi.ExecArgMax`). `vi.WaitBudget` /
  `vi.Kill` / `vi.Probe` exist (`user/go/vi/proc.go`, `kill.go`).
- **Files.** Full paths are limited to 64 bytes (`max_path_len`).
  `vi.WriteFileSafe` writes through a temp file, fsync and rename, using the
  temp name `path~` (`user/go/vi/vi.go:656-689`). The host side resolves
  every path with `VFWire.resolveSubpath` and refuses `..`, absolute paths
  and symlinks (`docs/hardware-contract.md:177-195`). The SDK has no mkdir.
- **Windows.** `sys_win_query` (slot 19) answers only for the caller's own
  window. The Go seat's model is `TabStrip` (`user/go/gotabwm/tabs.go`:
  `MaxTabs = 16`, per tab `ID`, `Title`, `Pinned`, `Frozen`, plus the strip
  focus). WM_RPC is a 38-byte frame in a 64-byte mailbox slot. The ring
  holds 8 messages (`vi/ipc.go:26-32`). Kinds 1–15 are used and **16 is
  free** (`vi/wmclient.go:88-115`, `user/src/lib/ui/abi.zig:28-37`). The
  kernel routes by mailbox and does not interpret `kind` (`wmclient.go:98-100`).
  Seat dispatch is `serviceRPC` → `gateRPC` → `applyRPC`
  (`user/go/gotabwm/interop.go:176-191`, `292-319`).
- **JSON cost.** ADR 0042 §1 measured that the reflect-based
  `encoding/json` decoder pushes a guest ELF past the 2,097,152-byte ceiling.
  `json.Valid` alone costs about 512 KiB.
- **Tick.** `timer.period_ns` = 1 s (ADR 0043 Context). A `vi.Sleep(1)` poll
  can therefore park for up to a second. Budgets below are in seconds for
  that reason.

## Scope

In: one guest daemon, one host client/harness, one additive WM_RPC kind,
two small exported helpers in `shlib`, one gate spec, docs rows.

### Non-goals (explicit)

- **No remote desktop or input injection.** No pointer or key events, no
  focus or raise, no pixels or screenshots. `ui.windows` is read-only. RFB
  (ADR 0037) remains the pixel path.
- **No in-OS native agent.** No model, planner or agent loop runs in the
  guest. That is a separate future spec.
- **No Linux-compat layer.** No ELF personality, syscall translation or
  libc shim that would let droid/Devin binaries run directly. ADR 0030 /
  AGENTS.md (no libc, no POSIX) still apply.
- No LAN or remote exposure, no TLS, no session encryption, no multiple
  clients. No new syscall, no runner flag, no kernel change.
- No subdirectories, file listing, delete, rename, or append in the
  sandbox. No streaming exec output, stdin to commands, or background jobs.
- Not on the boot path: no `SERVICES.JSON` row, no `apps.txt` row, no
  autostart.

## D1. Transport and framing

- **Socket:** guest TCP port **4747**, fixed in v1, through `vi.Listen`. One
  client at a time, enforced by the kernel. After every session ends,
  `AGENTD.ELF` closes and listens again. It exits only when it is killed or
  at startup refusal (D2).
- **Host path:** the runner's hermetic `--net` stream adapter only, with
  `agentctl.py` as the `--net-tcp-connect-stream` executable. Its
  stdin/stdout are the wire, and its stderr carries the `AGENTCTL:` lines
  the gate reads. An outside agent uses this channel by being, or wrapping,
  that executable. The loopback-socket bridge is cut (E1).
- **Framing:** JSON Lines. Each message is one UTF-8 JSON object on one line
  ending in LF. A CR directly before the LF is stripped. Limits:
  **256 bytes per line before auth**, **8192 bytes per line after auth**,
  each counting the LF. The daemon buffers at most 16 KiB of pipelined
  input. Requests are handled strictly in order, with one response per
  request, written in full before the next line is parsed.
- **Request shape: one flat object.** `id` is a required integer in
  1..2^31−1. `verb` is a required string. Arguments are top-level sibling
  keys. A value may only be a string, an integer (no sign, fraction or
  exponent; ≤ 2^31−1) or `true`/`false`. `null`, arrays, nested objects,
  duplicate keys, unknown keys and missing required keys all get
  `bad_request`. A line that is not one JSON object gets `bad_json`.
- **Parser:** owned by `agentd` (`wire.go`), written for this flat grammar
  and RFC 8259 string escapes. It must **not** import `encoding/json`
  (ADR 0042 §1 size evidence). Host tests use `encoding/json` as a
  differential oracle.
- **Response shape:** `{"id":N,"ok":true,"result":{…}}` or
  `{"id":N,"ok":false,"error":{"code":"…","message":"…"}}`. `id` is `null`
  when the request id could not be read. `message` is a fixed English
  sentence per code and never echoes request bytes. Byte payloads are
  standard base64 with padding (`*_b64`). Text fields (names, titles) are
  UTF-8, and invalid bytes become U+FFFD.

## D2. Trust model and auth — fail closed

**Who may connect:** only a party that holds the `agent-hmac` key **and**
can reach guest TCP. Today the only route to guest TCP is a process launched
by the runner on the same Mac, as the same user. The key is the gate. The
topology is assumed, not trusted.

**Key provisioning:** done on the host side, never inside the guest.
`SECRETS.TXT` carries `agent-hmac<TAB>1000<TAB><value><TAB>AGENTD.ELF` and
`OWNERS.TXT` pins `AGENTD.ELF<TAB>644<TAB>0<TAB>-`. The value is used
byte-for-byte as stored (≤ 64 bytes, ADR 0024 D8). GOSH, its children and
every other image cannot read it.

**Startup posture.** Checks run in this order. Any failure prints one marker
and exits 1 **before** `vi.Listen`:

1. `vi.Principal()` must report uid 1000 and caps 0. Otherwise
   `agentd: refuse privileged`. The channel never carries `uid_system`
   authority.
2. `agent-hmac` must be present. Otherwise `agentd: refuse no-credential`.
   **There is no `open` mode.**
3. `/host/AGENT` must be a listable directory. Otherwise
   `agentd: refuse no-root`.
4. Listen on 4747. Failure (for example, TCP held by another process)
   prints `agentd: refuse listen errno=<name>`.

`--allow-exec` is the only flag. Without it, `gosh.run` returns
`verb_disabled`. Any other argv token prints `agentd: refuse argv` and exits
1.

**Handshake** (one attempt per connection):

```
S: {"proto":"virelai-agent/1","auth":"hmac-sha256","challenge":"<64 hex>"}
C: {"auth":"<64 lowercase hex>"}
S: {"ok":true,"session":"ready","verbs":["proc.list","proc.get","fs.read","fs.write","ui.windows","gosh.run"]}
```

- The challenge is 32 fresh bytes from `vi.Random` (slot 72) per
  connection.
- MAC = `HMAC-SHA256(key, "VIRELAI-AGENT/1 hmac-sha256" || 0x00 ||
  challenge[32])`. This domain differs from `VIRELAIOS-AUTH/1`, so a GOSH
  `net` MAC can never answer this server. Compare in constant time. Wipe the
  key, challenge and reply buffers after the verdict.
- `verbs` lists only enabled verbs (`gosh.run` is absent without
  `--allow-exec`).
- Failures send one error line and then close: a wrong MAC, or any first
  line other than exactly `{"auth":"<64 hex>"}`, is `auth_failed`. A first
  line with a `verb` key is `auth_required`. No complete line within
  **10 s** is `auth_timeout`. After any auth failure the daemon waits
  **1 s** before listening again (brute-force damping on a 256-bit key).
- Pinned vector (class A, Go and Python). Key = ASCII `a5` × 32 (64 bytes),
  challenge = `00 01 … 1f`, MAC =
  `e907b2015a16de6504cc2bc61da0d60156c3abe2b035601372840acb58feff04`.
  Computed with Python `hmac`/`hashlib` while drafting this ADR. The Go
  implementation must reproduce it.

**Session:** the session ends after **60 s** idle (`idle_timeout`, fatal),
on peer FIN/RST, or on `line_too_long`.

**Authority ceiling:** `uid_user`, no caps. Exactly that much and no more:

- `fs.*` can only reach flat names in `/host/AGENT/` (D3).
- `gosh.run` is **explicitly an escape hatch from that bound**. It runs
  arbitrary GOSH as `uid_user`, so it can reach every `/host` path a
  `uid_user` process can. That is why it is opt-in. The kernel still denies
  secret-class reads, writes to paths owned by `uid_system`, and kills
  across principals (ADR 0024 D3–D5, D8). A per-process path jail is cut
  (E3).

**Not provided** (stated, not hidden):

- Post-auth confidentiality, integrity, or protection against replay within
  a session. The stream is plaintext, as in ADR 0024 D7.
- Server authentication to the client.
- More than one client.
- TCP for anything else in the guest while `AGENTD.ELF` holds the socket.
  That includes `gosh.run` commands that use the network: fetch, DNS, SSH
  and RFB fail as busy.
- Guaranteed `ui.windows` rows. The seat query rides the M97g-F2 bind, so
  a co-resident EL0 process cannot forge a reply that satisfies the
  caller's wait without quoting the session token (D5). The rows are
  still only as honest as the seat's own strip state.

## D3. Command surface (complete)

`NAME` means a sandbox file name. It is 1–31 bytes from `[A-Za-z0-9._-]`,
the first byte is alphanumeric, and it is never `.` or `..`. It resolves to
`/host/AGENT/<NAME>`, at most 43 bytes, which leaves room for the
`WriteFileSafe` `~` temp. Matching is case-insensitive, as in the kernel
(ADR 0024 D4). The validator is a pure function, `paths.go`.

| Verb | Args | `result` on success |
|---|---|---|
| `proc.list` | none | `{"procs":[{"pid":N,"name":S,"state":"created"\|"running"\|"exited","exit_status":N\|null}]}`. At most 64 rows, in kernel order. `exit_status` is set only when `exited`. |
| `proc.get` | `pid`: int ≥ 1 | `{"pid":N,"name":S,"state":…,"exit_status":…}` (one row) |
| `fs.read` | `path`: NAME | `{"path":S,"size":N,"data_b64":S}`. The whole file, ≤ 4096 bytes. |
| `fs.write` | `path`: NAME, `data_b64`: base64 of ≤ 4096 bytes | `{"path":S,"size":N}`. Create or replace, atomic through `vi.WriteFileSafe`. |
| `ui.windows` | none | `{"seat":"gotabwm"\|"none","focused":I\|null,"windows":[{"index":I,"id":N,"title":S,"focused":B,"pinned":B,"frozen":B}]}` |
| `gosh.run` | `cmd`: string; `timeout_ms`: int 1..30000, default 10000 | `{"exit_status":N,"stdout_b64":S,"truncated":B}` |

Verb semantics that are binding:

- **`proc.get`** uses the same snapshot as `proc.list`. A pid that is absent
  is `not_found`.
- **`fs.read`** opens read-only. A file over 4096 bytes is `too_large`. The
  daemon never returns a partial read in v1.
- **`fs.write`** decodes base64 strictly: padding is required, there is no
  whitespace, and the alphabet is standard. A bad body is `bad_request`.
  More than 4096 decoded bytes is `too_large`, checked before any file call.
- **`ui.windows`** uses the seat query from D5. `seat:"none"` with an empty
  list is a success when no seat is registered (`vi.WmctlSeatPid() <= 0`).
  A Zig seat, or a Go seat that answers `applied=0`, is `seat_unsupported`.
  No complete answer within 10 s — including a bind that never completes —
  is `seat_timeout`. `focused` and the per-row flag reflect the seat
  strip's focus. The first call against a registered seat opens the
  daemon's bind window and walks the ownership challenge, so it costs two
  extra round trips once per daemon lifetime.
- **`gosh.run`**:
  1. `cmd` must be 1–192 bytes of printable ASCII (0x20–0x7e), or the
     request fails with `too_large` (length) or `cmd_rejected` (bytes).
  2. `cmd` must pass `shlib.CheckAgentLine(cmd)`, or it fails with
     `cmd_rejected`. That check runs GOSH's real tokenizer. It refuses an
     unbalanced quote or trailing backslash, and any unquoted `>`, `>>` or
     `&`. It also requires that tokenizing `cmd + " > X"` yields the
     original tokens plus exactly one trailing `tokOut, "X"`, which catches
     `#` comments and escapes that would otherwise eat the appended
     redirect.
  3. The daemon deletes `/host/AGENTD.OUT` and runs
     `vi.Exec("GOSH.ELF", "-c", cmd + " > /host/AGENTD.OUT")`. A spawn
     error is `spawn_failed`.
  4. It waits with `vi.WaitBudget(pid, timeout)`. When the budget expires
     it calls `vi.Kill(pid)`, confirms through `vi.Probe`, and answers
     `timed_out`.
  5. It reads up to 4096 + 1 bytes, sets `truncated` when the output is
     over 4096, and deletes the file.
  6. A non-zero `exit_status` is still `ok:true`: the command ran.
  - **Observed capture contract (pinned):** a builtin's stdout — success
    or failure text — goes through the shell's output sink, so the
    redirect captures it. An external app writes fd 1 itself: under `>`
    its bytes bypass the capture, the file is still written (empty), the
    external's status is the line's status, and nothing diagnoses the
    loss. A pipeline that names an external refuses before any write with
    the shell's own diagnostic (`cannot capture an external app's output
    yet` / `a piped command must be a builtin or tool`). The agent reports
    what the shell did — `stdout_b64` is whatever `AGENTD.OUT` holds, and
    an external's empty capture is reported honestly as empty. Pinned in
    `shlib/agentline_observed_test.go`.
  - The working directory is GOSH's default `/host`, **not** `/host/AGENT`.
  - `AGENTD.OUT` lives outside the sandbox on purpose.

## D4. Out-of-bounds requests and the error model

The rule is **refuse before touching anything.** Request validation (shape,
types, ranges, NAME, `cmd`) happens entirely before any syscall. A refused
request has no side effect. A refusal after auth leaves the session open.
Only codes marked *fatal* close it.

| Code | When | Fatal |
|---|---|---|
| `bad_json` | the line is not one JSON object, or is not valid UTF-8 | no |
| `bad_request` | missing, unknown, duplicate or mistyped field; value out of range; nested value; `null` | no |
| `unknown_verb` | `verb` is not in D3 | no |
| `path_rejected` | `path` is not a NAME (`..`, `/`, absolute, `~`, NUL, empty, > 31 bytes, bad charset) | no |
| `not_found` | ENOENT from the file ABI, or a pid that is absent | no |
| `access_denied` | EACCES from the kernel (trust policy) | no |
| `not_a_file` | the name is a directory | no |
| `too_large` | file or body > 4096 bytes, or `cmd` > 192 bytes | no |
| `cmd_rejected` | `cmd` fails the byte rule or `CheckAgentLine` | no |
| `verb_disabled` | `gosh.run` without `--allow-exec` | no |
| `spawn_failed` | `vi.Exec` of `GOSH.ELF` failed | no |
| `timed_out` | `gosh.run` budget exhausted; the child was killed | no |
| `seat_unsupported` / `seat_timeout` | see `ui.windows` | no |
| `io_error` | any other negative kernel result (`message` carries `vi.ErrnoName`) | no |
| `auth_required` / `auth_failed` / `auth_timeout` | D2 | **yes** |
| `line_too_long` | a line exceeds its limit (bytes discarded unparsed) | **yes** |
| `idle_timeout` | 60 s without a request | **yes** |

## D5. Seat query: WM_RPC kind 16 `WINDOWS_QUERY` (additive, bound)

The query rides the M97g-F2 sender-authentication bind like every other
kind (owner ruling 2026-10-13: **auth wins** — the pre-auth exemption the
landed squash used is dropped; `ui.windows` requires an authenticated bind
first, and that is the contract).

- **Request:** `kind=16`, `id` = a window the caller owns, `seq` and
  `reply_to` as usual, `title[0]` = `start` (page index 0..15). `id` is
  the bound window and `x/y/w/h` are the auth union, so the page index
  rides the first title byte — the only payload field the bind leaves.
- **Seat handling:** `serviceRPC` routes kind 16 through `gateRPC` like
  everything else. An unbound `id` draws the ownership challenge; a bound
  `id` with the wrong `reply_to` or token draws a bare refusal and no
  rows; a proven or credentialed request applies and is served by
  `serveWindowsQuery`. The ownership echo is itself a page request — its
  bound answer both mints the session token and opens the page.
- **Reply:** every frame is `kind=16|0x80` with the request's seq,
  `Pad=Bound`, and `x/y/w/h` quoting the session token — which the row
  payload therefore cannot share. A row frame carries `ID` = strip index,
  `Applied=1`, and packs `title[0:2]` = kernel window id LE, `title[2]` =
  flags (bit 0 focused, bit 1 pinned, bit 2 frozen), `title[3:]` = tab
  title, NUL-padded and truncated to 21 bytes. Every request ends with
  ONE `Applied=0` end-of-page frame whose `title[0]` is the strip count —
  without a `W` to quote, that frame is how the client learns the page is
  done and whether another `start` remains. A send that fails ends the
  page without a retry, and the client's budget expires instead.
- **Bounds:** at most 5 frames per request (4 rows + end), which fits the
  8-slot ring (ENOSPC is defined behavior). At most 4 requests cover
  `MaxTabs = 16`.
- **Client:** `vi.WmWindows(winID, selfName)` in `user/go/vi/wmquery.go`,
  reusing the package's bind/ack machinery (`wmToken`, `bindSetTitle`,
  `wmBindMaxRounds`). Agentd is the only caller; it opens one kernel
  window lazily on the first `ui.windows` call and never declares it, so
  the daemon's bind window stays off the strip it reads. A forged bound
  frame quoting a different value is consumed and dropped; a token the
  seat forgot is re-challenged and re-bound.
- **Not changed:** the Zig seats and the kernel. Zig TABWM answers unknown
  kinds `applied=0`, which becomes `seat_unsupported`. The 38-byte frame
  layout and the bind invariants are untouched.

## D6. Markers and the never-logged contract

Each event writes one serial line through `vi.ConsoleLine`, printed after
its step succeeds:

```
agentd: start exec=on|off
agentd: listen 4747
agentd: accepted
agentd: auth ok
agentd: auth fail reason=mac|malformed|preauth|timeout
agentd: req id=<n> verb=<verb> ok
agentd: refuse id=<n> verb=<verb|-> code=<code>
agentd: spawn pid=<n>
agentd: reap pid=<n> status=<n>
agentd: session end reason=client_close|<fatal code>
agentd: refuse privileged|no-credential|no-root|argv|listen errno=<name>
gotabwm: wq start=<i> rows=<n> count=<n>
```

The key, challenge, MAC, request paths, file bytes, `cmd` text and command
output **never** reach serial, `APPLOG`, or crash receipts. Class B
enforces this with `serial-absent` sentinels. The host client never prints
the key either.

## Acceptance criteria

1. **AC1 build.** `bash tools/go/build-agentd.sh` produces
   `.build/go/AGENTD.ELF` of at most 2,097,152 bytes. The script refuses
   larger output by name. `user/go/agentd` does not import
   `encoding/json`, `fmt` or `crypto/*`.
2. **AC2 class A, Go.** From `user/go`,
   `go test ./agentd ./shlib ./vi ./gotabwm` is green and includes:
   - Wire reader differential against `encoding/json`: accepted and refused
     corpora, every D1 refusal, and a size-bounded fuzz seed set.
   - Golden response encodings.
   - A table for every D4 code.
   - The NAME validator table (all `path_rejected` cases in the Gates
     matrix plus case variants).
   - The pinned HMAC vector, a constant-time compare, and key wipe.
   - Startup posture order (fake syscall hook for each refusal).
   - `CheckAgentLine` accept and refuse table.
   - Kind 16 seat paging (0, 1, 4, 5, 16 tabs; start past end; ENOSPC
     mid-page).
   - `vi.WmWindows` assembly and timeout.
3. **AC3 class A, Python.** `python3 -m unittest tools/agentctl/test_agentctl.py`
   is green: pinned vector, framing, line bounds, journey script parsing.
4. **AC4 the journey requested in the brief** (`go-agentd` run 01). The host
   harness connects, authenticates and runs `proc.list`, which includes
   `AGENTD.ELF` running. `gosh.run {"cmd":"echo hello"}` returns
   `stdout_b64` that decodes to `hello\n` with `exit_status` 0.
   `fs.write HELLO.TXT` is byte-equal on the host
   (`share-equals AGENT/HELLO.TXT`), `fs.read` round-trips it, and
   `ui.windows` returns `seat:"gotabwm"` with ≥ 1 row titled `Calc` and
   exactly one focused row.
5. **AC5 every verb, red and green, on class B.** The matrix below holds,
   and every D4 code has at least one class-A test.
6. **AC6 fail-closed posture on class B.** Runs 02–08 hold. Each one
   proves that nothing listens, or that the session closed, *and* that no
   verb ran (`agentd: req` absent).
7. **AC7 never-logged.** In every run, the serial log and runner output omit
   the key text, the MAC, and the payload and stdout sentinels.
8. **AC8 no regressions.** `just verify-portable` is green, and `go-sh`,
   `go-wm-seat`, `go-wm-tabs` and `live-ssh-server` are green on the
   reference host (they cover shlib, the seat's RPC loop and the SDK).
9. **AC9 untouched.** The diff has nothing under `kernel/`, `host/`,
   `boot/`, `user/src/`, `image/` or `user/go/init/`, and leaves
   `vi/conn.go` and `vi/wmclient.go` alone. The boot default is unchanged.
10. **AC10 docs.** This ADR moves to Accepted with observed figures (ELF
    bytes, per-run wall time) and any amendment. The M98 row in
    `docs/status.md` is edited in place. `docs/testing.md` gains the
    `go-agentd` entry.

## Gates

### Class B — `tools/gate/specs/go-agentd.spec` (one spec, eight runs)

`vgate_share seed`, `-DSPIKE`. Staging follows `live-rfb.spec` (`wm=none`,
then the seat is exec'd explicitly) and `live-ssh-server.spec` (secret and
owner rows). The share is staged with `AGENTD.ELF`, `GOSH.ELF`,
`GOTABWM.ELF`, `GOCALC.ELF`, the `AGENT/` directory, `AGENT/SEED.TXT`
(fixed bytes) and `AGENT/BIG.BIN` (4097 bytes). Each client run uses
`--net --net-arp-respond 10.0.0.2 --net-tcp-connect 10.0.0.1:4747
--net-tcp-connect-stream tools/agentctl/agentctl.py
--net-tcp-connect-stream-arg harness --net-tcp-connect-stream-arg
--journey=<J> --net-tcp-connect-after 'agentd: listen 4747'`. The key
reaches the harness through a `$RUN_DIR` file, never argv text that is
logged.

| Run | Setup | Journey | Must hold |
|---|---|---|---|
| 01 | seat + `AGENTD.ELF --allow-exec` + Calc, `--net-tcp-connect-intruder` | `full` | AC4 greens. Every in-session red in the matrix below. Final 8193-byte line → `line_too_long`, `session end reason=line_too_long`. Intruder SYN refused, session intact. `AGENTCTL: PASS full`, probe status 0 |
| 02 | `AGENTD.ELF` | `badmac` | `auth_failed`. `auth fail reason=mac`. `agentd: listen 4747` ≥ 2 (relistened). `auth ok` and `req` absent |
| 03 | `AGENTD.ELF` | `preauth` (sends `proc.list` first) | `auth_required`, `reason=preauth`, `req` absent |
| 04 | `AGENTD.ELF` | `mute` | `auth_timeout` within 15 s, `reason=timeout` |
| 05 | `AGENTD.ELF` (no flag, no seat) | `noexec` | `verbs` lacks `gosh.run`. `gosh.run` → `verb_disabled`, `agentd: spawn` absent. `ui.windows` → `seat:"none"`, `[]` |
| 06 | monitor `exec -u0 AGENTD.ELF` | none | `agentd: refuse privileged`, `listen` absent |
| 07 | no `agent-hmac` row | none | `agentd: refuse no-credential`, `listen` absent |
| 08 | no `AGENT/` directory | none | `agentd: refuse no-root`, `listen` absent |

Every run also asserts that the serial log omits the key, the payload
sentinel and the stdout sentinel. Run 01's python assert compares the share
root listing with the staged set plus `AGENT/HELLO.TXT` and
`AGENTD.OUT`-absent, and checks that `SECRETS.TXT` is byte-unchanged.

#### Amendment (landed, observed 2026-10-12)

**Run 01 stages GOCALC last.** `scheduler.max_tasks` is 16 and a live Go
runtime holds ~4 task slots (main + sysmon + startup Ms — measured via the
`tasks` monitor dump: kernel 3 + 4 per Go process). Seat + Calc + agentd +
a `gosh.run` child would need 19 slots, so the four cannot coexist. Run 01
therefore execs `GOCALC.ELF` on the first `verb=ui.windows` marker — after
every `gosh.run` call in the journey — and the harness polls `ui.windows`
until the Calc row registers (`UI_WAIT`, 60 s). AC4's assertions are
unchanged; only the staging order moved.

Two `gosh.run` robustness fixes ride the same bound: a spawn that lands
`ENOSPC` retries for ≤ 2 s on yields (a just-exited child's slots stay
zombie until the idle task reaps them), and after `WaitBudget` the daemon
yield-polls `Probe` for `ProbeAbsent` before answering so a back-to-back
`gosh.run` sees a clean pool.

**Observed figures:** `AGENTD.ELF` 1,769,632 bytes (ceiling 2,097,152);
`go-agentd` 8/8 PASS, ~3 min wall for all eight runs on the reference
host; guest class A `go test ./agentd ./shlib ./vi ./gotabwm` green; host
class A `python3 -m unittest tools/agentctl/test_agentctl.py` 21 tests
green.

#### Amendment (post-merge owner rulings, 2026-10-13)

The merge's `Closes` auto-closed the card before close-out; the owner
reopened it and ruled on two points, both implemented here:

1. **Kind 16 rides the bind.** The landed pre-auth exemption conflicted
   with M97g-F2 (binding is keyed by `id`, which the exemption had reused
   as the page index). D5 is rewritten: `id` is a caller-owned window,
   `title[0]` is the page index, and bound replies quote the session
   token in `x/y/w/h`. Because the row payload can no longer share those
   fields, rows pack window id + flags + a 21-byte title into the title
   field, and every page ends with an `Applied=0` frame carrying the
   strip count. Agentd opens one undeclared kernel window to bind with;
   it never joins the strip it reads. Observed on the gate: the open
   must be at or above the kernel's resize floor — a 1x1 window faulted
   the compositor's paint path — so the bind window opens 128x64 and
   hides via `sys_win_set_visible` immediately (plumbing, not pixels).
2. **GOSH redirect pinned as observed.** `CheckAgentLine` untouched. The
   `>` redirect captures builtin stdout (success and failure text); an
   external app's fd-1 output bypasses capture and the file is written
   empty; an external in a pipeline refuses before any write. That is
   the spec now, pinned in `shlib/agentline_observed_test.go` and in the
   D3 capture bullet.

### Per-verb red/green matrix (run 01 unless noted)

| Verb | Green | Red |
|---|---|---|
| `proc.list` | contains `AGENTD.ELF` `running` | extra key `x:1` → `bad_request` |
| `proc.get` | own pid → `AGENTD.ELF` | `pid:0` → `bad_request`; `pid:4000` → `not_found`; `pid:"1"` → `bad_request` |
| `fs.read` | `SEED.TXT` exact bytes; `HELLO.TXT` round-trip | `../SECRETS.TXT`, `/host/SECRETS.TXT`, `SUB/X`, `.`, `..`, `""`, 32-byte name, `X~`, `A\u0000B` → `path_rejected`; `NOPE.TXT` → `not_found`; `BIG.BIN` → `too_large` |
| `fs.write` | `HELLO.TXT` (payload sentinel) → `share-equals` | 4097 bytes → `too_large`; `"data_b64":"@@"` → `bad_request`; `../X` → `path_rejected`; share root unchanged |
| `gosh.run` | `echo hello` → `hello\n`, 0; `cat NOPE.TXT` → `ok:true`, status ≠ 0; `cat /host/SECRETS.TXT` → `ok:true`, status ≠ 0, stdout lacks key (ceiling evidence) | `echo a > X`, `echo a #c`, `echo a &`, `echo 'a`, `"echo a\nls"` → `cmd_rejected`; 193 bytes → `too_large`; `timeout_ms:0` / `30001` → `bad_request`; `sleep 5` + `timeout_ms:1000` → `timed_out` + `agentd: reap`; run 05 → `verb_disabled` |
| `ui.windows` | `gotabwm`, ≥ 1 `Calc` row, one focused; run 05 `none` | extra key → `bad_request`; `seat_unsupported`/`seat_timeout` class A |
| framing | — | `{` → `bad_json`; `{"verb":"proc.list"}` → `bad_request`; `{"id":1,"verb":"nope"}` → `unknown_verb`; duplicate `id` → `bad_request`; nested `{"a":{}}` → `bad_request`; `null` → `bad_request`; 8193 bytes → `line_too_long` (fatal, last) |

The harness prints one `AGENTCTL: ok <step>` or `AGENTCTL: FAIL <step>
<why>` line per step and exits non-zero on the first FAIL. The spec asserts
`AGENTCTL: PASS <journey>` and `NET-TCP-STREAM: probe exited status=0`.

## File touches

**Touches:** `docs/decisions/0044-agent-control-channel.md`,
`docs/status.md`, `docs/testing.md`, `user/go/agentd/**`,
`user/go/shlib/agentline.go`, `user/go/shlib/agentline_test.go`,
`user/go/shlib/agentline_observed_test.go`,
`user/go/vi/vi.go`, `user/go/vi/wmquery.go`, `user/go/vi/wmquery_test.go`,
`user/go/gotabwm/interop.go`, `user/go/gotabwm/windows_query.go`,
`user/go/gotabwm/windows_query_test.go`, `tools/go/build-agentd.sh`,
`tools/agentctl/**`, `tools/gate/specs/go-agentd.spec`

- `user/go/agentd/`: `main.go` (posture, listen loop, session), `wire.go`
  (reader and writer), `verbs.go`, `paths.go`, `auth.go`, plus `*_test.go`.
- `shlib/agentline.go`: `CheckAgentLine` and an exported
  `HMACSHA256(key, msg) [32]byte` wrapper over the existing `hmac.go`
  (no copy of SHA-256).
- `gotabwm/interop.go`: kind 16 routes through `gateRPC` like every other
  kind; on `apply` it is served by `serveWindowsQuery` instead of
  `applyRPC`/`replyRPC`.
- `tools/agentctl/`: `agentctl.py` (client `Session` class + `harness`
  journeys) and `test_agentctl.py`. Python stdlib only (`hmac`, `hashlib`,
  `base64`, `json`), PSF license, no new dependency.
- **Not touched:** `kernel/**`, `host/**`, `boot/**`, `user/src/**`,
  `image/**`, `user/go/init/**`, `user/go/vi/conn.go`,
  `user/go/vi/wmclient.go`, `docs/gate-fleet-inventory.md`.

## Cut to their own epics (not in this spec)

- **E1 — Operator reachability.** A loopback-socket bridge (`127.0.0.1`,
  one client) so an agent started independently can attach to a running VM.
  It also needs an auth-deadline story, because the guest's 10 s clock
  starts when the runner dials, before any agent exists (the `rfb-tape.sh`
  race). Same family as ADR 0037 Open issue 1.
- **E2 — MCP adapter.** An MCP stdio server whose tools map 1:1 onto D3.
  It sits on top of `agentctl.Session` and needs nothing new in the guest.
- **E3 — Exec confinement.** A per-process path root or capability so that
  `gosh.run` stops being an escape hatch. Kernel and ADR 0024 work.
- **E4 — Richer surface.** Sandbox subdirectories, list, delete, ranged
  reads, streaming output, stdin, stderr capture, a cwd, concurrent jobs.
- **E5 — UI depth.** Full window geometry and z-order for non-tab windows,
  then any input or focus verbs (that is the remote-desktop line, and it
  needs its own threat model).
- **E6 — Transport hardening.** Session encryption (ChaCha20-Poly1305,
  M47), Ed25519 client keys, multiple clients (needs multi-connection TCP),
  and a declarative INIT service row that is disabled by default.

## Risks and stop conditions

- **ELF ceiling.** If importing `shlib` pushes `AGENTD.ELF` over the
  2 MiB ceiling, stop. Copying is forbidden. Extract the tokenizer and HMAC
  into a leaf package, record that as an amendment here, and add the extra
  touch to the claim.
- **Tick latency.** Budgets assume up to about 1 s per poll. If run 01 cannot
  finish within a 240 s `--timeout`, record the measured per-verb latency
  here and stop. Do not add a kernel tick change or a runner flag.
- **Seat behaviour — resolved.** The landed squash served kind 16 ahead of
  `gateRPC` (a pre-auth exemption justified by read-only semantics). The
  owner ruled the exemption conflicts with the M97g-F2 bind invariants:
  kind 16 now rides the normal bind (D5 rewrite above), the protocol was
  not weakened, and `ui.windows` requires an authenticated bind first.
- **Unexpected GOSH behaviour — resolved.** Observed and pinned in class A
  (`agentline_observed_test.go`) and in the D3 capture bullet above: the
  redirect captures builtin output only; an external app's fd-1 output
  bypasses it and the file is still written empty. `CheckAgentLine` was
  not widened or otherwise touched.

## Rejected alternatives

- **The serial console or `--console-tcp` as the channel.** It is shared
  with GOSH and the monitor, there is no framing, and agent traffic would
  interleave with human I/O.
- **A file mailbox on the host share** (request and response files that are
  polled). There is no connection to authenticate, requests and responses
  race other share writers, and polling makes it worse than TCP.
- **A new runner-hosted control socket.** That would be host-side policy in
  Swift with no guest authentication, would touch `main.swift`, and is
  E1's job.
- **The `VIRELAIOS-AUTH/1` domain and the `net-hmac` key.** That would
  share a credential with GOSH's net front-end. A separate key bound to
  `AGENTD.ELF` keeps the blast radius to one image.
- **An in-process `shlib` engine instead of spawning GOSH.** External
  children's stdout would need fd plumbing that the engine does not own.
  The brief asks for a spawned GOSH, and GOSSHD already proves the
  redirect pattern.
- **Reflect-based `encoding/json`.** It is over the ELF ceiling (ADR 0042
  §1).
