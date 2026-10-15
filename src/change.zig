const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store.zig");
const json = @import("json.zig");
const ed25519 = @import("ed25519.zig");
const Op = store.Op;
const Change = store.Change;

pub const ChangeError = error{
    ChangeMalformed,
    SigInvalid,
    OutOfMemory,
};

pub fn opTypeCode(t: []const u8) u8 {
    if (std.mem.eql(u8, t, "add")) return 1;
    if (std.mem.eql(u8, t, "modify")) return 2;
    if (std.mem.eql(u8, t, "delete")) return 3;
    if (std.mem.eql(u8, t, "move")) return 4;
    if (std.mem.eql(u8, t, "rename")) return 5;
    return 0;
}

const KeyedOp = struct {
    uuid: [16]u8,
    code: u8,
    idx: usize,
};

fn keyedOpLessThan(_: void, a: KeyedOp, b: KeyedOp) bool {
    switch (std.mem.order(u8, &a.uuid, &b.uuid)) {
        .lt => return true,
        .gt => return false,
        .eq => {
            if (a.code != b.code) return a.code < b.code;
            return a.idx < b.idx;
        },
    }
}

/// Sorts ops by `(atom_id UUID bytes, opTypeCode(type))`, matching `sortOps` in `user/go/flint/change.go`.
pub fn sortOpsAlloc(allocator: Allocator, ops: []const Op) ChangeError![]Op {
    const keyed = try allocator.alloc(KeyedOp, ops.len);
    defer allocator.free(keyed);

    for (ops, 0..) |op, i| {
        const u = store.parseUUID(op.atom_id) orelse return error.ChangeMalformed;
        const c = opTypeCode(op.type);
        if (c == 0) return error.ChangeMalformed;
        keyed[i] = .{ .uuid = u, .code = c, .idx = i };
    }

    std.mem.sort(KeyedOp, keyed, {}, keyedOpLessThan);

    const out = try allocator.alloc(Op, ops.len);
    for (keyed, 0..) |k, i| {
        out[i] = ops[k.idx];
    }
    return out;
}

fn writeU32LE(w: *std.Io.Writer, v: u32) std.Io.Writer.Error!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try w.writeAll(&b);
}

fn writeU64LE(w: *std.Io.Writer, v: u64) std.Io.Writer.Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try w.writeAll(&b);
}

fn writeLenStr(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try writeU32LE(w, @intCast(s.len));
    try w.writeAll(s);
}

fn writeOptStr(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    if (s.len == 0) {
        try w.writeByte(0);
    } else {
        try w.writeByte(1);
        try writeLenStr(w, s);
    }
}

fn writeOptHash32(w: *std.Io.Writer, h: []const u8) ChangeError!void {
    if (h.len == 0) {
        w.writeByte(0) catch return error.OutOfMemory;
        return;
    }
    const raw = store.decodeLowerHexFixed(32, h) orelse return error.ChangeMalformed;
    w.writeByte(1) catch return error.OutOfMemory;
    w.writeAll(&raw) catch return error.OutOfMemory;
}

fn writeOptUUID(w: *std.Io.Writer, s_opt: ?[]const u8) ChangeError!void {
    if (s_opt == null or s_opt.?.len == 0) {
        w.writeByte(0) catch return error.OutOfMemory;
        return;
    }
    const u = store.parseUUID(s_opt.?) orelse return error.ChangeMalformed;
    w.writeByte(1) catch return error.OutOfMemory;
    w.writeAll(&u) catch return error.OutOfMemory;
}

pub fn writeOpBytes(w: *std.Io.Writer, op: Op) ChangeError!void {
    const code = opTypeCode(op.type);
    if (code == 0) return error.ChangeMalformed;
    const aid = store.parseUUID(op.atom_id) orelse return error.ChangeMalformed;

    w.writeByte(code) catch return error.OutOfMemory;
    w.writeAll(&aid) catch return error.OutOfMemory;
    writeOptStr(w, op.kind) catch return error.OutOfMemory;
    writeOptStr(w, op.new_name) catch return error.OutOfMemory;
    if (op.new_span) |sp| {
        w.writeByte(1) catch return error.OutOfMemory;
        writeLenStr(w, sp.file) catch return error.OutOfMemory;
        writeU32LE(w, sp.start) catch return error.OutOfMemory;
        writeU32LE(w, sp.end) catch return error.OutOfMemory;
    } else {
        w.writeByte(0) catch return error.OutOfMemory;
    }
    try writeOptHash32(w, op.new_hash);
    try writeOptHash32(w, op.new_sig_hash);
    try writeOptHash32(w, op.old_hash);
}

/// Computes `SHA-256("FLINT-OPS/1\x00" || u32le(n) || op_bytes(op_1) || ...)`
/// after sorting ops by `(atom_id, type)`, matching `opsHash` in `user/go/flint/change.go`.
pub fn opsHash(allocator: Allocator, ops: []const Op) ChangeError![32]u8 {
    const sorted = try sortOpsAlloc(allocator, ops);
    defer allocator.free(sorted);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    aw.writer.writeAll("FLINT-OPS/1\x00") catch return error.OutOfMemory;
    writeU32LE(&aw.writer, @intCast(sorted.len)) catch return error.OutOfMemory;
    for (sorted) |op| {
        try writeOpBytes(&aw.writer, op);
    }

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(aw.written(), &digest, .{});
    return digest;
}

/// Builds the canonical `FLINT-CHANGE/1\x00` binary preimage for a `Change`,
/// matching `sigMsg` in `user/go/flint/change.go` and `docs/adr-0049.md` §Canonical bytes.
pub fn sigMsg(allocator: Allocator, c: *const Change) ChangeError![]u8 {
    const id_bytes = store.parseUUID(c.id) orelse return error.ChangeMalformed;
    const stream_bytes = store.parseUUID(c.stream) orelse return error.ChangeMalformed;
    const author_bytes = store.decodeLowerHexFixed(32, c.author) orelse return error.ChangeMalformed;
    const oh = try opsHash(allocator, c.ops);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    aw.writer.writeAll("FLINT-CHANGE/1\x00") catch return error.OutOfMemory;
    aw.writer.writeAll(&id_bytes) catch return error.OutOfMemory;
    try writeOptUUID(&aw.writer, c.parent);
    aw.writer.writeAll(&stream_bytes) catch return error.OutOfMemory;
    writeU64LE(&aw.writer, @bitCast(c.ts)) catch return error.OutOfMemory;
    aw.writer.writeAll(&author_bytes) catch return error.OutOfMemory;
    writeLenStr(&aw.writer, c.message) catch return error.OutOfMemory;
    try writeOptUUID(&aw.writer, c.merged);
    aw.writer.writeAll(&oh) catch return error.OutOfMemory;

    return aw.toOwnedSlice();
}

/// Parses and validates a single JSONL line into a `Change`,
/// matching `ParseChange` in `user/go/flint/change.go`.
pub fn parseChange(allocator: Allocator, raw_line: []const u8) ChangeError!Change {
    const s = std.mem.trimEnd(u8, raw_line, "\r\n");
    if (s.len == 0) return error.ChangeMalformed;

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, s, .{}) catch return error.ChangeMalformed;
    defer parsed.deinit();

    var c = json.parseChangeFromValue(allocator, parsed.value) catch |err| switch (err) {
        error.ChangeMalformed, error.StreamMalformed => return error.ChangeMalformed,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer c.deinit(allocator);

    if (c.ts <= 0) return error.ChangeMalformed;
    if (!store.isValidHex128(c.sig)) return error.ChangeMalformed;

    const msg = try sigMsg(allocator, &c);
    allocator.free(msg);

    return c;
}

/// Verifies the Ed25519 signature of a parsed `Change`,
/// matching `VerifyChange` in `user/go/flint/change.go`.
pub fn verifyChange(allocator: Allocator, c: *const Change) ChangeError!void {
    const msg = try sigMsg(allocator, c);
    defer allocator.free(msg);

    const pub_bytes = store.decodeLowerHexFixed(32, c.author) orelse return error.ChangeMalformed;
    const sig_bytes = store.decodeLowerHexFixed(64, c.sig) orelse return error.ChangeMalformed;

    if (!ed25519.verify(msg, sig_bytes, pub_bytes)) {
        return error.SigInvalid;
    }
}

/// Signs a `Change` in place with a 32-byte Ed25519 seed (used by tests).
pub fn signChangeWithSeed(allocator: Allocator, c: *Change, seed: [32]u8) !void {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const pub_hex = store.encodeLowerHexFixed(32, kp.public_key.toBytes());
    allocator.free(c.author);
    c.author = try allocator.dupe(u8, &pub_hex);

    const msg = try sigMsg(allocator, c);
    defer allocator.free(msg);

    const sig = try kp.sign(msg, null);
    const sig_hex = store.encodeLowerHexFixed(64, sig.toBytes());
    allocator.free(c.sig);
    c.sig = try allocator.dupe(u8, &sig_hex);
}
