const std = @import("std");
const Allocator = std.mem.Allocator;

pub const MaxFileReadBytes: usize = 4 * 1024 * 1024;
pub const MaxChanges: usize = 4096;
pub const MaxMessageBytes: usize = 512;
pub const MaxStreamNameBytes: usize = 32;
pub const MaxLineBytes: usize = 4 * 1024 * 1024;
pub const DefaultReadLimit: usize = 256;
pub const MaxReadLimit: usize = 1024;

pub const RefusalCode = enum {
    stream_missing,
    stream_exists,
    stale_head,
    change_malformed,
    change_missing,
    sig_invalid,
    store_too_large,
    stream_malformed,
    stream_torn,
    message_invalid,
    usage,
    proto_version,
    auth_required,
    auth_failed,
    author_not_allowed,
    store_not_found,
    store_missing,
    store_io,
    secret_malformed,

    pub fn asText(self: RefusalCode) []const u8 {
        return switch (self) {
            .stream_missing => "stream_missing",
            .stream_exists => "stream_exists",
            .stale_head => "stale_head",
            .change_malformed => "change_malformed",
            .change_missing => "change_missing",
            .sig_invalid => "sig_invalid",
            .store_too_large => "store_too_large",
            .stream_malformed => "stream_malformed",
            .stream_torn => "stream_torn",
            .message_invalid => "message_invalid",
            .usage => "usage",
            .proto_version => "proto_version",
            .auth_required => "auth_required",
            .auth_failed => "auth_failed",
            .author_not_allowed => "author_not_allowed",
            .store_not_found => "store_not_found",
            .store_missing => "store_missing",
            .store_io => "store_io",
            .secret_malformed => "secret_malformed",
        };
    }
};

pub const Span = struct {
    file: []const u8,
    start: u32,
    end: u32,

    pub fn clone(self: Span, allocator: Allocator) !Span {
        return .{
            .file = try allocator.dupe(u8, self.file),
            .start = self.start,
            .end = self.end,
        };
    }

    pub fn deinit(self: *Span, allocator: Allocator) void {
        allocator.free(self.file);
    }

    pub fn eql(a: Span, b: Span) bool {
        return std.mem.eql(u8, a.file, b.file) and a.start == b.start and a.end == b.end;
    }
};

pub const ForkOrigin = struct {
    stream: []const u8,
    change: []const u8,

    pub fn clone(self: ForkOrigin, allocator: Allocator) !ForkOrigin {
        const s_copy = try allocator.dupe(u8, self.stream);
        errdefer allocator.free(s_copy);
        const c_copy = try allocator.dupe(u8, self.change);
        return .{
            .stream = s_copy,
            .change = c_copy,
        };
    }

    pub fn deinit(self: *ForkOrigin, allocator: Allocator) void {
        allocator.free(self.stream);
        allocator.free(self.change);
    }
};

pub const Stream = struct {
    id: []const u8,
    name: []const u8,
    head: ?[]const u8 = null,
    created: i64 = 0,
    forked_from: ?ForkOrigin = null,

    pub fn clone(self: Stream, allocator: Allocator) !Stream {
        const id_copy = try allocator.dupe(u8, self.id);
        errdefer allocator.free(id_copy);
        const name_copy = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name_copy);
        const head_copy = if (self.head) |h| try allocator.dupe(u8, h) else null;
        errdefer if (head_copy) |h| allocator.free(h);
        var ff_copy: ?ForkOrigin = if (self.forked_from) |ff| try ff.clone(allocator) else null;
        errdefer if (ff_copy) |*ff| ff.deinit(allocator);

        return .{
            .id = id_copy,
            .name = name_copy,
            .head = head_copy,
            .created = self.created,
            .forked_from = ff_copy,
        };
    }

    pub fn deinit(self: *Stream, allocator: Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        if (self.head) |h| allocator.free(h);
        if (self.forked_from) |*ff| ff.deinit(allocator);
    }
};

pub const Op = struct {
    type: []const u8,
    atom_id: []const u8,
    kind: []const u8 = "",
    new_name: []const u8 = "",
    new_span: ?Span = null,
    new_hash: []const u8 = "",
    new_sig_hash: []const u8 = "",
    old_hash: []const u8 = "",

    pub fn clone(self: Op, allocator: Allocator) !Op {
        const type_copy = try allocator.dupe(u8, self.type);
        errdefer allocator.free(type_copy);
        const atom_id_copy = try allocator.dupe(u8, self.atom_id);
        errdefer allocator.free(atom_id_copy);
        const kind_copy = if (self.kind.len > 0) try allocator.dupe(u8, self.kind) else "";
        errdefer if (kind_copy.len > 0) allocator.free(kind_copy);
        const new_name_copy = if (self.new_name.len > 0) try allocator.dupe(u8, self.new_name) else "";
        errdefer if (new_name_copy.len > 0) allocator.free(new_name_copy);
        var new_span_copy: ?Span = if (self.new_span) |sp| try sp.clone(allocator) else null;
        errdefer if (new_span_copy) |*sp| sp.deinit(allocator);
        const new_hash_copy = if (self.new_hash.len > 0) try allocator.dupe(u8, self.new_hash) else "";
        errdefer if (new_hash_copy.len > 0) allocator.free(new_hash_copy);
        const new_sig_hash_copy = if (self.new_sig_hash.len > 0) try allocator.dupe(u8, self.new_sig_hash) else "";
        errdefer if (new_sig_hash_copy.len > 0) allocator.free(new_sig_hash_copy);
        const old_hash_copy = if (self.old_hash.len > 0) try allocator.dupe(u8, self.old_hash) else "";

        return .{
            .type = type_copy,
            .atom_id = atom_id_copy,
            .kind = kind_copy,
            .new_name = new_name_copy,
            .new_span = new_span_copy,
            .new_hash = new_hash_copy,
            .new_sig_hash = new_sig_hash_copy,
            .old_hash = old_hash_copy,
        };
    }

    pub fn deinit(self: *Op, allocator: Allocator) void {
        allocator.free(self.type);
        allocator.free(self.atom_id);
        if (self.kind.len > 0) allocator.free(self.kind);
        if (self.new_name.len > 0) allocator.free(self.new_name);
        if (self.new_span) |*sp| sp.deinit(allocator);
        if (self.new_hash.len > 0) allocator.free(self.new_hash);
        if (self.new_sig_hash.len > 0) allocator.free(self.new_sig_hash);
        if (self.old_hash.len > 0) allocator.free(self.old_hash);
    }
};

pub const Change = struct {
    id: []const u8,
    parent: ?[]const u8 = null,
    stream: []const u8,
    ts: i64,
    author: []const u8,
    message: []const u8,
    ops: []Op,
    merged: ?[]const u8 = null,
    sig: []const u8,

    pub fn clone(self: Change, allocator: Allocator) !Change {
        const id_copy = try allocator.dupe(u8, self.id);
        errdefer allocator.free(id_copy);
        const parent_copy = if (self.parent) |p| try allocator.dupe(u8, p) else null;
        errdefer if (parent_copy) |p| allocator.free(p);
        const stream_copy = try allocator.dupe(u8, self.stream);
        errdefer allocator.free(stream_copy);
        const author_copy = try allocator.dupe(u8, self.author);
        errdefer allocator.free(author_copy);
        const msg_copy = try allocator.dupe(u8, self.message);
        errdefer allocator.free(msg_copy);

        const ops_copy = try allocator.alloc(Op, self.ops.len);
        var initialized_ops: usize = 0;
        errdefer {
            for (ops_copy[0..initialized_ops]) |*op| op.deinit(allocator);
            allocator.free(ops_copy);
        }
        for (self.ops, 0..) |op, idx| {
            ops_copy[idx] = try op.clone(allocator);
            initialized_ops += 1;
        }

        const merged_copy = if (self.merged) |m| try allocator.dupe(u8, m) else null;
        errdefer if (merged_copy) |m| allocator.free(m);
        const sig_copy = try allocator.dupe(u8, self.sig);

        return .{
            .id = id_copy,
            .parent = parent_copy,
            .stream = stream_copy,
            .ts = self.ts,
            .author = author_copy,
            .message = msg_copy,
            .ops = ops_copy,
            .merged = merged_copy,
            .sig = sig_copy,
        };
    }

    pub fn deinit(self: *Change, allocator: Allocator) void {
        allocator.free(self.id);
        if (self.parent) |p| allocator.free(p);
        allocator.free(self.stream);
        allocator.free(self.author);
        allocator.free(self.message);
        for (self.ops) |*op| op.deinit(allocator);
        allocator.free(self.ops);
        if (self.merged) |m| allocator.free(m);
        allocator.free(self.sig);
    }
};

pub fn isLowerHexByte(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
}

pub fn isLowerHexLen(s: []const u8, n: usize) bool {
    if (s.len != n) return false;
    for (s) |c| {
        if (!isLowerHexByte(c)) return false;
    }
    return true;
}

pub fn isValidHex64(s: []const u8) bool {
    return isLowerHexLen(s, 64);
}

pub fn isValidHex128(s: []const u8) bool {
    return isLowerHexLen(s, 128);
}

fn hexNibble(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @intCast(c - '0');
    if (c >= 'a' and c <= 'f') return @intCast(c - 'a' + 10);
    return null;
}

/// Parses a canonical 36-char lowercase UUID (`8-4-4-4-12`) into 16 raw bytes,
/// matching `ParseUUID` in `user/go/flint/uuid.go`.
pub fn parseUUID(s: []const u8) ?[16]u8 {
    if (s.len != 36) return null;
    if (s[8] != '-' or s[13] != '-' or s[18] != '-' or s[23] != '-') return null;
    var out: [16]u8 = undefined;
    var bi: usize = 0;
    var i: usize = 0;
    while (i < 36) {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            i += 1;
            continue;
        }
        const hi = hexNibble(s[i]) orelse return null;
        const lo = hexNibble(s[i + 1]) orelse return null;
        out[bi] = (@as(u8, hi) << 4) | @as(u8, lo);
        bi += 1;
        i += 2;
    }
    return out;
}

pub fn isValidUUID(s: []const u8) bool {
    return parseUUID(s) != null;
}

/// Validates a stream name (`[a-z0-9-]{1,32}`), matching `isValidStreamName` in `user/go/flint/stream.go`.
pub fn isValidStreamName(s: []const u8) bool {
    if (s.len == 0 or s.len > MaxStreamNameBytes) return false;
    for (s) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-';
        if (!ok) return false;
    }
    return true;
}

/// Validates a commit message (`1..=512` bytes of valid UTF-8, not all whitespace),
/// matching `user/go/flint/commit.go` and `docs/flint-server-spec.md` §2.3.
pub fn isValidMessage(s: []const u8) bool {
    if (std.mem.trim(u8, s, " \t\r\n").len == 0 or s.len > MaxMessageBytes) return false;
    return std.unicode.utf8ValidateSlice(s);
}

pub fn validateStreamShape(st: *const Stream) bool {
    if (!isValidUUID(st.id)) return false;
    if (!isValidStreamName(st.name)) return false;
    if (st.created < 0) return false;
    if (st.head) |h| {
        if (!isValidUUID(h)) return false;
    }
    if (st.forked_from) |ff| {
        if (!isValidUUID(ff.stream) or !isValidUUID(ff.change)) return false;
    }
    return true;
}

pub fn decodeLowerHexFixed(comptime N: usize, s: []const u8) ?[N]u8 {
    if (s.len != N * 2) return null;
    var out: [N]u8 = undefined;
    for (0..N) |i| {
        const hi = hexNibble(s[i * 2]) orelse return null;
        const lo = hexNibble(s[i * 2 + 1]) orelse return null;
        out[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }
    return out;
}

pub fn encodeLowerHexFixed(comptime N: usize, bytes: [N]u8) [N * 2]u8 {
    const hex_chars = "0123456789abcdef";
    var out: [N * 2]u8 = undefined;
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out;
}

test "validators and UUID parsing" {
    try std.testing.expect(isValidUUID("0199de2d-dc00-7000-8000-000000000001"));
    try std.testing.expect(!isValidUUID("0199DE2D-DC00-7000-8000-000000000001")); // uppercase

    try std.testing.expect(isValidStreamName("main"));
    try std.testing.expect(isValidStreamName("feat-1"));
    try std.testing.expect(!isValidStreamName(""));
    try std.testing.expect(!isValidStreamName("Bad_Name"));
    try std.testing.expect(!isValidStreamName("bad/name"));
    try std.testing.expect(!isValidStreamName("bad.name"));
}
