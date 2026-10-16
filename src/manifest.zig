// Content layer: signed complete-inventory manifest records
// (docs/flint-blobs-spec.md). Manifests bind a stream+change revision to a
// path-sorted list of content-addressed blobs under a dedicated
// `flint-manifest-v1` signature domain. Change canonical bytes and
// signatures are untouched.

const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store.zig");
const ed25519 = @import("ed25519.zig");
const change_mod = @import("change.zig");
const json = @import("json.zig");

/// Domain-separated signature preimage prefix — disjoint from
/// FLINT-CHANGE/1 so a manifest signature can never stand in for a Change.
pub const manifest_domain = "flint-manifest-v1\n";

pub const ManifestFile = struct {
    path: []const u8,
    blob: ?[]const u8,
    bytes: u64,
    mode: u64,
    reason: ?[]const u8,

    pub fn deinit(self: ManifestFile, allocator: Allocator) void {
        allocator.free(self.path);
        if (self.blob) |b| allocator.free(b);
        if (self.reason) |r| allocator.free(r);
    }
};

pub const Manifest = struct {
    stream: []const u8,
    change: []const u8,
    author: []const u8,
    files: []ManifestFile,
    sig: []const u8,

    pub fn deinit(self: Manifest, allocator: Allocator) void {
        allocator.free(self.stream);
        allocator.free(self.change);
        allocator.free(self.author);
        for (self.files) |f| f.deinit(allocator);
        allocator.free(self.files);
        allocator.free(self.sig);
    }
};

fn isHexLower(s: []const u8) bool {
    for (s) |c| {
        if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return false;
    }
    return true;
}

fn isValidManifestPath(p: []const u8) bool {
    if (p.len == 0 or p[0] == '/' or std.mem.endsWith(u8, p, "/")) return false;
    var it = std.mem.splitScalar(u8, p, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
    }
    return true;
}

fn jsonStr(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn jsonInt(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |n| n,
        else => null,
    };
}

/// Parses one manifest line (no trailing newline) into an owned Manifest.
/// Structural errors return error.ManifestMalformed.
pub fn parseManifestLine(allocator: Allocator, line: []const u8) !Manifest {
    const trimmed = std.mem.trimEnd(u8, line, "\r\n");
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch
        return error.ManifestMalformed;
    defer parsed.deinit();
    if (parsed.value != .object) return error.ManifestMalformed;
    const obj = parsed.value.object;

    const stream_s = jsonStr(obj.get("stream") orelse return error.ManifestMalformed) orelse
        return error.ManifestMalformed;
    const change_s = jsonStr(obj.get("change") orelse return error.ManifestMalformed) orelse
        return error.ManifestMalformed;
    const author_s = jsonStr(obj.get("author") orelse return error.ManifestMalformed) orelse
        return error.ManifestMalformed;
    const sig_s = jsonStr(obj.get("sig") orelse return error.ManifestMalformed) orelse
        return error.ManifestMalformed;
    const files_v = obj.get("files") orelse return error.ManifestMalformed;
    if (files_v != .array) return error.ManifestMalformed;

    if (stream_s.len != 36 or change_s.len != 36) return error.ManifestMalformed;
    if (author_s.len != 64 or !isHexLower(author_s)) return error.ManifestMalformed;
    if (sig_s.len != 128 or !isHexLower(sig_s)) return error.ManifestMalformed;

    var files: std.ArrayList(ManifestFile) = .empty;
    errdefer {
        for (files.items) |f| f.deinit(allocator);
        files.deinit(allocator);
    }

    for (files_v.array.items) |fv| {
        if (fv != .object) return error.ManifestMalformed;
        const fo = fv.object;
        const path_s = jsonStr(fo.get("path") orelse return error.ManifestMalformed) orelse
            return error.ManifestMalformed;
        const blob_v = fo.get("blob") orelse return error.ManifestMalformed;
        const bytes_i = jsonInt(fo.get("bytes") orelse return error.ManifestMalformed) orelse
            return error.ManifestMalformed;
        const mode_i = jsonInt(fo.get("mode") orelse return error.ManifestMalformed) orelse
            return error.ManifestMalformed;
        if (bytes_i < 0 or mode_i < 0) return error.ManifestMalformed;
        if (!isValidManifestPath(path_s)) return error.ManifestMalformed;

        var blob: ?[]const u8 = null;
        switch (blob_v) {
            .null => {},
            .string => |b| {
                if (b.len != 64 or !isHexLower(b)) return error.ManifestMalformed;
                blob = try allocator.dupe(u8, b);
            },
            else => return error.ManifestMalformed,
        }
        errdefer if (blob) |b| allocator.free(b);
        var reason: ?[]const u8 = null;
        if (fo.get("reason")) |rv| {
            const rs = jsonStr(rv) orelse return error.ManifestMalformed;
            reason = try allocator.dupe(u8, rs);
        }
        if (blob == null and reason == null) return error.ManifestMalformed;

        try files.append(allocator, .{
            .path = try allocator.dupe(u8, path_s),
            .blob = blob,
            .bytes = @intCast(bytes_i),
            .mode = @intCast(mode_i),
            .reason = reason,
        });
    }

    // Canonical writers emit path-sorted inventories; enforce on read so a
    // reordered line can't smuggle two mappings for one path.
    if (files.items.len > 1) {
        for (files.items[1..], 0..) |f, i| {
            if (std.mem.order(u8, files.items[i].path, f.path) != .lt) {
                return error.ManifestMalformed;
            }
        }
    }

    return .{
        .stream = try allocator.dupe(u8, stream_s),
        .change = try allocator.dupe(u8, change_s),
        .author = try allocator.dupe(u8, author_s),
        .files = try files.toOwnedSlice(allocator),
        .sig = try allocator.dupe(u8, sig_s),
    };
}

/// Canonical manifest body — `{"stream":..,"change":..,"author":..,"files":[..]}`
/// with no `sig` field — re-serialized from the parsed record for signature
/// verification. Fields are emitted in the spec's fixed order.
fn marshalBody(allocator: Allocator, m: *const Manifest) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    const w = &aw.writer;
    try w.writeAll("{\"stream\":");
    try json.writeGoJsonString(w, m.stream);
    try w.writeAll(",\"change\":");
    try json.writeGoJsonString(w, m.change);
    try w.writeAll(",\"author\":");
    try json.writeGoJsonString(w, m.author);
    try w.writeAll(",\"files\":[");
    for (m.files, 0..) |f, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"path\":");
        try json.writeGoJsonString(w, f.path);
        try w.writeAll(",\"blob\":");
        if (f.blob) |b| try json.writeGoJsonString(w, b) else try w.writeAll("null");
        try w.print(",\"bytes\":{d},\"mode\":{d}", .{ f.bytes, f.mode });
        if (f.reason) |r| {
            try w.writeAll(",\"reason\":");
            try json.writeGoJsonString(w, r);
        }
        try w.writeByte('}');
    }
    try w.writeAll("]}");
    return aw.toOwnedSlice();
}

/// Signature preimage: domain || canonical body bytes.
pub fn sigMsg(allocator: Allocator, m: *const Manifest) ![]u8 {
    const body = try marshalBody(allocator, m);
    defer allocator.free(body);
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    try aw.writer.writeAll(manifest_domain);
    try aw.writer.writeAll(body);
    return aw.toOwnedSlice();
}

/// Verifies m.sig under m.author's Ed25519 key over the canonical preimage.
pub fn verifyManifest(allocator: Allocator, m: *const Manifest) !bool {
    const author = store.decodeLowerHexFixed(32, m.author) orelse return error.ManifestMalformed;
    const sig = store.decodeLowerHexFixed(64, m.sig) orelse return error.ManifestMalformed;
    const msg = try sigMsg(allocator, m);
    defer allocator.free(msg);
    return ed25519.verify(msg, sig, author);
}
