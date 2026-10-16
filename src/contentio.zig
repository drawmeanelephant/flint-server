const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const manifest = @import("manifest.zig");
const storeio = @import("storeio.zig");
const jsonl = @import("jsonl.zig");

const StoreError = storeio.StoreError;
const appendSync = storeio.appendSync;
const syncDir = storeio.syncDir;
const dirExists = storeio.dirExists;
const fileExists = storeio.fileExists;
const writeFileSafe = storeio.writeFileSafe;
const readFileBounded = storeio.readFileBounded;
const isAuthorAllowed = storeio.isAuthorAllowed;
const loadStoreIndex = storeio.loadStoreIndex;
const loadStream = storeio.loadStream;

// --- Content layer: blobs/ and manifests/ (flint-client
// docs/flint-blobs-spec.md §1/§9, spec_rev 4). Both top-level dirs are
// created lazily on first write and ignored by pre-content readers, so a
// blobs-enabled store stays portable to a pre-blobs client.

fn blobPathForId(allocator: Allocator, root_path: []const u8, id_hex: []const u8) Allocator.Error![]u8 {
    return std.fs.path.join(allocator, &.{ root_path, "blobs", id_hex[0..2], id_hex[2..] });
}

/// Creates `blobs/<aa>/` and its parents with the same fsync chain
/// `initStore` uses, so a blob's directory entries survive a crash.
fn ensureBlobDir(io: Io, allocator: Allocator, root_path: []const u8, aa: []const u8) StoreError!void {
    const blobs_dir = try std.fs.path.join(allocator, &.{ root_path, "blobs" });
    defer allocator.free(blobs_dir);
    const sub_dir = try std.fs.path.join(allocator, &.{ blobs_dir, aa });
    defer allocator.free(sub_dir);

    if (dirExists(io, sub_dir)) return;
    const blobs_new = !dirExists(io, blobs_dir);

    Io.Dir.cwd().createDirPath(io, sub_dir) catch return error.IoFailure;
    try syncDir(io, blobs_dir);
    if (blobs_new) try syncDir(io, root_path);
}

/// Ensures `<root>/manifests/` exists (created lazily on first
/// `put_manifest`), fsyncing the store root so the entry is durable.
pub fn ensureManifestsDir(io: Io, allocator: Allocator, root_path: []const u8) StoreError!void {
    const manifests_dir = try std.fs.path.join(allocator, &.{ root_path, "manifests" });
    defer allocator.free(manifests_dir);
    if (dirExists(io, manifests_dir)) return;

    Io.Dir.cwd().createDirPath(io, manifests_dir) catch return error.IoFailure;
    try syncDir(io, root_path);
}

fn manifestLogPathFor(
    allocator: Allocator,
    root_path: []const u8,
    stream_id: []const u8,
) Allocator.Error![]u8 {
    const file_name = try std.fmt.allocPrint(allocator, "{s}.jsonl", .{stream_id});
    defer allocator.free(file_name);
    return std.fs.path.join(allocator, &.{ root_path, "manifests", file_name });
}

/// Stores blob bytes under `blobs/<2hex>/<62hex>` after checking that
/// `id_hex` is the SHA-256 of the decoded `hex` payload (spec §9 `blob_put`).
/// Content-addressed, so an already-present id is idempotently ok.
pub fn putBlob(
    io: Io,
    allocator: Allocator,
    root_path: []const u8,
    id_hex: []const u8,
    hex: []const u8,
) StoreError!void {
    const id_bytes = store.decodeLowerHexFixed(32, id_hex) orelse return error.BlobMalformed;
    if (hex.len % 2 != 0) return error.BlobMalformed;
    const decoded_len = hex.len / 2;
    if (decoded_len > store.MaxBlobBytes) return error.BlobTooLarge;

    const bytes = try allocator.alloc(u8, decoded_len);
    defer allocator.free(bytes);
    for (0..decoded_len) |i| {
        const hi = store.hexNibble(hex[i * 2]) orelse return error.BlobMalformed;
        const lo = store.hexNibble(hex[i * 2 + 1]) orelse return error.BlobMalformed;
        bytes[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &digest, &id_bytes)) return error.BlobMalformed;

    const blob_path = try blobPathForId(allocator, root_path, id_hex);
    defer allocator.free(blob_path);
    if (fileExists(io, blob_path)) return;

    try ensureBlobDir(io, allocator, root_path, id_hex[0..2]);
    try writeFileSafe(io, allocator, blob_path, bytes);
}

/// Reads a blob by id, checking `id` against the stored bytes on every read
/// (spec §0: a corrupt or substituted blob is `blob_malformed`).
/// Returns the raw bytes (caller owns).
pub fn getBlob(
    io: Io,
    allocator: Allocator,
    root_path: []const u8,
    id_hex: []const u8,
) StoreError![]u8 {
    const id_bytes = store.decodeLowerHexFixed(32, id_hex) orelse return error.BlobMalformed;
    const blob_path = try blobPathForId(allocator, root_path, id_hex);
    defer allocator.free(blob_path);

    const bytes = readFileBounded(io, allocator, blob_path, store.MaxBlobBytes) catch |err| switch (err) {
        // readFileBounded reports FileNotFound as StreamMissing; a blob
        // miss has its own refusal name.
        error.StreamMissing => return error.BlobMissing,
        else => return err,
    };
    errdefer allocator.free(bytes);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &digest, &id_bytes)) return error.BlobMalformed;

    return bytes;
}

pub const ManifestLog = struct {
    /// Verbatim line bytes (no trailing newline), owned.
    raw_lines: [][]u8,
    /// Parsed `change` field of each line, parallel to `raw_lines`, owned.
    changes: [][]u8,

    pub fn deinit(self: *ManifestLog, allocator: Allocator) void {
        for (self.raw_lines) |line| allocator.free(line);
        allocator.free(self.raw_lines);
        for (self.changes) |id| allocator.free(id);
        allocator.free(self.changes);
    }
};

/// Loads `manifests/<stream_id>.jsonl`: every raw line plus its bound
/// `change` id. A missing log is an empty log (a stream may be
/// content-less); a torn final line or a line that fails
/// `parseManifestLine` is `ManifestTorn` — the log is never rewritten, so
/// corrupt content is surfaced, never silently served.
pub fn loadManifestLog(
    io: Io,
    allocator: Allocator,
    root_path: []const u8,
    stream_id: []const u8,
) StoreError!ManifestLog {
    const log_path = try manifestLogPathFor(allocator, root_path, stream_id);
    defer allocator.free(log_path);

    var raw: []u8 = &.{};
    var has_file = false;
    if (fileExists(io, log_path)) {
        raw = try readFileBounded(io, allocator, log_path, store.MaxManifestLogBytes);
        has_file = true;
    }
    defer if (has_file) allocator.free(raw);

    const lines = jsonl.readJsonlLines(allocator, raw) catch |err| switch (err) {
        error.StreamTorn => return error.ManifestTorn,
        error.ChangeMalformed => return error.ManifestTorn,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer allocator.free(lines);

    if (lines.len > store.MaxManifestLines) return error.StoreTooLarge;

    var raw_lines: std.ArrayList([]u8) = .empty;
    errdefer {
        for (raw_lines.items) |line| allocator.free(line);
        raw_lines.deinit(allocator);
    }
    var change_ids: std.ArrayList([]u8) = .empty;
    errdefer {
        for (change_ids.items) |id| allocator.free(id);
        change_ids.deinit(allocator);
    }

    for (lines) |line| {
        var m = manifest.parseManifestLine(allocator, line) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.ManifestTorn,
        };
        defer m.deinit(allocator);
        if (!std.mem.eql(u8, m.stream, stream_id)) return error.ManifestTorn;

        try raw_lines.append(allocator, try allocator.dupe(u8, line));
        try change_ids.append(allocator, try allocator.dupe(u8, m.change));
    }

    return .{
        .raw_lines = try raw_lines.toOwnedSlice(allocator),
        .changes = try change_ids.toOwnedSlice(allocator),
    };
}

/// Validates and appends signed manifest lines to
/// `manifests/<stream>.jsonl` without touching the stream record or the
/// Change log (spec §9 `put_manifest`). `stream_arg` is a stream id or
/// name; returns the count of newly stored lines — byte-identical resends
/// skip, so republishing is idempotent. All-or-nothing.
pub fn putManifestStreamLines(
    io: Io,
    allocator: Allocator,
    root_path: []const u8,
    stream_arg: []const u8,
    raw_lines: []const []const u8,
    allow_authors: ?[]const [64]u8,
) StoreError!usize {
    var idx = try loadStoreIndex(io, allocator, root_path);
    defer idx.deinit(allocator);

    const found = idx.findByNameOrId(stream_arg) orelse return error.StreamMissing;
    const stream_id = found.id;

    var loaded = try loadStream(io, allocator, root_path, stream_id);
    defer loaded.deinit(allocator);

    // 1-256 raw lines per request, mirroring deposit (spec §6); the whole
    // batch validates before anything is written.
    if (raw_lines.len == 0 or raw_lines.len > store.MaxManifestBatch) {
        return error.ChangeMalformed;
    }

    var log = try loadManifestLog(io, allocator, root_path, stream_id);
    defer log.deinit(allocator);

    var parsed_batch: std.ArrayList(store.Manifest) = .empty;
    defer {
        for (parsed_batch.items) |*m| m.deinit(allocator);
        parsed_batch.deinit(allocator);
    }
    var batch_raws: std.ArrayList([]const u8) = .empty;
    defer batch_raws.deinit(allocator);

    var append_buf: std.Io.Writer.Allocating = .init(allocator);
    defer append_buf.deinit();

    var parsed_count: usize = 0;

    for (raw_lines) |raw_line| {
        const trimmed = std.mem.trimEnd(u8, raw_line, "\r\n");
        var m = manifest.parseManifestLine(allocator, trimmed) catch |err| switch (err) {
            error.ChangeMalformed => return error.ChangeMalformed,
            error.ManifestTorn => return error.ManifestTorn,
            error.OutOfMemory => return error.OutOfMemory,
            else => unreachable,
        };
        errdefer m.deinit(allocator);

        if (!std.mem.eql(u8, m.stream, stream_id)) return error.ChangeMalformed;

        // Dedupe by `change` like deposit dedupes by Change id: a
        // byte-identical repeat skips; the same `change` under different
        // bytes is an id conflict.
        var duplicate = false;
        for (log.raw_lines, log.changes) |eraw, ecid| {
            if (std.mem.eql(u8, ecid, m.change)) {
                if (!std.mem.eql(u8, eraw, trimmed)) return error.ChangeIdConflict;
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            for (parsed_batch.items, batch_raws.items) |pm, braw| {
                if (std.mem.eql(u8, pm.change, m.change)) {
                    if (!std.mem.eql(u8, braw, trimmed)) return error.ChangeIdConflict;
                    duplicate = true;
                    break;
                }
            }
        }
        if (duplicate) {
            m.deinit(allocator);
            continue;
        }

        // The bound Change must sit in this stream's log — head chain or
        // detached — and the manifest's author must be its author (§5).
        const bound = blk: {
            for (loaded.changes) |*c| {
                if (std.mem.eql(u8, c.id, m.change)) break :blk c;
            }
            return error.ChangeMissing;
        };
        if (!std.mem.eql(u8, m.author, bound.author)) return error.ChangeMalformed;

        manifest.verifyManifest(allocator, &m, bound.author) catch |err| switch (err) {
            error.SigInvalid => return error.SigInvalid,
            error.ChangeMalformed => return error.ChangeMalformed,
            error.OutOfMemory => return error.OutOfMemory,
            else => unreachable,
        };

        if (!isAuthorAllowed(m.author, allow_authors)) {
            return error.AuthorNotAllowed;
        }

        append_buf.writer.writeAll(trimmed) catch return error.OutOfMemory;
        append_buf.writer.writeByte('\n') catch return error.OutOfMemory;

        // batch_raws first: once m moves into parsed_batch its errdefer must
        // not still fire on a later failure in this iteration.
        try batch_raws.append(allocator, trimmed);
        try parsed_batch.append(allocator, m);
        parsed_count += 1;
    }

    if (log.raw_lines.len + parsed_count > store.MaxManifestLines) {
        return error.StoreTooLarge;
    }

    const log_path = try manifestLogPathFor(allocator, root_path, stream_id);
    defer allocator.free(log_path);

    var existing_log_len: usize = 0;
    if (fileExists(io, log_path)) {
        var f = Io.Dir.cwd().openFile(io, log_path, .{ .mode = .read_only }) catch return error.IoFailure;
        existing_log_len = @intCast(f.length(io) catch {
            f.close(io);
            return error.IoFailure;
        });
        f.close(io);
    }
    if (existing_log_len + append_buf.written().len > store.MaxManifestLogBytes) {
        return error.StoreTooLarge;
    }

    if (parsed_count > 0) {
        try ensureManifestsDir(io, allocator, root_path);
        try appendSync(io, log_path, append_buf.written());
    }

    return parsed_count;
}
