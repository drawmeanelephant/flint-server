// Content-layer wire conformance (issue #43): blob_put/blob_get and
// put_manifest/get_manifest per docs/flint-blobs-spec.md §9.

const std = @import("std");
const Io = std.Io;
const store = @import("store.zig");
const json = @import("json.zig");
const storeio = @import("storeio.zig");
const contentio = @import("contentio.zig");
const manifest_mod = @import("manifest.zig");
const change_mod = @import("change.zig");
const serve = @import("serve.zig");

const conformance = @import("conformance_test.zig");
const TempStore = conformance.TempStore;
const makeSignedChangeLine = conformance.makeSignedChangeLine;

/// Builds a signed manifest line; files_json is raw canonical JSON.
fn makeSignedManifestLine(
    alloc: std.mem.Allocator,
    s_seed: [32]u8,
    stream: []const u8,
    change_id: []const u8,
    files_json: []const u8,
) ![]u8 {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(s_seed);
    const author_hex = store.encodeLowerHexFixed(32, kp.public_key.toBytes());
    const body = try std.fmt.allocPrint(
        alloc,
        "{{\"stream\":\"{s}\",\"change\":\"{s}\",\"author\":\"{s}\",\"files\":{s}}}",
        .{ stream, change_id, author_hex, files_json },
    );
    defer alloc.free(body);
    const preimage = try std.fmt.allocPrint(alloc, "{s}{s}", .{ manifest_mod.manifest_domain, body });
    defer alloc.free(preimage);
    var seed = s_seed;
    defer std.crypto.secureZero(u8, &seed);
    const kp2 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const sig = try kp2.sign(preimage, null);
    const sig_hex = store.encodeLowerHexFixed(64, sig.toBytes());
    return std.fmt.allocPrint(
        alloc,
        "{s},\"sig\":\"{s}\"}}",
        .{ body[0 .. body.len - 1], sig_hex },
    );
}

fn serveOnce(io: Io, allocator: std.mem.Allocator, root: []const u8, req: []const u8) ![]u8 {
    var in = Io.Reader.fixed(req);
    var outp: Io.Writer.Allocating = .init(allocator);
    errdefer outp.deinit();
    try serve.serveStream(io, allocator, .{ .root_path = root }, &in, &outp.writer);
    return outp.toOwnedSlice();
}

test "B3: blob_put/blob_get round trip, id-checked; put_manifest/get_manifest verify sig + dedupe (#43)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ts = try TempStore.init(allocator);
    defer ts.deinit(allocator);

    const seed = store.decodeLowerHexFixed(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    const stream_id = "0199de2d-dc00-7000-8000-000000000020";
    const c1_id = "0199de2d-dc00-7000-8000-000000000201";

    try storeio.createStream(io, allocator, ts.root_path, .{
        .id = stream_id,
        .name = "main",
        .head = null,
        .created = 1760000000000,
    });
    const c1_line = try makeSignedChangeLine(allocator, seed, c1_id, null, stream_id, 1760000000000, "base", &.{}, null);
    defer allocator.free(c1_line);
    const head = try storeio.appendStreamChanges(io, allocator, ts.root_path, stream_id, null, &.{c1_line}, null);
    defer allocator.free(head.?);

    // blob_put + blob_get round trip.
    const data = "pub const a: u32 = 1;\n";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const id_hex = store.encodeLowerHexFixed(32, digest);
    var data_hex: [data.len * 2]u8 = undefined;
    const digits = "0123456789abcdef";
    for (data, 0..) |b, i| {
        data_hex[2 * i] = digits[b >> 4];
        data_hex[2 * i + 1] = digits[b & 0x0f];
    }

    {
        const req = try std.fmt.allocPrint(
            allocator,
            "{{\"op\":\"blob_put\",\"seq\":1,\"id\":\"{s}\",\"hex\":\"{s}\"}}\n",
            .{ id_hex, data_hex },
        );
        defer allocator.free(req);
        const resp = try serveOnce(io, allocator, ts.root_path, req);
        defer allocator.free(resp);
        try std.testing.expectEqualStrings("{\"seq\":1,\"ok\":true}\n", resp);
    }
    {
        const req = try std.fmt.allocPrint(
            allocator,
            "{{\"op\":\"blob_get\",\"seq\":1,\"id\":\"{s}\"}}\n",
            .{id_hex},
        );
        defer allocator.free(req);
        const resp = try serveOnce(io, allocator, ts.root_path, req);
        defer allocator.free(resp);
        const want = try std.fmt.allocPrint(
            allocator,
            "{{\"seq\":1,\"ok\":true,\"hex\":\"{s}\"}}\n",
            .{data_hex},
        );
        defer allocator.free(want);
        try std.testing.expectEqualStrings(want, resp);
    }
    // blob_get absent -> blob_missing; wrong-hash put -> blob_malformed.
    {
        const zeros = "0000000000000000000000000000000000000000000000000000000000000000";
        const req = try std.fmt.allocPrint(
            allocator,
            "{{\"op\":\"blob_get\",\"seq\":1,\"id\":\"{s}\"}}\n{{\"op\":\"blob_put\",\"seq\":2,\"id\":\"{s}\",\"hex\":\"61\"}}\n",
            .{ zeros, zeros },
        );
        defer allocator.free(req);
        const resp = try serveOnce(io, allocator, ts.root_path, req);
        defer allocator.free(resp);
        try std.testing.expectEqualStrings(
            "{\"seq\":1,\"ok\":false,\"refuse\":\"blob_missing\",\"detail\":\"blob not found\"}\n{\"seq\":2,\"ok\":false,\"refuse\":\"blob_malformed\",\"detail\":\"blob content-id mismatch\"}\n",
            resp,
        );
    }

    // put_manifest: signed line for c1 lands; get_manifest returns it.
    const files = try std.fmt.allocPrint(
        allocator,
        "[{{\"path\":\"main.zig\",\"blob\":\"{s}\",\"bytes\":{d},\"mode\":420}}]",
        .{ id_hex, data.len },
    );
    defer allocator.free(files);
    const mline = try makeSignedManifestLine(allocator, seed, stream_id, c1_id, files);
    defer allocator.free(mline);

    {
        var req: Io.Writer.Allocating = .init(allocator);
        defer req.deinit();
        try req.writer.writeAll("{\"op\":\"put_manifest\",\"seq\":1,\"stream\":\"main\",\"lines\":[");
        try json.writeGoJsonString(&req.writer, mline);
        try req.writer.writeAll("]}\n{\"op\":\"get_manifest\",\"seq\":2,\"stream\":\"main\",\"after\":null}\n");
        const resp = try serveOnce(io, allocator, ts.root_path, req.written());
        defer allocator.free(resp);

        var esc: Io.Writer.Allocating = .init(allocator);
        defer esc.deinit();
        try json.writeGoJsonString(&esc.writer, mline);
        const want = try std.fmt.allocPrint(
            allocator,
            "{{\"seq\":1,\"ok\":true,\"stored\":1}}\n{{\"seq\":2,\"ok\":true,\"lines\":[{s}]}}\n",
            .{esc.written()},
        );
        defer allocator.free(want);
        try std.testing.expectEqualStrings(want, resp);
    }

    // Resend dedupes (stored=0); manifest for unknown change -> change_missing.
    {
        var req: Io.Writer.Allocating = .init(allocator);
        defer req.deinit();
        try req.writer.writeAll("{\"op\":\"put_manifest\",\"seq\":1,\"stream\":\"main\",\"lines\":[");
        try json.writeGoJsonString(&req.writer, mline);
        try req.writer.writeAll("]}\n");
        const resp = try serveOnce(io, allocator, ts.root_path, req.written());
        defer allocator.free(resp);
        try std.testing.expectEqualStrings("{\"seq\":1,\"ok\":true,\"stored\":0}\n", resp);
    }
    const orphan_m = try makeSignedManifestLine(allocator, seed, stream_id, "0199de2d-dc00-7000-8000-000000000999", "[]");
    defer allocator.free(orphan_m);
    {
        var req: Io.Writer.Allocating = .init(allocator);
        defer req.deinit();
        try req.writer.writeAll("{\"op\":\"put_manifest\",\"seq\":1,\"stream\":\"main\",\"lines\":[");
        try json.writeGoJsonString(&req.writer, orphan_m);
        try req.writer.writeAll("]}\n");
        const resp = try serveOnce(io, allocator, ts.root_path, req.written());
        defer allocator.free(resp);
        try std.testing.expectEqualStrings(
            "{\"seq\":1,\"ok\":false,\"refuse\":\"change_missing\",\"detail\":\"change not found\"}\n",
            resp,
        );
    }

    // Tampered manifest sig -> SigInvalid (verified under the change author).
    var bad = try allocator.dupe(u8, mline);
    defer allocator.free(bad);
    bad[mline.len - 3] = if (bad[mline.len - 3] == '0') '1' else '0';
    {
        var detail: ?[]const u8 = null;
        try std.testing.expectError(
            error.SigInvalid,
            contentio.putManifestLines(io, allocator, ts.root_path, stream_id, &.{bad}, null, &detail),
        );
    }

    // Same change id under different bytes -> id conflict, nothing stored.
    const conflict = try makeSignedManifestLine(allocator, seed, stream_id, c1_id, "[]");
    defer allocator.free(conflict);
    {
        var detail: ?[]const u8 = null;
        try std.testing.expectError(
            error.ManifestMalformed,
            contentio.putManifestLines(io, allocator, ts.root_path, stream_id, &.{conflict}, null, &detail),
        );
        try std.testing.expectEqualStrings("id conflict", detail.?);
    }
}
