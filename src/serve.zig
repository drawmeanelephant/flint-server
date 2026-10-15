const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const proto = @import("proto.zig");

pub const ServeConfig = struct {
    root_path: []const u8,
    auth_key: ?[32]u8 = null,
    allow_authors: ?[]const [64]u8 = null,
    fixed_nonce: ?[16]u8 = null,
};

/// Serves a single NDJSON session reading lines from `reader` and writing responses to `writer`.
pub fn serveStream(
    io: Io,
    allocator: Allocator,
    cfg: ServeConfig,
    reader: *Io.Reader,
    writer: *Io.Writer,
) !void {
    var session = proto.Session{
        .root_path = cfg.root_path,
        .auth_key = cfg.auth_key,
        .allow_authors = cfg.allow_authors,
        .fixed_nonce = cfg.fixed_nonce,
    };

    var line_buf: Io.Writer.Allocating = .init(allocator);
    defer line_buf.deinit();

    while (true) {
        line_buf.clearRetainingCapacity();
        var got_delimiter = true;
        _ = reader.streamDelimiterLimit(&line_buf.writer, '\n', .limited(store.MaxLineBytes + 1)) catch |err| switch (err) {
            error.StreamTooLong => {
                try proto.writeRefusal(writer, 0, .store_too_large, "line exceeds 4 MiB");
                try writer.flush();
                break;
            },
            error.ReadFailed => return error.ReadFailed,
            error.WriteFailed => return error.OutOfMemory,
        };

        if (reader.peekByte()) |b| {
            if (b == '\n') {
                reader.toss(1);
            }
        } else |err| switch (err) {
            error.EndOfStream => {
                got_delimiter = false;
            },
            error.ReadFailed => return error.ReadFailed,
        }

        if (!got_delimiter and line_buf.written().len == 0) {
            break;
        }

        try proto.handleLine(io, allocator, &session, line_buf.written(), writer);
        try writer.flush();

        if (session.close_after_reply or !got_delimiter) {
            break;
        }
    }
}

pub fn serveStdio(io: Io, allocator: Allocator, cfg: ServeConfig) !void {
    var stderr_buf: [256]u8 = undefined;
    var stderr_w = Io.File.stderr().writerStreaming(io, &stderr_buf);
    try stderr_w.interface.writeAll("flintd: ready\n");
    try stderr_w.interface.flush();

    var in_buf: [64 * 1024]u8 = undefined;
    var out_buf: [64 * 1024]u8 = undefined;
    var stdin_r = Io.File.stdin().readerStreaming(io, &in_buf);
    var stdout_w = Io.File.stdout().writerStreaming(io, &out_buf);

    try serveStream(io, allocator, cfg, &stdin_r.interface, &stdout_w.interface);
}

/// A `Stream.Reader` equivalent for accepted TCP connections that applies
/// `timeout` to every underlying read, so an idle or stalled peer cannot
/// starve the serial accept loop (spec §3.3 keeps serialized sessions; the
/// deadline only bounds how long one session may hold the loop).
///
/// The concrete failure — `error.Timeout` when the deadline expires — is
/// stored in `err` and surfaced through the interface as `error.ReadFailed`,
/// matching `Io.net.Stream.Reader` conventions.
pub const TimedReader = struct {
    interface: Io.Reader,
    stream: Io.net.Stream,
    io: Io,
    timeout: Io.Timeout,
    err: ?anyerror,

    pub fn init(stream: Io.net.Stream, io: Io, buffer: []u8, timeout: Io.Timeout) TimedReader {
        return .{
            .interface = .{
                .vtable = &.{ .stream = streamImpl, .readVec = readVec },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
            .stream = stream,
            .io = io,
            .timeout = timeout,
            .err = null,
        };
    }

    fn streamImpl(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(io_r, &data);
        io_w.advance(n);
        return n;
    }

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const r: *TimedReader = @alignCast(@fieldParentPtr("interface", io_r));
        const io = r.io;
        var iovecs_buffer: [8][]u8 = undefined;
        const dest_n, const data_size = try io_r.writableVector(&iovecs_buffer, data);
        const dest = iovecs_buffer[0..dest_n];
        std.debug.assert(dest[0].len > 0);

        var storage: [1]Io.Operation.Storage = undefined;
        var batch: Io.Batch = .init(&storage);
        batch.addAt(0, .{ .net_read = .{
            .socket_handle = r.stream.socket.handle,
            .data = dest,
        } });
        batch.awaitConcurrent(io, r.timeout) catch |err| {
            batch.cancel(io);
            r.err = err;
            return error.ReadFailed;
        };
        const completion = batch.next().?;
        const result = completion.result.net_read catch |err| {
            r.err = err;
            return error.ReadFailed;
        };
        if (result.data_len == 0) {
            return error.EndOfStream;
        }
        if (result.data_len > data_size) {
            io_r.end += result.data_len - data_size;
            return data_size;
        }
        return result.data_len;
    }
};

pub fn parseListenAddress(io: Io, addr_str: []const u8) !Io.net.IpAddress {
    return Io.net.IpAddress.parseLiteral(addr_str) catch {
        const colon = std.mem.lastIndexOfScalar(u8, addr_str, ':') orelse return error.InvalidAddress;
        const host = addr_str[0..colon];
        const port_str = addr_str[colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;
        return resolveListenHost(io, host, port);
    };
}

/// Resolves `host` to a listen address, accepting literal IPs and resolving
/// hostnames via the same `Io.net.HostName.lookup` path the client uses on
/// dial — so `--listen=localhost:4748` works.
fn resolveListenHost(io: Io, host: []const u8, port: u16) !Io.net.IpAddress {
    if (Io.net.IpAddress.parse(host, port)) |literal| {
        return literal;
    } else |_| {}

    const host_name = Io.net.HostName.init(host) catch return error.InvalidAddress;
    var results_buffer: [16]Io.net.HostName.LookupResult = undefined;
    var results: Io.Queue(Io.net.HostName.LookupResult) = .init(&results_buffer);
    var canonical_name_buffer: [Io.net.HostName.max_len]u8 = undefined;
    try host_name.lookup(io, &results, .{
        .port = port,
        .canonical_name_buffer = &canonical_name_buffer,
    });
    // lookup closes the queue before returning; buffered results still drain.
    // Prefer IPv4 so that e.g. localhost binds where 127.0.0.1 clients reach it.
    var fallback: ?Io.net.IpAddress = null;
    while (results.getOneUncancelable(io)) |result| {
        switch (result) {
            .address => |address| switch (address) {
                .ip4 => return address,
                .ip6 => if (fallback == null) {
                    fallback = address;
                },
            },
            .canonical_name => continue,
        }
    } else |_| {}
    return fallback orelse error.UnknownHostName;
}

test "parseListenAddress accepts literals and resolves hostnames" {
    const io = std.testing.io;

    const v4 = try parseListenAddress(io, "127.0.0.1:4748");
    try std.testing.expectEqual(@as(u16, 4748), v4.getPort());

    const v6 = try parseListenAddress(io, "[::1]:4748");
    try std.testing.expectEqual(@as(u16, 4748), v6.getPort());

    const resolved = try parseListenAddress(io, "localhost:4748");
    try std.testing.expectEqual(@as(u16, 4748), resolved.getPort());

    try std.testing.expectError(error.InvalidPort, parseListenAddress(io, "localhost:notaport"));
    try std.testing.expectError(error.InvalidAddress, parseListenAddress(io, "no-port-here"));
}

pub fn serveTcp(
    io: Io,
    allocator: Allocator,
    cfg: ServeConfig,
    listen_str: []const u8,
    max_conns: ?usize,
    read_timeout: Io.Timeout,
) !void {
    const addr = try parseListenAddress(io, listen_str);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var stderr_buf: [256]u8 = undefined;
    var stderr_w = Io.File.stderr().writerStreaming(io, &stderr_buf);
    try stderr_w.interface.print("flintd: listening {f}\n", .{server.socket.address});
    try stderr_w.interface.flush();

    var served: usize = 0;
    while (true) {
        if (max_conns) |limit| {
            if (served >= limit) break;
        }
        var stream = server.accept(io) catch |err| switch (err) {
            error.SocketNotListening => break,
            else => return err,
        };
        defer stream.close(io);

        stderr_w.interface.print("flintd: connect {f}\n", .{stream.socket.address}) catch {};
        stderr_w.interface.flush() catch {};

        var r_buf: [64 * 1024]u8 = undefined;
        var w_buf: [64 * 1024]u8 = undefined;
        var timed_r = TimedReader.init(stream, io, &r_buf, read_timeout);
        var net_w = stream.writer(io, &w_buf);

        serveStream(io, allocator, cfg, &timed_r.interface, &net_w.interface) catch |err| {
            const timed_out = if (timed_r.err) |e| e == error.Timeout else false;
            const reason: []const u8 = if (timed_out) "idle_timeout" else @errorName(err);
            stderr_w.interface.print("flintd: disconnect {f} reason={s}\n", .{ stream.socket.address, reason }) catch {};
            stderr_w.interface.flush() catch {};
            served += 1;
            continue;
        };
        stderr_w.interface.print("flintd: disconnect {f}\n", .{stream.socket.address}) catch {};
        stderr_w.interface.flush() catch {};
        served += 1;
    }
}

test "TimedReader: idle peer surfaces Timeout and ends the session" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const storeio = @import("storeio.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const listen_addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var client = try server.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    var stream = try server.accept(io);
    defer stream.close(io);

    var r_buf: [4096]u8 = undefined;
    var timed_r = TimedReader.init(
        stream,
        io,
        &r_buf,
        .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(50), .clock = .awake } },
    );
    var out: Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    // Peer connects but never sends a line: the read deadline must expire.
    try std.testing.expectError(
        error.ReadFailed,
        serveStream(io, allocator, .{ .root_path = root_path }, &timed_r.interface, &out.writer),
    );
    try std.testing.expectEqual(error.Timeout, timed_r.err.?);
}

test "TimedReader: active peer is served normally before the deadline" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const storeio = @import("storeio.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const listen_addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var client = try server.socket.address.connect(io, .{ .mode = .stream });
    var stream = try server.accept(io);
    defer stream.close(io);

    var w_buf: [1024]u8 = undefined;
    var client_w = client.writer(io, &w_buf);
    try client_w.interface.writeAll("{\"op\":\"heads\",\"seq\":3}\n");
    try client_w.interface.flush();
    client.close(io); // deliver the line, then EOF

    var r_buf: [4096]u8 = undefined;
    var timed_r = TimedReader.init(
        stream,
        io,
        &r_buf,
        .{ .duration = .{ .raw = Io.Duration.fromSeconds(5), .clock = .awake } },
    );
    var out: Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try serveStream(io, allocator, .{ .root_path = root_path }, &timed_r.interface, &out.writer);
    try std.testing.expectEqualStrings(
        "{\"seq\":3,\"ok\":true,\"heads\":{}}\n",
        out.written(),
    );
}
