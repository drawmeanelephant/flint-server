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
        _ = reader.streamDelimiter(&line_buf.writer, '\n') catch |err| switch (err) {
            error.EndOfStream => {
                got_delimiter = false;
            },
            error.ReadFailed => return error.ReadFailed,
            error.WriteFailed => return error.OutOfMemory,
        };

        if (got_delimiter) {
            reader.toss(1); // consume '\n'
        } else if (line_buf.written().len == 0) {
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

pub fn parseListenAddress(addr_str: []const u8) !Io.net.IpAddress {
    return Io.net.IpAddress.parseLiteral(addr_str) catch {
        const colon = std.mem.lastIndexOfScalar(u8, addr_str, ':') orelse return error.InvalidAddress;
        const host = addr_str[0..colon];
        const port_str = addr_str[colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;
        return Io.net.IpAddress.parse(host, port);
    };
}

pub fn serveTcp(
    io: Io,
    allocator: Allocator,
    cfg: ServeConfig,
    listen_str: []const u8,
    max_conns: ?usize,
) !void {
    const addr = try parseListenAddress(listen_str);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    {
        var stderr_buf: [256]u8 = undefined;
        var stderr_w = Io.File.stderr().writerStreaming(io, &stderr_buf);
        try stderr_w.interface.print("flintd: listening {f}\n", .{server.socket.address});
        try stderr_w.interface.flush();
    }

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

        var r_buf: [64 * 1024]u8 = undefined;
        var w_buf: [64 * 1024]u8 = undefined;
        var net_r = stream.reader(io, &r_buf);
        var net_w = stream.writer(io, &w_buf);

        serveStream(io, allocator, cfg, &net_r.interface, &net_w.interface) catch {};
        served += 1;
    }
}
