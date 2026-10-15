const std = @import("std");
const Io = std.Io;
const store = @import("store.zig");

// Values are a closed allowlist, never arbitrary client strings.
pub const Operation = enum { unknown, hello, auth, list, heads, open, read, create, append };
pub const Outcome = enum { handled, io_error };

pub const Request = struct {
    connection: [16]u8,
    seq: ?u32,
    operation: Operation,
    outcome: Outcome,
};

pub fn writeRequest(w: *Io.Writer, request: Request) Io.Writer.Error!void {
    // The connection ID is generated locally. Encoding its bytes here rather
    // than accepting arbitrary text keeps JSON and redaction guarantees local.
    const connection = store.encodeLowerHexFixed(16, request.connection);
    try w.print("{{\"event\":\"request\",\"connection\":\"{s}\",\"seq\":", .{connection});
    if (request.seq) |seq| {
        try w.print("{d}", .{seq});
    } else {
        try w.writeAll("null");
    }
    try w.print(",\"operation\":\"{s}\",\"outcome\":\"{s}\"}}\n", .{
        @tagName(request.operation), @tagName(request.outcome),
    });
}

pub fn emit(io: Io, request: Request) void {
    var buffer: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    writeRequest(&writer, request) catch return;
    // A stalled collector must not block the serial protocol server. Records
    // are best-effort: a failed, partial, or timed-out write is never retried.
    const result = Io.operateTimeout(io, .{ .file_write_streaming = .{
        .file = Io.File.stderr(),
        .data = &.{writer.buffered()},
    } }, .{ .duration = .{ .raw = .fromMilliseconds(1), .clock = .awake } }) catch return;
    _ = result.file_write_streaming catch return;
}

test "request logging emits only typed allowlisted metadata" {
    var writer: Io.Writer.Allocating = .init(std.testing.allocator);
    defer writer.deinit();
    try writeRequest(&writer.writer, .{
        .connection = @splat(0xab),
        .seq = 42,
        .operation = .auth,
        .outcome = .handled,
    });
    try std.testing.expectEqualStrings(
        "{\"event\":\"request\",\"connection\":\"abababababababababababababababab\",\"seq\":42,\"operation\":\"auth\",\"outcome\":\"handled\"}\n",
        writer.written(),
    );
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, writer.written(), .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 5), parsed.value.object.count());
}
