const std = @import("std");
const Allocator = std.mem.Allocator;

pub const JsonlError = error{
    StreamTorn,
    ChangeMalformed,
    OutOfMemory,
};

/// Splits a `.jsonl` file into individual lines without trailing `\r` or `\n`,
/// matching `ReadJSONLLines` in `user/go/flint/change.go`:
/// - An empty file is valid and returns an empty slice.
/// - A non-empty file whose last byte is not `\n` returns `error.StreamTorn`.
/// - An empty line inside the file returns `error.ChangeMalformed`.
pub fn readJsonlLines(allocator: Allocator, data: []const u8) JsonlError![][]const u8 {
    if (data.len == 0) {
        return try allocator.alloc([]const u8, 0);
    }
    if (data[data.len - 1] != '\n') {
        return error.StreamTorn;
    }

    var lines: std.ArrayList([]const u8) = .empty;
    errdefer lines.deinit(allocator);

    var start: usize = 0;
    for (data, 0..) |b, i| {
        if (b == '\n') {
            var line = data[start..i];
            if (line.len > 0 and line[line.len - 1] == '\r') {
                line = line[0 .. line.len - 1];
            }
            if (line.len == 0) {
                return error.ChangeMalformed;
            }
            try lines.append(allocator, line);
            start = i + 1;
        }
    }
    return lines.toOwnedSlice(allocator);
}

test "readJsonlLines empty, valid, torn, and empty inner line" {
    const empty = try readJsonlLines(std.testing.allocator, "");
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    const valid = try readJsonlLines(std.testing.allocator, "{\"a\":1}\n{\"b\":2}\r\n");
    defer std.testing.allocator.free(valid);
    try std.testing.expectEqual(@as(usize, 2), valid.len);
    try std.testing.expectEqualStrings("{\"a\":1}", valid[0]);
    try std.testing.expectEqualStrings("{\"b\":2}", valid[1]);

    try std.testing.expectError(error.StreamTorn, readJsonlLines(std.testing.allocator, "{\"a\":1}"));
    try std.testing.expectError(error.ChangeMalformed, readJsonlLines(std.testing.allocator, "{\"a\":1}\n\n"));
}
