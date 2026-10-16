const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store.zig");
const Span = store.Span;
const ForkOrigin = store.ForkOrigin;
const Stream = store.Stream;
const Op = store.Op;
const Change = store.Change;

pub const ParseError = error{
    ChangeMalformed,
    StreamMalformed,
    OutOfMemory,
};

/// Writes a JSON string matching Go's `encoding/json.Marshal` byte-for-byte,
/// including HTML escaping (`<`, `>`, `&` -> `\u003c`, `\u003e`, `\u0026`),
/// control characters `< 0x20` (except `\t`, `\n`, `\r` which use short escapes,
/// while `\x08` and `\x0c` use `\u0008` and `\u000c`), and U+2028 / U+2029.
pub fn writeGoJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    const hex = "0123456789abcdef";
    try w.writeByte('"');
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        switch (c) {
            '\\' => {
                try w.writeAll("\\\\");
                i += 1;
            },
            '"' => {
                try w.writeAll("\\\"");
                i += 1;
            },
            '\n' => {
                try w.writeAll("\\n");
                i += 1;
            },
            '\r' => {
                try w.writeAll("\\r");
                i += 1;
            },
            '\t' => {
                try w.writeAll("\\t");
                i += 1;
            },
            '<', '>', '&' => {
                try w.writeAll("\\u00");
                try w.writeByte(hex[c >> 4]);
                try w.writeByte(hex[c & 0x0f]);
                i += 1;
            },
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
                try w.writeAll("\\u00");
                try w.writeByte(hex[c >> 4]);
                try w.writeByte(hex[c & 0x0f]);
                i += 1;
            },
            0xe2 => {
                if (i + 2 < s.len and s[i + 1] == 0x80 and (s[i + 2] == 0xa8 or s[i + 2] == 0xa9)) {
                    if (s[i + 2] == 0xa8) {
                        try w.writeAll("\\u2028");
                    } else {
                        try w.writeAll("\\u2029");
                    }
                    i += 3;
                } else {
                    try w.writeByte(c);
                    i += 1;
                }
            },
            else => {
                try w.writeByte(c);
                i += 1;
            },
        }
    }
    try w.writeByte('"');
}

pub fn writeNullableString(w: *std.Io.Writer, opt: ?[]const u8) std.Io.Writer.Error!void {
    if (opt) |s| {
        try writeGoJsonString(w, s);
    } else {
        try w.writeAll("null");
    }
}

pub fn writeSpan(w: *std.Io.Writer, sp: Span) std.Io.Writer.Error!void {
    try w.writeAll("{\"file\":");
    try writeGoJsonString(w, sp.file);
    try w.print(",\"start\":{d},\"end\":{d}}}", .{ sp.start, sp.end });
}

pub fn writeOp(w: *std.Io.Writer, op: Op) std.Io.Writer.Error!void {
    try w.writeAll("{\"type\":");
    try writeGoJsonString(w, op.type);
    try w.writeAll(",\"atom_id\":");
    try writeGoJsonString(w, op.atom_id);
    if (op.kind.len > 0) {
        try w.writeAll(",\"kind\":");
        try writeGoJsonString(w, op.kind);
    }
    if (op.new_name.len > 0) {
        try w.writeAll(",\"new_name\":");
        try writeGoJsonString(w, op.new_name);
    }
    if (op.new_span) |sp| {
        try w.writeAll(",\"new_span\":");
        try writeSpan(w, sp);
    }
    if (op.new_hash.len > 0) {
        try w.writeAll(",\"new_hash\":");
        try writeGoJsonString(w, op.new_hash);
    }
    if (op.new_sig_hash.len > 0) {
        try w.writeAll(",\"new_sig_hash\":");
        try writeGoJsonString(w, op.new_sig_hash);
    }
    if (op.old_hash.len > 0) {
        try w.writeAll(",\"old_hash\":");
        try writeGoJsonString(w, op.old_hash);
    }
    try w.writeByte('}');
}

pub fn writeOpsArray(w: *std.Io.Writer, ops: []const Op) std.Io.Writer.Error!void {
    try w.writeByte('[');
    for (ops, 0..) |op, i| {
        if (i > 0) try w.writeByte(',');
        try writeOp(w, op);
    }
    try w.writeByte(']');
}

pub fn writeForkOrigin(w: *std.Io.Writer, ff: ForkOrigin) std.Io.Writer.Error!void {
    try w.writeAll("{\"stream\":");
    try writeGoJsonString(w, ff.stream);
    try w.writeAll(",\"change\":");
    try writeGoJsonString(w, ff.change);
    try w.writeByte('}');
}

pub fn writeStream(w: *std.Io.Writer, st: Stream) std.Io.Writer.Error!void {
    try w.writeAll("{\"id\":");
    try writeGoJsonString(w, st.id);
    try w.writeAll(",\"name\":");
    try writeGoJsonString(w, st.name);
    try w.writeAll(",\"head\":");
    try writeNullableString(w, st.head);
    try w.print(",\"created\":{d},\"forked_from\":", .{st.created});
    if (st.forked_from) |ff| {
        try writeForkOrigin(w, ff);
    } else {
        try w.writeAll("null");
    }
    try w.writeByte('}');
}

pub fn marshalStreamRecord(allocator: Allocator, st: Stream) Allocator.Error![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    writeStream(&aw.writer, st) catch return error.OutOfMemory;
    aw.writer.writeByte('\n') catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

pub fn writeChange(w: *std.Io.Writer, c: *const Change) std.Io.Writer.Error!void {
    try w.writeAll("{\"id\":");
    try writeGoJsonString(w, c.id);
    try w.writeAll(",\"parent\":");
    try writeNullableString(w, c.parent);
    try w.writeAll(",\"stream\":");
    try writeGoJsonString(w, c.stream);
    try w.print(",\"ts\":{d},\"author\":", .{c.ts});
    try writeGoJsonString(w, c.author);
    try w.writeAll(",\"message\":");
    try writeGoJsonString(w, c.message);
    try w.writeAll(",\"ops\":");
    try writeOpsArray(w, c.ops);
    try w.writeAll(",\"merged\":");
    try writeNullableString(w, c.merged);
    try w.writeAll(",\"sig\":");
    try writeGoJsonString(w, c.sig);
    try w.writeByte('}');
}

pub fn marshalChangeLine(allocator: Allocator, c: *const Change) Allocator.Error![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    writeChange(&aw.writer, c) catch return error.OutOfMemory;
    aw.writer.writeByte('\n') catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

fn getOptString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return "";
    return switch (val) {
        .string => |s| s,
        .null => "",
        else => null,
    };
}

fn getNullableString(obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        .null => null,
        else => error.InvalidType,
    };
}

fn getOptInt(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const val = obj.get(key) orelse return 0;
    return switch (val) {
        .integer => |n| n,
        .null => 0,
        else => null,
    };
}

pub fn parseSpanFromValue(allocator: Allocator, val: std.json.Value) ParseError!Span {
    const obj = switch (val) {
        .object => |o| o,
        else => return error.ChangeMalformed,
    };
    const file_raw = getOptString(obj, "file") orelse return error.ChangeMalformed;
    const start_i64 = getOptInt(obj, "start") orelse return error.ChangeMalformed;
    const end_i64 = getOptInt(obj, "end") orelse return error.ChangeMalformed;
    if (start_i64 < 0 or start_i64 > std.math.maxInt(u32)) return error.ChangeMalformed;
    if (end_i64 < 0 or end_i64 > std.math.maxInt(u32)) return error.ChangeMalformed;

    return .{
        .file = try allocator.dupe(u8, file_raw),
        .start = @intCast(start_i64),
        .end = @intCast(end_i64),
    };
}

pub fn parseOpFromValue(allocator: Allocator, val: std.json.Value) ParseError!Op {
    const obj = switch (val) {
        .object => |o| o,
        else => return error.ChangeMalformed,
    };
    const type_raw = getOptString(obj, "type") orelse return error.ChangeMalformed;
    const atom_id_raw = getOptString(obj, "atom_id") orelse return error.ChangeMalformed;
    const kind_raw = getOptString(obj, "kind") orelse return error.ChangeMalformed;
    const new_name_raw = getOptString(obj, "new_name") orelse return error.ChangeMalformed;
    const new_hash_raw = getOptString(obj, "new_hash") orelse return error.ChangeMalformed;
    const new_sig_hash_raw = getOptString(obj, "new_sig_hash") orelse return error.ChangeMalformed;
    const old_hash_raw = getOptString(obj, "old_hash") orelse return error.ChangeMalformed;

    const type_copy = try allocator.dupe(u8, type_raw);
    errdefer allocator.free(type_copy);
    const atom_id_copy = try allocator.dupe(u8, atom_id_raw);
    errdefer allocator.free(atom_id_copy);
    const kind_copy = if (kind_raw.len > 0) try allocator.dupe(u8, kind_raw) else "";
    errdefer if (kind_copy.len > 0) allocator.free(kind_copy);
    const new_name_copy = if (new_name_raw.len > 0) try allocator.dupe(u8, new_name_raw) else "";
    errdefer if (new_name_copy.len > 0) allocator.free(new_name_copy);

    var new_span_copy: ?Span = null;
    if (obj.get("new_span")) |sp_val| {
        switch (sp_val) {
            .null => {},
            .object => {
                new_span_copy = try parseSpanFromValue(allocator, sp_val);
            },
            else => return error.ChangeMalformed,
        }
    }
    errdefer if (new_span_copy) |*sp| sp.deinit(allocator);

    const new_hash_copy = if (new_hash_raw.len > 0) try allocator.dupe(u8, new_hash_raw) else "";
    errdefer if (new_hash_copy.len > 0) allocator.free(new_hash_copy);
    const new_sig_hash_copy = if (new_sig_hash_raw.len > 0) try allocator.dupe(u8, new_sig_hash_raw) else "";
    errdefer if (new_sig_hash_copy.len > 0) allocator.free(new_sig_hash_copy);
    const old_hash_copy = if (old_hash_raw.len > 0) try allocator.dupe(u8, old_hash_raw) else "";

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

pub fn parseStreamFromValue(allocator: Allocator, val: std.json.Value) ParseError!Stream {
    const obj = switch (val) {
        .object => |o| o,
        else => return error.StreamMalformed,
    };

    // Spec §2.5: id, name, created must be present.
    const id_val = obj.get("id") orelse return error.StreamMalformed;
    const name_val = obj.get("name") orelse return error.StreamMalformed;
    const created_val = obj.get("created") orelse return error.StreamMalformed;

    const id_raw = switch (id_val) {
        .string => |s| s,
        else => return error.StreamMalformed,
    };
    const name_raw = switch (name_val) {
        .string => |s| s,
        else => return error.StreamMalformed,
    };
    const created = switch (created_val) {
        .integer => |n| n,
        else => return error.StreamMalformed,
    };

    const head_raw = getNullableString(obj, "head") catch return error.StreamMalformed;

    var ff_copy: ?ForkOrigin = null;
    if (obj.get("forked_from")) |ff_val| {
        switch (ff_val) {
            .null => {},
            .object => |ff_obj| {
                const ff_stream = getOptString(ff_obj, "stream") orelse return error.StreamMalformed;
                const ff_change = getOptString(ff_obj, "change") orelse return error.StreamMalformed;
                const s_dup = try allocator.dupe(u8, ff_stream);
                errdefer allocator.free(s_dup);
                const c_dup = try allocator.dupe(u8, ff_change);
                ff_copy = .{ .stream = s_dup, .change = c_dup };
            },
            else => return error.StreamMalformed,
        }
    }
    errdefer if (ff_copy) |*ff| ff.deinit(allocator);

    const id_copy = try allocator.dupe(u8, id_raw);
    errdefer allocator.free(id_copy);
    const name_copy = try allocator.dupe(u8, name_raw);
    errdefer allocator.free(name_copy);
    const head_copy = if (head_raw) |h| try allocator.dupe(u8, h) else null;
    errdefer if (head_copy) |h| allocator.free(h);

    var st = Stream{
        .id = id_copy,
        .name = name_copy,
        .head = head_copy,
        .created = created,
        .forked_from = ff_copy,
    };
    if (!store.validateStreamShape(&st)) {
        return error.StreamMalformed;
    }
    return st;
}

pub fn parseStreamSlice(allocator: Allocator, raw: []const u8) ParseError!Stream {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return error.StreamMalformed;
    defer parsed.deinit();
    return parseStreamFromValue(allocator, parsed.value);
}

pub fn parseChangeFromValue(allocator: Allocator, val: std.json.Value) ParseError!Change {
    const obj = switch (val) {
        .object => |o| o,
        else => return error.ChangeMalformed,
    };
    const id_raw = getOptString(obj, "id") orelse return error.ChangeMalformed;
    const parent_raw = getNullableString(obj, "parent") catch return error.ChangeMalformed;
    const stream_raw = getOptString(obj, "stream") orelse return error.ChangeMalformed;
    const ts = getOptInt(obj, "ts") orelse return error.ChangeMalformed;
    const author_raw = getOptString(obj, "author") orelse return error.ChangeMalformed;
    const message_raw = getOptString(obj, "message") orelse return error.ChangeMalformed;
    const merged_raw = getNullableString(obj, "merged") catch return error.ChangeMalformed;
    const sig_raw = getOptString(obj, "sig") orelse return error.ChangeMalformed;

    const ops_val = obj.get("ops") orelse return error.ChangeMalformed;
    const ops_arr = switch (ops_val) {
        .array => |arr| arr.items,
        else => return error.ChangeMalformed,
    };

    const id_copy = try allocator.dupe(u8, id_raw);
    errdefer allocator.free(id_copy);
    const parent_copy = if (parent_raw) |p| try allocator.dupe(u8, p) else null;
    errdefer if (parent_copy) |p| allocator.free(p);
    const stream_copy = try allocator.dupe(u8, stream_raw);
    errdefer allocator.free(stream_copy);
    const author_copy = try allocator.dupe(u8, author_raw);
    errdefer allocator.free(author_copy);
    const msg_copy = try allocator.dupe(u8, message_raw);
    errdefer allocator.free(msg_copy);

    const ops_copy = try allocator.alloc(Op, ops_arr.len);
    var initialized_ops: usize = 0;
    errdefer {
        for (ops_copy[0..initialized_ops]) |*op| op.deinit(allocator);
        allocator.free(ops_copy);
    }
    for (ops_arr, 0..) |op_v, idx| {
        ops_copy[idx] = try parseOpFromValue(allocator, op_v);
        initialized_ops += 1;
    }

    const merged_copy = if (merged_raw) |m| try allocator.dupe(u8, m) else null;
    errdefer if (merged_copy) |m| allocator.free(m);
    const sig_copy = try allocator.dupe(u8, sig_raw);

    return .{
        .id = id_copy,
        .parent = parent_copy,
        .stream = stream_copy,
        .ts = ts,
        .author = author_copy,
        .message = msg_copy,
        .ops = ops_copy,
        .merged = merged_copy,
        .sig = sig_copy,
    };
}

test "parseStreamSlice rejects shape-invalid records without double-free" {
    const cases = [_][]const u8{
        \\{"id":"0199de2d-dc00-7000-8000-000000000010","name":"main","head":"h","created":1,"forked_from":null}
        ,
        \\{"id":"0199de2d-dc00-7000-8000-000000000010","name":"Bad_Name","head":null,"created":1,"forked_from":null}
        ,
        \\{"id":"not-a-uuid","name":"main","head":null,"created":1,"forked_from":null}
        ,
        \\{"id":"0199de2d-dc00-7000-8000-000000000010","name":"main","head":"h","created":1,"forked_from":{"stream":"s","change":"c"}}
        ,
    };
    for (cases) |raw| {
        try std.testing.expectError(error.StreamMalformed, parseStreamSlice(std.testing.allocator, raw));
    }
}

test "writeGoJsonString escapes HTML and control chars like Go encoding/json" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    try writeGoJsonString(&aw.writer, "a<b>c&d\n\t\r\"\\\x08\x0c\u{2028}\u{2029}");
    try std.testing.expectEqualStrings(
        "\"a\\u003cb\\u003ec\\u0026d\\n\\t\\r\\\"\\\\\\u0008\\u000c\\u2028\\u2029\"",
        aw.written(),
    );
}
