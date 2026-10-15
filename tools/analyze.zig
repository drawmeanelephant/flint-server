const std = @import("std");
const Io = std.Io;
const Ast = std.zig.Ast;

fn isDecision(tag: Ast.Node.Tag) bool {
    const name = @tagName(tag);
    return tag == .if_simple or tag == .@"if" or
        tag == .while_simple or tag == .while_cont or tag == .@"while" or
        tag == .for_simple or tag == .@"for" or
        std.mem.startsWith(u8, name, "switch_case") or
        tag == .@"catch" or tag == .@"orelse" or
        tag == .bool_and or tag == .bool_or;
}

fn complexity(tree: *const Ast, function: Ast.Node.Index) usize {
    const first = tree.firstToken(function);
    const last = tree.lastToken(function);
    var count: usize = 1;
    for (tree.nodes.items(.tag), 0..) |tag, index| {
        const node: Ast.Node.Index = @fromBackingInt(@as(u32, @intCast(index)));
        const token = tree.nodeMainToken(node);
        if (token >= first and token <= last and isDecision(tag)) count += 1;
    }
    return count;
}

fn readSource(io: Io, allocator: std.mem.Allocator, path: []const u8) ![:0]u8 {
    var file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const length = try file.length(io);
    if (length > 1024 * 1024) return error.SourceTooLarge;
    const source = try allocator.allocSentinel(u8, @intCast(length), 0);
    errdefer allocator.free(source);
    var offset: usize = 0;
    while (offset < source.len) {
        var chunks = [1][]u8{source[offset..]};
        const count = try file.readPositional(io, &chunks, offset);
        if (count == 0) return error.UnexpectedEndOfFile;
        offset += count;
    }
    return source;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    var buffer: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(init.io, &buffer);
    for (args[1..]) |path| {
        const source = try readSource(init.io, allocator, path);
        var tree = try Ast.parse(allocator, source, .{});
        defer tree.deinit(allocator);
        if (tree.errors.len != 0) return error.InvalidZigSource;
        for (tree.nodes.items(.tag), 0..) |tag, index| {
            if (tag != .fn_decl) continue;
            const node: Ast.Node.Index = @fromBackingInt(@as(u32, @intCast(index)));
            var parameters: [1]Ast.Node.Index = undefined;
            const function = tree.fullFnProto(&parameters, node).?;
            const name = tree.tokenSlice(function.name_token.?);
            try stdout.interface.print("{s}\t{s}\t{d}\n", .{ path, name, complexity(&tree, node) });
        }
    }
    try stdout.interface.flush();
}

test "complexity counts AST decisions and ignores comments and string contents" {
    const source =
        \\fn example(a: bool, b: ?bool) bool {
        \\    // if for while catch: these are not executable branches.
        \\    const text = "if for while";
        \\    _ = text;
        \\    return if (a and (b orelse false)) true else false;
        \\}
    ;
    var tree = try Ast.parse(std.testing.allocator, source, .{});
    defer tree.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), tree.errors.len);
    const function = tree.rootDecls()[0];
    try std.testing.expectEqual(@as(usize, 4), complexity(&tree, function));
}
