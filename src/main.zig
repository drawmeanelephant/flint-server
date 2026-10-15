const std = @import("std");
const Io = std.Io;
const store = @import("store.zig");
const json = @import("json.zig");
const ed25519 = @import("ed25519.zig");
const change = @import("change.zig");
const jsonl = @import("jsonl.zig");
const storeio = @import("storeio.zig");
const auth = @import("auth.zig");
const proto = @import("proto.zig");
const serve = @import("serve.zig");

fn writeStderr(io: Io, msg: []const u8) void {
    var buf: [512]u8 = undefined;
    var w = Io.File.stderr().writerStreaming(io, &buf);
    w.interface.writeAll(msg) catch {};
    w.interface.flush() catch {};
}

fn writeStdout(io: Io, msg: []const u8) void {
    var buf: [512]u8 = undefined;
    var w = Io.File.stdout().writerStreaming(io, &buf);
    w.interface.writeAll(msg) catch {};
    w.interface.flush() catch {};
}

fn printRefusal(io: Io, code: store.RefusalCode, detail: []const u8) void {
    var buf: [512]u8 = undefined;
    var w = Io.File.stderr().writerStreaming(io, &buf);
    if (detail.len > 0) {
        w.interface.print("flintd: refuse {s} {s}\n", .{ code.asText(), detail }) catch {};
    } else {
        w.interface.print("flintd: refuse {s}\n", .{code.asText()}) catch {};
    }
    w.interface.flush() catch {};
}

fn printUsage(io: Io) void {
    writeStdout(io, "flintd: usage\n");
}

fn printHelp(io: Io) void {
    writeStdout(io,
        \\usage: flintd <command> [flags]
        \\
        \\commands:
        \\  init --store=<dir>
        \\      Initialize a store (streams/ + index). --store or FLINT_STORE required.
        \\  serve --store=<dir> [--stdio | --listen=<host>:<port>]
        \\        [--auth-key=<file>] [--allow-author=<file>] [--read-timeout=<sec>]
        \\      Serve the store over stdio or TCP. --stdio and --listen are mutually
        \\      exclusive; default --listen=127.0.0.1:4748.
        \\
        \\note: --store may also come from FLINT_STORE.
        \\
    );
}

fn resolveStoreRoot(flag_store: ?[]const u8, env_map: *const std.process.Environ.Map) ?[]const u8 {
    if (flag_store) |s| {
        if (s.len > 0) return s;
    }
    if (env_map.get("FLINT_STORE")) |env_s| {
        if (env_s.len > 0) return env_s;
    }
    return null;
}

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.gpa;
    const io = init.io;

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printHelp(io);
            return 0;
        }
    }
    if (args.len < 2) {
        printUsage(io);
        return 2;
    }

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "help")) {
        printHelp(io);
        return 0;
    }
    if (std.mem.eql(u8, cmd, "init")) {
        var flag_store: ?[]const u8 = null;
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.startsWith(u8, arg, "--store=")) {
                flag_store = arg["--store=".len..];
            } else if (std.mem.eql(u8, arg, "--store")) {
                if (i + 1 >= args.len) {
                    printRefusal(io, .usage, "missing argument for --store");
                    return 2;
                }
                i += 1;
                flag_store = args[i];
            } else {
                printRefusal(io, .usage, "unknown flag for init");
                return 2;
            }
        }

        const root_path = resolveStoreRoot(flag_store, init.environ_map) orelse {
            printRefusal(io, .store_not_found, "no --store and FLINT_STORE unset");
            return 1;
        };

        storeio.initStore(io, allocator, root_path) catch |err| switch (err) {
            error.StreamExists => {
                printRefusal(io, .stream_exists, "streams/ already exists");
                return 1;
            },
            else => {
                const info = storeio.refusalForError(err);
                printRefusal(io, info.code, info.detail);
                return 1;
            },
        };

        const out_msg = try std.fmt.allocPrint(allocator, "flintd: init ok store={s}\n", .{root_path});
        defer allocator.free(out_msg);
        writeStdout(io, out_msg);
        return 0;
    } else if (std.mem.eql(u8, cmd, "serve")) {
        var flag_store: ?[]const u8 = null;
        var use_stdio = false;
        var listen_addr: ?[]const u8 = null;
        var auth_key_path: ?[]const u8 = null;
        var allow_author_path: ?[]const u8 = null;
        var read_timeout_sec: u32 = 60;

        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.startsWith(u8, arg, "--store=")) {
                flag_store = arg["--store=".len..];
            } else if (std.mem.eql(u8, arg, "--store")) {
                if (i + 1 >= args.len) {
                    printRefusal(io, .usage, "missing argument for --store");
                    return 2;
                }
                i += 1;
                flag_store = args[i];
            } else if (std.mem.eql(u8, arg, "--stdio")) {
                use_stdio = true;
            } else if (std.mem.startsWith(u8, arg, "--listen=")) {
                listen_addr = arg["--listen=".len..];
            } else if (std.mem.eql(u8, arg, "--listen")) {
                if (i + 1 >= args.len) {
                    printRefusal(io, .usage, "missing argument for --listen");
                    return 2;
                }
                i += 1;
                listen_addr = args[i];
            } else if (std.mem.startsWith(u8, arg, "--auth-key=")) {
                auth_key_path = arg["--auth-key=".len..];
            } else if (std.mem.eql(u8, arg, "--auth-key")) {
                if (i + 1 >= args.len) {
                    printRefusal(io, .usage, "missing argument for --auth-key");
                    return 2;
                }
                i += 1;
                auth_key_path = args[i];
            } else if (std.mem.startsWith(u8, arg, "--allow-author=")) {
                allow_author_path = arg["--allow-author=".len..];
            } else if (std.mem.eql(u8, arg, "--allow-author")) {
                if (i + 1 >= args.len) {
                    printRefusal(io, .usage, "missing argument for --allow-author");
                    return 2;
                }
                i += 1;
                allow_author_path = args[i];
            } else if (std.mem.startsWith(u8, arg, "--read-timeout=")) {
                read_timeout_sec = std.fmt.parseInt(u32, arg["--read-timeout=".len..], 10) catch {
                    printRefusal(io, .usage, "invalid --read-timeout value");
                    return 2;
                };
            } else if (std.mem.eql(u8, arg, "--read-timeout")) {
                if (i + 1 >= args.len) {
                    printRefusal(io, .usage, "missing argument for --read-timeout");
                    return 2;
                }
                i += 1;
                read_timeout_sec = std.fmt.parseInt(u32, args[i], 10) catch {
                    printRefusal(io, .usage, "invalid --read-timeout value");
                    return 2;
                };
            } else {
                printRefusal(io, .usage, "unknown flag for serve");
                return 2;
            }
        }

        if (use_stdio and listen_addr != null) {
            printRefusal(io, .usage, "cannot specify both --stdio and --listen");
            return 2;
        }

        const root_path = resolveStoreRoot(flag_store, init.environ_map) orelse {
            printRefusal(io, .store_not_found, "no --store and FLINT_STORE unset");
            return 1;
        };

        var auth_key: ?[32]u8 = null;
        if (auth_key_path) |akp| {
            auth_key = auth.loadAuthKeyFile(io, allocator, akp) catch {
                printRefusal(io, .usage, "invalid --auth-key file");
                return 2;
            };
        }

        var allow_authors: ?[][64]u8 = null;
        defer if (allow_authors) |aa| allocator.free(aa);
        if (allow_author_path) |aap| {
            allow_authors = auth.loadAllowAuthorFile(io, allocator, aap) catch {
                printRefusal(io, .usage, "invalid --allow-author file");
                return 2;
            };
        }

        // Validate store exists and is healthy before serving.
        {
            var idx = storeio.loadStoreIndex(io, allocator, root_path) catch |err| {
                const info = storeio.refusalForError(err);
                printRefusal(io, info.code, info.detail);
                return 1;
            };
            idx.deinit(allocator);
        }

        const cfg = serve.ServeConfig{
            .root_path = root_path,
            .auth_key = auth_key,
            .allow_authors = allow_authors,
        };

        if (use_stdio) {
            serve.serveStdio(io, allocator, cfg) catch {
                writeStderr(io, "flintd: stdio session error\n");
                return 1;
            };
        } else {
            const bind_str = listen_addr orelse "127.0.0.1:4748";
            const read_timeout: Io.Timeout = if (read_timeout_sec == 0)
                .none
            else
                .{ .duration = .{ .raw = Io.Duration.fromSeconds(read_timeout_sec), .clock = .awake } };
            serve.serveTcp(io, allocator, cfg, bind_str, null, read_timeout) catch |err| {
                var detail_buf: [128]u8 = undefined;
                const detail = std.fmt.bufPrint(
                    &detail_buf,
                    "failed to listen on {s}: {s}",
                    .{ bind_str, @errorName(err) },
                ) catch "failed to listen on address";
                printRefusal(io, .usage, detail);
                return 1;
            };
        }
        return 0;
    } else {
        printRefusal(io, .usage, "unknown command");
        return 2;
    }
}

test {
    _ = store;
    _ = json;
    _ = ed25519;
    _ = change;
    _ = jsonl;
    _ = storeio;
    _ = auth;
    _ = proto;
    _ = serve;
    _ = @import("conformance_test.zig");
}
