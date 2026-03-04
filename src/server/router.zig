const std = @import("std");
const net = std.net;
const Bridge = @import("../bridge/bridge.zig").Bridge;
const Config = @import("../bridge/config.zig").Config;
const resp = @import("response.zig");
const middleware = @import("middleware.zig");

pub fn run(gpa: std.mem.Allocator, bridge: *Bridge, cfg: Config) !void {
    const address = try net.Address.parseIp4(cfg.host, cfg.port);
    var tcp_server = try address.listen(.{
        .reuse_address = true,
    });
    defer tcp_server.deinit();

    std.log.info("server ready on {s}:{d}", .{ cfg.host, cfg.port });

    while (true) {
        const conn = tcp_server.accept() catch |err| {
            std.log.err("accept error: {s}", .{@errorName(err)});
            continue;
        };

        const thread = std.Thread.spawn(.{}, handleConnection, .{ gpa, bridge, cfg, conn }) catch |err| {
            std.log.err("thread spawn error: {s}", .{@errorName(err)});
            conn.stream.close();
            continue;
        };
        thread.detach();
    }
}

fn handleConnection(gpa: std.mem.Allocator, bridge: *Bridge, cfg: Config, conn: net.Server.Connection) void {
    defer conn.stream.close();

    var arena_impl = std.heap.ArenaAllocator.init(gpa);
    defer arena_impl.deinit();
    const arena = arena_impl.allocator();

    // Create Reader and Writer from the net.Stream
    var read_buf: [8192]u8 = undefined;
    var net_reader = net.Stream.Reader.init(conn.stream, &read_buf);
    var write_buf: [8192]u8 = undefined;
    var net_writer = net.Stream.Writer.init(conn.stream, &write_buf);

    var http_server = std.http.Server.init(net_reader.interface(), &net_writer.interface);

    while (true) {
        var request = http_server.receiveHead() catch |err| {
            if (err == error.EndOfStream) return;
            std.log.debug("receiveHead error: {s}", .{@errorName(err)});
            return;
        };

        // Auth check
        if (!middleware.checkAuth(&request, cfg)) {
            resp.sendError(&request, 401, "Unauthorized");
            return;
        }

        // Route dispatch
        route(&request, arena, bridge);

        // Check keep-alive
        if (!request.head.keep_alive) return;
    }
}

fn route(request: *std.http.Server.Request, arena: std.mem.Allocator, bridge: *Bridge) void {
    const path = request.head.target;
    const clean_path = if (std.mem.indexOfScalar(u8, path, '?')) |idx| path[0..idx] else path;

    if (std.mem.eql(u8, clean_path, "/health")) {
        handleHealth(request, arena, bridge);
    } else if (std.mem.eql(u8, clean_path, "/tabs")) {
        handleTabs(request, arena, bridge);
    } else {
        resp.sendError(request, 404, "Not Found");
    }
}

fn handleHealth(request: *std.http.Server.Request, arena: std.mem.Allocator, bridge: *Bridge) void {
    const tab_count = bridge.tabCount();
    const body = std.fmt.allocPrint(arena, "{{\"ok\":true,\"tabs\":{d},\"version\":\"0.1.0\"}}", .{tab_count}) catch {
        resp.sendError(request, 500, "Internal Server Error");
        return;
    };
    resp.sendJson(request, body);
}

fn handleTabs(request: *std.http.Server.Request, arena: std.mem.Allocator, bridge: *Bridge) void {
    const tabs = bridge.listTabs(arena) catch {
        resp.sendError(request, 500, "Internal Server Error");
        return;
    };
    var json_buf: std.ArrayList(u8) = .empty;
    const writer = json_buf.writer(arena);

    writer.writeAll("[") catch return;
    for (tabs, 0..) |tab, i| {
        if (i > 0) writer.writeAll(",") catch return;
        writer.print("{{\"id\":\"{s}\",\"url\":\"{s}\",\"title\":\"{s}\"}}", .{ tab.id, tab.url, tab.title }) catch return;
    }
    writer.writeAll("]") catch return;

    resp.sendJson(request, json_buf.items);
}

test "route matching" {
    const path = "/health?foo=bar";
    const clean = if (std.mem.indexOfScalar(u8, path, '?')) |idx| path[0..idx] else path;
    try std.testing.expectEqualStrings("/health", clean);
}
