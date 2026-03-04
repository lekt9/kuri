const std = @import("std");
const protocol = @import("protocol.zig");

pub const CdpClient = struct {
    allocator: std.mem.Allocator,
    cdp_url: []const u8,
    next_id: std.atomic.Value(u32),
    connected: bool,

    pub fn init(allocator: std.mem.Allocator, cdp_url: []const u8) CdpClient {
        return .{
            .allocator = allocator,
            .cdp_url = cdp_url,
            .next_id = std.atomic.Value(u32).init(1),
            .connected = false,
        };
    }

    pub fn nextId(self: *CdpClient) u32 {
        return self.next_id.fetchAdd(1, .monotonic);
    }

    /// Build a JSON-RPC message for a CDP command.
    pub fn buildMessage(self: *CdpClient, allocator: std.mem.Allocator, method: []const u8, params_json: ?[]const u8) ![]const u8 {
        const id = self.nextId();
        if (params_json) |p| {
            return std.fmt.allocPrint(allocator, "{{\"id\":{d},\"method\":\"{s}\",\"params\":{s}}}", .{ id, method, p });
        } else {
            return std.fmt.allocPrint(allocator, "{{\"id\":{d},\"method\":\"{s}\"}}", .{ id, method });
        }
    }

    pub fn deinit(self: *CdpClient) void {
        _ = self;
    }
};

test "CdpClient message building" {
    var client = CdpClient.init(std.testing.allocator, "ws://localhost:9222");
    defer client.deinit();

    const msg = try client.buildMessage(std.testing.allocator, "Page.navigate", "{\"url\":\"https://example.com\"}");
    defer std.testing.allocator.free(msg);

    try std.testing.expect(std.mem.indexOf(u8, msg, "Page.navigate") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "https://example.com") != null);
}

test "CdpClient id increments" {
    var client = CdpClient.init(std.testing.allocator, "ws://localhost:9222");
    defer client.deinit();

    const id1 = client.nextId();
    const id2 = client.nextId();
    try std.testing.expect(id2 == id1 + 1);
}
