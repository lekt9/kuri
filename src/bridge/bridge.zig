const std = @import("std");

pub const TabEntry = struct {
    id: []const u8,
    url: []const u8,
    title: []const u8,
    created_at: i64,
    last_accessed: i64,
};

pub const RefCache = struct {
    refs: std.StringHashMap(u32),
    node_count: usize,

    pub fn init(allocator: std.mem.Allocator) RefCache {
        return .{
            .refs = std.StringHashMap(u32).init(allocator),
            .node_count = 0,
        };
    }

    pub fn deinit(self: *RefCache) void {
        self.refs.deinit();
    }
};

pub const Bridge = struct {
    allocator: std.mem.Allocator,
    tabs: std.StringHashMap(TabEntry),
    snapshots: std.StringHashMap(RefCache),
    mu: std.Thread.RwLock,

    pub fn init(allocator: std.mem.Allocator) Bridge {
        return .{
            .allocator = allocator,
            .tabs = std.StringHashMap(TabEntry).init(allocator),
            .snapshots = std.StringHashMap(RefCache).init(allocator),
            .mu = .{},
        };
    }

    pub fn deinit(self: *Bridge) void {
        // Clean up snapshot caches
        var snap_it = self.snapshots.valueIterator();
        while (snap_it.next()) |cache| {
            cache.deinit();
        }
        self.snapshots.deinit();
        self.tabs.deinit();
    }

    pub fn tabCount(self: *Bridge) usize {
        self.mu.lockShared();
        defer self.mu.unlockShared();
        return self.tabs.count();
    }

    pub fn getTab(self: *Bridge, tab_id: []const u8) ?TabEntry {
        self.mu.lockShared();
        defer self.mu.unlockShared();
        return self.tabs.get(tab_id);
    }

    pub fn putTab(self: *Bridge, entry: TabEntry) !void {
        self.mu.lock();
        defer self.mu.unlock();
        try self.tabs.put(entry.id, entry);
    }

    pub fn removeTab(self: *Bridge, tab_id: []const u8) void {
        self.mu.lock();
        defer self.mu.unlock();
        _ = self.tabs.remove(tab_id);
        if (self.snapshots.getPtr(tab_id)) |cache| {
            cache.deinit();
        }
        _ = self.snapshots.remove(tab_id);
    }

    pub fn listTabs(self: *Bridge, allocator: std.mem.Allocator) ![]TabEntry {
        self.mu.lockShared();
        defer self.mu.unlockShared();

        var list: std.ArrayList(TabEntry) = .empty;
        var it = self.tabs.valueIterator();
        while (it.next()) |entry| {
            try list.append(allocator, entry.*);
        }
        return list.toOwnedSlice(allocator);
    }
};

test "bridge init/deinit" {
    var bridge = Bridge.init(std.testing.allocator);
    defer bridge.deinit();
    try std.testing.expectEqual(@as(usize, 0), bridge.tabCount());
}

test "bridge tab CRUD" {
    var bridge = Bridge.init(std.testing.allocator);
    defer bridge.deinit();

    const entry = TabEntry{
        .id = "tab-1",
        .url = "https://example.com",
        .title = "Example",
        .created_at = 1000,
        .last_accessed = 1000,
    };
    try bridge.putTab(entry);
    try std.testing.expectEqual(@as(usize, 1), bridge.tabCount());

    const got = bridge.getTab("tab-1");
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings("https://example.com", got.?.url);

    bridge.removeTab("tab-1");
    try std.testing.expectEqual(@as(usize, 0), bridge.tabCount());
}
