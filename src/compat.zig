const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;

/// Cross-platform getenv. On POSIX uses std.posix.getenv (zero-copy).
/// On Windows uses a static thread-local buffer with std.process.getEnvVarOwned workaround.
/// Returns null when the variable is not set.
pub fn getenv(name: []const u8) ?[]const u8 {
    if (is_windows) {
        return getenvWindows(name);
    } else {
        return std.posix.getenv(name);
    }
}

/// Windows getenv implementation using a static thread-local buffer.
fn getenvWindows(name: []const u8) ?[]const u8 {
    // Convert name to null-terminated sentinel slice
    var name_buf: [256]u8 = undefined;
    if (name.len >= name_buf.len) return null;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;
    const name_z: [:0]const u8 = name_buf[0..name.len :0];

    // Use Zig's cross-platform env lookup (allocates)
    const S = struct {
        threadlocal var buf: [8192]u8 = undefined;
        threadlocal var len: usize = 0;
    };
    const val = std.process.getEnvVarOwned(std.heap.page_allocator, name_z) catch return null;
    defer std.heap.page_allocator.free(val);
    if (val.len >= S.buf.len) return null;
    @memcpy(S.buf[0..val.len], val);
    S.len = val.len;
    return S.buf[0..S.len];
}

/// Cross-platform home directory: HOME on POSIX, USERPROFILE on Windows.
/// Falls back to /tmp (POSIX) or C:\temp (Windows).
pub fn getHomeDir() []const u8 {
    if (is_windows) {
        return getenv("USERPROFILE") orelse getenv("HOME") orelse "C:\\temp";
    } else {
        return getenv("HOME") orelse "/tmp";
    }
}

/// Cross-platform socket read-timeout.
pub fn setRecvTimeout(handle: std.net.Stream.Handle, timeout_sec: i32) void {
    if (is_windows) {
        // Windows SO_RCVTIMEO takes a DWORD in milliseconds
        const ms: u32 = @intCast(@as(i64, timeout_sec) * 1000);
        const SOL_SOCKET = 0xffff;
        const SO_RCVTIMEO = 0x1006;
        _ = std.os.windows.ws2_32.setsockopt(
            handle,
            SOL_SOCKET,
            SO_RCVTIMEO,
            @ptrCast(std.mem.asBytes(&ms)),
            @intCast(@sizeOf(u32)),
        );
    } else {
        const timeout = std.posix.timeval{ .sec = timeout_sec, .usec = 0 };
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
    }
}
