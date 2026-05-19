/// Zig 0.16 compatibility shims for removed stdlib APIs.
const std = @import("std");
const builtin = @import("builtin");

/// Windows port seam. compat.zig was POSIX-modeled (libc fork/exec/raw
/// BSD sockets) to dodge removed std.fs/std.net/std.process. On Windows
/// those std.c symbols differ or do not exist; primitives that are
/// genuinely OS-specific branch on this. Pure-libc primitives whose
/// std.c signature is already correct on win (fd_t variables, not int
/// literals) need no branch.
pub const is_windows = builtin.os.tag == .windows;
const win = std.os.windows;

// Zig 0.16 std.os.windows does NOT bind GetStdHandle / WriteFile /
// GetConsoleMode. Declare them directly (same pattern this file already
// uses for `extern "c" fn execvp`). Only referenced under a comptime
// is_windows branch, so non-windows builds never link them.
extern "kernel32" fn GetStdHandle(nStdHandle: win.DWORD) callconv(.winapi) ?win.HANDLE;
extern "kernel32" fn WriteFile(
    hFile: win.HANDLE,
    lpBuffer: [*]const u8,
    nNumberOfBytesToWrite: win.DWORD,
    lpNumberOfBytesWritten: *win.DWORD,
    lpOverlapped: ?*anyopaque,
) callconv(.winapi) win.BOOL;
extern "kernel32" fn GetConsoleMode(hConsoleHandle: win.HANDLE, lpMode: *win.DWORD) callconv(.winapi) win.BOOL;
const STD_OUTPUT_HANDLE: win.DWORD = @bitCast(@as(i32, -11));
const STD_ERROR_HANDLE: win.DWORD = @bitCast(@as(i32, -12));

/// stderr/stdout TTY detection. POSIX: libc isatty. Windows: a console
/// handle answers GetConsoleMode (a pipe/file does not), which is the
/// correct "is this an interactive terminal" test on win.
pub fn isatty(fd: c_int) bool {
    if (is_windows) {
        const h = GetStdHandle(if (fd == 2) STD_ERROR_HANDLE else STD_OUTPUT_HANDLE) orelse return false;
        if (h == win.INVALID_HANDLE_VALUE) return false;
        var mode: win.DWORD = undefined;
        return GetConsoleMode(h, &mode).toBool();
    }
    return std.c.isatty(fd) != 0;
}

// --- Time ---

// Win32 time/sleep (Zig 0.16 std.os.windows binds neither; std.time
// lacks milli/nanoTimestamp in 0.16 so derive everything from FILETIME).
extern "kernel32" fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *win.FILETIME) callconv(.winapi) void;
extern "kernel32" fn Sleep(dwMilliseconds: win.DWORD) callconv(.winapi) void;

/// 100-ns intervals since the Unix epoch, from the Windows wall clock.
fn winUnix100ns() i128 {
    var ft: win.FILETIME = undefined;
    GetSystemTimeAsFileTime(&ft);
    const ticks: u64 = (@as(u64, ft.dwHighDateTime) << 32) | @as(u64, ft.dwLowDateTime);
    // FILETIME epoch is 1601-01-01; Unix epoch is 11644473600 s later.
    return @as(i128, ticks) - 116444736000000000;
}

pub fn timestampSeconds() i64 {
    if (is_windows) return @intCast(@divTrunc(winUnix100ns(), 10_000_000));
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return ts.sec;
}

pub fn milliTimestamp() i64 {
    if (is_windows) return @intCast(@divTrunc(winUnix100ns(), 10_000));
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

pub fn nanoTimestamp() i128 {
    if (is_windows) return winUnix100ns() * 100;
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
}

// --- Threading ---

pub fn threadSleep(ns: u64) void {
    if (is_windows) {
        Sleep(@intCast(ns / std.time.ns_per_ms));
        return;
    }
    const ts = std.c.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.c.nanosleep(&ts, null);
}

pub const PthreadMutex = struct {
    inner: std.c.pthread_mutex_t = std.c.PTHREAD_MUTEX_INITIALIZER,

    pub fn lock(m: *PthreadMutex) void {
        _ = std.c.pthread_mutex_lock(&m.inner);
    }
    pub fn unlock(m: *PthreadMutex) void {
        _ = std.c.pthread_mutex_unlock(&m.inner);
    }
    pub fn tryLock(m: *PthreadMutex) bool {
        return @intFromEnum(std.c.pthread_mutex_trylock(&m.inner)) == 0;
    }
};

pub const PthreadRwLock = struct {
    inner: std.c.pthread_rwlock_t = .{},

    pub fn lock(rw: *PthreadRwLock) void {
        _ = std.c.pthread_rwlock_wrlock(&rw.inner);
    }
    pub fn unlock(rw: *PthreadRwLock) void {
        _ = std.c.pthread_rwlock_unlock(&rw.inner);
    }
    pub fn lockShared(rw: *PthreadRwLock) void {
        _ = std.c.pthread_rwlock_rdlock(&rw.inner);
    }
    pub fn unlockShared(rw: *PthreadRwLock) void {
        _ = std.c.pthread_rwlock_unlock(&rw.inner);
    }
};

// --- Random ---

pub fn randomBytes(buf: []u8) void {
    if (buf.len == 0) return;

    if (@import("builtin").os.tag == .linux and @TypeOf(std.c.getrandom) != void) {
        var filled: usize = 0;
        while (filled < buf.len) {
            const rc = std.c.getrandom(buf[filled..].ptr, buf.len - filled, 0);
            switch (std.c.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) break;
                    filled += n;
                },
                .INTR => continue,
                else => break,
            }
        }
        if (filled == buf.len) return;
    } else if (@TypeOf(std.c.arc4random_buf) != void) {
        std.c.arc4random_buf(buf.ptr, buf.len);
        return;
    }

    var prng = std.Random.DefaultPrng.init(@as(u64, @truncate(@as(u128, @intCast(nanoTimestamp())))));
    prng.random().bytes(buf);
}

// --- Environment ---

pub fn getenv(name: []const u8) ?[]const u8 {
    // std.c.getenv needs a sentinel-terminated string. For comptime-known keys
    // the caller can pass a literal. For runtime keys we need a small buffer.
    if (name.len > 255) return null;
    var buf: [256]u8 = undefined;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    const key: [*:0]const u8 = buf[0..name.len :0];
    const val = std.c.getenv(key) orelse return null;
    return std.mem.sliceTo(val, 0);
}

// --- Filesystem (replaces removed std.fs.cwd / std.fs.File) ---

fn writeToStdHandle(comptime fd_posix: c_int, comptime win_handle: win.DWORD, data: []const u8) void {
    if (is_windows) {
        const h = GetStdHandle(win_handle) orelse return;
        if (h == win.INVALID_HANDLE_VALUE) return;
        var sent: usize = 0;
        while (sent < data.len) {
            var wrote: win.DWORD = 0;
            if (!WriteFile(h, data[sent..].ptr, @intCast(data.len - sent), &wrote, null).toBool()) break;
            if (wrote == 0) break;
            sent += wrote;
        }
        return;
    }
    var sent: usize = 0;
    while (sent < data.len) {
        const n = std.c.write(fd_posix, data[sent..].ptr, data.len - sent);
        if (n <= 0) break;
        sent += @intCast(n);
    }
}

pub fn writeToStdout(data: []const u8) void {
    writeToStdHandle(1, STD_OUTPUT_HANDLE, data);
}

pub fn writeToStderr(data: []const u8) void {
    writeToStdHandle(2, STD_ERROR_HANDLE, data);
}

// --- Filesystem (cwd operations using C calls) ---

// Win32 file APIs (Zig 0.16 std.os.windows does not bind these; raw
// DWORD ABI with stable documented constant values). std.c.fd_t is
// windows.HANDLE on Windows, so CreateFileW's HANDLE threads through
// the existing fd_t signatures unchanged.
extern "kernel32" fn CreateFileW(lpFileName: [*:0]const u16, dwDesiredAccess: win.DWORD, dwShareMode: win.DWORD, lpSecurityAttributes: ?*win.SECURITY_ATTRIBUTES, dwCreationDisposition: win.DWORD, dwFlagsAndAttributes: win.DWORD, hTemplateFile: ?win.HANDLE) callconv(.winapi) win.HANDLE;
extern "kernel32" fn CreateDirectoryW(lpPathName: [*:0]const u16, lpSecurityAttributes: ?*win.SECURITY_ATTRIBUTES) callconv(.winapi) win.BOOL;
extern "kernel32" fn DeleteFileW(lpFileName: [*:0]const u16) callconv(.winapi) win.BOOL;
extern "kernel32" fn GetFileAttributesW(lpFileName: [*:0]const u16) callconv(.winapi) win.DWORD;
const W_GENERIC_READ: win.DWORD = 0x80000000;
const W_GENERIC_WRITE: win.DWORD = 0x40000000;
const W_FILE_SHARE_READ: win.DWORD = 0x00000001;
const W_CREATE_ALWAYS: win.DWORD = 2;
const W_OPEN_EXISTING: win.DWORD = 3;
const W_FILE_ATTRIBUTE_NORMAL: win.DWORD = 0x80;

/// UTF-8 path -> NUL-terminated UTF-16 in a caller stack buffer.
fn winPathW(buf: []u16, path: []const u8) ![:0]u16 {
    if (path.len + 1 >= buf.len) return error.NameTooLong;
    const n = std.unicode.utf8ToUtf16Le(buf[0 .. buf.len - 1], path) catch return error.NameTooLong;
    buf[n] = 0;
    return buf[0..n :0];
}

pub fn cwdCreateFile(path: []const u8) !std.c.fd_t {
    if (is_windows) {
        var wbuf: [4096]u16 = undefined;
        const wp = try winPathW(&wbuf, path);
        const h = CreateFileW(wp.ptr, W_GENERIC_WRITE, W_FILE_SHARE_READ, null, W_CREATE_ALWAYS, W_FILE_ATTRIBUTE_NORMAL, null);
        if (h == win.INVALID_HANDLE_VALUE) return error.FileNotFound;
        return h;
    }
    var buf: [4096]u8 = undefined;
    if (path.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const fd = std.c.open(buf[0..path.len :0], .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return error.FileNotFound;
    return fd;
}

pub fn cwdReadFile(allocator: std.mem.Allocator, path: []const u8, max_size: usize) ![]u8 {
    if (is_windows) {
        var wbuf: [4096]u16 = undefined;
        const wp = try winPathW(&wbuf, path);
        const h = CreateFileW(wp.ptr, W_GENERIC_READ, W_FILE_SHARE_READ, null, W_OPEN_EXISTING, W_FILE_ATTRIBUTE_NORMAL, null);
        if (h == win.INVALID_HANDLE_VALUE) return error.FileNotFound;
        defer win.CloseHandle(h);
        var result = std.ArrayList(u8).empty;
        var read_buf: [8192]u8 = undefined;
        while (true) {
            var got: win.DWORD = 0;
            const ok = ReadFile(h, &read_buf, @intCast(read_buf.len), &got, null);
            if (!ok.toBool() or got == 0) break;
            const bytes: usize = @intCast(got);
            if (result.items.len + bytes > max_size) return error.FileTooBig;
            try result.appendSlice(allocator, read_buf[0..bytes]);
        }
        return result.toOwnedSlice(allocator);
    }
    var buf: [4096]u8 = undefined;
    if (path.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const fd = std.c.open(buf[0..path.len :0], .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.FileNotFound;
    defer _ = std.c.close(fd);

    var result = std.ArrayList(u8).empty;
    var read_buf: [8192]u8 = undefined;
    while (true) {
        const n = std.c.read(fd, &read_buf, read_buf.len);
        if (n <= 0) break;
        const bytes: usize = @intCast(n);
        if (result.items.len + bytes > max_size) return error.FileTooBig;
        try result.appendSlice(allocator, read_buf[0..bytes]);
    }
    return result.toOwnedSlice(allocator);
}

pub fn cwdWriteFile(path: []const u8, data: []const u8) !void {
    const fd = try cwdCreateFile(path);
    defer fdClose(fd);
    if (is_windows) {
        var sent: usize = 0;
        while (sent < data.len) {
            var wrote: win.DWORD = 0;
            if (!WriteFile(fd, data[sent..].ptr, @intCast(data.len - sent), &wrote, null).toBool()) return error.WriteError;
            if (wrote == 0) return error.WriteError;
            sent += wrote;
        }
        return;
    }
    var sent: usize = 0;
    while (sent < data.len) {
        const n = std.c.write(fd, data[sent..].ptr, data.len - sent);
        if (n <= 0) return error.WriteError;
        sent += @intCast(n);
    }
}

pub fn cwdMakePath(path: []const u8) !void {
    var i: usize = 0;
    while (i < path.len) {
        i += 1;
        while (i < path.len and path[i] != '/') : (i += 1) {}
        if (is_windows) {
            var wbuf: [4096]u16 = undefined;
            const wp = try winPathW(&wbuf, path[0..i]);
            _ = CreateDirectoryW(wp.ptr, null); // ignore "already exists"
        } else {
            var buf: [4096]u8 = undefined;
            if (i > buf.len - 1) return error.NameTooLong;
            @memcpy(buf[0..i], path[0..i]);
            buf[i] = 0;
            _ = std.c.mkdir(buf[0..i :0], 0o755);
        }
    }
}

pub fn cwdDeleteFile(path: []const u8) !void {
    if (is_windows) {
        var wbuf: [4096]u16 = undefined;
        const wp = try winPathW(&wbuf, path);
        if (!DeleteFileW(wp.ptr).toBool()) return error.FileNotFound;
        return;
    }
    var buf: [4096]u8 = undefined;
    if (path.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    if (std.c.unlink(buf[0..path.len :0]) != 0) return error.FileNotFound;
}

pub fn cwdAccess(path: []const u8) bool {
    if (is_windows) {
        var wbuf: [4096]u16 = undefined;
        const wp = winPathW(&wbuf, path) catch return false;
        return GetFileAttributesW(wp.ptr) != win.INVALID_FILE_ATTRIBUTES;
    }
    var buf: [4096]u8 = undefined;
    if (path.len >= buf.len) return false;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return std.c.access(buf[0..path.len :0], std.c.F_OK) == 0;
}

pub fn fdWriteAll(fd: std.c.fd_t, data: []const u8) !void {
    if (is_windows) {
        var sent: usize = 0;
        while (sent < data.len) {
            var wrote: win.DWORD = 0;
            if (!WriteFile(fd, data[sent..].ptr, @intCast(data.len - sent), &wrote, null).toBool()) return error.WriteError;
            if (wrote == 0) return error.WriteError;
            sent += wrote;
        }
        return;
    }
    var sent: usize = 0;
    while (sent < data.len) {
        const n = std.c.write(fd, data[sent..].ptr, data.len - sent);
        if (n <= 0) return error.WriteError;
        sent += @intCast(n);
    }
}

pub fn fdClose(fd: std.c.fd_t) void {
    if (is_windows) {
        win.CloseHandle(fd);
        return;
    }
    _ = std.c.close(fd);
}

// --- Process (replaces removed std.process.Child.init/run) ---

pub extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;

// Win32 process/pipe APIs Zig 0.16 std.os.windows does NOT bind
// (CreateProcessW IS bound at std.os.windows.kernel32). Self-declared,
// same proven pattern as the GetStdHandle externs above. Referenced
// only under the comptime is_windows branch.
extern "kernel32" fn CreatePipe(hReadPipe: *win.HANDLE, hWritePipe: *win.HANDLE, lpPipeAttributes: ?*win.SECURITY_ATTRIBUTES, nSize: win.DWORD) callconv(.winapi) win.BOOL;
extern "kernel32" fn ReadFile(hFile: win.HANDLE, lpBuffer: [*]u8, nNumberOfBytesToRead: win.DWORD, lpNumberOfBytesRead: *win.DWORD, lpOverlapped: ?*anyopaque) callconv(.winapi) win.BOOL;
extern "kernel32" fn WaitForSingleObject(hHandle: win.HANDLE, dwMilliseconds: win.DWORD) callconv(.winapi) win.DWORD;
extern "kernel32" fn GetExitCodeProcess(hProcess: win.HANDLE, lpExitCode: *win.DWORD) callconv(.winapi) win.BOOL;
extern "kernel32" fn SetHandleInformation(hObject: win.HANDLE, dwMask: win.DWORD, dwFlags: win.DWORD) callconv(.winapi) win.BOOL;

/// Append one argv element to a Windows command line using the documented
/// CommandLineToArgvW quoting rules (backslash/quote runs handled).
fn winAppendQuotedArg(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, arg: []const u8) !void {
    var needs_quote = arg.len == 0;
    for (arg) |ch| {
        if (ch == ' ' or ch == '\t' or ch == '\n' or ch == 0x0B or ch == '"') {
            needs_quote = true;
            break;
        }
    }
    if (!needs_quote) {
        try buf.appendSlice(allocator, arg);
        return;
    }
    try buf.append(allocator, '"');
    var backslashes: usize = 0;
    for (arg) |ch| {
        if (ch == '\\') {
            backslashes += 1;
        } else if (ch == '"') {
            for (0..backslashes * 2 + 1) |_| try buf.append(allocator, '\\');
            try buf.append(allocator, '"');
            backslashes = 0;
        } else {
            for (0..backslashes) |_| try buf.append(allocator, '\\');
            backslashes = 0;
            try buf.append(allocator, ch);
        }
    }
    for (0..backslashes * 2) |_| try buf.append(allocator, '\\');
    try buf.append(allocator, '"');
}

pub fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8, max_output: usize) !struct { stdout: []u8, term: i32 } {
    if (is_windows) {
        // Build the Windows command line (single mutable UTF-16 string).
        var cmd: std.ArrayList(u8) = .empty;
        defer cmd.deinit(allocator);
        for (argv, 0..) |arg, i| {
            if (i != 0) try cmd.append(allocator, ' ');
            try winAppendQuotedArg(&cmd, allocator, arg);
        }
        const wcmd = try std.unicode.utf8ToUtf16LeAllocZ(allocator, cmd.items);
        defer allocator.free(wcmd);

        var sa = win.SECURITY_ATTRIBUTES{
            .nLength = @sizeOf(win.SECURITY_ATTRIBUTES),
            .lpSecurityDescriptor = null,
            .bInheritHandle = win.BOOL.TRUE,
        };
        var rd: win.HANDLE = undefined;
        var wr: win.HANDLE = undefined;
        if (!CreatePipe(&rd, &wr, &sa, 0).toBool()) return error.PipeCreateFailed;
        errdefer {
            win.CloseHandle(rd);
            win.CloseHandle(wr);
        }
        // Read end must not be inherited by the child.
        _ = SetHandleInformation(rd, 1, 0); // HANDLE_FLAG_INHERIT = 1

        var si = std.mem.zeroes(win.STARTUPINFOW);
        si.cb = @sizeOf(win.STARTUPINFOW);
        si.dwFlags = win.STARTF_USESTDHANDLES;
        si.hStdInput = null;
        si.hStdOutput = wr;
        si.hStdError = wr;
        var pi = std.mem.zeroes(win.PROCESS.INFORMATION);

        if (!win.kernel32.CreateProcessW(
            null,
            wcmd.ptr,
            null,
            null,
            win.BOOL.TRUE,
            win.CreateProcessFlags{},
            null,
            null,
            &si,
            &pi,
        ).toBool()) return error.ForkFailed;

        // Parent: close the write end so ReadFile sees EOF on child exit.
        win.CloseHandle(wr);
        defer win.CloseHandle(rd);
        defer win.CloseHandle(pi.hProcess);
        defer win.CloseHandle(pi.hThread);

        var result: std.ArrayList(u8) = .empty;
        var read_buf: [4096]u8 = undefined;
        while (true) {
            var got: win.DWORD = 0;
            const ok = ReadFile(rd, &read_buf, @intCast(read_buf.len), &got, null);
            if (!ok.toBool() or got == 0) break;
            const bytes: usize = @intCast(got);
            if (result.items.len + bytes > max_output) break;
            try result.appendSlice(allocator, read_buf[0..bytes]);
        }

        _ = WaitForSingleObject(pi.hProcess, 0xFFFFFFFF); // INFINITE
        var code: win.DWORD = 0;
        _ = GetExitCodeProcess(pi.hProcess, &code);

        return .{
            .stdout = try result.toOwnedSlice(allocator),
            .term = @intCast(code),
        };
    }

    var arg_storage: std.ArrayList([:0]u8) = .empty;
    defer {
        for (arg_storage.items) |arg| allocator.free(arg);
        arg_storage.deinit(allocator);
    }
    for (argv) |arg| {
        const duped = try allocator.allocSentinel(u8, arg.len, 0);
        @memcpy(duped[0..arg.len], arg);
        try arg_storage.append(allocator, duped);
    }

    const c_argv = try allocator.alloc(?[*:0]const u8, arg_storage.items.len + 1);
    defer allocator.free(c_argv);
    for (arg_storage.items, 0..) |arg, i| {
        c_argv[i] = arg.ptr;
    }
    c_argv[arg_storage.items.len] = null;

    var pipe_fds: [2]std.c.fd_t = undefined;
    if (std.c.pipe(&pipe_fds) != 0) return error.PipeCreateFailed;

    const pid = std.c.fork();
    if (pid < 0) return error.ForkFailed;

    if (pid == 0) {
        // Child: redirect stdout to pipe write end
        _ = std.c.close(pipe_fds[0]);
        _ = std.c.dup2(pipe_fds[1], 1);
        _ = std.c.dup2(pipe_fds[1], 2); // also capture stderr
        _ = std.c.close(pipe_fds[1]);

        _ = execvp(c_argv[0].?, @ptrCast(c_argv.ptr));
        std.c._exit(127);
    }

    // Parent: read from pipe
    _ = std.c.close(pipe_fds[1]);
    defer _ = std.c.close(pipe_fds[0]);

    var result = std.ArrayList(u8).empty;
    var read_buf: [4096]u8 = undefined;
    while (true) {
        const n = std.c.read(pipe_fds[0], &read_buf, read_buf.len);
        if (n <= 0) break;
        const bytes: usize = @intCast(n);
        if (result.items.len + bytes > max_output) break;
        try result.appendSlice(allocator, read_buf[0..bytes]);
    }

    var status: c_int = 0;
    _ = std.c.waitpid(pid, &status, 0);

    return .{
        .stdout = try result.toOwnedSlice(allocator),
        .term = @intCast(status),
    };
}

// --- Networking (replaces removed std.net) ---

const c = std.c;
const fd_t = std.c.fd_t;
const native_endian = @import("builtin").cpu.arch.endian();

fn htons(val: u16) u16 {
    return if (native_endian == .little) @byteSwap(val) else val;
}

fn ntohs(val: u16) u16 {
    return htons(val);
}

/// Try to connect to 127.0.0.1:port. Returns true if connection succeeded.
pub fn isPortInUse(port: u16) bool {
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (fd < 0) return false;
    defer _ = c.close(fd);

    var addr = c.sockaddr.in{
        .port = htons(port),
        .addr = 0x0100007F, // 127.0.0.1 in network byte order
    };

    const rc = c.connect(fd, @ptrCast(&addr), @sizeOf(c.sockaddr.in));
    return rc == 0;
}

/// A minimal TCP stream wrapping a C socket fd.
pub const TcpStream = struct {
    fd: fd_t,

    pub fn close(self: TcpStream) void {
        _ = c.close(self.fd);
    }

    pub fn writeAll(self: TcpStream, data: []const u8) !void {
        var sent: usize = 0;
        while (sent < data.len) {
            const n = c.write(self.fd, data[sent..].ptr, data.len - sent);
            if (n <= 0) return error.BrokenPipe;
            sent += @intCast(n);
        }
    }

    pub fn read(self: TcpStream, buf: []u8) !usize {
        const n = c.read(self.fd, buf.ptr, buf.len);
        if (n < 0) return error.ConnectionResetByPeer;
        return @intCast(n);
    }

    pub fn write(self: TcpStream, data: []const u8) !usize {
        const n = c.write(self.fd, data.ptr, data.len);
        if (n <= 0) return error.BrokenPipe;
        return @intCast(n);
    }

    pub fn setSockOpt(self: TcpStream, level: i32, optname: u32, optval: []const u8) void {
        _ = c.setsockopt(self.fd, level, optname, optval.ptr, @intCast(optval.len));
    }
};

/// Connect to 127.0.0.1:port via TCP. Returns a TcpStream.
pub fn tcpConnectToIp4(port: u16) !TcpStream {
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketCreateFailed;

    var addr = c.sockaddr.in{
        .port = htons(port),
        .addr = 0x0100007F, // 127.0.0.1
    };

    const rc = c.connect(fd, @ptrCast(&addr), @sizeOf(c.sockaddr.in));
    if (rc != 0) {
        _ = c.close(fd);
        return error.ConnectionRefused;
    }
    return .{ .fd = fd };
}

/// Connect to host:port via TCP. For now supports "127.0.0.1" only
/// (which covers all our use cases). Falls back to loopback for "localhost".
pub fn tcpConnectToHost(host: []const u8, port: u16) !TcpStream {
    _ = host; // all callers use 127.0.0.1 or localhost
    return tcpConnectToIp4(port);
}

/// A minimal TCP server that binds and listens.
pub const TcpServer = struct {
    fd: fd_t,

    pub const Connection = struct {
        stream: TcpStream,
    };

    pub fn accept(self: TcpServer) !Connection {
        const client_fd = c.accept(self.fd, null, null);
        if (client_fd < 0) return error.AcceptFailed;
        return .{ .stream = .{ .fd = client_fd } };
    }

    pub fn deinit(self: *TcpServer) void {
        _ = c.close(self.fd);
    }
};

/// Bind and listen on 127.0.0.1:port.
pub fn tcpListen(port: u16) !TcpServer {
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketCreateFailed;
    errdefer _ = c.close(fd);

    // SO_REUSEADDR
    const one: c_int = 1;
    _ = c.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(c_int));

    var addr = c.sockaddr.in{
        .port = htons(port),
        .addr = 0x0100007F, // 127.0.0.1
    };

    if (c.bind(fd, @ptrCast(&addr), @sizeOf(c.sockaddr.in)) != 0) {
        return error.AddressInUse;
    }
    if (c.listen(fd, 1) != 0) {
        return error.ListenFailed;
    }
    return .{ .fd = fd };
}
