// network.zig — outbound HTTP for the bundle replay sandbox.
//
// Phase 1 implementation: subprocess to `curl_chrome131` (curl-impersonate-chrome).
// Trade-off: ~5ms per-call overhead vs ~0ms for libcurl FFI, but zero linker
// complexity. The Client interface is stable, so a future libcurl-impersonate
// FFI backend can drop in without changing runtime.zig.
//
// Curl-impersonate ships per-Chrome-version binaries on PATH after
//   brew install lwthiker/taps/curl-impersonate
// On Linux: `apt install curl-impersonate` or vendor the static binary.
//
// The binary name is derived from `impersonate_profile` in Client.Options.

const std = @import("std");
const compat = @import("../compat.zig");

pub const Header = struct {
    name: []const u8,
    value: []const u8,

    pub fn dupe(self: Header, allocator: std.mem.Allocator) !Header {
        return .{
            .name = try allocator.dupe(u8, self.name),
            .value = try allocator.dupe(u8, self.value),
        };
    }
};

pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    domain: []const u8 = "",
    path: []const u8 = "/",
    expires: i64 = 0, // 0 = session
    secure: bool = false,
    http_only: bool = false,
    same_site: []const u8 = "",
};

pub const CookieJar = struct {
    allocator: std.mem.Allocator,
    cookies: std.ArrayList(Cookie),
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator) CookieJar {
        return .{
            .allocator = allocator,
            .cookies = .empty,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *CookieJar) void {
        self.cookies.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Parse a Set-Cookie header value and merge into the jar. The format is:
    ///   name=value; Path=/; Domain=.x.com; Expires=...; Secure; HttpOnly; SameSite=Lax
    pub fn applySetCookie(self: *CookieJar, default_host: []const u8, header_value: []const u8) !void {
        const a = self.arena.allocator();

        var iter = std.mem.splitScalar(u8, header_value, ';');
        const first = std.mem.trim(u8, iter.first(), " \t");
        const eq = std.mem.indexOfScalar(u8, first, '=') orelse return;
        const name = std.mem.trim(u8, first[0..eq], " \t");
        const value = std.mem.trim(u8, first[eq + 1 ..], " \t");
        if (name.len == 0) return;

        var cookie = Cookie{
            .name = try a.dupe(u8, name),
            .value = try a.dupe(u8, value),
            .domain = try a.dupe(u8, default_host),
            .path = "/",
        };

        while (iter.next()) |raw_attr| {
            const attr = std.mem.trim(u8, raw_attr, " \t");
            if (attr.len == 0) continue;
            const ae = std.mem.indexOfScalar(u8, attr, '=');
            if (ae) |aep| {
                const k = std.mem.trim(u8, attr[0..aep], " \t");
                const v = std.mem.trim(u8, attr[aep + 1 ..], " \t");
                if (std.ascii.eqlIgnoreCase(k, "domain")) {
                    cookie.domain = try a.dupe(u8, std.mem.trimStart(u8, v, "."));
                } else if (std.ascii.eqlIgnoreCase(k, "path")) {
                    cookie.path = try a.dupe(u8, v);
                } else if (std.ascii.eqlIgnoreCase(k, "max-age")) {
                    const ma = std.fmt.parseInt(i64, v, 10) catch 0;
                    if (ma > 0) cookie.expires = compat.timestampSeconds() + ma;
                } else if (std.ascii.eqlIgnoreCase(k, "samesite")) {
                    cookie.same_site = try a.dupe(u8, v);
                }
                // Expires (HTTP-date) intentionally ignored — Max-Age takes precedence
                // and most session cookies use Max-Age in modern stacks.
            } else {
                if (std.ascii.eqlIgnoreCase(attr, "secure")) cookie.secure = true;
                if (std.ascii.eqlIgnoreCase(attr, "httponly")) cookie.http_only = true;
            }
        }

        // Replace existing cookie with same name+domain+path, else append.
        var i: usize = 0;
        while (i < self.cookies.items.len) : (i += 1) {
            const c = self.cookies.items[i];
            if (std.mem.eql(u8, c.name, cookie.name) and
                std.mem.eql(u8, c.domain, cookie.domain) and
                std.mem.eql(u8, c.path, cookie.path))
            {
                self.cookies.items[i] = cookie;
                return;
            }
        }
        try self.cookies.append(self.allocator, cookie);
    }

    /// Write `name1=value1; name2=value2` for cookies matching the given host.
    pub fn formatHeaderValue(
        self: *CookieJar,
        scratch: std.mem.Allocator,
        host: []const u8,
        out: *std.ArrayList(u8),
    ) !void {
        _ = scratch;
        const now = compat.timestampSeconds();
        var first_written = true;
        for (self.cookies.items) |c| {
            if (c.expires > 0 and c.expires < now) continue;
            if (!hostMatchesDomain(host, c.domain)) continue;
            if (!first_written) try out.appendSlice(self.allocator, "; ");
            try out.appendSlice(self.allocator, c.name);
            try out.append(self.allocator, '=');
            try out.appendSlice(self.allocator, c.value);
            first_written = false;
        }
    }

    pub fn snapshot(self: *CookieJar, allocator: std.mem.Allocator) ![]Cookie {
        const out = try allocator.alloc(Cookie, self.cookies.items.len);
        for (self.cookies.items, 0..) |c, i| {
            out[i] = .{
                .name = try allocator.dupe(u8, c.name),
                .value = try allocator.dupe(u8, c.value),
                .domain = try allocator.dupe(u8, c.domain),
                .path = try allocator.dupe(u8, c.path),
                .expires = c.expires,
                .secure = c.secure,
                .http_only = c.http_only,
                .same_site = try allocator.dupe(u8, c.same_site),
            };
        }
        return out;
    }
};

fn hostMatchesDomain(host: []const u8, domain: []const u8) bool {
    if (domain.len == 0) return true;
    if (std.mem.eql(u8, host, domain)) return true;
    if (host.len > domain.len + 1 and host[host.len - domain.len - 1] == '.' and
        std.mem.endsWith(u8, host, domain)) return true;
    return false;
}

pub const Client = struct {
    pub const Options = struct {
        impersonate_profile: []const u8 = "chrome131",
        target_origin: []const u8 = "",
        max_response_bytes: usize = 16 * 1024 * 1024,
        connect_timeout_s: u32 = 10,
        max_total_s: u32 = 30,
    };

    allocator: std.mem.Allocator,
    options: Options,

    pub fn init(allocator: std.mem.Allocator, options: Options) Client {
        return .{ .allocator = allocator, .options = options };
    }

    pub fn deinit(self: *Client) void {
        _ = self;
    }

    pub const SendArgs = struct {
        method: []const u8,
        url: []const u8,
        headers_json: []const u8 = "",
        body: ?[]const u8 = null,
        cookie_jar: *CookieJar,
    };

    pub fn send(self: *Client, args: SendArgs) !Response {
        return runCurlImpersonate(self, args);
    }

    /// Resolve the curl binary to invoke.
    ///   1. $UNBROWSE_CURL_IMPERSONATE — explicit override (full path or name)
    ///   2. curl_<profile>           — curl-impersonate naming convention
    fn binaryName(self: *Client, buf: []u8) ![]const u8 {
        if (compat.getenv("UNBROWSE_CURL_IMPERSONATE")) |v| {
            return std.fmt.bufPrint(buf, "{s}", .{v});
        }
        return std.fmt.bufPrint(buf, "curl_{s}", .{self.options.impersonate_profile});
    }
};

pub const Response = struct {
    allocator: std.mem.Allocator,
    status: u16,
    status_text: []const u8,
    final_url: []const u8,
    headers: []Header,
    body: []const u8,
    redirected: bool,

    pub fn deinit(self: *Response) void {
        const a = self.allocator;
        for (self.headers) |h| {
            a.free(h.name);
            a.free(h.value);
        }
        a.free(self.headers);
        a.free(self.status_text);
        a.free(self.final_url);
        a.free(self.body);
    }
};

fn runCurlImpersonate(client: *Client, args: Client.SendArgs) !Response {
    const a = client.allocator;

    // Resolve binary name.
    var bin_buf: [64]u8 = undefined;
    const bin_name = try client.binaryName(&bin_buf);

    // If a body is provided, write it to a tempfile and reference via @path.
    // If a body is provided, write it to a tempfile and reference via @path.
    var body_path: ?[:0]u8 = null;
    defer if (body_path) |p| {
        _ = std.c.unlink(p.ptr);
        a.free(p);
    };
    if (args.body) |b| {
        if (b.len > 0) {
            const ts: i64 = compat.milliTimestamp();
            const path = try std.fmt.allocPrintSentinel(a, "/tmp/kuri-sandbox-{d}-{x}.body", .{ ts, std.hash.Wyhash.hash(0, b) }, 0);
            const fd = std.c.open(path.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
            if (fd < 0) {
                a.free(path);
                return error.TempFileOpenFailed;
            }
            defer _ = std.c.close(fd);
            _ = std.c.write(fd, b.ptr, b.len);
            body_path = path;
        }
    }

    // Build argv.
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(a);

    try argv.append(a, bin_name);
    try argv.append(a, "--silent");
    try argv.append(a, "--include");
    try argv.append(a, "--location");
    try argv.append(a, "--max-redirs");
    try argv.append(a, "10");

    var ct_buf: [16]u8 = undefined;
    const ct = try std.fmt.bufPrint(&ct_buf, "{d}", .{client.options.connect_timeout_s});
    try argv.append(a, "--connect-timeout");
    try argv.append(a, ct);

    var mt_buf: [16]u8 = undefined;
    const mt = try std.fmt.bufPrint(&mt_buf, "{d}", .{client.options.max_total_s});
    try argv.append(a, "--max-time");
    try argv.append(a, mt);

    // Write the response (with --include headers prefix) to a tempfile so we
    // don't need stdout pipe collection (which OOMs in std.process.run on macOS).
    const out_path = try std.fmt.allocPrintSentinel(a, "/tmp/kuri-sandbox-{d}-{x}.out", .{ compat.milliTimestamp(), std.hash.Wyhash.hash(1, args.url) }, 0);
    defer {
        _ = std.c.unlink(out_path.ptr);
        a.free(out_path);
    }
    try argv.append(a, "--output");
    try argv.append(a, out_path);
    try argv.append(a, "--write-out");
    try argv.append(a, "\n%{url_effective}");
    try argv.append(a, "--request");
    try argv.append(a, args.method);

    // Request headers.
    var header_storage: std.ArrayList([]u8) = .empty;
    defer {
        for (header_storage.items) |s| a.free(s);
        header_storage.deinit(a);
    }
    if (args.headers_json.len > 0) {
        try parseHeadersJson(a, args.headers_json, &header_storage, &argv);
    }

    // Cookie header.
    const url_parsed = try parseUrl(args.url);
    var cookie_buf: std.ArrayList(u8) = .empty;
    defer cookie_buf.deinit(a);
    try args.cookie_jar.formatHeaderValue(a, url_parsed.host, &cookie_buf);
    if (cookie_buf.items.len > 0) {
        const cookie_arg = try std.fmt.allocPrint(a, "Cookie: {s}", .{cookie_buf.items});
        try header_storage.append(a, cookie_arg);
        try argv.append(a, "--header");
        try argv.append(a, cookie_arg);
    }


    // Body via @path (curl reads from disk to avoid stdin pipe complexity).
    if (body_path) |p| {
        const data_arg = try std.fmt.allocPrint(a, "@{s}", .{p});
        try argv.append(a, "--data-binary");
        try argv.append(a, data_arg);
    }
    try argv.append(a, args.url);


    // Build argv_z (null-terminated C strings + null sentinel) for execvp.
    var argv_storage: std.ArrayList([:0]u8) = .empty;
    defer {
        for (argv_storage.items) |arg| a.free(arg);
        argv_storage.deinit(a);
    }
    for (argv.items) |arg| {
        const arg_z = try a.allocSentinel(u8, arg.len, 0);
        @memcpy(arg_z[0..arg.len], arg);
        try argv_storage.append(a, arg_z);
    }
    const argv_z = try a.alloc(?[*:0]const u8, argv_storage.items.len + 1);
    defer a.free(argv_z);
    for (argv_storage.items, 0..) |arg, i| argv_z[i] = arg.ptr;
    argv_z[argv_storage.items.len] = null;

    // fork + execvp (matches kuri/chrome/launcher.zig pattern; std.process.spawn
    // OOMs on the io vtable kuri uses).
    const pid = std.c.fork();
    if (pid < 0) {
        std.log.warn("[sandbox-net] fork failed", .{});
        return error.CurlFailed;
    }
    if (pid == 0) {
        // Child: redirect stdout/stderr to /dev/null then exec.
        const devnull = std.c.open("/dev/null", .{ .ACCMODE = .WRONLY }, @as(c_uint, 0));
        if (devnull >= 0) {
            _ = std.c.dup2(devnull, 1);
            _ = std.c.dup2(devnull, 2);
            _ = std.c.close(devnull);
        }
        _ = compat.execvp(argv_z[0].?, @ptrCast(argv_z.ptr));
        std.c.exit(127);
    }
    // Parent: waitpid for completion.
    var status: c_int = 0;
    _ = std.c.waitpid(pid, &status, 0);
    const exit_code: c_int = (status >> 8) & 0xff;
    if (exit_code != 0) {
        // Distinguish "binary not found" (exit 127) from "curl ran but failed".
        if (exit_code == 127) {
            std.log.warn(
                "[sandbox-net] curl binary '{s}' not found on PATH. " ++
                "Install curl-impersonate (brew install lwthiker/taps/curl-impersonate) or " ++
                "set UNBROWSE_CURL_IMPERSONATE=/path/to/binary.",
                .{bin_name},
            );
            return error.CurlBinaryMissing;
        }
        std.log.warn("[sandbox-net] curl exit {d}", .{exit_code});
        return error.CurlFailed;
    }

    // Read the response from the tempfile.
    const out_fd = std.c.open(out_path.ptr, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (out_fd < 0) {
        std.log.warn("[sandbox-net] cannot read curl output {s}", .{out_path});
        return error.CurlFailed;
    }
    defer _ = std.c.close(out_fd);

    var raw = std.ArrayList(u8).empty;
    defer raw.deinit(a);
    var read_buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = std.c.read(out_fd, &read_buf, read_buf.len);
        if (n <= 0) break;
        try raw.appendSlice(a, read_buf[0..@intCast(n)]);
        if (raw.items.len > client.options.max_response_bytes) return error.ResponseTooLarge;
    }

    return parseCurlOutput(a, raw.items, args.url, args.cookie_jar, url_parsed.host);
}

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    is_https: bool,
};

fn parseUrl(url: []const u8) !ParsedUrl {
    var rest = url;
    var is_https = false;
    if (std.mem.startsWith(u8, rest, "https://")) {
        rest = rest[8..]; is_https = true;
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest[7..];
    } else return error.BadScheme;
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..slash];
    const colon = std.mem.indexOfScalar(u8, authority, ':');
    if (colon) |c| {
        const port = std.fmt.parseInt(u16, authority[c + 1 ..], 10) catch (if (is_https) @as(u16, 443) else 80);
        return .{ .host = authority[0..c], .port = port, .is_https = is_https };
    }
    return .{ .host = authority, .port = if (is_https) 443 else 80, .is_https = is_https };
}

fn parseHeadersJson(
    allocator: std.mem.Allocator,
    json_str: []const u8,
    storage: *std.ArrayList([]u8),
    argv: *std.ArrayList([]const u8),
) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;
    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        const k = entry.key_ptr.*;
        const v_node = entry.value_ptr.*;
        const v: []const u8 = switch (v_node) {
            .string => |s| s,
            else => continue,
        };
        const arg = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ k, v });
        try storage.append(allocator, arg);
        try argv.append(allocator, "--header");
        try argv.append(allocator, arg);
    }
}

// (collectAll removed — std.process.run handles stdout/stderr collection)

/// Parse curl --include output (multiple header blocks if redirected, then body,
/// then trailing `\n%{url_effective}` from --write-out).
fn parseCurlOutput(
    a: std.mem.Allocator,
    raw: []const u8,
    request_url: []const u8,
    jar: *CookieJar,
    request_host: []const u8,
) !Response {
    // Strip the trailing url_effective line (added by --write-out).
    // It's the last line after the body, preceded by `\n`.
    var body_end = raw.len;
    var final_url: []const u8 = request_url;
    if (std.mem.lastIndexOfScalar(u8, raw, '\n')) |last_nl| {
        const after = std.mem.trim(u8, raw[last_nl + 1 ..], " \t\r\n");
        if (std.mem.startsWith(u8, after, "http://") or std.mem.startsWith(u8, after, "https://")) {
            final_url = after;
            body_end = last_nl;
        }
    }
    const trimmed = raw[0..body_end];

    // Split header blocks (one per redirect hop) from body.
    // Each block ends with \r\n\r\n. The LAST block before the body is what we want.
    var search_idx: usize = 0;
    var last_split: usize = 0;
    while (std.mem.indexOfPos(u8, trimmed, search_idx, "\r\n\r\n")) |pos| {
        // If the next block starts with "HTTP/", it's another header block (redirect).
        const next_start = pos + 4;
        last_split = next_start;
        if (next_start >= trimmed.len) break;
        if (std.mem.startsWith(u8, trimmed[next_start..], "HTTP/")) {
            search_idx = next_start;
            continue;
        }
        break;
    }
    const header_block = trimmed[0..if (last_split > 0) last_split - 4 else trimmed.len];
    const body = if (last_split > 0 and last_split <= trimmed.len) trimmed[last_split..] else "";

    // Parse status line + headers.
    var status: u16 = 0;
    var status_text: []const u8 = "";
    var headers_list = std.ArrayList(Header).empty;
    defer headers_list.deinit(a);
    errdefer for (headers_list.items) |h| { a.free(h.name); a.free(h.value); };

    var redirected = false;
    var line_iter = std.mem.splitSequence(u8, header_block, "\r\n");
    var first_line = true;
    while (line_iter.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "HTTP/")) {
            if (status != 0) redirected = true;
            const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
            const after = line[sp1 + 1 ..];
            const sp2 = std.mem.indexOfScalar(u8, after, ' ');
            const status_str = if (sp2) |i| after[0..i] else after;
            status = std.fmt.parseInt(u16, status_str, 10) catch 0;
            status_text = if (sp2) |i| after[i + 1 ..] else "";
            first_line = false;
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (name.len == 0) continue;

        if (std.ascii.eqlIgnoreCase(name, "set-cookie")) {
            jar.applySetCookie(request_host, value) catch {};
        }

        try headers_list.append(a, .{
            .name = try a.dupe(u8, name),
            .value = try a.dupe(u8, value),
        });
    }

    return .{
        .allocator = a,
        .status = status,
        .status_text = try a.dupe(u8, status_text),
        .final_url = try a.dupe(u8, final_url),
        .headers = try headers_list.toOwnedSlice(a),
        .body = try a.dupe(u8, body),
        .redirected = redirected,
    };
}

test "cookie jar set/get roundtrip" {
    const a = std.testing.allocator;
    var jar = CookieJar.init(a);
    defer jar.deinit();

    try jar.applySetCookie("example.com", "session=abc123; Path=/; Domain=.example.com; Secure; HttpOnly; SameSite=Lax");
    try jar.applySetCookie("example.com", "csrf=tok9; Path=/");

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(a);
    try jar.formatHeaderValue(a, "www.example.com", &buf);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "session=abc123") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "csrf=tok9") != null);
}

test "host matches domain" {
    try std.testing.expect(hostMatchesDomain("example.com", "example.com"));
    try std.testing.expect(hostMatchesDomain("www.example.com", "example.com"));
    try std.testing.expect(!hostMatchesDomain("example.com", "other.com"));
    try std.testing.expect(!hostMatchesDomain("evilexample.com", "example.com"));
}
