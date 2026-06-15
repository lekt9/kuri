// curl_lib.zig — Zig FFI over statically-linked libcurl-impersonate.
//
// libcurl-impersonate is built into the kuri binary at link time
// (see vendor/curl-impersonate/<arch>-<os>/libcurl-impersonate.a). This file
// is the ONLY place the C API surface is exposed; everything else in the
// codebase calls into Zig-friendly types here.
//
// Key addition over standard libcurl: curl_easy_impersonate(handle, target,
// default_headers) which configures the TLS handshake, HTTP/2 settings,
// and default header set to mimic a specific Chrome/Firefox/Safari version.
//
// API used:
//   curl_easy_init/cleanup    — handle lifecycle
//   curl_easy_setopt          — request configuration
//   curl_easy_impersonate     — the impersonation knob (chrome131, etc.)
//   curl_easy_perform         — synchronous request
//   curl_easy_getinfo         — extract response status, final URL, etc.
//   curl_slist_append/free_all — header list management
//
// Cookie jar: we don't use libcurl's COOKIEJAR (per-process file). Instead
// we drive cookies through CURLOPT_COOKIE for outgoing and parse Set-Cookie
// from response headers ourselves into the existing CookieJar in network.zig.
// Same lifecycle, no on-disk file, no cross-request leaking.

const std = @import("std");
const compat = @import("../compat.zig");

// ───────────────────────────────────────────────────────────────────────────
// C declarations
// ───────────────────────────────────────────────────────────────────────────
const c = struct {
    const CURLcode = c_int;
    const CURLINFO = c_int;
    const CURLoption = c_int;
    const CURL = anyopaque;
    const curl_slist = extern struct {
        data: ?[*:0]const u8,
        next: ?*curl_slist,
    };

    // CURLcode constants (subset).
    const CURLE_OK: CURLcode = 0;

    // CURLINFO constants. Values from curl/curl.h.
    const CURLINFO_RESPONSE_CODE: CURLINFO = 0x200002; // long
    const CURLINFO_EFFECTIVE_URL: CURLINFO = 0x100001; // char*
    const CURLINFO_REDIRECT_COUNT: CURLINFO = 0x20000C; // long

    // CURLoption constants — see curl/curl.h. Values are stable.
    const CURLOPT_URL: CURLoption = 10002;
    const CURLOPT_HTTPHEADER: CURLoption = 10023;
    const CURLOPT_WRITEFUNCTION: CURLoption = 20011;
    const CURLOPT_WRITEDATA: CURLoption = 10001;
    const CURLOPT_HEADERFUNCTION: CURLoption = 20079;
    const CURLOPT_HEADERDATA: CURLoption = 10029;
    const CURLOPT_CUSTOMREQUEST: CURLoption = 10036;
    const CURLOPT_POSTFIELDS: CURLoption = 10015;
    const CURLOPT_POSTFIELDSIZE_LARGE: CURLoption = 30120;
    const CURLOPT_FOLLOWLOCATION: CURLoption = 52;
    const CURLOPT_MAXREDIRS: CURLoption = 68;
    const CURLOPT_TIMEOUT_MS: CURLoption = 155;
    const CURLOPT_CONNECTTIMEOUT_MS: CURLoption = 156;
    const CURLOPT_NOSIGNAL: CURLoption = 99;
    const CURLOPT_COOKIE: CURLoption = 10022;
    const CURLOPT_USERAGENT: CURLoption = 10018;
    const CURLOPT_ACCEPT_ENCODING: CURLoption = 10102;
    const CURLOPT_PROXY: CURLoption = 10004;

    extern "c" fn curl_easy_init() ?*CURL;
    extern "c" fn curl_easy_cleanup(handle: *CURL) void;
    extern "c" fn curl_easy_perform(handle: *CURL) CURLcode;
    extern "c" fn curl_easy_setopt(handle: *CURL, option: CURLoption, ...) CURLcode;
    extern "c" fn curl_easy_getinfo(handle: *CURL, info: CURLINFO, ...) CURLcode;
    extern "c" fn curl_easy_strerror(code: CURLcode) [*:0]const u8;

    extern "c" fn curl_slist_append(list: ?*curl_slist, str: [*:0]const u8) ?*curl_slist;
    extern "c" fn curl_slist_free_all(list: ?*curl_slist) void;

    /// libcurl-impersonate addition: configure TLS handshake + HTTP/2 settings
    /// + default header set to mimic the named browser target.
    /// `target` examples: "chrome131", "chrome120", "firefox133", "safari17_0".
    /// `default_headers`: 1 to add the browser's default headers, 0 to skip.
    extern "c" fn curl_easy_impersonate(handle: *CURL, target: [*:0]const u8, default_headers: c_int) CURLcode;
};

// ───────────────────────────────────────────────────────────────────────────
// Public types
// ───────────────────────────────────────────────────────────────────────────

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: []const u8,
    url: []const u8,
    headers: []const Header = &.{},
    body: ?[]const u8 = null,
    cookie_header: []const u8 = "", // pre-formatted "name=val; name=val"
    impersonate: []const u8 = "chrome131",
    connect_timeout_ms: u32 = 10_000,
    total_timeout_ms: u32 = 30_000,
    follow_redirects: bool = true,
    max_redirects: u32 = 10,
    /// Optional proxy URL — e.g. "http://user:pass@host:port" or "socks5://host:port".
    /// libcurl parses user:pass from the URL, so no separate USERPWD setopt needed.
    proxy: ?[]const u8 = null,
};

pub const Response = struct {
    allocator: std.mem.Allocator,
    status: u16,
    final_url: []const u8,
    redirect_count: u32,
    /// Raw response headers buffer. Lines separated by `\r\n`. Includes the
    /// HTTP status line. Caller parses for Set-Cookie etc.
    raw_headers: []const u8,
    body: []const u8,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.final_url);
        self.allocator.free(self.raw_headers);
        self.allocator.free(self.body);
    }
};

pub const Error = error{
    CurlInitFailed,
    CurlSetoptFailed,
    CurlImpersonateFailed,
    CurlPerformFailed,
    OutOfMemory,
    BadHeader,
    NotImplementedOnWindows,
};

// ───────────────────────────────────────────────────────────────────────────
// Pure-Zig fallback (Windows): std.http.Client
// ───────────────────────────────────────────────────────────────────────────
//
// libcurl-impersonate is not linked on the x86_64-windows-gnu target (the
// vendored archives are MSVC-ABI). Rather than fail every `fetch`, we run the
// request through Zig's std.http.Client. It produces the same Response shape
// (status + raw CRLF header block + decompressed body), so network.zig's
// status/Set-Cookie parsing works unchanged. The one capability lost vs the
// curl path is browser TLS impersonation — anti-bot sites still escalate to
// CDP browse, which uses a different path entirely.

const default_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ++
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

fn performStd(allocator: std.mem.Allocator, req: Request) Error!Response {
    return performStdInner(allocator, req) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.CurlPerformFailed,
    };
}

fn performStdInner(allocator: std.mem.Allocator, req: Request) !Response {
    var client: std.http.Client = .{
        .allocator = allocator,
        .io = std.Io.Threaded.global_single_threaded.io(),
    };
    defer client.deinit();

    // Outgoing headers: caller headers + cookie header + a default User-Agent
    // when the caller did not supply one.
    var extra: std.ArrayList(std.http.Header) = .empty;
    defer extra.deinit(allocator);
    var has_ua = false;
    for (req.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "user-agent")) has_ua = true;
        try extra.append(allocator, .{ .name = h.name, .value = h.value });
    }
    if (!has_ua) try extra.append(allocator, .{ .name = "User-Agent", .value = default_ua });
    if (req.cookie_header.len > 0) {
        try extra.append(allocator, .{ .name = "Cookie", .value = req.cookie_header });
    }

    const method = std.meta.stringToEnum(std.http.Method, req.method) orelse .GET;
    const uri = try std.Uri.parse(req.url);

    var redirect_buf: [16 * 1024]u8 = undefined;
    var http_req = try client.request(method, uri, .{
        // Follow redirects internally (parity with libcurl FOLLOWLOCATION); the
        // final response head/body is what network.zig parses.
        .redirect_behavior = @enumFromInt(@as(u16, @intCast(req.max_redirects))),
        .extra_headers = extra.items,
    });
    defer http_req.deinit();

    if (req.body) |b| {
        const body_mut = try allocator.dupe(u8, b);
        defer allocator.free(body_mut);
        try http_req.sendBodyComplete(body_mut);
    } else {
        try http_req.sendBodiless();
    }

    var response = try http_req.receiveHead(&redirect_buf);
    const status_code: u16 = @intFromEnum(response.head.status);

    // head.bytes is the raw CRLF header block including the HTTP status line —
    // exactly the format network.zig expects in Response.raw_headers.
    const raw_headers = try allocator.dupe(u8, response.head.bytes);
    errdefer allocator.free(raw_headers);

    const final_url = try allocator.dupe(u8, req.url);
    errdefer allocator.free(final_url);

    var body_buf: std.ArrayList(u8) = .empty;
    errdefer body_buf.deinit(allocator);
    var transfer_buf: [8192]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    const reader = response.readerDecompressing(&transfer_buf, &decompress, &decompress_buf);
    try reader.appendRemainingUnlimited(allocator, &body_buf);

    return .{
        .allocator = allocator,
        .status = status_code,
        .final_url = final_url,
        .redirect_count = 0,
        .raw_headers = raw_headers,
        .body = try body_buf.toOwnedSlice(allocator),
    };
}

// ───────────────────────────────────────────────────────────────────────────
// Public entry point
// ───────────────────────────────────────────────────────────────────────────

/// Synchronous request with full Chrome (or Firefox/Safari) impersonation.
/// Caller owns the returned Response and must call `deinit`.
pub fn perform(allocator: std.mem.Allocator, req: Request) Error!Response {
    // Windows: libcurl-impersonate is not linked (the vendored .lib archives are
    // MSVC-ABI, incompatible with the x86_64-windows-gnu cross-target). Route through
    // the pure-Zig std.http.Client path instead of failing, so `fetch` works on
    // Windows. Returning before any curl extern keeps those symbols unreferenced, so
    // the binary still links. The only capability lost vs the curl path is browser
    // TLS impersonation; anti-bot sites still escalate to CDP browse (go/snap/close),
    // which does not use this path.
    if (comptime @import("builtin").os.tag == .windows) return performStd(allocator, req);
    const easy = c.curl_easy_init() orelse return error.CurlInitFailed;
    defer c.curl_easy_cleanup(easy);

    // Buffers for response capture. We append into ArrayLists from the C
    // callbacks, then move ownership into Response on success.
    var body_buf: std.ArrayList(u8) = .empty;
    errdefer body_buf.deinit(allocator);
    var hdr_buf: std.ArrayList(u8) = .empty;
    errdefer hdr_buf.deinit(allocator);

    var ctx: CallbackCtx = .{
        .allocator = allocator,
        .body = &body_buf,
        .headers = &hdr_buf,
    };

    // 1. Impersonate target (sets TLS + HTTP/2 + default headers).
    const impersonate_z = try allocator.dupeZ(u8, req.impersonate);
    defer allocator.free(impersonate_z);
    if (c.curl_easy_impersonate(easy, impersonate_z.ptr, 1) != c.CURLE_OK) {
        return error.CurlImpersonateFailed;
    }

    // 2. URL.
    const url_z = try allocator.dupeZ(u8, req.url);
    defer allocator.free(url_z);
    try setoptCheck(easy, c.CURLOPT_URL, url_z.ptr);

    // 2b. Proxy (optional). libcurl honors user:pass embedded in the URL,
    // so a single setopt is sufficient for "http://user:pass@host:port".
    var proxy_z: ?[:0]u8 = null;
    defer if (proxy_z) |p| allocator.free(p);
    if (req.proxy) |p| {
        proxy_z = try allocator.dupeZ(u8, p);
        try setoptCheck(easy, c.CURLOPT_PROXY, proxy_z.?.ptr);
    }
    // 3. Method.
    const method_z = try allocator.dupeZ(u8, req.method);
    defer allocator.free(method_z);
    try setoptCheck(easy, c.CURLOPT_CUSTOMREQUEST, method_z.ptr);

    // 4. Body.
    var body_owned: ?[:0]u8 = null;
    defer if (body_owned) |b| allocator.free(b);
    if (req.body) |b| {
        body_owned = try allocator.dupeZ(u8, b);
        try setoptCheck(easy, c.CURLOPT_POSTFIELDS, body_owned.?.ptr);
        try setoptCheckLong(easy, c.CURLOPT_POSTFIELDSIZE_LARGE, @as(c_longlong, @intCast(b.len)));
    }

    // 5. Custom headers — these are ADDED to the impersonated default set, NOT
    //    replacing them. Standard libcurl-impersonate behavior.
    var slist: ?*c.curl_slist = null;
    defer if (slist) |s| c.curl_slist_free_all(s);

    for (req.headers) |h| {
        const line = try std.fmt.allocPrintSentinel(allocator, "{s}: {s}", .{ h.name, h.value }, 0);
        defer allocator.free(line);
        slist = c.curl_slist_append(slist, line.ptr) orelse return error.BadHeader;
    }
    if (slist != null) {
        try setoptCheck(easy, c.CURLOPT_HTTPHEADER, slist);
    }

    // 6. Cookie header (we drive cookies; no on-disk jar).
    var cookie_owned: ?[:0]u8 = null;
    defer if (cookie_owned) |co| allocator.free(co);
    if (req.cookie_header.len > 0) {
        cookie_owned = try allocator.dupeZ(u8, req.cookie_header);
        try setoptCheck(easy, c.CURLOPT_COOKIE, cookie_owned.?.ptr);
    }

    // 7. Redirects + timeouts.
    try setoptCheckLong(easy, c.CURLOPT_FOLLOWLOCATION, if (req.follow_redirects) @as(c_longlong, 1) else 0);
    try setoptCheckLong(easy, c.CURLOPT_MAXREDIRS, @as(c_longlong, @intCast(req.max_redirects)));
    try setoptCheckLong(easy, c.CURLOPT_CONNECTTIMEOUT_MS, @as(c_longlong, @intCast(req.connect_timeout_ms)));
    try setoptCheckLong(easy, c.CURLOPT_TIMEOUT_MS, @as(c_longlong, @intCast(req.total_timeout_ms)));
    try setoptCheckLong(easy, c.CURLOPT_NOSIGNAL, 1);
    // Empty string = "advertise all supported encodings AND auto-decode response".
    // Without this we'd get gzip-compressed bodies (since impersonate() set
    // Accept-Encoding to Chrome's default "gzip, deflate, br, zstd").
    try setoptCheck(easy, c.CURLOPT_ACCEPT_ENCODING, @as([*:0]const u8, ""));

    // 8. Capture callbacks.
    try setoptCheck(easy, c.CURLOPT_WRITEFUNCTION, &writeCb);
    try setoptCheck(easy, c.CURLOPT_WRITEDATA, &ctx);
    try setoptCheck(easy, c.CURLOPT_HEADERFUNCTION, &headerCb);
    try setoptCheck(easy, c.CURLOPT_HEADERDATA, &ctx);

    // 9. Run.
    const code = c.curl_easy_perform(easy);
    if (code != c.CURLE_OK) {
        const msg = c.curl_easy_strerror(code);
        std.log.warn("[curl_lib] perform failed code={d}: {s}", .{ code, std.mem.span(msg) });
        return error.CurlPerformFailed;
    }
    if (ctx.alloc_failed) return error.OutOfMemory;

    // 10. Extract response info.
    var status_l: c_long = 0;
    _ = c.curl_easy_getinfo(easy, c.CURLINFO_RESPONSE_CODE, &status_l);
    var url_p: ?[*:0]const u8 = null;
    _ = c.curl_easy_getinfo(easy, c.CURLINFO_EFFECTIVE_URL, &url_p);
    var redirects_l: c_long = 0;
    _ = c.curl_easy_getinfo(easy, c.CURLINFO_REDIRECT_COUNT, &redirects_l);

    const final_url_dup = if (url_p) |p|
        try allocator.dupe(u8, std.mem.span(p))
    else
        try allocator.dupe(u8, req.url);

    return .{
        .allocator = allocator,
        .status = @intCast(status_l),
        .final_url = final_url_dup,
        .redirect_count = @intCast(redirects_l),
        .raw_headers = try hdr_buf.toOwnedSlice(allocator),
        .body = try body_buf.toOwnedSlice(allocator),
    };
}

// ───────────────────────────────────────────────────────────────────────────
// Internals
// ───────────────────────────────────────────────────────────────────────────

const CallbackCtx = struct {
    allocator: std.mem.Allocator,
    body: *std.ArrayList(u8),
    headers: *std.ArrayList(u8),
    alloc_failed: bool = false,
};

/// libcurl write callback: WRITEFUNCTION(ptr, size, nmemb, userdata) → bytes_written
fn writeCb(ptr: [*]const u8, size: usize, nmemb: usize, userdata: ?*anyopaque) callconv(.c) usize {
    const ctx_ptr: *CallbackCtx = @ptrCast(@alignCast(userdata orelse return 0));
    const total = size * nmemb;
    ctx_ptr.body.appendSlice(ctx_ptr.allocator, ptr[0..total]) catch {
        ctx_ptr.alloc_failed = true;
        return 0;
    };
    return total;
}

/// libcurl header callback: same shape as WRITEFUNCTION, called once per header line.
fn headerCb(ptr: [*]const u8, size: usize, nmemb: usize, userdata: ?*anyopaque) callconv(.c) usize {
    const ctx_ptr: *CallbackCtx = @ptrCast(@alignCast(userdata orelse return 0));
    const total = size * nmemb;
    ctx_ptr.headers.appendSlice(ctx_ptr.allocator, ptr[0..total]) catch {
        ctx_ptr.alloc_failed = true;
        return 0;
    };
    return total;
}

fn setoptCheck(easy: *c.CURL, opt: c.CURLoption, val: anytype) Error!void {
    if (c.curl_easy_setopt(easy, opt, val) != c.CURLE_OK) return error.CurlSetoptFailed;
}

fn setoptCheckLong(easy: *c.CURL, opt: c.CURLoption, val: c_longlong) Error!void {
    if (c.curl_easy_setopt(easy, opt, val) != c.CURLE_OK) return error.CurlSetoptFailed;
}

test "curl_easy_init returns a handle" {
    const easy = c.curl_easy_init() orelse return error.SkipZigTest;
    c.curl_easy_cleanup(easy);
}

test "GET against tls.peet.ws via curl-impersonate (live)" {
    // Skip in CI (no network). Run with `zig build test-curl-live`.
    if (compat.getenv("CURL_LIB_LIVE_TEST") == null) return error.SkipZigTest;
    const a = std.testing.allocator;
    var resp = try perform(a, .{
        .method = "GET",
        .url = "https://tls.peet.ws/api/all",
        .impersonate = "chrome131",
    });
    defer resp.deinit();
    try std.testing.expect(resp.status == 200);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "ja4") != null);
}
