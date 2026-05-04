// handler.zig — POST /v1/sandbox/replay request handler.
//
// Receives a JSON body describing what to replay, runs the bundle in the
// QuickJS sandbox with curl-impersonate outbound, returns harvested cookies
// + any post-eval extraction the caller asked for.
//
// Body shape:
//   {
//     "target_origin":   "https://reddit.com",
//     "target_href":     "https://www.reddit.com/search/?q=foo",
//     "bundle_url":      "https://...",        // OR
//     "bundle_source":   "<inline JS>",        // raw JS to eval
//     "fingerprint":     "chrome_mac_arm",     // pool key (default builtin)
//     "impersonate":     "chrome131",          // curl-impersonate profile
//     "post_eval":       "JSON.stringify(...)",// optional extraction expr
//     "timeout_ms":      5000
//   }
//
// Response:
//   {
//     "ok": true,
//     "ms": 142,
//     "cookies": [ { "name": "...", "value": "...", "domain": "...", ... } ],
//     "post_eval": "<json>",                   // present iff post_eval was sent
//     "egress_bytes": 12345
//   }

const std = @import("std");
const compat = @import("../compat.zig");
const runtime = @import("runtime.zig");
const network = @import("network.zig");
const fingerprint_mod = @import("fingerprint.zig");

const Sandbox = runtime.Sandbox;
const Fingerprint = fingerprint_mod.Fingerprint;

pub const Request = struct {
    target_origin: []const u8,
    target_href: ?[]const u8 = null,
    bundle_url: ?[]const u8 = null,
    bundle_source: ?[]const u8 = null,
    fingerprint_id: []const u8 = "chrome_mac_arm",
    impersonate_profile: []const u8 = "chrome131",
    post_eval: ?[]const u8 = null,
    timeout_ms: u32 = 5_000,

    pub fn parse(allocator: std.mem.Allocator, body: []const u8) !Request {
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.NotAnObject;
        const obj = parsed.value.object;

        return .{
            .target_origin = try dupeOrEmpty(allocator, obj.get("target_origin")),
            .target_href = try dupeOpt(allocator, obj.get("target_href")),
            .bundle_url = try dupeOpt(allocator, obj.get("bundle_url")),
            .bundle_source = try dupeOpt(allocator, obj.get("bundle_source")),
            .fingerprint_id = try dupeOrDefault(allocator, obj.get("fingerprint"), "chrome_mac_arm"),
            .impersonate_profile = try dupeOrDefault(allocator, obj.get("impersonate"), "chrome131"),
            .post_eval = try dupeOpt(allocator, obj.get("post_eval")),
            .timeout_ms = @intCast(if (obj.get("timeout_ms")) |v| (if (v == .integer) v.integer else 5_000) else 5_000),
        };
    }
};

fn dupeOpt(allocator: std.mem.Allocator, v: ?std.json.Value) !?[]const u8 {
    if (v == null) return null;
    return switch (v.?) {
        .string => |s| try allocator.dupe(u8, s),
        else => null,
    };
}

fn dupeOrEmpty(allocator: std.mem.Allocator, v: ?std.json.Value) ![]const u8 {
    return (try dupeOpt(allocator, v)) orelse try allocator.dupe(u8, "");
}

fn dupeOrDefault(allocator: std.mem.Allocator, v: ?std.json.Value, default: []const u8) ![]const u8 {
    return (try dupeOpt(allocator, v)) orelse try allocator.dupe(u8, default);
}

pub fn pickFingerprint(id: []const u8, target_origin: []const u8, target_href: ?[]const u8, referrer: []const u8) Fingerprint {
    var fp = if (std.mem.eql(u8, id, "chrome_windows"))
        Fingerprint.builtinChromeWindows()
    else
        Fingerprint.builtinChromeMacARM();

    fp.target_origin = target_origin;
    fp.target_href = target_href orelse target_origin;
    fp.referrer = referrer;
    return fp;
}

/// Run a single replay request. Returns the JSON response body to send.
pub fn run(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const t0 = compat.milliTimestamp();

    const req = try Request.parse(allocator, body);
    defer freeRequest(allocator, req);

    const fp = pickFingerprint(req.fingerprint_id, req.target_origin, req.target_href, "");

    const sb = try Sandbox.init(allocator, .{
        .fingerprint = fp,
        .target_origin = req.target_origin,
        .target_href = req.target_href,
        .timeout_ms = req.timeout_ms,
        .impersonate_profile = req.impersonate_profile,
    });
    defer sb.deinit();

    try sb.installShim();

    // Source: either inline bundle_source, or fetch bundle_url through the
    // sandbox's own network so it goes through curl-impersonate.
    var bundle_source_owned: ?[]u8 = null;
    defer if (bundle_source_owned) |s| allocator.free(s);

    const source: []const u8 = blk: {
        if (req.bundle_source) |s| break :blk s;
        if (req.bundle_url) |url| {
            var jar = network.CookieJar.init(allocator);
            defer jar.deinit();
            var cli = network.Client.init(allocator, .{
                .impersonate_profile = req.impersonate_profile,
                .target_origin = req.target_origin,
            });
            defer cli.deinit();
            var resp = try cli.send(.{
                .method = "GET",
                .url = url,
                .headers_json = "{\"Accept\":\"*/*\"}",
                .body = null,
                .cookie_jar = &jar,
            });
            defer resp.deinit();
            bundle_source_owned = try allocator.dupe(u8, resp.body);
            break :blk bundle_source_owned.?;
        }
        return error.NoBundleProvided;
    };

    sb.evalBundle(source, "<bundle>") catch {
        // Bundle errored — still proceed to harvest whatever cookies it set
        // before the error. Many bundles raise after a successful set-cookie.
    };

    // Optional post-eval extraction.
    var post_eval_result: ?[]u8 = null;
    defer if (post_eval_result) |r| allocator.free(r);
    if (req.post_eval) |expr| {
        post_eval_result = sb.evalJson(expr) catch null;
    }

    const cookies = try sb.cookie_jar.snapshot(allocator);
    defer {
        for (cookies) |c| {
            allocator.free(c.name);
            allocator.free(c.value);
            allocator.free(c.domain);
            allocator.free(c.path);
            allocator.free(c.same_site);
        }
        allocator.free(cookies);
    }

    return try buildResponseJson(allocator, .{
        .ms = @intCast(compat.milliTimestamp() - t0),
        .cookies = cookies,
        .post_eval = post_eval_result,
        .egress_bytes = sb.egress_bytes,
    });
}

fn freeRequest(allocator: std.mem.Allocator, r: Request) void {
    allocator.free(r.target_origin);
    if (r.target_href) |s| allocator.free(s);
    if (r.bundle_url) |s| allocator.free(s);
    if (r.bundle_source) |s| allocator.free(s);
    allocator.free(r.fingerprint_id);
    allocator.free(r.impersonate_profile);
    if (r.post_eval) |s| allocator.free(s);
}

const ResponseSummary = struct {
    ms: u32,
    cookies: []const network.Cookie,
    post_eval: ?[]const u8,
    egress_bytes: usize,
};

fn buildResponseJson(allocator: std.mem.Allocator, r: ResponseSummary) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"ok\":true,\"ms\":");
    try buf.print(allocator, "{d}", .{r.ms});
    try buf.appendSlice(allocator, ",\"egress_bytes\":");
    try buf.print(allocator, "{d}", .{r.egress_bytes});
    try buf.appendSlice(allocator, ",\"cookies\":[");
    for (r.cookies, 0..) |c, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.append(allocator, '{');
        try writeJsonStr(allocator, &buf, "name", c.name);
        try buf.append(allocator, ',');
        try writeJsonStr(allocator, &buf, "value", c.value);
        try buf.append(allocator, ',');
        try writeJsonStr(allocator, &buf, "domain", c.domain);
        try buf.append(allocator, ',');
        try writeJsonStr(allocator, &buf, "path", c.path);
        try buf.appendSlice(allocator, ",\"expires\":");
        try buf.print(allocator, "{d}", .{c.expires});
        try buf.appendSlice(allocator, ",\"secure\":");
        try buf.appendSlice(allocator, if (c.secure) "true" else "false");
        try buf.appendSlice(allocator, ",\"http_only\":");
        try buf.appendSlice(allocator, if (c.http_only) "true" else "false");
        try buf.append(allocator, ',');
        try writeJsonStr(allocator, &buf, "same_site", c.same_site);
        try buf.append(allocator, '}');
    }
    try buf.append(allocator, ']');

    if (r.post_eval) |pe| {
        // pe is JSON or the literal string "undefined" (when expression is undefined).
        // JSON has no `undefined` literal — coerce to null.
        try buf.appendSlice(allocator, ",\"post_eval\":");
        if (std.mem.eql(u8, pe, "undefined") or pe.len == 0) {
            try buf.appendSlice(allocator, "null");
        } else {
            try buf.appendSlice(allocator, pe);
        }
    }
    try buf.append(allocator, '}');
    return buf.toOwnedSlice(allocator);
}

fn writeJsonStr(a: std.mem.Allocator, buf: *std.ArrayList(u8), key: []const u8, value: []const u8) !void {
    try buf.append(a, '"');
    try buf.appendSlice(a, key);
    try buf.appendSlice(a, "\":\"");
    for (value) |c| {
        switch (c) {
            '"' => try buf.appendSlice(a, "\\\""),
            '\\' => try buf.appendSlice(a, "\\\\"),
            '\n' => try buf.appendSlice(a, "\\n"),
            '\r' => try buf.appendSlice(a, "\\r"),
            '\t' => try buf.appendSlice(a, "\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => try buf.print(a, "\\u{x:0>4}", .{c}),
            else => try buf.append(a, c),
        }
    }
    try buf.append(a, '"');
}
