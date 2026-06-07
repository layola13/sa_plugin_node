const std = @import("std");
const builtin = @import("builtin");
const plugin_api = @import("plugin_api");
const base = @import("node_saasm_api.zig");
const linux = std.os.linux;
const posix = std.posix;

const SaSlice = extern struct {
    ptr: [*]const u8,
    len: u64,
};

const UnsupportedStatus = @intFromEnum(plugin_api.AbiStatus.failed);

fn fail() u32 {
    return UnsupportedStatus;
}

fn writeOwnedBytes(out_ptr: ?*?[*]const u8, out_len: ?*u64, bytes: []const u8) u32 {
    const owned = std.heap.page_allocator.dupe(u8, bytes) catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

fn writeOwnedString(out_ptr: ?*?[*]const u8, out_len: ?*u64, text: []const u8) u32 {
    return writeOwnedBytes(out_ptr, out_len, text);
}

fn writeOwnedBool(out_bool: ?*u32, value: bool) u32 {
    out_bool.?.* = if (value) 1 else 0;
    return 0;
}

fn writeJsonValue(out_ptr: ?*?[*]const u8, out_len: ?*u64, value: anytype) u32 {
    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();
    std.json.stringify(value, .{}, json.writer()) catch return fail();
    const owned = json.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

fn writeStatusJson(out_ptr: ?*?[*]const u8, out_len: ?*u64, module_name: []const u8, supported: bool, reason: []const u8) u32 {
    var buffer: [256]u8 = undefined;
    const json = std.fmt.bufPrint(
        &buffer,
        "{{\"module\":\"{s}\",\"supported\":{s},\"reason\":\"{s}\"}}",
        .{ module_name, if (supported) "true" else "false", reason },
    ) catch return fail();
    return writeOwnedString(out_ptr, out_len, json);
}

// --- Async hooks ---
var async_resource_next_id: u64 = 1;
var async_resource_last_id: u64 = 0;

fn jsonEscapeAppend(out: *std.ArrayList(u8), bytes: []const u8) !void {
    for (bytes) |b| {
        switch (b) {
            '"' => try out.appendSlice("\\\""),
            '\\' => try out.appendSlice("\\\\"),
            '\n' => try out.appendSlice("\\n"),
            '\r' => try out.appendSlice("\\r"),
            '\t' => try out.appendSlice("\\t"),
            else => if (b < 0x20) try out.writer().print("\\u{x:0>4}", .{b}) else try out.append(b),
        }
    }
}

fn appendJsonString(out: *std.ArrayList(u8), bytes: []const u8) !void {
    try out.append('"');
    try jsonEscapeAppend(out, bytes);
    try out.append('"');
}

fn appendEnvStringField(out: *std.ArrayList(u8), name: []const u8, env_name: []const u8) !void {
    try out.appendSlice(",\"");
    try out.appendSlice(name);
    try out.appendSlice("\":");
    if (std.posix.getenv(env_name)) |value| {
        try appendJsonString(out, value);
    } else {
        try out.appendSlice("null");
    }
}

fn appendStringArray(out: *std.ArrayList(u8), items: []const []const u8) !void {
    try out.append('[');
    for (items, 0..) |item, i| {
        if (i != 0) try out.append(',');
        try appendJsonString(out, item);
    }
    try out.append(']');
}

const AsyncResourceHandle = struct {
    allocator: std.mem.Allocator,
    id: u64,
    type_name: []u8,
    trigger_async_id: u64,

    fn deinit(self: *AsyncResourceHandle) void {
        self.allocator.free(self.type_name);
        self.allocator.destroy(self);
    }
};

pub export fn sa_node_plugin_async_hooks_snapshot_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var buffer: [256]u8 = undefined;
    const json = std.fmt.bufPrint(
        &buffer,
        "{{\"executionAsyncId\":{d},\"triggerAsyncId\":0,\"providers\":[]}}",
        .{async_resource_last_id},
    ) catch return fail();
    return writeOwnedString(out_ptr, out_len, json);
}

pub export fn sa_node_plugin_async_hooks_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "async_hooks", true, "snapshot and AsyncResource shims are exposed");
}

pub export fn sa_node_plugin_async_hooks_execution_async_id(out_id: ?*u64) u32 {
    out_id.?.* = async_resource_last_id;
    return 0;
}

pub export fn sa_node_plugin_async_hooks_trigger_async_id(out_id: ?*u64) u32 {
    out_id.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_async_hooks_async_resource_create(type_ptr: ?[*]const u8, type_len: u64, trigger_async_id: u64, out_handle: ?*?*anyopaque) u32 {
    const type_name = type_ptr.?[0..type_len];
    const allocator = std.heap.page_allocator;
    const handle = allocator.create(AsyncResourceHandle) catch return fail();
    handle.* = .{
        .allocator = allocator,
        .id = async_resource_next_id,
        .type_name = allocator.dupe(u8, type_name) catch {
            allocator.destroy(handle);
            return fail();
        },
        .trigger_async_id = trigger_async_id,
    };
    async_resource_next_id += 1;
    async_resource_last_id = handle.id;
    out_handle.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_async_hooks_async_resource_free(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| {
        const handle: *AsyncResourceHandle = @ptrCast(@alignCast(ptr));
        handle.deinit();
    }
    return 0;
}

pub export fn sa_node_plugin_async_hooks_async_resource_snapshot_json(handle_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *AsyncResourceHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    var buffer: [256]u8 = undefined;
    const json = std.fmt.bufPrint(
        &buffer,
        "{{\"id\":{d},\"type\":\"{s}\",\"triggerAsyncId\":{d}}}",
        .{ handle.id, handle.type_name, handle.trigger_async_id },
    ) catch return fail();
    return writeOwnedString(out_ptr, out_len, json);
}

// --- Diagnostics channel ---
const DiagnosticsChannel = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    subscribers: std.ArrayList(?*anyopaque),
    enabled: bool = false,

    fn init(allocator: std.mem.Allocator, name: []const u8) !*DiagnosticsChannel {
        const self = try allocator.create(DiagnosticsChannel);
        self.* = .{
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
            .subscribers = std.ArrayList(?*anyopaque).init(allocator),
            .enabled = false,
        };
        return self;
    }

    fn deinit(self: *DiagnosticsChannel) void {
        self.allocator.free(self.name);
        self.subscribers.deinit();
        self.allocator.destroy(self);
    }
};

pub export fn sa_node_plugin_diagnostics_channel_create(name_ptr: ?[*]const u8, name_len: u64, out_channel: ?*?*anyopaque) u32 {
    const name = name_ptr.?[0..name_len];
    const channel = DiagnosticsChannel.init(std.heap.page_allocator, name) catch return fail();
    out_channel.?.* = @ptrCast(channel);
    return 0;
}

pub export fn sa_node_plugin_diagnostics_channel_subscribe(channel_ptr: ?*anyopaque, callback: ?*anyopaque) u32 {
    const channel: *DiagnosticsChannel = @ptrCast(@alignCast(channel_ptr orelse return fail()));
    channel.subscribers.append(callback) catch return fail();
    channel.enabled = true;
    return 0;
}

pub export fn sa_node_plugin_diagnostics_channel_unsubscribe(channel_ptr: ?*anyopaque, callback: ?*anyopaque) u32 {
    const channel: *DiagnosticsChannel = @ptrCast(@alignCast(channel_ptr orelse return fail()));
    var i: usize = 0;
    while (i < channel.subscribers.items.len) : (i += 1) {
        if (channel.subscribers.items[i] == callback) {
            _ = channel.subscribers.orderedRemove(i);
            break;
        }
    }
    channel.enabled = channel.subscribers.items.len > 0;
    return 0;
}

pub export fn sa_node_plugin_diagnostics_channel_publish(channel_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64, out_count: ?*u64) u32 {
    const channel: *DiagnosticsChannel = @ptrCast(@alignCast(channel_ptr orelse return fail()));
    _ = data_ptr;
    _ = data_len;
    out_count.?.* = channel.subscribers.items.len;
    return 0;
}

pub export fn sa_node_plugin_diagnostics_channel_has_subscribers(channel_ptr: ?*anyopaque, out_bool: ?*u32) u32 {
    const channel: *DiagnosticsChannel = @ptrCast(@alignCast(channel_ptr orelse return fail()));
    return writeOwnedBool(out_bool, channel.subscribers.items.len > 0);
}

pub export fn sa_node_plugin_diagnostics_channel_free(channel_ptr: ?*anyopaque) u32 {
    if (channel_ptr) |ptr| {
        const channel: *DiagnosticsChannel = @ptrCast(@alignCast(ptr));
        channel.deinit();
    }
    return 0;
}

pub export fn sa_node_plugin_diagnostics_channel_snapshot_json(channel_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const channel: *DiagnosticsChannel = @ptrCast(@alignCast(channel_ptr orelse return fail()));
    var buffer: [256]u8 = undefined;
    const json = std.fmt.bufPrint(
        &buffer,
        "{{\"name\":\"{s}\",\"enabled\":{s},\"subscribers\":{d}}}",
        .{ channel.name, if (channel.enabled) "true" else "false", channel.subscribers.items.len },
    ) catch return fail();
    return writeOwnedString(out_ptr, out_len, json);
}

pub export fn sa_node_plugin_async_context_tracking_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "async_context_tracking", true, "async_hooks compatibility shims");
}

pub export fn sa_node_plugin_command_line_options_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    const node_options_present = std.posix.getenv("NODE_OPTIONS") != null;
    const sa_plugin_dev = std.posix.getenv("SA_PLUGIN_DEV") != null;
    out.appendSlice("{\"module\":\"command_line_options\",\"supported\":true,\"mode\":\"native-process-env\",\"argvSource\":\"std.process.args\",\"nodeOptionsPresent\":") catch return fail();
    out.appendSlice(if (node_options_present) "true" else "false") catch return fail();
    out.appendSlice(",\"saPluginDev\":") catch return fail();
    out.appendSlice(if (sa_plugin_dev) "true" else "false") catch return fail();
    appendEnvStringField(&out, "nodeOptions", "NODE_OPTIONS") catch return fail();
    out.appendSlice(",\"recognizedFamilies\":[\"--inspect\",\"--require\",\"--input-type\",\"--conditions\",\"--experimental-*\",\"--trace-*\"],\"limitations\":[\"flags are reported for host/tooling compatibility\",\"no V8 or JavaScript loader flags are executed by this native plugin\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_debugger_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "debugger", false, "debugger protocol is not modeled");
}

pub export fn sa_node_plugin_deprecated_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"module\":\"deprecated\",\"supported\":true,\"mode\":\"compatibility-metadata\",\"capabilities\":[\"util.deprecate registry\",\"idempotent deprecation codes\",\"status reporting\"],\"limitations\":[\"no JavaScript wrapper invocation semantics\",\"warnings are recorded as native metadata instead of emitted through process warning events\"]}");
}

pub export fn sa_node_plugin_environment_variables_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "environment_variables", true, "backed by process env shims");
}

pub export fn sa_node_plugin_errors_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"module\":\"errors\",\"supported\":true,\"mode\":\"native-error-codes\",\"codes\":[\"ERR_INVALID_ARG_TYPE\",\"ERR_INVALID_ARG_VALUE\",\"ERR_OUT_OF_RANGE\",\"ERR_SYSTEM_ERROR\",\"ENOENT\",\"EACCES\",\"ECONNREFUSED\",\"ECONNRESET\",\"ETIMEDOUT\"],\"limitations\":[\"no JavaScript Error subclass prototypes\",\"native APIs return status codes and JSON diagnostics\"]}");
}

pub export fn sa_node_plugin_internationalization_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"internationalization\",\"supported\":true,\"mode\":\"locale-env-and-unicode-primitives\",\"icu\":false") catch return fail();
    appendEnvStringField(&out, "lang", "LANG") catch return fail();
    appendEnvStringField(&out, "lcAll", "LC_ALL") catch return fail();
    appendEnvStringField(&out, "lcCtype", "LC_CTYPE") catch return fail();
    appendEnvStringField(&out, "timezone", "TZ") catch return fail();
    out.appendSlice(",\"encoding\":\"utf-8\",\"capabilities\":[\"UTF-8 string/byte conversion\",\"TextEncoder/TextDecoder compatible helpers\",\"locale and timezone discovery from process environment\"],\"limitations\":[\"full ICU collation/date/number formatting is not bundled\",\"Intl JavaScript constructors are outside this native plugin surface\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_iterable_streams_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const stream_types = [_][]const u8{ "Readable", "Writable", "Duplex", "Transform", "PassThrough", "WebReadableStream", "WebWritableStream", "WebTransformStream" };
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"iterable_streams\",\"supported\":true,\"mode\":\"poll-read-byte-iterators\",\"streamTypes\":") catch return fail();
    appendStringArray(&out, &stream_types) catch return fail();
    out.appendSlice(",\"capabilities\":[\"native stream handles\",\"pipeline state tracking\",\"finished/destroyed state tracking\",\"compose state tracking\",\"web stream read/write/enqueue helpers\"],\"limitations\":[\"no JavaScript Symbol.asyncIterator callbacks\",\"iteration is exposed through explicit native read/poll helpers\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_permissions_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const dev_mode = std.posix.getenv("SA_PLUGIN_DEV") != null;
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"permissions\",\"supported\":true,\"model\":\"sa-plugin-manifest\",\"sandboxEnforced\":false,\"devMode\":") catch return fail();
    out.appendSlice(if (dev_mode) "true" else "false") catch return fail();
    out.appendSlice(",\"declared\":{\"fs\":10,\"net\":2,\"env\":5,\"processSpawn\":true},\"limitations\":[\"Node --permission runtime flags are not enforced by this plugin\",\"host sandbox and sap.json are authoritative\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_repl_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "repl", false, "interactive REPL is not modeled");
}

pub export fn sa_node_plugin_test_runner_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"module\":\"test_runner\",\"supported\":true,\"backend\":\"sa test\",\"mode\":\"sync-native-harness\",\"capabilities\":[\"status\",\"tests\",\"assertions\"],\"limitations\":[\"no JavaScript callback scheduling\",\"no TAP stream object model\"]}");
}

pub export fn sa_node_plugin_web_crypto_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "web_crypto", true, "getRandomValues, randomUUID, and digest are exposed as sync helpers");
}

const WebStreamKind = enum { readable, writable, transform_readable, transform_writable };

const WebStreamHandle = struct {
    allocator: std.mem.Allocator,
    kind: WebStreamKind,
    buffer: std.ArrayList(u8),
    read_offset: usize = 0,
    closed: bool = false,
    peer: ?*WebStreamHandle = null,

    fn init(allocator: std.mem.Allocator, kind: WebStreamKind) !*WebStreamHandle {
        const handle = try allocator.create(WebStreamHandle);
        handle.* = .{
            .allocator = allocator,
            .kind = kind,
            .buffer = std.ArrayList(u8).init(allocator),
        };
        return handle;
    }

    fn readableBytes(self: *const WebStreamHandle) usize {
        return if (self.buffer.items.len > self.read_offset) self.buffer.items.len - self.read_offset else 0;
    }

    fn compactIfNeeded(self: *WebStreamHandle) void {
        if (self.read_offset == 0) return;
        if (self.read_offset >= self.buffer.items.len) {
            self.buffer.clearRetainingCapacity();
            self.read_offset = 0;
            return;
        }
        if (self.read_offset >= 4096 and self.read_offset * 2 >= self.buffer.items.len) {
            std.mem.copyForwards(u8, self.buffer.items[0..self.readableBytes()], self.buffer.items[self.read_offset..]);
            self.buffer.shrinkRetainingCapacity(self.readableBytes());
            self.read_offset = 0;
        }
    }

    fn deinit(self: *WebStreamHandle) void {
        self.buffer.deinit();
        self.allocator.destroy(self);
    }
};

fn webStreamNew(kind: WebStreamKind, out_handle: ?*?*anyopaque) u32 {
    const handle = WebStreamHandle.init(std.heap.page_allocator, kind) catch return fail();
    out_handle.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_web_streams_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "web_streams", true, "ReadableStream, WritableStream, and TransformStream byte-buffer helpers are exposed");
}

pub export fn sa_node_plugin_web_streams_readable_new(out_handle: ?*?*anyopaque) u32 {
    return webStreamNew(.readable, out_handle);
}

pub export fn sa_node_plugin_web_streams_writable_new(out_handle: ?*?*anyopaque) u32 {
    return webStreamNew(.writable, out_handle);
}

pub export fn sa_node_plugin_web_streams_transform_new(out_readable: ?*?*anyopaque, out_writable: ?*?*anyopaque) u32 {
    const allocator = std.heap.page_allocator;
    const readable = WebStreamHandle.init(allocator, .transform_readable) catch return fail();
    errdefer readable.deinit();
    const writable = WebStreamHandle.init(allocator, .transform_writable) catch return fail();
    readable.peer = writable;
    writable.peer = readable;
    out_readable.?.* = @ptrCast(readable);
    out_writable.?.* = @ptrCast(writable);
    return 0;
}

pub export fn sa_node_plugin_web_streams_enqueue(handle_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const handle: *WebStreamHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    if (handle.closed) return fail();
    switch (handle.kind) {
        .readable, .transform_readable => {},
        .writable, .transform_writable => return fail(),
    }
    handle.buffer.appendSlice(data_ptr.?[0..data_len]) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_web_streams_write(handle_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const handle: *WebStreamHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    if (handle.closed) return fail();
    switch (handle.kind) {
        .writable => handle.buffer.appendSlice(data_ptr.?[0..data_len]) catch return fail(),
        .transform_writable => {
            const readable = handle.peer orelse return fail();
            if (readable.closed) return fail();
            readable.buffer.appendSlice(data_ptr.?[0..data_len]) catch return fail();
        },
        .readable, .transform_readable => return fail(),
    }
    return 0;
}

pub export fn sa_node_plugin_web_streams_read(handle_ptr: ?*anyopaque, max_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *WebStreamHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    switch (handle.kind) {
        .readable, .transform_readable => {},
        .writable, .transform_writable => return fail(),
    }
    const available = handle.readableBytes();
    const n = @min(available, @as(usize, @intCast(max_len)));
    const status = writeOwnedBytes(out_ptr, out_len, handle.buffer.items[handle.read_offset .. handle.read_offset + n]);
    if (status != 0) return status;
    handle.read_offset += n;
    handle.compactIfNeeded();
    return 0;
}

pub export fn sa_node_plugin_web_streams_snapshot_json(handle_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *WebStreamHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    const kind = switch (handle.kind) {
        .readable => "readable",
        .writable => "writable",
        .transform_readable => "transform_readable",
        .transform_writable => "transform_writable",
    };
    var buffer: [192]u8 = undefined;
    const json = std.fmt.bufPrint(
        &buffer,
        "{{\"kind\":\"{s}\",\"closed\":{s},\"queuedBytes\":{d},\"readOffset\":{d},\"hasPeer\":{s}}}",
        .{ kind, if (handle.closed) "true" else "false", handle.readableBytes(), handle.read_offset, if (handle.peer != null) "true" else "false" },
    ) catch return fail();
    return writeOwnedString(out_ptr, out_len, json);
}

pub export fn sa_node_plugin_web_streams_close(handle_ptr: ?*anyopaque) u32 {
    const handle: *WebStreamHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    handle.closed = true;
    return 0;
}

pub export fn sa_node_plugin_web_streams_free(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| {
        const handle: *WebStreamHandle = @ptrCast(@alignCast(ptr));
        if (handle.peer) |peer| peer.peer = null;
        handle.deinit();
    }
    return 0;
}

// --- Perf hooks ---
var perf_origin_ms: i64 = 0;
var perf_marks = std.StringHashMap(i64).init(std.heap.page_allocator);
var perf_measures = std.StringHashMap(i64).init(std.heap.page_allocator);

fn perfOriginMs() i64 {
    if (perf_origin_ms == 0) perf_origin_ms = std.time.milliTimestamp();
    return perf_origin_ms;
}

pub export fn sa_node_plugin_perf_hooks_now_ms(out_ms: ?*f64) u32 {
    const now = @as(f64, @floatFromInt(std.time.milliTimestamp() - perfOriginMs()));
    out_ms.?.* = now;
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_time_origin_ms(out_ms: ?*f64) u32 {
    out_ms.?.* = @as(f64, @floatFromInt(perfOriginMs()));
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_mark(name_ptr: ?[*]const u8, name_len: u64) u32 {
    const name = name_ptr.?[0..name_len];
    const dup = std.heap.page_allocator.dupe(u8, name) catch return fail();
    perf_marks.put(dup, std.time.milliTimestamp()) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_measure(name_ptr: ?[*]const u8, name_len: u64, start_ptr: ?[*]const u8, start_len: u64, end_ptr: ?[*]const u8, end_len: u64, out_ms: ?*f64) u32 {
    const name = name_ptr.?[0..name_len];
    const start_name = start_ptr.?[0..start_len];
    const end_name = end_ptr.?[0..end_len];
    const start_ms = perf_marks.get(start_name) orelse perfOriginMs();
    const end_ms = perf_marks.get(end_name) orelse std.time.milliTimestamp();
    const duration = @as(f64, @floatFromInt(end_ms - start_ms));
    out_ms.?.* = duration;
    const dup = std.heap.page_allocator.dupe(u8, name) catch return fail();
    perf_measures.put(dup, @as(i64, @intFromFloat(duration))) catch return fail();
    return 0;
}

fn appendPerfEntries(list: *std.ArrayList(u8), kind: []const u8, entries: *std.StringHashMap(i64)) !void {
    var it = entries.iterator();
    while (it.next()) |entry| {
        try list.appendSlice(if (list.items.len > 1) "," else "");
        try std.json.stringify(.{
            .kind = kind,
            .name = entry.key_ptr.*,
            .value = entry.value_ptr.*,
        }, .{}, list.writer());
    }
}

pub export fn sa_node_plugin_perf_hooks_entries_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();
    json.appendSlice("[") catch return fail();
    var first = true;
    {
        var it = perf_marks.iterator();
        while (it.next()) |entry| {
            if (!first) json.appendSlice(",") catch return fail();
            first = false;
            const record = .{ .kind = "mark", .name = entry.key_ptr.*, .startTime = entry.value_ptr.* };
            std.json.stringify(record, .{}, json.writer()) catch return fail();
        }
    }
    {
        var it = perf_measures.iterator();
        while (it.next()) |entry| {
            if (!first) json.appendSlice(",") catch return fail();
            first = false;
            const record = .{ .kind = "measure", .name = entry.key_ptr.*, .duration = entry.value_ptr.* };
            std.json.stringify(record, .{}, json.writer()) catch return fail();
        }
    }
    json.appendSlice("]") catch return fail();
    const owned = json.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_clear_marks() u32 {
    perf_marks.clearRetainingCapacity();
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_clear_measures() u32 {
    perf_measures.clearRetainingCapacity();
    return 0;
}

// --- Report ---
pub export fn sa_node_plugin_report_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "report", true, "diagnostic report shim");
}

pub export fn sa_node_plugin_report_get_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = std.posix.getcwd(&cwd_buf) catch "/";
    const report = .{
        .node = "sa_plugin_node",
        .pid = std.c.getpid(),
        .ppid = std.c.getppid(),
        .cwd = cwd,
        .platform = @tagName(builtin.os.tag),
        .arch = @tagName(builtin.cpu.arch),
        .version = "sci-compatible",
    };
    return writeJsonValue(out_ptr, out_len, report);
}

pub export fn sa_node_plugin_report_write_file(filename_ptr: ?[*]const u8, filename_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var report_ptr: ?[*]const u8 = null;
    var report_len: u64 = 0;
    if (sa_node_plugin_report_get_json(&report_ptr, &report_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(report_ptr, report_len);

    const filename = if (filename_ptr) |ptr| ptr[0..filename_len] else "sa-report.json";
    const path = std.heap.page_allocator.dupe(u8, filename) catch return fail();
    defer std.heap.page_allocator.free(path);

    const file_path = if (std.fs.path.isAbsolute(path))
        path
    else
        std.fs.path.resolve(std.heap.page_allocator, &.{path}) catch return fail();
    if (file_path.ptr != path.ptr) {
        defer std.heap.page_allocator.free(file_path);
    }

    const dir_file = if (std.fs.path.isAbsolute(file_path))
        std.fs.createFileAbsolute(file_path, .{}) catch return fail()
    else
        std.fs.cwd().createFile(file_path, .{}) catch return fail();
    defer dir_file.close();
    dir_file.writeAll(report_ptr.?[0..report_len]) catch return fail();
    return writeOwnedString(out_ptr, out_len, file_path);
}

// --- SEA ---
pub export fn sa_node_plugin_sea_is_sea(out_bool: ?*u32) u32 {
    return writeOwnedBool(out_bool, std.posix.getenv("SA_NODE_SEA_ASSETS") != null or std.posix.getenv("SA_NODE_SEA_ASSET_DIR") != null);
}

pub export fn sa_node_plugin_sea_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "sea", true, "single executable application shims are exposed");
}

pub export fn sa_node_plugin_sea_asset_keys_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.append('[') catch return fail();
    var first = true;

    if (std.process.getEnvVarOwned(std.heap.page_allocator, "SA_NODE_SEA_ASSETS")) |json_text| {
        defer std.heap.page_allocator.free(json_text);
        var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, json_text, .{}) catch null;
        if (parsed) |*tree| {
            defer tree.deinit();
            if (tree.value == .object) {
                var it = tree.value.object.iterator();
                while (it.next()) |entry| {
                    if (!first) out.append(',') catch return fail();
                    first = false;
                    appendJsonString(&out, entry.key_ptr.*) catch return fail();
                }
            }
        }
    } else |_| {}

    if (std.process.getEnvVarOwned(std.heap.page_allocator, "SA_NODE_SEA_ASSET_DIR")) |dir_path| {
        defer std.heap.page_allocator.free(dir_path);
        var dir = if (std.fs.path.isAbsolute(dir_path))
            std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch null
        else
            std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch null;
        if (dir) |*d| {
            defer d.close();
            var it = d.iterate();
            while (it.next() catch null) |entry| {
                if (entry.kind != .file) continue;
                if (!first) out.append(',') catch return fail();
                first = false;
                appendJsonString(&out, entry.name) catch return fail();
            }
        }
    } else |_| {}

    out.append(']') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn seaLookupAsset(key: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "SA_NODE_SEA_ASSETS")) |json_text| {
        defer allocator.free(json_text);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
        defer parsed.deinit();
        if (parsed.value == .object) {
            if (parsed.value.object.get(key)) |value| {
                return switch (value) {
                    .string => |s| allocator.dupe(u8, s),
                    .integer => |n| std.fmt.allocPrint(allocator, "{d}", .{n}),
                    .float => |n| std.fmt.allocPrint(allocator, "{d}", .{n}),
                    .bool => |b| allocator.dupe(u8, if (b) "true" else "false"),
                    else => blk: {
                        var out = std.ArrayList(u8).init(allocator);
                        errdefer out.deinit();
                        try std.json.stringify(value, .{}, out.writer());
                        break :blk out.toOwnedSlice();
                    },
                };
            }
        }
    } else |_| {}

    if (std.process.getEnvVarOwned(allocator, "SA_NODE_SEA_ASSET_DIR")) |dir_path| {
        defer allocator.free(dir_path);
        if (std.mem.indexOfScalar(u8, key, '/') != null or std.mem.indexOfScalar(u8, key, 0) != null) return error.AssetNotFound;
        const full_path = try std.fs.path.join(allocator, &.{ dir_path, key });
        defer allocator.free(full_path);
        const file = if (std.fs.path.isAbsolute(full_path))
            std.fs.openFileAbsolute(full_path, .{}) catch return error.AssetNotFound
        else
            std.fs.cwd().openFile(full_path, .{}) catch return error.AssetNotFound;
        defer file.close();
        return file.readToEndAlloc(allocator, 64 * 1024 * 1024);
    } else |_| {}

    return error.AssetNotFound;
}

fn seaWriteEncodedAsset(bytes: []const u8, encoding: []const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (encoding.len == 0 or std.ascii.eqlIgnoreCase(encoding, "utf8") or std.ascii.eqlIgnoreCase(encoding, "utf-8")) {
        return writeOwnedBytes(out_ptr, out_len, bytes);
    }
    if (std.ascii.eqlIgnoreCase(encoding, "base64")) {
        const enc_len = std.base64.standard.Encoder.calcSize(bytes.len);
        const out = std.heap.page_allocator.alloc(u8, enc_len) catch return fail();
        _ = std.base64.standard.Encoder.encode(out, bytes);
        out_ptr.?.* = out.ptr;
        out_len.?.* = out.len;
        return 0;
    }
    if (std.ascii.eqlIgnoreCase(encoding, "hex")) {
        const out = std.heap.page_allocator.alloc(u8, bytes.len * 2) catch return fail();
        _ = std.fmt.bufPrint(out, "{s}", .{std.fmt.fmtSliceHexLower(bytes)}) catch {
            std.heap.page_allocator.free(out);
            return fail();
        };
        out_ptr.?.* = out.ptr;
        out_len.?.* = out.len;
        return 0;
    }
    return fail();
}

pub export fn sa_node_plugin_sea_get_asset(key_ptr: ?[*]const u8, key_len: u64, encoding_ptr: ?[*]const u8, encoding_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const key = if (key_ptr) |ptr| ptr[0..key_len] else return fail();
    const encoding = if (encoding_ptr) |ptr| ptr[0..encoding_len] else "";
    const bytes = seaLookupAsset(key, std.heap.page_allocator) catch {
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return fail();
    };
    defer std.heap.page_allocator.free(bytes);
    return seaWriteEncodedAsset(bytes, encoding, out_ptr, out_len);
}

pub export fn sa_node_plugin_sea_get_raw_asset(key_ptr: ?[*]const u8, key_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const key = if (key_ptr) |ptr| ptr[0..key_len] else return fail();
    const bytes = seaLookupAsset(key, std.heap.page_allocator) catch {
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return fail();
    };
    out_ptr.?.* = bytes.ptr;
    out_len.?.* = bytes.len;
    return 0;
}

pub export fn sa_node_plugin_sea_get_asset_as_blob(key_ptr: ?[*]const u8, key_len: u64, out_ptr: ?*?*anyopaque) u32 {
    const key = if (key_ptr) |ptr| ptr[0..key_len] else return fail();
    const bytes = seaLookupAsset(key, std.heap.page_allocator) catch {
        out_ptr.?.* = null;
        return fail();
    };
    const blob = std.heap.page_allocator.create(WebStreamHandle) catch {
        std.heap.page_allocator.free(bytes);
        return fail();
    };
    blob.* = .{ .allocator = std.heap.page_allocator, .kind = .readable, .buffer = std.ArrayList(u8).init(std.heap.page_allocator) };
    blob.buffer.appendSlice(bytes) catch {
        std.heap.page_allocator.free(bytes);
        blob.buffer.deinit();
        std.heap.page_allocator.destroy(blob);
        return fail();
    };
    std.heap.page_allocator.free(bytes);
    out_ptr.?.* = @ptrCast(blob);
    return 0;
}

// --- Trace events ---
const TracingHandle = struct {
    allocator: std.mem.Allocator,
    categories: []u8,
    enabled: bool,

    fn deinit(self: *TracingHandle) void {
        self.allocator.free(self.categories);
        self.allocator.destroy(self);
    }
};

pub export fn sa_node_plugin_trace_events_create_tracing(categories_ptr: ?[*]const u8, categories_len: u64, out_handle: ?*?*anyopaque) u32 {
    const categories = categories_ptr.?[0..categories_len];
    const allocator = std.heap.page_allocator;
    const handle = allocator.create(TracingHandle) catch return fail();
    handle.* = .{
        .allocator = allocator,
        .categories = allocator.dupe(u8, categories) catch {
            allocator.destroy(handle);
            return fail();
        },
        .enabled = false,
    };
    out_handle.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_trace_events_tracing_enable(handle_ptr: ?*anyopaque) u32 {
    const handle: *TracingHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    handle.enabled = true;
    return 0;
}

pub export fn sa_node_plugin_trace_events_tracing_disable(handle_ptr: ?*anyopaque) u32 {
    const handle: *TracingHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    handle.enabled = false;
    return 0;
}

pub export fn sa_node_plugin_trace_events_get_enabled_categories(handle_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TracingHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    if (!handle.enabled) {
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return 0;
    }
    return writeOwnedString(out_ptr, out_len, handle.categories);
}

pub export fn sa_node_plugin_trace_events_tracing_free(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| {
        const handle: *TracingHandle = @ptrCast(@alignCast(ptr));
        handle.deinit();
    }
    return 0;
}

// --- TTY ---
const TtyHandle = struct {
    allocator: std.mem.Allocator,
    fd: posix.fd_t,
    is_write: bool,
    raw_mode: bool = false,
    saved_termios: ?posix.termios = null,

    fn deinit(self: *TtyHandle) void {
        self.allocator.destroy(self);
    }
};

fn ttyFdFromU64(fd: u64) ?posix.fd_t {
    return std.math.cast(posix.fd_t, fd);
}

fn ttyHandleFd(handle_ptr: ?*anyopaque, default_fd: posix.fd_t) posix.fd_t {
    if (handle_ptr) |ptr| {
        const handle: *TtyHandle = @ptrCast(@alignCast(ptr));
        return handle.fd;
    }
    return default_fd;
}

fn makeTtyHandle(fd: posix.fd_t, is_write: bool, out_handle: ?*?*anyopaque) u32 {
    const handle = std.heap.page_allocator.create(TtyHandle) catch return fail();
    handle.* = .{
        .allocator = std.heap.page_allocator,
        .fd = fd,
        .is_write = is_write,
        .raw_mode = false,
    };
    out_handle.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_tty_isatty(fd: u64, out_bool: ?*u64) u32 {
    out_bool.?.* = if (posix.isatty(ttyFdFromU64(fd) orelse return fail())) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_tty_read_stream_new(fd: u64, out_handle: ?*?*anyopaque) u32 {
    return makeTtyHandle(ttyFdFromU64(fd) orelse return fail(), false, out_handle);
}

pub export fn sa_node_plugin_tty_write_stream_new(fd: u64, out_handle: ?*?*anyopaque) u32 {
    return makeTtyHandle(ttyFdFromU64(fd) orelse return fail(), true, out_handle);
}

pub export fn sa_node_plugin_tty_stream_set_raw_mode(handle_ptr: ?*anyopaque, flag: u64) u32 {
    const handle = if (handle_ptr) |ptr| @as(*TtyHandle, @ptrCast(@alignCast(ptr))) else return 0;
    if (!posix.isatty(handle.fd)) {
        handle.raw_mode = flag != 0;
        return 0;
    }
    if (flag != 0) {
        var term = posix.tcgetattr(handle.fd) catch return fail();
        if (handle.saved_termios == null) handle.saved_termios = term;
        term.iflag.BRKINT = false;
        term.iflag.ICRNL = false;
        term.iflag.INPCK = false;
        term.iflag.ISTRIP = false;
        term.iflag.IXON = false;
        term.oflag.OPOST = false;
        term.cflag.CSIZE = .CS8;
        term.lflag.ECHO = false;
        term.lflag.ICANON = false;
        term.lflag.IEXTEN = false;
        term.lflag.ISIG = false;
        term.cc[@intFromEnum(linux.V.MIN)] = 1;
        term.cc[@intFromEnum(linux.V.TIME)] = 0;
        posix.tcsetattr(handle.fd, .FLUSH, term) catch return fail();
        handle.raw_mode = true;
    } else {
        if (handle.saved_termios) |saved| posix.tcsetattr(handle.fd, .FLUSH, saved) catch return fail();
        handle.raw_mode = false;
    }
    return 0;
}

pub export fn sa_node_plugin_tty_stream_get_window_size(handle_ptr: ?*anyopaque, out_cols: ?*u64, out_rows: ?*u64) u32 {
    var cols: u64 = 0;
    var rows: u64 = 0;
    const fd = ttyHandleFd(handle_ptr, 1);
    if (posix.isatty(fd)) {
        var wsz: posix.winsize = undefined;
        const rc = linux.ioctl(fd, linux.T.IOCGWINSZ, @intFromPtr(&wsz));
        if (posix.errno(rc) == .SUCCESS) {
            cols = wsz.col;
            rows = wsz.row;
        }
    }
    if (std.posix.getenv("COLUMNS")) |value| cols = std.fmt.parseInt(u64, value, 10) catch 0;
    if (std.posix.getenv("LINES")) |value| rows = std.fmt.parseInt(u64, value, 10) catch 0;
    out_cols.?.* = cols;
    out_rows.?.* = rows;
    return 0;
}

pub export fn sa_node_plugin_tty_stream_get_color_depth(handle_ptr: ?*anyopaque, out_depth: ?*u64) u32 {
    const fd = ttyHandleFd(handle_ptr, 1);
    var depth: u64 = 1;
    if (std.posix.getenv("NO_COLOR") != null) {
        depth = 1;
    } else if (std.posix.getenv("FORCE_COLOR")) |value| {
        depth = if (std.mem.eql(u8, value, "0")) 1 else 24;
    } else if (std.posix.getenv("COLORTERM")) |value| {
        depth = if (std.mem.indexOf(u8, value, "truecolor") != null or std.mem.indexOf(u8, value, "24bit") != null) 24 else 8;
    } else if (std.posix.getenv("TERM")) |value| {
        depth = if (std.mem.indexOf(u8, value, "256color") != null) 8 else if (posix.isatty(fd)) 4 else 1;
    } else if (posix.isatty(fd)) {
        depth = 4;
    }
    out_depth.?.* = depth;
    return 0;
}

pub export fn sa_node_plugin_tty_stream_has_colors(handle_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    var depth: u64 = 0;
    if (sa_node_plugin_tty_stream_get_color_depth(handle_ptr, &depth) != 0) return fail();
    out_bool.?.* = if (depth > 1) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_tty_stream_free(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| {
        const handle: *TtyHandle = @ptrCast(@alignCast(ptr));
        handle.deinit();
    }
    return 0;
}

// --- Worker threads ---
var worker_env_data = std.StringHashMap([]u8).init(std.heap.page_allocator);
var worker_main_thread_messages = std.ArrayList([]u8).init(std.heap.page_allocator);

const MessagePortHandle = struct {
    allocator: std.mem.Allocator,
    inbox: std.ArrayList([]u8),
    peer: ?*MessagePortHandle = null,
    closed: bool = false,

    fn init(allocator: std.mem.Allocator) !*MessagePortHandle {
        const self = try allocator.create(MessagePortHandle);
        self.* = .{
            .allocator = allocator,
            .inbox = std.ArrayList([]u8).init(allocator),
            .peer = null,
            .closed = false,
        };
        return self;
    }

    fn deinit(self: *MessagePortHandle) void {
        for (self.inbox.items) |msg| self.allocator.free(msg);
        self.inbox.deinit();
        self.allocator.destroy(self);
    }
};

pub export fn sa_node_plugin_worker_threads_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "worker_threads", true, "main-thread compatibility");
}

pub export fn sa_node_plugin_worker_threads_worker_data(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "null");
}

pub export fn sa_node_plugin_worker_threads_is_main_thread(out_bool: ?*u64) u32 {
    out_bool.?.* = 1;
    return 0;
}

pub export fn sa_node_plugin_worker_threads_is_internal_thread(out_bool: ?*u64) u32 {
    out_bool.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_worker_threads_thread_id(out_id: ?*u64) u32 {
    out_id.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_worker_threads_thread_name(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "main");
}

fn rlimitMb(resource: std.posix.rlimit_resource) u64 {
    const limit = std.posix.getrlimit(resource) catch return 0;
    const cur: u64 = @intCast(limit.cur);
    if (cur == 0 or cur > (1 << 60)) return 0;
    return cur / (1024 * 1024);
}

pub export fn sa_node_plugin_worker_threads_resource_limits_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const stack_mb = rlimitMb(.STACK);
    const old_mb = rlimitMb(.AS);
    var buf: [160]u8 = undefined;
    const json = std.fmt.bufPrint(
        &buf,
        "{{\"maxOldGenerationSizeMb\":{d},\"maxYoungGenerationSizeMb\":0,\"codeRangeSizeMb\":0,\"stackSizeMb\":{d}}}",
        .{ old_mb, stack_mb },
    ) catch return fail();
    return writeOwnedString(out_ptr, out_len, json);
}

pub export fn sa_node_plugin_worker_threads_set_environment_data(key_ptr: ?[*]const u8, key_len: u64, value_ptr: ?[*]const u8, value_len: u64) u32 {
    const key = if (key_ptr) |ptr| ptr[0..key_len] else "";
    const value = if (value_ptr) |ptr| ptr[0..value_len] else "";
    const key_dup = std.heap.page_allocator.dupe(u8, key) catch return fail();
    const value_dup = std.heap.page_allocator.dupe(u8, value) catch {
        std.heap.page_allocator.free(key_dup);
        return fail();
    };
    const replaced = worker_env_data.fetchPut(key_dup, value_dup) catch {
        std.heap.page_allocator.free(key_dup);
        std.heap.page_allocator.free(value_dup);
        return fail();
    };
    if (replaced) |existing| {
        std.heap.page_allocator.free(existing.key);
        std.heap.page_allocator.free(existing.value);
    }
    return 0;
}

pub export fn sa_node_plugin_worker_threads_get_environment_data(key_ptr: ?[*]const u8, key_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const key = if (key_ptr) |ptr| ptr[0..key_len] else "";
    if (worker_env_data.get(key)) |value| {
        return writeOwnedBytes(out_ptr, out_len, value);
    }
    out_ptr.?.* = null;
    out_len.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_worker_threads_message_channel_new(out_port1: ?*?*anyopaque, out_port2: ?*?*anyopaque) u32 {
    const allocator = std.heap.page_allocator;
    const port1 = MessagePortHandle.init(allocator) catch return fail();
    const port2 = MessagePortHandle.init(allocator) catch {
        port1.deinit();
        return fail();
    };
    port1.peer = port2;
    port2.peer = port1;
    out_port1.?.* = @ptrCast(port1);
    out_port2.?.* = @ptrCast(port2);
    return 0;
}

pub export fn sa_node_plugin_worker_threads_message_port_post_message(port_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const port: *MessagePortHandle = @ptrCast(@alignCast(port_ptr orelse return fail()));
    if (port.closed) return fail();
    const peer = port.peer orelse return fail();
    const data = data_ptr.?[0..data_len];
    const dup = std.heap.page_allocator.dupe(u8, data) catch return fail();
    peer.inbox.append(dup) catch {
        std.heap.page_allocator.free(dup);
        return fail();
    };
    return 0;
}

pub export fn sa_node_plugin_worker_threads_message_port_receive_message(port_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const port: *MessagePortHandle = @ptrCast(@alignCast(port_ptr orelse return fail()));
    if (port.inbox.items.len == 0) {
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return 0;
    }
    const msg = port.inbox.orderedRemove(0);
    out_ptr.?.* = msg.ptr;
    out_len.?.* = msg.len;
    return 0;
}

pub export fn sa_node_plugin_worker_threads_receive_message_on_port(port_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_worker_threads_message_port_receive_message(port_ptr, out_ptr, out_len);
}

pub export fn sa_node_plugin_worker_threads_post_message_to_thread(thread_id: u64, data_ptr: ?[*]const u8, data_len: u64, out_bool: ?*u64) u32 {
    if (thread_id != 0 and thread_id != 1) {
        out_bool.?.* = 0;
        return 0;
    }
    const data = if (data_ptr) |ptr| ptr[0..data_len] else "";
    const dup = std.heap.page_allocator.dupe(u8, data) catch return fail();
    worker_main_thread_messages.append(dup) catch {
        std.heap.page_allocator.free(dup);
        return fail();
    };
    out_bool.?.* = 1;
    return 0;
}

pub export fn sa_node_plugin_worker_threads_message_port_close(port_ptr: ?*anyopaque) u32 {
    const port: *MessagePortHandle = @ptrCast(@alignCast(port_ptr orelse return fail()));
    port.closed = true;
    return 0;
}

pub export fn sa_node_plugin_worker_threads_message_port_free(port_ptr: ?*anyopaque) u32 {
    if (port_ptr) |ptr| {
        const port: *MessagePortHandle = @ptrCast(@alignCast(ptr));
        if (port.peer) |peer| peer.peer = null;
        port.deinit();
    }
    return 0;
}

// --- Child process ---
pub export fn sa_node_plugin_child_process_exec_sync_json(argv_ptr: ?*const anyopaque, argv_len: u64, cwd_ptr: ?[*]const u8, cwd_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const slices: [*]const SaSlice = @ptrCast(@alignCast(argv_ptr orelse return fail()));
    var argv = std.heap.page_allocator.alloc([]const u8, argv_len) catch return fail();
    defer std.heap.page_allocator.free(argv);

    var i: usize = 0;
    while (i < argv_len) : (i += 1) {
        argv[i] = slices[i].ptr[0..slices[i].len];
    }

    var out_code: u32 = 0;
    var stdout_ptr: ?[*]const u8 = null;
    var stdout_len: u64 = 0;
    var stderr_ptr: ?[*]const u8 = null;
    var stderr_len: u64 = 0;

    const status = base.sa_node_plugin_process_exec(
        @ptrCast(argv.ptr),
        argv_len,
        cwd_ptr,
        cwd_len,
        &out_code,
        &stdout_ptr,
        &stdout_len,
        &stderr_ptr,
        &stderr_len,
    );
    if (status != 0) return status;
    if (stdout_ptr) |ptr| {
        defer _ = base.sa_node_plugin_free_buffer(ptr, stdout_len);
    }
    if (stderr_ptr) |ptr| {
        defer _ = base.sa_node_plugin_free_buffer(ptr, stderr_len);
    }

    const stdout = if (stdout_ptr) |ptr| ptr[0..stdout_len] else "";
    const stderr = if (stderr_ptr) |ptr| ptr[0..stderr_len] else "";
    const payload = .{
        .code = out_code,
        .stdout = stdout,
        .stderr = stderr,
    };
    return writeJsonValue(out_ptr, out_len, payload);
}

pub export fn sa_node_plugin_child_process_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "child_process", true, "sync exec wrapper over process_exec");
}

// --- Cluster ---
const cluster_sched_none: u64 = 1;
const cluster_sched_rr: u64 = 2;

var cluster_scheduling_policy: u64 = cluster_sched_rr;

const ClusterPrimaryConfig = struct {
    allocator: std.mem.Allocator,
    exec: ?[]u8 = null,
    args: std.ArrayList([]u8),
    cwd: ?[]u8 = null,
    env: std.process.EnvMap,
    use_custom_env: bool = false,

    fn init(allocator: std.mem.Allocator) ClusterPrimaryConfig {
        return .{
            .allocator = allocator,
            .args = std.ArrayList([]u8).init(allocator),
            .env = std.process.EnvMap.init(allocator),
        };
    }

    fn clear(self: *ClusterPrimaryConfig) void {
        if (self.exec) |exec| {
            self.allocator.free(exec);
            self.exec = null;
        }
        if (self.cwd) |cwd| {
            self.allocator.free(cwd);
            self.cwd = null;
        }
        for (self.args.items) |arg| self.allocator.free(arg);
        self.args.clearRetainingCapacity();
        self.env.deinit();
        self.env = std.process.EnvMap.init(self.allocator);
        self.use_custom_env = false;
    }
};

var cluster_primary_config = ClusterPrimaryConfig.init(std.heap.page_allocator);

const ClusterWorkerHandle = struct {
    allocator: std.mem.Allocator,
    child: std.process.Child,
    command: []u8,
    args: std.ArrayList([]u8),
    cwd: ?[]u8 = null,
    env_count: u64 = 0,
    connected: bool = true,
    disconnected_requested: bool = false,
    exited: bool = false,
    exit_code: ?u8 = null,
    signal_code: ?u32 = null,

    fn deinit(self: *ClusterWorkerHandle) void {
        if (!self.exited) {
            if (self.child.stdin) |*stdin_file| {
                stdin_file.close();
                self.child.stdin = null;
            }
            if (self.child.stdout) |*stdout_file| {
                stdout_file.close();
                self.child.stdout = null;
            }
            if (self.child.stderr) |*stderr_file| {
                stderr_file.close();
                self.child.stderr = null;
            }
            std.posix.kill(self.child.id, std.posix.SIG.KILL) catch {};
            const waited = std.posix.waitpid(self.child.id, 0);
            clusterWorkerDecodeStatus(self, waited.status);
        } else {
            if (self.child.stdin) |*stdin_file| {
                stdin_file.close();
                self.child.stdin = null;
            }
            if (self.child.stdout) |*stdout_file| {
                stdout_file.close();
                self.child.stdout = null;
            }
            if (self.child.stderr) |*stderr_file| {
                stderr_file.close();
                self.child.stderr = null;
            }
        }
        self.allocator.free(self.command);
        if (self.cwd) |cwd| self.allocator.free(cwd);
        for (self.args.items) |arg| self.allocator.free(arg);
        self.args.deinit();
        self.allocator.destroy(self);
    }
};

fn clusterSignalNameToNumber(name: []const u8) ?u8 {
    if (name.len == 0) return std.posix.SIG.TERM;
    if (std.ascii.eqlIgnoreCase(name, "0")) return 0;
    if (std.ascii.eqlIgnoreCase(name, "SIGTERM") or std.ascii.eqlIgnoreCase(name, "TERM")) return std.posix.SIG.TERM;
    if (std.ascii.eqlIgnoreCase(name, "SIGKILL") or std.ascii.eqlIgnoreCase(name, "KILL")) return std.posix.SIG.KILL;
    if (std.ascii.eqlIgnoreCase(name, "SIGINT") or std.ascii.eqlIgnoreCase(name, "INT")) return std.posix.SIG.INT;
    if (std.ascii.eqlIgnoreCase(name, "SIGHUP") or std.ascii.eqlIgnoreCase(name, "HUP")) return std.posix.SIG.HUP;
    if (std.ascii.eqlIgnoreCase(name, "SIGQUIT") or std.ascii.eqlIgnoreCase(name, "QUIT")) return std.posix.SIG.QUIT;
    if (std.ascii.eqlIgnoreCase(name, "SIGABRT") or std.ascii.eqlIgnoreCase(name, "ABRT")) return std.posix.SIG.ABRT;
    if (std.ascii.eqlIgnoreCase(name, "SIGALRM") or std.ascii.eqlIgnoreCase(name, "ALRM")) return std.posix.SIG.ALRM;
    if (std.ascii.eqlIgnoreCase(name, "SIGUSR1") or std.ascii.eqlIgnoreCase(name, "USR1")) return std.posix.SIG.USR1;
    if (std.ascii.eqlIgnoreCase(name, "SIGUSR2") or std.ascii.eqlIgnoreCase(name, "USR2")) return std.posix.SIG.USR2;
    if (std.ascii.eqlIgnoreCase(name, "SIGPIPE") or std.ascii.eqlIgnoreCase(name, "PIPE")) return std.posix.SIG.PIPE;
    if (std.ascii.eqlIgnoreCase(name, "SIGCHLD") or std.ascii.eqlIgnoreCase(name, "CHLD")) return std.posix.SIG.CHLD;
    if (std.ascii.eqlIgnoreCase(name, "SIGCONT") or std.ascii.eqlIgnoreCase(name, "CONT")) return std.posix.SIG.CONT;
    if (std.ascii.eqlIgnoreCase(name, "SIGSTOP") or std.ascii.eqlIgnoreCase(name, "STOP")) return std.posix.SIG.STOP;
    if (std.ascii.eqlIgnoreCase(name, "SIGTSTP") or std.ascii.eqlIgnoreCase(name, "TSTP")) return std.posix.SIG.TSTP;
    if (std.ascii.eqlIgnoreCase(name, "SIGTTIN") or std.ascii.eqlIgnoreCase(name, "TTIN")) return std.posix.SIG.TTIN;
    if (std.ascii.eqlIgnoreCase(name, "SIGTTOU") or std.ascii.eqlIgnoreCase(name, "TTOU")) return std.posix.SIG.TTOU;
    return null;
}

fn clusterSignalFromNumber(signal: u64) ?u8 {
    if (signal > std.math.maxInt(u8)) return null;
    return @intCast(signal);
}

fn clusterParseStoredArgs(args_ptr: ?[*]const u8, args_len: u64, out: *std.ArrayList([]u8), allocator: std.mem.Allocator) !void {
    if (args_len == 0) return;
    const ptr = args_ptr orelse return error.InvalidArgs;
    if (args_len <= 64) {
        const first_ptr = std.mem.readInt(usize, ptr[0..@sizeOf(usize)], .little);
        const first_len = std.mem.readInt(u64, ptr[8..16], .little);
        if (first_ptr > 4096 and first_len > 0 and first_len <= 1024 * 1024) {
            var i: usize = 0;
            while (i < args_len) : (i += 1) {
                const off = i * 16;
                const arg_ptr_int = std.mem.readInt(usize, ptr[off..][0..@sizeOf(usize)], .little);
                const arg_len = std.mem.readInt(u64, ptr[off + 8 ..][0..8], .little);
                if (arg_ptr_int == 0 or arg_len > 1024 * 1024) return error.InvalidArgs;
                const arg_ptr: [*]const u8 = @ptrFromInt(arg_ptr_int);
                try out.append(try allocator.dupe(u8, arg_ptr[0..@intCast(arg_len)]));
            }
            return;
        }
    }
    try out.append(try allocator.dupe(u8, ptr[0..args_len]));
}

fn clusterSetNonBlocking(file: std.fs.File) u32 {
    const flags = std.posix.fcntl(file.handle, std.posix.F.GETFL, 0) catch return fail();
    const new_flags = flags | (@as(usize, 1) << @bitOffsetOf(std.posix.O, "NONBLOCK"));
    _ = std.posix.fcntl(file.handle, std.posix.F.SETFL, new_flags) catch return fail();
    return 0;
}

fn clusterCloseStreams(worker: *ClusterWorkerHandle) void {
    if (worker.child.stdin) |*stdin_file| {
        stdin_file.close();
        worker.child.stdin = null;
    }
    if (worker.child.stdout) |*stdout_file| {
        stdout_file.close();
        worker.child.stdout = null;
    }
    if (worker.child.stderr) |*stderr_file| {
        stderr_file.close();
        worker.child.stderr = null;
    }
}

fn clusterWorkerDecodeStatus(worker: *ClusterWorkerHandle, status: u32) void {
    worker.exited = true;
    worker.connected = false;
    if (std.c.W.IFEXITED(status)) {
        worker.exit_code = std.c.W.EXITSTATUS(status);
        worker.signal_code = null;
    } else if (std.c.W.IFSIGNALED(status)) {
        worker.exit_code = null;
        worker.signal_code = std.c.W.TERMSIG(status);
    } else {
        worker.exit_code = null;
        worker.signal_code = null;
    }
}

fn clusterPrimarySnapshotJson(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"exec\":") catch return fail();
    if (cluster_primary_config.exec) |exec| {
        appendJsonString(&out, exec) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"args\":[") catch return fail();
    for (cluster_primary_config.args.items, 0..) |arg, i| {
        if (i != 0) out.append(',') catch return fail();
        appendJsonString(&out, arg) catch return fail();
    }
    out.appendSlice("],\"cwd\":") catch return fail();
    if (cluster_primary_config.cwd) |cwd| {
        appendJsonString(&out, cwd) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"useCustomEnv\":") catch return fail();
    out.appendSlice(if (cluster_primary_config.use_custom_env) "true" else "false") catch return fail();
    out.appendSlice(",\"env\":{") catch return fail();
    var first = true;
    var it = cluster_primary_config.env.iterator();
    while (it.next()) |entry| {
        if (!first) out.append(',') catch return fail();
        first = false;
        appendJsonString(&out, entry.key_ptr.*) catch return fail();
        out.append(':') catch return fail();
        appendJsonString(&out, entry.value_ptr.*) catch return fail();
    }
    out.appendSlice("}}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn clusterSetupPrimaryJson(config_ptr: ?[*]const u8, config_len: u64) u32 {
    const config_text = (config_ptr orelse return fail())[0..config_len];
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, config_text, .{}) catch return fail();
    defer parsed.deinit();
    if (parsed.value != .object) return fail();

    cluster_primary_config.clear();
    errdefer cluster_primary_config.clear();

    if (parsed.value.object.get("exec")) |exec_value| {
        if (exec_value != .string) return fail();
        cluster_primary_config.exec = std.heap.page_allocator.dupe(u8, exec_value.string) catch return fail();
    }

    if (parsed.value.object.get("args")) |args_value| {
        if (args_value != .array) return fail();
        for (args_value.array.items) |item| {
            if (item != .string) return fail();
            cluster_primary_config.args.append(std.heap.page_allocator.dupe(u8, item.string) catch return fail()) catch return fail();
        }
    }

    if (parsed.value.object.get("cwd")) |cwd_value| {
        if (cwd_value == .null) {
            cluster_primary_config.cwd = null;
        } else {
            if (cwd_value != .string) return fail();
            cluster_primary_config.cwd = std.heap.page_allocator.dupe(u8, cwd_value.string) catch return fail();
        }
    }

    if (parsed.value.object.get("env")) |env_value| {
        if (env_value != .object) return fail();
        cluster_primary_config.use_custom_env = true;
        var env_it = env_value.object.iterator();
        while (env_it.next()) |entry| {
            if (entry.value_ptr.* != .string) return fail();
            cluster_primary_config.env.put(entry.key_ptr.*, entry.value_ptr.*.string) catch return fail();
        }
    }

    return 0;
}

fn clusterWorkerRefresh(worker: *ClusterWorkerHandle) void {
    if (worker.exited) return;
    const waited = std.posix.waitpid(worker.child.id, std.c.W.NOHANG);
    if (waited.pid == 0) return;
    clusterWorkerDecodeStatus(worker, waited.status);
}

fn clusterWorkerHandle(worker_ptr: ?*anyopaque) ?*ClusterWorkerHandle {
    return if (worker_ptr) |ptr| @ptrCast(@alignCast(ptr)) else null;
}

fn clusterWorkerSnapshotJson(worker: *ClusterWorkerHandle, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    clusterWorkerRefresh(worker);
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"pid\":") catch return fail();
    out.writer().print("{d}", .{worker.child.id}) catch return fail();
    out.appendSlice(",\"connected\":") catch return fail();
    out.appendSlice(if (worker.connected) "true" else "false") catch return fail();
    out.appendSlice(",\"exited\":") catch return fail();
    out.appendSlice(if (worker.exited) "true" else "false") catch return fail();
    out.appendSlice(",\"command\":") catch return fail();
    appendJsonString(&out, worker.command) catch return fail();
    out.appendSlice(",\"args\":[") catch return fail();
    for (worker.args.items, 0..) |arg, i| {
        if (i != 0) out.append(',') catch return fail();
        appendJsonString(&out, arg) catch return fail();
    }
    out.append(']') catch return fail();
    out.appendSlice(",\"cwd\":") catch return fail();
    if (worker.cwd) |cwd| {
        appendJsonString(&out, cwd) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"envCount\":") catch return fail();
    out.writer().print("{d}", .{worker.env_count}) catch return fail();
    out.appendSlice(",\"disconnectRequested\":") catch return fail();
    out.appendSlice(if (worker.disconnected_requested) "true" else "false") catch return fail();
    out.appendSlice(",\"exitCode\":") catch return fail();
    if (worker.exit_code) |code| {
        out.writer().print("{d}", .{code}) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"signalCode\":") catch return fail();
    if (worker.signal_code) |sig| {
        out.writer().print("{d}", .{sig}) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn clusterSpawnWorker(exec: []const u8, args: []const []const u8, cwd: ?[]const u8, env_map: ?*const std.process.EnvMap, env_count: u64, out_worker: ?*?*anyopaque) u32 {
    const allocator = std.heap.page_allocator;
    const argv = allocator.alloc([]const u8, args.len + 1) catch return fail();
    defer allocator.free(argv);
    argv[0] = exec;
    for (args, 0..) |arg, i| argv[i + 1] = arg;

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.cwd = cwd;
    child.env_map = env_map;
    child.spawn() catch return fail();
    if (clusterSetNonBlocking(child.stdout.?) != 0) {
        _ = child.kill() catch {};
        return fail();
    }

    const worker = allocator.create(ClusterWorkerHandle) catch {
        _ = child.kill() catch {};
        return fail();
    };
    errdefer allocator.destroy(worker);

    const command = allocator.dupe(u8, exec) catch {
        _ = child.kill() catch {};
        return fail();
    };
    errdefer allocator.free(command);

    var owned_args = std.ArrayList([]u8).init(allocator);
    errdefer {
        for (owned_args.items) |arg| allocator.free(arg);
        owned_args.deinit();
    }
    for (args) |arg| owned_args.append(allocator.dupe(u8, arg) catch {
        _ = child.kill() catch {};
        return fail();
    }) catch {
        _ = child.kill() catch {};
        return fail();
    };

    worker.* = .{
        .allocator = allocator,
        .child = child,
        .command = command,
        .args = owned_args,
        .cwd = if (cwd) |dir| allocator.dupe(u8, dir) catch {
            _ = child.kill() catch {};
            return fail();
        } else null,
        .env_count = env_count,
    };
    out_worker.?.* = @ptrCast(worker);
    return 0;
}

pub export fn sa_node_plugin_cluster_is_primary(out_bool: ?*u64) u32 {
    out_bool.?.* = 1;
    return 0;
}

pub export fn sa_node_plugin_cluster_is_worker(out_bool: ?*u64) u32 {
    out_bool.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_cluster_get_scheduling_policy(out_policy: ?*u64) u32 {
    out_policy.?.* = cluster_scheduling_policy;
    return 0;
}

pub export fn sa_node_plugin_cluster_set_scheduling_policy(policy: u64) u32 {
    if (policy != cluster_sched_none and policy != cluster_sched_rr) return fail();
    cluster_scheduling_policy = policy;
    return 0;
}

pub export fn sa_node_plugin_cluster_setup_primary(exec_ptr: ?[*]const u8, exec_len: u64, args_ptr: ?[*]const u8, args_len: u64) u32 {
    const exec = if (exec_len == 0) "" else (exec_ptr orelse return fail())[0..exec_len];
    cluster_primary_config.clear();
    errdefer cluster_primary_config.clear();
    if (exec.len > 0) {
        cluster_primary_config.exec = std.heap.page_allocator.dupe(u8, exec) catch return fail();
    }
    clusterParseStoredArgs(args_ptr, args_len, &cluster_primary_config.args, std.heap.page_allocator) catch {
        cluster_primary_config.clear();
        return fail();
    };
    return 0;
}

pub export fn sa_node_plugin_cluster_setup_primary_json(config_ptr: ?[*]const u8, config_len: u64) u32 {
    return clusterSetupPrimaryJson(config_ptr, config_len);
}

pub export fn sa_node_plugin_cluster_primary_snapshot_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return clusterPrimarySnapshotJson(out_ptr, out_len);
}

pub export fn sa_node_plugin_cluster_fork(exec_ptr: ?[*]const u8, exec_len: u64, args_ptr: ?[*]const u8, args_len: u64, out_worker: ?*?*anyopaque) u32 {
    const allocator = std.heap.page_allocator;
    var effective_args = std.ArrayList([]u8).init(allocator);
    defer {
        for (effective_args.items) |arg| allocator.free(arg);
        effective_args.deinit();
    }

    const exec = blk: {
        if (exec_len > 0) break :blk (exec_ptr orelse return fail())[0..exec_len];
        if (cluster_primary_config.exec) |configured| break :blk configured;
        return fail();
    };

    if (args_len > 0) {
        clusterParseStoredArgs(args_ptr, args_len, &effective_args, allocator) catch return fail();
    } else {
        for (cluster_primary_config.args.items) |arg| effective_args.append(allocator.dupe(u8, arg) catch return fail()) catch return fail();
    }

    const args_view = allocator.alloc([]const u8, effective_args.items.len) catch return fail();
    defer allocator.free(args_view);
    for (effective_args.items, 0..) |arg, i| args_view[i] = arg;
    const cwd = if (cluster_primary_config.cwd) |configured| configured else null;
    const env_map: ?*const std.process.EnvMap = if (cluster_primary_config.use_custom_env) &cluster_primary_config.env else null;
    const env_count: u64 = if (cluster_primary_config.use_custom_env) cluster_primary_config.env.count() else 0;
    return clusterSpawnWorker(exec, args_view, cwd, env_map, env_count, out_worker);
}

pub export fn sa_node_plugin_cluster_worker_pid(worker_ptr: ?*anyopaque, out_pid: ?*u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    out_pid.?.* = @intCast(worker.child.id);
    return 0;
}

pub export fn sa_node_plugin_cluster_worker_send_message(worker_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    clusterWorkerRefresh(worker);
    if (!worker.connected or worker.exited) return fail();
    const stdin_file = worker.child.stdin orelse return fail();
    const data = if (data_len == 0) "" else (data_ptr orelse return fail())[0..data_len];
    stdin_file.writeAll(data) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_cluster_worker_receive_message(worker_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    clusterWorkerRefresh(worker);
    const stdout_file = worker.child.stdout orelse {
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return 0;
    };

    var buf: [4096]u8 = undefined;
    const n = stdout_file.read(&buf) catch |err| switch (err) {
        error.WouldBlock => {
            out_ptr.?.* = null;
            out_len.?.* = 0;
            return 0;
        },
        else => return fail(),
    };
    if (n == 0) {
        clusterWorkerRefresh(worker);
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return 0;
    }
    return writeOwnedBytes(out_ptr, out_len, buf[0..n]);
}

pub export fn sa_node_plugin_cluster_worker_disconnect(worker_ptr: ?*anyopaque) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    worker.disconnected_requested = true;
    if (worker.child.stdin) |*stdin_file| {
        stdin_file.close();
        worker.child.stdin = null;
    }
    worker.connected = false;
    clusterWorkerRefresh(worker);
    return 0;
}

pub export fn sa_node_plugin_cluster_worker_kill(worker_ptr: ?*anyopaque, signal: u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    clusterWorkerRefresh(worker);
    if (worker.exited) return 0;
    const sig = clusterSignalFromNumber(if (signal == 0) std.posix.SIG.TERM else signal) orelse return fail();
    std.posix.kill(worker.child.id, sig) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_cluster_worker_kill_signal(worker_ptr: ?*anyopaque, signal_ptr: ?[*]const u8, signal_len: u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    clusterWorkerRefresh(worker);
    if (worker.exited) return 0;
    const signal = if (signal_ptr) |ptr| ptr[0..signal_len] else "SIGTERM";
    const sig = clusterSignalNameToNumber(signal) orelse return fail();
    std.posix.kill(worker.child.id, sig) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_cluster_worker_is_connected(worker_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    clusterWorkerRefresh(worker);
    out_bool.?.* = if (worker.connected and !worker.exited) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_cluster_worker_is_alive(worker_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    clusterWorkerRefresh(worker);
    out_bool.?.* = if (worker.exited) 0 else 1;
    return 0;
}

pub export fn sa_node_plugin_cluster_worker_exited_after_disconnect(worker_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    clusterWorkerRefresh(worker);
    out_bool.?.* = if (worker.disconnected_requested and worker.exited) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_cluster_worker_wait_json(worker_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    if (!worker.exited) {
        const waited = std.posix.waitpid(worker.child.id, 0);
        clusterWorkerDecodeStatus(worker, waited.status);
        clusterCloseStreams(worker);
    }
    return clusterWorkerSnapshotJson(worker, out_ptr, out_len);
}

pub export fn sa_node_plugin_cluster_worker_snapshot_json(worker_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const worker = clusterWorkerHandle(worker_ptr) orelse return fail();
    return clusterWorkerSnapshotJson(worker, out_ptr, out_len);
}

pub export fn sa_node_plugin_cluster_worker_free(worker_ptr: ?*anyopaque) u32 {
    if (worker_ptr) |ptr| {
        const worker: *ClusterWorkerHandle = @ptrCast(@alignCast(ptr));
        worker.deinit();
    }
    return 0;
}

// --- Timers promises ---
const TimersPromisesIntervalHandle = struct {
    allocator: std.mem.Allocator,
    delay_ms: u64,
    value: []u8,
    next_deadline_ms: i64,
    closed: bool = false,
    tick_count: u64 = 0,

    fn init(allocator: std.mem.Allocator, delay_ms: u64, value: []const u8) !*TimersPromisesIntervalHandle {
        const handle = try allocator.create(TimersPromisesIntervalHandle);
        errdefer allocator.destroy(handle);
        const owned_value = try allocator.dupe(u8, value);
        handle.* = .{
            .allocator = allocator,
            .delay_ms = delay_ms,
            .value = owned_value,
            .next_deadline_ms = std.time.milliTimestamp() + @as(i64, @intCast(delay_ms)),
        };
        return handle;
    }

    fn deinit(self: *TimersPromisesIntervalHandle) void {
        self.allocator.free(self.value);
        self.allocator.destroy(self);
    }
};

fn sleepMs(ms: u64) void {
    std.time.sleep(ms * std.time.ns_per_ms);
}

pub export fn sa_node_plugin_timers_promises_set_timeout(ms: u64, value_ptr: ?[*]const u8, value_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    sleepMs(ms);
    const value = if (value_ptr) |ptr| ptr[0..value_len] else "";
    return writeOwnedBytes(out_ptr, out_len, value);
}

pub export fn sa_node_plugin_timers_promises_set_immediate(value_ptr: ?[*]const u8, value_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    std.Thread.yield() catch {};
    const value = if (value_ptr) |ptr| ptr[0..value_len] else "";
    return writeOwnedBytes(out_ptr, out_len, value);
}

pub export fn sa_node_plugin_timers_promises_scheduler_wait(ms: u64) u32 {
    sleepMs(ms);
    return 0;
}

pub export fn sa_node_plugin_timers_promises_scheduler_yield() u32 {
    std.Thread.yield() catch {};
    return 0;
}

pub export fn sa_node_plugin_timers_promises_set_interval(ms: u64, value_ptr: ?[*]const u8, value_len: u64, out_interval: ?*?*anyopaque) u32 {
    const value = if (value_ptr) |ptr| ptr[0..value_len] else "";
    const handle = TimersPromisesIntervalHandle.init(std.heap.page_allocator, ms, value) catch return fail();
    out_interval.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_timers_promises_interval_next(interval_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64, out_done: ?*u32) u32 {
    const handle: *TimersPromisesIntervalHandle = @ptrCast(@alignCast(interval_ptr orelse return fail()));
    if (handle.closed) {
        out_ptr.?.* = null;
        out_len.?.* = 0;
        out_done.?.* = 1;
        return 0;
    }
    const now = std.time.milliTimestamp();
    if (handle.next_deadline_ms > now) {
        sleepMs(@intCast(handle.next_deadline_ms - now));
    }
    handle.tick_count += 1;
    handle.next_deadline_ms += @as(i64, @intCast(handle.delay_ms));
    out_done.?.* = 0;
    return writeOwnedBytes(out_ptr, out_len, handle.value);
}

pub export fn sa_node_plugin_timers_promises_interval_return(interval_ptr: ?*anyopaque) u32 {
    const handle: *TimersPromisesIntervalHandle = @ptrCast(@alignCast(interval_ptr orelse return fail()));
    handle.closed = true;
    return 0;
}

pub export fn sa_node_plugin_timers_promises_interval_snapshot_json(interval_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TimersPromisesIntervalHandle = @ptrCast(@alignCast(interval_ptr orelse return fail()));
    var buffer: [192]u8 = undefined;
    const json = std.fmt.bufPrint(&buffer, "{{\"delayMs\":{d},\"closed\":{s},\"tickCount\":{d}}}", .{ handle.delay_ms, if (handle.closed) "true" else "false", handle.tick_count }) catch return fail();
    return writeOwnedString(out_ptr, out_len, json);
}

pub export fn sa_node_plugin_timers_promises_interval_free(interval_ptr: ?*anyopaque) u32 {
    if (interval_ptr) |ptr| {
        const handle: *TimersPromisesIntervalHandle = @ptrCast(@alignCast(ptr));
        handle.deinit();
    }
    return 0;
}

// --- HTTP/2 h2c client subset backed by libnghttp2 ---
const Nghttp2Session = opaque {};
const Nghttp2SessionCallbacks = opaque {};
const Nghttp2Frame = opaque {};

const Nghttp2Nv = extern struct {
    name: [*]u8,
    value: [*]u8,
    namelen: usize,
    valuelen: usize,
    flags: u8,
};

const Nghttp2DataSource = extern union {
    fd: c_int,
    ptr: ?*anyopaque,
};

const Nghttp2DataProvider = extern struct {
    source: Nghttp2DataSource,
    read_callback: ?*const fn (?*Nghttp2Session, i32, [*]u8, usize, *u32, *Nghttp2DataSource, ?*anyopaque) callconv(.c) isize,
};

const Nghttp2Version = extern struct {
    age: c_int,
    version_num: c_int,
    version_str: [*:0]const u8,
    proto_str: [*:0]const u8,
    proto_str_len: usize,
};

const Nghttp2OnHeaderCallback = *const fn (?*Nghttp2Session, ?*const Nghttp2Frame, [*]const u8, usize, [*]const u8, usize, u8, ?*anyopaque) callconv(.c) c_int;
const Nghttp2OnDataChunkRecvCallback = *const fn (?*Nghttp2Session, u8, i32, [*]const u8, usize, ?*anyopaque) callconv(.c) c_int;
const Nghttp2OnFrameRecvCallback = *const fn (?*Nghttp2Session, ?*const Nghttp2Frame, ?*anyopaque) callconv(.c) c_int;

const Nghttp2CallbacksNewFn = *const fn (*?*Nghttp2SessionCallbacks) callconv(.c) c_int;
const Nghttp2CallbacksDelFn = *const fn (?*Nghttp2SessionCallbacks) callconv(.c) void;
const Nghttp2SetOnHeaderFn = *const fn (?*Nghttp2SessionCallbacks, Nghttp2OnHeaderCallback) callconv(.c) void;
const Nghttp2SetOnDataChunkRecvFn = *const fn (?*Nghttp2SessionCallbacks, Nghttp2OnDataChunkRecvCallback) callconv(.c) void;
const Nghttp2SetOnFrameRecvFn = *const fn (?*Nghttp2SessionCallbacks, Nghttp2OnFrameRecvCallback) callconv(.c) void;
const Nghttp2SessionClientNewFn = *const fn (*?*Nghttp2Session, ?*const Nghttp2SessionCallbacks, ?*anyopaque) callconv(.c) c_int;
const Nghttp2SessionDelFn = *const fn (?*Nghttp2Session) callconv(.c) void;
const Nghttp2SubmitRequestFn = *const fn (?*Nghttp2Session, ?*const anyopaque, [*]const Nghttp2Nv, usize, ?*const Nghttp2DataProvider, ?*anyopaque) callconv(.c) i32;
const Nghttp2SubmitSettingsFn = *const fn (?*Nghttp2Session, u8, ?*const anyopaque, usize) callconv(.c) c_int;
const Nghttp2SessionMemSendFn = *const fn (?*Nghttp2Session, *?[*]const u8) callconv(.c) isize;
const Nghttp2SessionMemRecvFn = *const fn (?*Nghttp2Session, [*]const u8, usize) callconv(.c) isize;
const Nghttp2SessionWantFn = *const fn (?*Nghttp2Session) callconv(.c) c_int;
const Nghttp2VersionFn = *const fn (c_int) callconv(.c) ?*const Nghttp2Version;

const Nghttp2Api = struct {
    lib: std.DynLib,
    callbacks_new: Nghttp2CallbacksNewFn,
    callbacks_del: Nghttp2CallbacksDelFn,
    callbacks_set_on_header_callback: Nghttp2SetOnHeaderFn,
    callbacks_set_on_data_chunk_recv_callback: Nghttp2SetOnDataChunkRecvFn,
    callbacks_set_on_frame_recv_callback: Nghttp2SetOnFrameRecvFn,
    session_client_new: Nghttp2SessionClientNewFn,
    session_del: Nghttp2SessionDelFn,
    submit_request: Nghttp2SubmitRequestFn,
    submit_settings: Nghttp2SubmitSettingsFn,
    session_mem_send: Nghttp2SessionMemSendFn,
    session_mem_recv: Nghttp2SessionMemRecvFn,
    session_want_read: Nghttp2SessionWantFn,
    session_want_write: Nghttp2SessionWantFn,
    version: Nghttp2VersionFn,
};

const NGHTTP2_NV_FLAG_NONE: u8 = 0;
const NGHTTP2_DATA_FLAG_EOF: u32 = 1;
const NGHTTP2_FLAG_NONE: u8 = 0;

const HTTP2_SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const HTTP2_SETTINGS_ENABLE_PUSH: u16 = 0x2;
const HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const HTTP2_SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const HTTP2_SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;
const HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
const HTTP2_MAX_FRAME_SIZE: u32 = 0x00ff_ffff;
const HTTP2_MAX_INITIAL_WINDOW_SIZE: u32 = 0x7fff_ffff;
const HTTP2_MAX_CUSTOM_SETTINGS: usize = 10;

const Http2SettingPair = struct {
    id: u16,
    value: u32,
};

fn http2AppendSetting(out: *std.ArrayList(u8), id: u16, value: u32) !void {
    try out.append(@intCast((id >> 8) & 0xff));
    try out.append(@intCast(id & 0xff));
    try out.append(@intCast((value >> 24) & 0xff));
    try out.append(@intCast((value >> 16) & 0xff));
    try out.append(@intCast((value >> 8) & 0xff));
    try out.append(@intCast(value & 0xff));
}

fn http2JsonNumber(value: std.json.Value) ?u32 {
    return switch (value) {
        .integer => |n| if (n >= 0 and n <= std.math.maxInt(u32)) @intCast(n) else null,
        .float => |n| blk: {
            if (!std.math.isFinite(n) or n < 0 or n > @as(f64, @floatFromInt(std.math.maxInt(u32)))) break :blk null;
            const rounded = @floor(n);
            if (rounded != n) break :blk null;
            break :blk @intFromFloat(n);
        },
        else => null,
    };
}

fn http2JsonBool(value: std.json.Value) ?bool {
    return switch (value) {
        .bool => |b| b,
        else => null,
    };
}

fn http2AppendNumericSetting(out: *std.ArrayList(u8), obj: std.json.ObjectMap, key: []const u8, id: u16, min: u32, max: u32) !void {
    const value = obj.get(key) orelse return;
    const n = http2JsonNumber(value) orelse return error.InvalidSetting;
    if (n < min or n > max) return error.InvalidSetting;
    try http2AppendSetting(out, id, n);
}

fn http2AppendBoolSetting(out: *std.ArrayList(u8), obj: std.json.ObjectMap, key: []const u8, id: u16) !void {
    const value = obj.get(key) orelse return;
    const enabled = http2JsonBool(value) orelse return error.InvalidSetting;
    try http2AppendSetting(out, id, if (enabled) 1 else 0);
}

fn http2AppendMaxHeaderSetting(out: *std.ArrayList(u8), obj: std.json.ObjectMap) !void {
    const list_value = obj.get("maxHeaderListSize");
    const size_value = obj.get("maxHeaderSize");
    const value = size_value orelse list_value orelse return;
    const n = http2JsonNumber(value) orelse return error.InvalidSetting;
    try http2AppendSetting(out, HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, n);
}

fn http2KnownSetting(id: u16) bool {
    return id == HTTP2_SETTINGS_HEADER_TABLE_SIZE or
        id == HTTP2_SETTINGS_ENABLE_PUSH or
        id == HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS or
        id == HTTP2_SETTINGS_INITIAL_WINDOW_SIZE or
        id == HTTP2_SETTINGS_MAX_FRAME_SIZE or
        id == HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE or
        id == HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL;
}

fn http2AppendCustomSettings(out: *std.ArrayList(u8), obj: std.json.ObjectMap) !void {
    const custom = obj.get("customSettings") orelse return;
    if (custom != .object) return error.InvalidSetting;
    if (custom.object.count() > HTTP2_MAX_CUSTOM_SETTINGS) return error.InvalidSetting;
    var it = custom.object.iterator();
    while (it.next()) |entry| {
        const id = std.fmt.parseInt(u16, entry.key_ptr.*, 10) catch return error.InvalidSetting;
        if (id == 0) return error.InvalidSetting;
        const n = http2JsonNumber(entry.value_ptr.*) orelse return error.InvalidSetting;
        if (http2KnownSetting(id)) continue;
        try http2AppendSetting(out, id, n);
    }
}

fn http2ReadSetting(buf: []const u8, offset: usize) Http2SettingPair {
    const id = (@as(u16, buf[offset]) << 8) | @as(u16, buf[offset + 1]);
    const value = (@as(u32, buf[offset + 2]) << 24) |
        (@as(u32, buf[offset + 3]) << 16) |
        (@as(u32, buf[offset + 4]) << 8) |
        @as(u32, buf[offset + 5]);
    return .{ .id = id, .value = value };
}

fn http2AppendJsonU32Field(out: *std.ArrayList(u8), first: *bool, name: []const u8, value: u32) !void {
    if (!first.*) try out.append(',');
    first.* = false;
    try appendJsonString(out, name);
    try out.writer().print(":{d}", .{value});
}

fn http2AppendJsonBoolField(out: *std.ArrayList(u8), first: *bool, name: []const u8, value: bool) !void {
    if (!first.*) try out.append(',');
    first.* = false;
    try appendJsonString(out, name);
    try out.appendSlice(if (value) ":true" else ":false");
}

pub export fn sa_node_plugin_http2_get_default_settings_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"headerTableSize\":4096,\"enablePush\":true,\"initialWindowSize\":65535,\"maxFrameSize\":16384,\"maxConcurrentStreams\":4294967295,\"maxHeaderListSize\":65535,\"maxHeaderSize\":65535,\"enableConnectProtocol\":false}");
}

pub export fn sa_node_plugin_http2_constants_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len,
        \\{"NGHTTP2_ERR_FRAME_SIZE_ERROR":-522,"NGHTTP2_SESSION_SERVER":0,"NGHTTP2_SESSION_CLIENT":1,"NGHTTP2_STREAM_STATE_IDLE":1,"NGHTTP2_STREAM_STATE_OPEN":2,"NGHTTP2_STREAM_STATE_RESERVED_LOCAL":3,"NGHTTP2_STREAM_STATE_RESERVED_REMOTE":4,"NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL":5,"NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE":6,"NGHTTP2_STREAM_STATE_CLOSED":7,"NGHTTP2_FLAG_NONE":0,"NGHTTP2_FLAG_END_STREAM":1,"NGHTTP2_FLAG_END_HEADERS":4,"NGHTTP2_FLAG_ACK":1,"NGHTTP2_FLAG_PADDED":8,"NGHTTP2_FLAG_PRIORITY":32,"DEFAULT_SETTINGS_HEADER_TABLE_SIZE":4096,"DEFAULT_SETTINGS_ENABLE_PUSH":1,"DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS":4294967295,"DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE":65535,"DEFAULT_SETTINGS_MAX_FRAME_SIZE":16384,"DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE":65535,"DEFAULT_SETTINGS_ENABLE_CONNECT_PROTOCOL":0,"MAX_MAX_FRAME_SIZE":16777215,"MIN_MAX_FRAME_SIZE":16384,"MAX_INITIAL_WINDOW_SIZE":2147483647,"NGHTTP2_SETTINGS_HEADER_TABLE_SIZE":1,"NGHTTP2_SETTINGS_ENABLE_PUSH":2,"NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS":3,"NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE":4,"NGHTTP2_SETTINGS_MAX_FRAME_SIZE":5,"NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE":6,"NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL":8,"PADDING_STRATEGY_NONE":0,"PADDING_STRATEGY_ALIGNED":1,"PADDING_STRATEGY_MAX":2,"PADDING_STRATEGY_CALLBACK":1,"NGHTTP2_NO_ERROR":0,"NGHTTP2_PROTOCOL_ERROR":1,"NGHTTP2_INTERNAL_ERROR":2,"NGHTTP2_FLOW_CONTROL_ERROR":3,"NGHTTP2_SETTINGS_TIMEOUT":4,"NGHTTP2_STREAM_CLOSED":5,"NGHTTP2_FRAME_SIZE_ERROR":6,"NGHTTP2_REFUSED_STREAM":7,"NGHTTP2_CANCEL":8,"NGHTTP2_COMPRESSION_ERROR":9,"NGHTTP2_CONNECT_ERROR":10,"NGHTTP2_ENHANCE_YOUR_CALM":11,"NGHTTP2_INADEQUATE_SECURITY":12,"NGHTTP2_HTTP_1_1_REQUIRED":13,"NGHTTP2_DEFAULT_WEIGHT":16,"HTTP2_HEADER_STATUS":":status","HTTP2_HEADER_METHOD":":method","HTTP2_HEADER_AUTHORITY":":authority","HTTP2_HEADER_SCHEME":":scheme","HTTP2_HEADER_PATH":":path","HTTP2_HEADER_PROTOCOL":":protocol","HTTP2_HEADER_ACCEPT_ENCODING":"accept-encoding","HTTP2_HEADER_ACCEPT_LANGUAGE":"accept-language","HTTP2_HEADER_ACCEPT_RANGES":"accept-ranges","HTTP2_HEADER_ACCEPT":"accept","HTTP2_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS":"access-control-allow-credentials","HTTP2_HEADER_ACCESS_CONTROL_ALLOW_HEADERS":"access-control-allow-headers","HTTP2_HEADER_ACCESS_CONTROL_ALLOW_METHODS":"access-control-allow-methods","HTTP2_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN":"access-control-allow-origin","HTTP2_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS":"access-control-expose-headers","HTTP2_HEADER_ACCESS_CONTROL_REQUEST_HEADERS":"access-control-request-headers","HTTP2_HEADER_ACCESS_CONTROL_REQUEST_METHOD":"access-control-request-method","HTTP2_HEADER_AGE":"age","HTTP2_HEADER_AUTHORIZATION":"authorization","HTTP2_HEADER_CACHE_CONTROL":"cache-control","HTTP2_HEADER_CONNECTION":"connection","HTTP2_HEADER_CONTENT_DISPOSITION":"content-disposition","HTTP2_HEADER_CONTENT_ENCODING":"content-encoding","HTTP2_HEADER_CONTENT_LENGTH":"content-length","HTTP2_HEADER_CONTENT_TYPE":"content-type","HTTP2_HEADER_COOKIE":"cookie","HTTP2_HEADER_DATE":"date","HTTP2_HEADER_ETAG":"etag","HTTP2_HEADER_FORWARDED":"forwarded","HTTP2_HEADER_HOST":"host","HTTP2_HEADER_IF_MODIFIED_SINCE":"if-modified-since","HTTP2_HEADER_IF_NONE_MATCH":"if-none-match","HTTP2_HEADER_IF_RANGE":"if-range","HTTP2_HEADER_LAST_MODIFIED":"last-modified","HTTP2_HEADER_LINK":"link","HTTP2_HEADER_LOCATION":"location","HTTP2_HEADER_RANGE":"range","HTTP2_HEADER_REFERER":"referer","HTTP2_HEADER_SERVER":"server","HTTP2_HEADER_SET_COOKIE":"set-cookie","HTTP2_HEADER_STRICT_TRANSPORT_SECURITY":"strict-transport-security","HTTP2_HEADER_TRANSFER_ENCODING":"transfer-encoding","HTTP2_HEADER_TE":"te","HTTP2_HEADER_UPGRADE_INSECURE_REQUESTS":"upgrade-insecure-requests","HTTP2_HEADER_UPGRADE":"upgrade","HTTP2_HEADER_USER_AGENT":"user-agent","HTTP2_HEADER_VARY":"vary","HTTP2_HEADER_X_CONTENT_TYPE_OPTIONS":"x-content-type-options","HTTP2_HEADER_X_FRAME_OPTIONS":"x-frame-options","HTTP2_HEADER_KEEP_ALIVE":"keep-alive","HTTP2_HEADER_PROXY_CONNECTION":"proxy-connection","HTTP2_HEADER_X_XSS_PROTECTION":"x-xss-protection","HTTP2_HEADER_ALT_SVC":"alt-svc","HTTP2_HEADER_CONTENT_SECURITY_POLICY":"content-security-policy","HTTP2_HEADER_EARLY_DATA":"early-data","HTTP2_HEADER_EXPECT_CT":"expect-ct","HTTP2_HEADER_ORIGIN":"origin","HTTP2_HEADER_PURPOSE":"purpose","HTTP2_HEADER_TIMING_ALLOW_ORIGIN":"timing-allow-origin","HTTP2_HEADER_X_FORWARDED_FOR":"x-forwarded-for","HTTP2_HEADER_PRIORITY":"priority","HTTP2_HEADER_ACCEPT_CHARSET":"accept-charset","HTTP2_HEADER_ACCESS_CONTROL_MAX_AGE":"access-control-max-age","HTTP2_HEADER_ALLOW":"allow","HTTP2_HEADER_CONTENT_LANGUAGE":"content-language","HTTP2_HEADER_CONTENT_LOCATION":"content-location","HTTP2_HEADER_CONTENT_MD5":"content-md5","HTTP2_HEADER_CONTENT_RANGE":"content-range","HTTP2_HEADER_DNT":"dnt","HTTP2_HEADER_EXPECT":"expect","HTTP2_HEADER_EXPIRES":"expires","HTTP2_HEADER_FROM":"from","HTTP2_HEADER_IF_MATCH":"if-match","HTTP2_HEADER_IF_UNMODIFIED_SINCE":"if-unmodified-since","HTTP2_HEADER_MAX_FORWARDS":"max-forwards","HTTP2_HEADER_PREFER":"prefer","HTTP2_HEADER_PROXY_AUTHENTICATE":"proxy-authenticate","HTTP2_HEADER_PROXY_AUTHORIZATION":"proxy-authorization","HTTP2_HEADER_REFRESH":"refresh","HTTP2_HEADER_RETRY_AFTER":"retry-after","HTTP2_HEADER_TRAILER":"trailer","HTTP2_HEADER_TK":"tk","HTTP2_HEADER_VIA":"via","HTTP2_HEADER_WARNING":"warning","HTTP2_HEADER_WWW_AUTHENTICATE":"www-authenticate","HTTP2_HEADER_HTTP2_SETTINGS":"http2-settings","HTTP2_METHOD_ACL":"ACL","HTTP2_METHOD_BASELINE_CONTROL":"BASELINE-CONTROL","HTTP2_METHOD_BIND":"BIND","HTTP2_METHOD_CHECKIN":"CHECKIN","HTTP2_METHOD_CHECKOUT":"CHECKOUT","HTTP2_METHOD_CONNECT":"CONNECT","HTTP2_METHOD_COPY":"COPY","HTTP2_METHOD_DELETE":"DELETE","HTTP2_METHOD_GET":"GET","HTTP2_METHOD_HEAD":"HEAD","HTTP2_METHOD_LABEL":"LABEL","HTTP2_METHOD_LINK":"LINK","HTTP2_METHOD_LOCK":"LOCK","HTTP2_METHOD_MERGE":"MERGE","HTTP2_METHOD_MKACTIVITY":"MKACTIVITY","HTTP2_METHOD_MKCALENDAR":"MKCALENDAR","HTTP2_METHOD_MKCOL":"MKCOL","HTTP2_METHOD_MKREDIRECTREF":"MKREDIRECTREF","HTTP2_METHOD_MKWORKSPACE":"MKWORKSPACE","HTTP2_METHOD_MOVE":"MOVE","HTTP2_METHOD_OPTIONS":"OPTIONS","HTTP2_METHOD_ORDERPATCH":"ORDERPATCH","HTTP2_METHOD_PATCH":"PATCH","HTTP2_METHOD_POST":"POST","HTTP2_METHOD_PRI":"PRI","HTTP2_METHOD_PROPFIND":"PROPFIND","HTTP2_METHOD_PROPPATCH":"PROPPATCH","HTTP2_METHOD_PUT":"PUT","HTTP2_METHOD_REBIND":"REBIND","HTTP2_METHOD_REPORT":"REPORT","HTTP2_METHOD_SEARCH":"SEARCH","HTTP2_METHOD_TRACE":"TRACE","HTTP2_METHOD_UNBIND":"UNBIND","HTTP2_METHOD_UNCHECKOUT":"UNCHECKOUT","HTTP2_METHOD_UNLINK":"UNLINK","HTTP2_METHOD_UNLOCK":"UNLOCK","HTTP2_METHOD_UPDATE":"UPDATE","HTTP2_METHOD_UPDATEREDIRECTREF":"UPDATEREDIRECTREF","HTTP2_METHOD_VERSION_CONTROL":"VERSION-CONTROL","HTTP_STATUS_CONTINUE":100,"HTTP_STATUS_SWITCHING_PROTOCOLS":101,"HTTP_STATUS_PROCESSING":102,"HTTP_STATUS_EARLY_HINTS":103,"HTTP_STATUS_OK":200,"HTTP_STATUS_CREATED":201,"HTTP_STATUS_ACCEPTED":202,"HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION":203,"HTTP_STATUS_NO_CONTENT":204,"HTTP_STATUS_RESET_CONTENT":205,"HTTP_STATUS_PARTIAL_CONTENT":206,"HTTP_STATUS_MULTI_STATUS":207,"HTTP_STATUS_ALREADY_REPORTED":208,"HTTP_STATUS_IM_USED":226,"HTTP_STATUS_MULTIPLE_CHOICES":300,"HTTP_STATUS_MOVED_PERMANENTLY":301,"HTTP_STATUS_FOUND":302,"HTTP_STATUS_SEE_OTHER":303,"HTTP_STATUS_NOT_MODIFIED":304,"HTTP_STATUS_USE_PROXY":305,"HTTP_STATUS_TEMPORARY_REDIRECT":307,"HTTP_STATUS_PERMANENT_REDIRECT":308,"HTTP_STATUS_BAD_REQUEST":400,"HTTP_STATUS_UNAUTHORIZED":401,"HTTP_STATUS_PAYMENT_REQUIRED":402,"HTTP_STATUS_FORBIDDEN":403,"HTTP_STATUS_NOT_FOUND":404,"HTTP_STATUS_METHOD_NOT_ALLOWED":405,"HTTP_STATUS_NOT_ACCEPTABLE":406,"HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED":407,"HTTP_STATUS_REQUEST_TIMEOUT":408,"HTTP_STATUS_CONFLICT":409,"HTTP_STATUS_GONE":410,"HTTP_STATUS_LENGTH_REQUIRED":411,"HTTP_STATUS_PRECONDITION_FAILED":412,"HTTP_STATUS_PAYLOAD_TOO_LARGE":413,"HTTP_STATUS_URI_TOO_LONG":414,"HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE":415,"HTTP_STATUS_RANGE_NOT_SATISFIABLE":416,"HTTP_STATUS_EXPECTATION_FAILED":417,"HTTP_STATUS_TEAPOT":418,"HTTP_STATUS_MISDIRECTED_REQUEST":421,"HTTP_STATUS_UNPROCESSABLE_ENTITY":422,"HTTP_STATUS_LOCKED":423,"HTTP_STATUS_FAILED_DEPENDENCY":424,"HTTP_STATUS_TOO_EARLY":425,"HTTP_STATUS_UPGRADE_REQUIRED":426,"HTTP_STATUS_PRECONDITION_REQUIRED":428,"HTTP_STATUS_TOO_MANY_REQUESTS":429,"HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE":431,"HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS":451,"HTTP_STATUS_INTERNAL_SERVER_ERROR":500,"HTTP_STATUS_NOT_IMPLEMENTED":501,"HTTP_STATUS_BAD_GATEWAY":502,"HTTP_STATUS_SERVICE_UNAVAILABLE":503,"HTTP_STATUS_GATEWAY_TIMEOUT":504,"HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED":505,"HTTP_STATUS_VARIANT_ALSO_NEGOTIATES":506,"HTTP_STATUS_INSUFFICIENT_STORAGE":507,"HTTP_STATUS_LOOP_DETECTED":508,"HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED":509,"HTTP_STATUS_NOT_EXTENDED":510,"HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED":511}
    );
}

pub export fn sa_node_plugin_http2_sensitive_headers(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "Symbol(sensitiveHeaders)");
}

pub export fn sa_node_plugin_http2_get_packed_settings(settings_json_ptr: ?[*]const u8, settings_json_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const settings_json = if (settings_json_ptr) |ptr| ptr[0..settings_json_len] else "{}";
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, settings_json, .{}) catch return fail();
    defer parsed.deinit();
    if (parsed.value != .object) return fail();
    const obj = parsed.value.object;

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();
    http2AppendCustomSettings(&out, obj) catch return fail();
    http2AppendNumericSetting(&out, obj, "headerTableSize", HTTP2_SETTINGS_HEADER_TABLE_SIZE, 0, std.math.maxInt(u32)) catch return fail();
    http2AppendNumericSetting(&out, obj, "maxConcurrentStreams", HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 0, std.math.maxInt(u32)) catch return fail();
    http2AppendNumericSetting(&out, obj, "initialWindowSize", HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 0, HTTP2_MAX_INITIAL_WINDOW_SIZE) catch return fail();
    http2AppendNumericSetting(&out, obj, "maxFrameSize", HTTP2_SETTINGS_MAX_FRAME_SIZE, 16_384, HTTP2_MAX_FRAME_SIZE) catch return fail();
    http2AppendMaxHeaderSetting(&out, obj) catch return fail();
    http2AppendBoolSetting(&out, obj, "enablePush", HTTP2_SETTINGS_ENABLE_PUSH) catch return fail();
    http2AppendBoolSetting(&out, obj, "enableConnectProtocol", HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL) catch return fail();

    const owned = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_http2_get_unpacked_settings_json(buf_ptr: ?[*]const u8, buf_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const buf = if (buf_ptr) |ptr| ptr[0..buf_len] else return fail();
    if (buf.len % 6 != 0) return fail();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();
    out.append('{') catch return fail();
    var first = true;
    var custom = std.ArrayList(Http2SettingPair).init(std.heap.page_allocator);
    defer custom.deinit();

    var offset: usize = 0;
    while (offset < buf.len) : (offset += 6) {
        const pair = http2ReadSetting(buf, offset);
        switch (pair.id) {
            HTTP2_SETTINGS_HEADER_TABLE_SIZE => http2AppendJsonU32Field(&out, &first, "headerTableSize", pair.value) catch return fail(),
            HTTP2_SETTINGS_ENABLE_PUSH => http2AppendJsonBoolField(&out, &first, "enablePush", pair.value != 0) catch return fail(),
            HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS => http2AppendJsonU32Field(&out, &first, "maxConcurrentStreams", pair.value) catch return fail(),
            HTTP2_SETTINGS_INITIAL_WINDOW_SIZE => http2AppendJsonU32Field(&out, &first, "initialWindowSize", pair.value) catch return fail(),
            HTTP2_SETTINGS_MAX_FRAME_SIZE => http2AppendJsonU32Field(&out, &first, "maxFrameSize", pair.value) catch return fail(),
            HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE => {
                http2AppendJsonU32Field(&out, &first, "maxHeaderListSize", pair.value) catch return fail();
                http2AppendJsonU32Field(&out, &first, "maxHeaderSize", pair.value) catch return fail();
            },
            HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL => http2AppendJsonBoolField(&out, &first, "enableConnectProtocol", pair.value != 0) catch return fail(),
            else => custom.append(pair) catch return fail(),
        }
    }

    if (custom.items.len > 0) {
        if (!first) out.append(',') catch return fail();
        first = false;
        out.appendSlice("\"customSettings\":{") catch return fail();
        for (custom.items, 0..) |pair, i| {
            if (i != 0) out.append(',') catch return fail();
            out.writer().print("\"{d}\":{d}", .{ pair.id, pair.value }) catch return fail();
        }
        out.append('}') catch return fail();
    }
    out.append('}') catch return fail();
    const owned = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

// --- QUIC / HTTP/3 metadata subset ---
fn dynLibAvailable(candidates: []const []const u8) bool {
    for (candidates) |candidate| {
        var lib = std.DynLib.open(candidate) catch continue;
        lib.close();
        return true;
    }
    return false;
}

fn quicNgTcp2Available() bool {
    const candidates = [_][]const u8{
        "libngtcp2.so.16",
        "libngtcp2.so",
        "/lib/x86_64-linux-gnu/libngtcp2.so.16",
        "/usr/lib/x86_64-linux-gnu/libngtcp2.so.16",
    };
    return dynLibAvailable(&candidates);
}

fn quicNgHttp3Available() bool {
    const candidates = [_][]const u8{
        "libnghttp3.so.9",
        "libnghttp3.so",
        "/lib/x86_64-linux-gnu/libnghttp3.so.9",
        "/usr/lib/x86_64-linux-gnu/libnghttp3.so.9",
    };
    return dynLibAvailable(&candidates);
}

fn quicOpenSslAvailable() bool {
    const candidates = [_][]const u8{
        "libssl.so.3",
        "libssl.so",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    };
    return dynLibAvailable(&candidates);
}

pub export fn sa_node_plugin_quic_constants_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len,
        \\{"cc":{"RENO":"reno","CUBIC":"cubic","BBR":"bbr"},"DEFAULT_CIPHERS":"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256","DEFAULT_GROUPS":"X25519:P-256:P-384:P-521","ALPN_H3":"h3","STREAM_DIRECTION_BIDIRECTIONAL":0,"STREAM_DIRECTION_UNIDIRECTIONAL":1}
    );
}

pub export fn sa_node_plugin_quic_capabilities_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const ngtcp2 = quicNgTcp2Available();
    const nghttp3 = quicNgHttp3Available();
    const openssl = quicOpenSslAvailable();
    const supported = ngtcp2 and nghttp3 and openssl;
    var buffer: [384]u8 = undefined;
    const json = std.fmt.bufPrint(
        &buffer,
        "{{\"module\":\"quic\",\"supported\":{s},\"ngtcp2\":{s},\"nghttp3\":{s},\"openssl\":{s},\"alpn\":[\"h3\"],\"reason\":\"{s}\"}}",
        .{
            if (supported) "true" else "false",
            if (ngtcp2) "true" else "false",
            if (nghttp3) "true" else "false",
            if (openssl) "true" else "false",
            if (supported) "ngtcp2, nghttp3, and OpenSSL are available" else "ngtcp2/nghttp3/OpenSSL stack is required for QUIC sessions",
        },
    ) catch return fail();
    return writeOwnedString(out_ptr, out_len, json);
}

pub export fn sa_node_plugin_http3_constants_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len,
        \\{"ALPN_H3":"h3","RFC_HTTP3":9114,"RFC_QPACK":9204,"RFC_HTTP_DATAGRAM":9297,"RFC_WEBSOCKETS_OVER_HTTP3":9220}
    );
}

var nghttp2_api: ?Nghttp2Api = null;
var nghttp2_api_mutex = std.Thread.Mutex{};

fn loadNghttp2Api() ?*Nghttp2Api {
    nghttp2_api_mutex.lock();
    defer nghttp2_api_mutex.unlock();
    if (nghttp2_api) |*api| return api;

    const candidates = [_][]const u8{
        "libnghttp2.so.14",
        "/lib/x86_64-linux-gnu/libnghttp2.so.14",
        "/usr/lib/x86_64-linux-gnu/libnghttp2.so.14",
    };

    for (candidates) |candidate| {
        var lib = std.DynLib.open(candidate) catch continue;
        const callbacks_new = lib.lookup(Nghttp2CallbacksNewFn, "nghttp2_session_callbacks_new") orelse {
            lib.close();
            continue;
        };
        const callbacks_del = lib.lookup(Nghttp2CallbacksDelFn, "nghttp2_session_callbacks_del") orelse {
            lib.close();
            continue;
        };
        const set_header = lib.lookup(Nghttp2SetOnHeaderFn, "nghttp2_session_callbacks_set_on_header_callback") orelse {
            lib.close();
            continue;
        };
        const set_data = lib.lookup(Nghttp2SetOnDataChunkRecvFn, "nghttp2_session_callbacks_set_on_data_chunk_recv_callback") orelse {
            lib.close();
            continue;
        };
        const set_frame = lib.lookup(Nghttp2SetOnFrameRecvFn, "nghttp2_session_callbacks_set_on_frame_recv_callback") orelse {
            lib.close();
            continue;
        };
        const session_client_new = lib.lookup(Nghttp2SessionClientNewFn, "nghttp2_session_client_new") orelse {
            lib.close();
            continue;
        };
        const session_del = lib.lookup(Nghttp2SessionDelFn, "nghttp2_session_del") orelse {
            lib.close();
            continue;
        };
        const submit_request = lib.lookup(Nghttp2SubmitRequestFn, "nghttp2_submit_request") orelse {
            lib.close();
            continue;
        };
        const submit_settings = lib.lookup(Nghttp2SubmitSettingsFn, "nghttp2_submit_settings") orelse {
            lib.close();
            continue;
        };
        const mem_send = lib.lookup(Nghttp2SessionMemSendFn, "nghttp2_session_mem_send") orelse {
            lib.close();
            continue;
        };
        const mem_recv = lib.lookup(Nghttp2SessionMemRecvFn, "nghttp2_session_mem_recv") orelse {
            lib.close();
            continue;
        };
        const want_read = lib.lookup(Nghttp2SessionWantFn, "nghttp2_session_want_read") orelse {
            lib.close();
            continue;
        };
        const want_write = lib.lookup(Nghttp2SessionWantFn, "nghttp2_session_want_write") orelse {
            lib.close();
            continue;
        };
        const version = lib.lookup(Nghttp2VersionFn, "nghttp2_version") orelse {
            lib.close();
            continue;
        };
        nghttp2_api = .{
            .lib = lib,
            .callbacks_new = callbacks_new,
            .callbacks_del = callbacks_del,
            .callbacks_set_on_header_callback = set_header,
            .callbacks_set_on_data_chunk_recv_callback = set_data,
            .callbacks_set_on_frame_recv_callback = set_frame,
            .session_client_new = session_client_new,
            .session_del = session_del,
            .submit_request = submit_request,
            .submit_settings = submit_settings,
            .session_mem_send = mem_send,
            .session_mem_recv = mem_recv,
            .session_want_read = want_read,
            .session_want_write = want_write,
            .version = version,
        };
        return &nghttp2_api.?;
    }
    return null;
}

const Http2ResponseState = struct {
    allocator: std.mem.Allocator,
    headers: std.ArrayList(Header),
    body: std.ArrayList(u8),
    status: u16 = 0,
    frames: u64 = 0,

    const Header = struct { name: []u8, value: []u8 };

    fn init(allocator: std.mem.Allocator) Http2ResponseState {
        return .{ .allocator = allocator, .headers = std.ArrayList(Header).init(allocator), .body = std.ArrayList(u8).init(allocator) };
    }

    fn deinit(self: *Http2ResponseState) void {
        for (self.headers.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.headers.deinit();
        self.body.deinit();
    }

    fn appendHeader(self: *Http2ResponseState, name: []const u8, value: []const u8) !void {
        const name_owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_owned);
        const value_owned = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_owned);
        if (std.mem.eql(u8, name, ":status")) {
            self.status = std.fmt.parseInt(u16, value, 10) catch 0;
        }
        try self.headers.append(.{ .name = name_owned, .value = value_owned });
    }

    fn toJson(self: *Http2ResponseState, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
        var json = std.ArrayList(u8).init(self.allocator);
        errdefer json.deinit();
        json.writer().print("{{\"status\":{d},\"headers\":{{", .{self.status}) catch return fail();
        var first = true;
        for (self.headers.items) |header| {
            if (std.mem.startsWith(u8, header.name, ":")) continue;
            if (!first) json.appendSlice(",") catch return fail();
            first = false;
            appendJsonString(&json, header.name) catch return fail();
            json.appendSlice(":") catch return fail();
            appendJsonString(&json, header.value) catch return fail();
        }
        json.appendSlice("},\"body\":") catch return fail();
        appendJsonString(&json, self.body.items) catch return fail();
        json.writer().print(",\"bodyLen\":{d},\"frames\":{d}}}", .{ self.body.items.len, self.frames }) catch return fail();
        const owned = json.toOwnedSlice() catch return fail();
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
};

fn http2OnHeader(_: ?*Nghttp2Session, _: ?*const Nghttp2Frame, name_ptr: [*]const u8, name_len: usize, value_ptr: [*]const u8, value_len: usize, _: u8, user_data: ?*anyopaque) callconv(.c) c_int {
    const state: *Http2ResponseState = @ptrCast(@alignCast(user_data orelse return -1));
    state.appendHeader(name_ptr[0..name_len], value_ptr[0..value_len]) catch return -1;
    return 0;
}

fn http2SetStatus(out_ptr: ?*?[*]const u8, out_len: ?*u64, status: []const u8) u32 {
    return writeOwnedString(out_ptr, out_len, status);
}

fn http2OnDataChunkRecv(_: ?*Nghttp2Session, _: u8, _: i32, data_ptr: [*]const u8, data_len: usize, user_data: ?*anyopaque) callconv(.c) c_int {
    const state: *Http2ResponseState = @ptrCast(@alignCast(user_data orelse return -1));
    state.body.appendSlice(data_ptr[0..data_len]) catch return -1;
    return 0;
}

fn http2OnFrameRecv(_: ?*Nghttp2Session, _: ?*const Nghttp2Frame, user_data: ?*anyopaque) callconv(.c) c_int {
    const state: *Http2ResponseState = @ptrCast(@alignCast(user_data orelse return -1));
    state.frames += 1;
    return 0;
}

fn http2DataRead(_: ?*Nghttp2Session, _: i32, buf: [*]u8, len: usize, data_flags: *u32, source: *Nghttp2DataSource, _: ?*anyopaque) callconv(.c) isize {
    const body: *[]const u8 = @ptrCast(@alignCast(source.ptr orelse return -1));
    const n = @min(len, body.*.len);
    @memcpy(buf[0..n], body.*[0..n]);
    body.* = body.*[n..];
    if (body.*.len == 0) data_flags.* |= NGHTTP2_DATA_FLAG_EOF;
    return @intCast(n);
}

fn http2FlushOutbound(api: *Nghttp2Api, session: ?*Nghttp2Session, stream: *std.net.Stream) u32 {
    while (api.session_want_write(session) != 0) {
        var data_ptr: ?[*]const u8 = null;
        const n = api.session_mem_send(session, &data_ptr);
        if (n < 0) return fail();
        if (n == 0) break;
        stream.writeAll(data_ptr.?[0..@intCast(n)]) catch return fail();
    }
    return 0;
}

fn http2ParseUrl(url: []const u8) !struct { scheme: []const u8, host: []const u8, port: u16, path: []const u8 } {
    const marker = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
    const scheme = url[0..marker];
    if (!std.mem.eql(u8, scheme, "http")) return error.UnsupportedScheme;
    const rest = url[marker + 3 ..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..slash];
    const path = if (slash < rest.len) rest[slash..] else "/";
    var host = authority;
    var port: u16 = 80;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = try std.fmt.parseInt(u16, authority[colon + 1 ..], 10);
    }
    if (host.len == 0) return error.InvalidUrl;
    return .{ .scheme = scheme, .host = host, .port = port, .path = path };
}

pub export fn sa_node_plugin_http2_client_request(url_ptr: ?[*]const u8, url_len: u64, method_ptr: ?[*]const u8, method_len: u64, body_ptr: ?[*]const u8, body_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadNghttp2Api() orelse return fail();
    const allocator = std.heap.page_allocator;
    const url = url_ptr.?[0..url_len];
    const parsed = http2ParseUrl(url) catch return fail();
    const method = if (method_ptr) |ptr| ptr[0..method_len] else "GET";
    const body = if (body_ptr) |ptr| ptr[0..body_len] else "";

    var stream = std.net.tcpConnectToHost(allocator, parsed.host, parsed.port) catch return http2SetStatus(out_ptr, out_len, "{\"error\":\"connect\"}");
    defer stream.close();

    var state = Http2ResponseState.init(allocator);
    defer state.deinit();

    var callbacks: ?*Nghttp2SessionCallbacks = null;
    if (api.callbacks_new(&callbacks) != 0) return fail();
    defer api.callbacks_del(callbacks);
    api.callbacks_set_on_header_callback(callbacks, http2OnHeader);
    api.callbacks_set_on_data_chunk_recv_callback(callbacks, http2OnDataChunkRecv);
    api.callbacks_set_on_frame_recv_callback(callbacks, http2OnFrameRecv);

    var session: ?*Nghttp2Session = null;
    if (api.session_client_new(&session, callbacks, @ptrCast(&state)) != 0) return fail();
    defer api.session_del(session);

    if (api.submit_settings(session, NGHTTP2_FLAG_NONE, null, 0) != 0) return fail();

    var authority_buf: [512]u8 = undefined;
    const authority = if (parsed.port == 80)
        std.fmt.bufPrint(&authority_buf, "{s}", .{parsed.host}) catch return fail()
    else
        std.fmt.bufPrint(&authority_buf, "{s}:{d}", .{ parsed.host, parsed.port }) catch return fail();

    var nva = [_]Nghttp2Nv{
        .{ .name = @constCast(@as([*]const u8, @ptrCast(":method".ptr))), .value = @constCast(method.ptr), .namelen = 7, .valuelen = method.len, .flags = NGHTTP2_NV_FLAG_NONE },
        .{ .name = @constCast(@as([*]const u8, @ptrCast(":scheme".ptr))), .value = @constCast(parsed.scheme.ptr), .namelen = 7, .valuelen = parsed.scheme.len, .flags = NGHTTP2_NV_FLAG_NONE },
        .{ .name = @constCast(@as([*]const u8, @ptrCast(":authority".ptr))), .value = @constCast(authority.ptr), .namelen = 10, .valuelen = authority.len, .flags = NGHTTP2_NV_FLAG_NONE },
        .{ .name = @constCast(@as([*]const u8, @ptrCast(":path".ptr))), .value = @constCast(parsed.path.ptr), .namelen = 5, .valuelen = parsed.path.len, .flags = NGHTTP2_NV_FLAG_NONE },
    };

    var body_slice = body;
    var provider = Nghttp2DataProvider{
        .source = .{ .ptr = @ptrCast(&body_slice) },
        .read_callback = http2DataRead,
    };
    const provider_ptr: ?*const Nghttp2DataProvider = if (body.len > 0) &provider else null;
    const req_id = api.submit_request(session, null, &nva, nva.len, provider_ptr, null);
    if (req_id < 0) return fail();
    if (http2FlushOutbound(api, session, &stream) != 0) return fail();

    var read_buf: [8192]u8 = undefined;
    var saw_response = false;
    var idle_reads: u8 = 0;
    while (api.session_want_read(session) != 0 and idle_reads < 4) {
        const n = stream.read(&read_buf) catch return fail();
        if (n == 0) break;
        idle_reads = 0;
        const consumed = api.session_mem_recv(session, &read_buf, n);
        if (consumed < 0) return fail();
        if (http2FlushOutbound(api, session, &stream) != 0) return fail();
        if (state.status != 0) saw_response = true;
        if (saw_response and state.body.items.len > 0) break;
    }

    if (!saw_response) return fail();
    return state.toJson(out_ptr, out_len);
}

pub export fn sa_node_plugin_http2_nghttp2_version_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadNghttp2Api() orelse return fail();
    const version = api.version(0) orelse return fail();
    var buffer: [192]u8 = undefined;
    const json = std.fmt.bufPrint(&buffer, "{{\"version\":\"{s}\",\"proto\":\"{s}\",\"versionNum\":{d}}}", .{ version.version_str, version.proto_str, version.version_num }) catch return fail();
    return writeOwnedString(out_ptr, out_len, json);
}

// --- Status-only compatibility shims ---
pub export fn sa_node_plugin_cluster_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"cluster\",\"supported\":true,\"mode\":\"native-subprocess-workers\",\"isPrimary\":true,\"isWorker\":false,\"schedulingPolicy\":") catch return fail();
    out.writer().print("{d}", .{cluster_scheduling_policy}) catch return fail();
    out.appendSlice(",\"capabilities\":[\"setupPrimary metadata\",\"fork subprocess worker handles\",\"stdin/stdout message exchange\",\"worker pid/alive/connected snapshot\",\"worker disconnect/kill/free\"],\"limitations\":[\"no JavaScript EventEmitter object model\",\"no shared libuv server handle distribution\",\"no Node internal IPC framing or serialization\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_domain_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "domain", false, "legacy Node domain API is not modeled");
}

pub export fn sa_node_plugin_inspector_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "inspector", false, "inspector protocol is not modeled");
}

pub export fn sa_node_plugin_http_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(
        out_ptr,
        out_len,
        "http",
        true,
        "HTTP/1 client/server, streaming, and WebSocket bridge are exposed",
    );
}

var http_max_idle_parsers: u64 = 1000;

pub export fn sa_node_plugin_http_max_header_size(out_size: ?*u64) u32 {
    (out_size orelse return fail()).* = 16 * 1024;
    return 0;
}

pub export fn sa_node_plugin_http_set_max_idle_http_parsers(max: u64) u32 {
    if (max == 0) return fail();
    http_max_idle_parsers = max;
    return 0;
}

pub export fn sa_node_plugin_http_methods_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(
        out_ptr,
        out_len,
        "[\"ACL\",\"BIND\",\"CHECKOUT\",\"CONNECT\",\"COPY\",\"DELETE\",\"GET\",\"HEAD\",\"LINK\",\"LOCK\",\"M-SEARCH\",\"MERGE\",\"MKACTIVITY\",\"MKCALENDAR\",\"MKCOL\",\"MOVE\",\"NOTIFY\",\"OPTIONS\",\"PATCH\",\"POST\",\"PROPFIND\",\"PROPPATCH\",\"PURGE\",\"PUT\",\"QUERY\",\"REBIND\",\"REPORT\",\"SEARCH\",\"SOURCE\",\"SUBSCRIBE\",\"TRACE\",\"UNBIND\",\"UNLINK\",\"UNLOCK\",\"UNSUBSCRIBE\"]",
    );
}

pub export fn sa_node_plugin_http_status_codes_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(
        out_ptr,
        out_len,
        "{\"100\":\"Continue\",\"101\":\"Switching Protocols\",\"102\":\"Processing\",\"103\":\"Early Hints\",\"200\":\"OK\",\"201\":\"Created\",\"202\":\"Accepted\",\"203\":\"Non-Authoritative Information\",\"204\":\"No Content\",\"205\":\"Reset Content\",\"206\":\"Partial Content\",\"207\":\"Multi-Status\",\"208\":\"Already Reported\",\"226\":\"IM Used\",\"300\":\"Multiple Choices\",\"301\":\"Moved Permanently\",\"302\":\"Found\",\"303\":\"See Other\",\"304\":\"Not Modified\",\"305\":\"Use Proxy\",\"307\":\"Temporary Redirect\",\"308\":\"Permanent Redirect\",\"400\":\"Bad Request\",\"401\":\"Unauthorized\",\"402\":\"Payment Required\",\"403\":\"Forbidden\",\"404\":\"Not Found\",\"405\":\"Method Not Allowed\",\"406\":\"Not Acceptable\",\"407\":\"Proxy Authentication Required\",\"408\":\"Request Timeout\",\"409\":\"Conflict\",\"410\":\"Gone\",\"411\":\"Length Required\",\"412\":\"Precondition Failed\",\"413\":\"Payload Too Large\",\"414\":\"URI Too Long\",\"415\":\"Unsupported Media Type\",\"416\":\"Range Not Satisfiable\",\"417\":\"Expectation Failed\",\"418\":\"I'm a Teapot\",\"421\":\"Misdirected Request\",\"422\":\"Unprocessable Entity\",\"423\":\"Locked\",\"424\":\"Failed Dependency\",\"425\":\"Too Early\",\"426\":\"Upgrade Required\",\"428\":\"Precondition Required\",\"429\":\"Too Many Requests\",\"431\":\"Request Header Fields Too Large\",\"451\":\"Unavailable For Legal Reasons\",\"500\":\"Internal Server Error\",\"501\":\"Not Implemented\",\"502\":\"Bad Gateway\",\"503\":\"Service Unavailable\",\"504\":\"Gateway Timeout\",\"505\":\"HTTP Version Not Supported\",\"506\":\"Variant Also Negotiates\",\"507\":\"Insufficient Storage\",\"508\":\"Loop Detected\",\"509\":\"Bandwidth Limit Exceeded\",\"510\":\"Not Extended\",\"511\":\"Network Authentication Required\"}",
    );
}

fn isHttpTokenByte(byte: u8) bool {
    return switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}

pub export fn sa_node_plugin_http_validate_header_name(name_ptr: ?[*]const u8, name_len: u64) u32 {
    const name = (name_ptr orelse return fail())[0..name_len];
    if (name.len == 0) return fail();
    for (name) |byte| {
        if (!isHttpTokenByte(byte)) return fail();
    }
    return 0;
}

pub export fn sa_node_plugin_http_validate_header_value(name_ptr: ?[*]const u8, name_len: u64, value_ptr: ?[*]const u8, value_len: u64) u32 {
    _ = name_len;
    _ = name_ptr orelse return fail();
    const value = (value_ptr orelse return fail())[0..value_len];
    for (value) |byte| {
        if (byte != '\t' and !(byte >= 0x20 and byte <= 0x7e) and byte < 0x80) return fail();
    }
    return 0;
}

pub export fn sa_node_plugin_https_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(
        out_ptr,
        out_len,
        "https",
        true,
        "HTTPS client requests are exposed through the HTTP client bridge",
    );
}

pub export fn sa_node_plugin_http2_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "http2", true, "HTTP/2 constants, default settings, packed settings helpers, and cleartext prior-knowledge client request helper are exposed; full session/server semantics are not modeled");
}

pub export fn sa_node_plugin_quic_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const supported = quicNgTcp2Available() and quicNgHttp3Available() and quicOpenSslAvailable();
    return writeStatusJson(
        out_ptr,
        out_len,
        "quic",
        supported,
        if (supported) "QUIC constants and native library capability detection are exposed; session APIs require ngtcp2/nghttp3 integration" else "QUIC constants are exposed but ngtcp2/nghttp3/OpenSSL stack is not fully available for sessions",
    );
}

pub export fn sa_node_plugin_http3_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const supported = quicNgTcp2Available() and quicNgHttp3Available() and quicOpenSslAvailable();
    return writeStatusJson(
        out_ptr,
        out_len,
        "http3",
        supported,
        if (supported) "HTTP/3 constants and native library capability detection are exposed; request/session APIs require ngtcp2/nghttp3 integration" else "HTTP/3 constants are exposed but ngtcp2/nghttp3/OpenSSL stack is not fully available for transport",
    );
}

pub export fn sa_node_plugin_tls_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "tls", true, "TLS default constants, native cipher helpers, native-system CA/root certificate helpers, SecureContext CA handles, client connect/write/read/close plus protocol, cipher, address, timeout, ref, and byte metadata are exposed; server and full TLSSocket event semantics are not modeled");
}

pub export fn sa_node_plugin_dgram_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "dgram", true, "UDP4/UDP6 socket create/bind/send/recv/close, connect, address metadata, buffer options, and multicast controls are exposed");
}

pub export fn sa_node_plugin_wasi_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "wasi", false, "WASI runtime is not modeled");
}

pub export fn sa_node_plugin_vfs_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "vfs", true, "in-memory file and directory helpers are exposed for deterministic virtual filesystem tests");
}

const VfsKind = enum { file, dir, symlink };

const VfsEntry = struct {
    kind: VfsKind,
    data: []u8 = &.{},

    fn deinit(self: *VfsEntry, allocator: std.mem.Allocator) void {
        if (self.kind == .file or self.kind == .symlink) allocator.free(self.data);
    }
};

const VfsLookup = struct {
    path: []u8,
    entry: VfsEntry,
};

const VfsHandle = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(VfsEntry),
    cwd: []u8,
    watchers: std.ArrayList(*VfsWatcherHandle),

    fn init(allocator: std.mem.Allocator) !*VfsHandle {
        const handle = try allocator.create(VfsHandle);
        handle.* = .{ .allocator = allocator, .entries = std.StringHashMap(VfsEntry).init(allocator), .cwd = try allocator.dupe(u8, "/"), .watchers = std.ArrayList(*VfsWatcherHandle).init(allocator) };
        const root_key = try allocator.dupe(u8, "/");
        try handle.entries.put(root_key, .{ .kind = .dir });
        return handle;
    }

    fn deinit(self: *VfsHandle) void {
        while (self.watchers.items.len > 0) {
            const watcher = self.watchers.pop().?;
            watcher.closed = true;
            watcher.deinit(false);
        }
        self.watchers.deinit();
        self.allocator.free(self.cwd);
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.entries.deinit();
        self.allocator.destroy(self);
    }
};

const VfsWatchEvent = struct {
    event_type: []u8,
    filename: []u8,

    fn deinit(self: *VfsWatchEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.event_type);
        allocator.free(self.filename);
    }
};

const VfsWatcherHandle = struct {
    vfs: *VfsHandle,
    path: []u8,
    recursive: bool,
    closed: bool = false,
    events: std.ArrayList(VfsWatchEvent),

    fn deinit(self: *VfsWatcherHandle, unlink: bool) void {
        if (unlink) {
            for (self.vfs.watchers.items, 0..) |watcher, i| {
                if (watcher == self) {
                    _ = self.vfs.watchers.orderedRemove(i);
                    break;
                }
            }
        }
        for (self.events.items) |*event| event.deinit(self.vfs.allocator);
        self.events.deinit();
        self.vfs.allocator.free(self.path);
        self.vfs.allocator.destroy(self);
    }
};

const VfsOpenFlags = packed struct(u8) {
    readable: bool = false,
    writable: bool = false,
    append: bool = false,
    truncate: bool = false,
    create: bool = false,
    exclusive: bool = false,
    _reserved: u2 = 0,
};

const VfsFileHandle = struct {
    vfs: *VfsHandle,
    path: []u8,
    position: u64,
    flags: VfsOpenFlags,
    closed: bool = false,

    fn deinit(self: *VfsFileHandle) void {
        self.vfs.allocator.free(self.path);
        self.vfs.allocator.destroy(self);
    }
};

const VfsDirEntryInfo = struct {
    name: []u8,
    entry_type: u32,

    fn deinit(self: *VfsDirEntryInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

const VfsDirHandle = struct {
    allocator: std.mem.Allocator,
    path: []u8,
    entries: std.ArrayList(VfsDirEntryInfo),
    index: usize = 0,
    closed: bool = false,

    fn deinit(self: *VfsDirHandle) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit();
        self.allocator.free(self.path);
        self.allocator.destroy(self);
    }
};

fn vfsFileHandle(ptr: ?*anyopaque) ?*VfsFileHandle {
    return @ptrCast(@alignCast(ptr orelse return null));
}

fn vfsDirHandle(ptr: ?*anyopaque) ?*VfsDirHandle {
    return @ptrCast(@alignCast(ptr orelse return null));
}

fn vfsWatcherHandle(ptr: ?*anyopaque) ?*VfsWatcherHandle {
    return @ptrCast(@alignCast(ptr orelse return null));
}

fn vfsFlagsFromMode(mode: u32) VfsOpenFlags {
    return switch (mode) {
        0 => .{ .readable = true },
        1 => .{ .readable = true, .writable = true },
        2 => .{ .writable = true, .truncate = true, .create = true },
        3 => .{ .readable = true, .writable = true, .truncate = true, .create = true },
        4 => .{ .writable = true, .append = true, .create = true },
        5 => .{ .readable = true, .writable = true, .append = true, .create = true },
        6 => .{ .writable = true, .truncate = true, .create = true, .exclusive = true },
        7 => .{ .readable = true, .writable = true, .truncate = true, .create = true, .exclusive = true },
        8 => .{ .writable = true, .append = true, .create = true, .exclusive = true },
        9 => .{ .readable = true, .writable = true, .append = true, .create = true, .exclusive = true },
        else => .{ .readable = true },
    };
}

fn vfsHandle(ptr: ?*anyopaque) ?*VfsHandle {
    return @ptrCast(@alignCast(ptr orelse return null));
}

fn vfsNormalize(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var parts = std.ArrayList([]const u8).init(allocator);
    defer parts.deinit();
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (parts.items.len > 0) _ = parts.pop();
            continue;
        }
        try parts.append(part);
    }
    if (parts.items.len == 0) return allocator.dupe(u8, "/");
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    for (parts.items) |part| {
        try out.append('/');
        try out.appendSlice(part);
    }
    return out.toOwnedSlice();
}

fn vfsResolve(handle: *VfsHandle, path: []const u8) ![]u8 {
    if (path.len > 0 and path[0] == '/') return vfsNormalize(handle.allocator, path);
    const joined = try std.fs.path.join(handle.allocator, &.{ handle.cwd, path });
    defer handle.allocator.free(joined);
    return vfsNormalize(handle.allocator, joined);
}

fn vfsResolveSymlinkTarget(handle: *VfsHandle, symlink_path: []const u8, target: []const u8) ![]u8 {
    if (target.len > 0 and target[0] == '/') return vfsNormalize(handle.allocator, target);
    const parent = try vfsParentPath(handle.allocator, symlink_path);
    defer handle.allocator.free(parent);
    const joined = try std.fs.path.join(handle.allocator, &.{ parent, target });
    defer handle.allocator.free(joined);
    return vfsNormalize(handle.allocator, joined);
}

fn vfsLookup(handle: *VfsHandle, path: []const u8, follow_final_symlink: bool, depth: u8) !VfsLookup {
    if (depth >= 40) return error.SymlinkLoop;
    var current = try vfsResolve(handle, path);
    errdefer handle.allocator.free(current);
    var current_depth = depth;
    while (true) {
        const entry = handle.entries.get(current) orelse return error.NotFound;
        if (entry.kind != .symlink or !follow_final_symlink) return .{ .path = current, .entry = entry };
        current_depth += 1;
        if (current_depth >= 40) return error.SymlinkLoop;
        const next = try vfsResolveSymlinkTarget(handle, current, entry.data);
        handle.allocator.free(current);
        current = next;
    }
}

fn vfsParentPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (std.mem.eql(u8, path, "/")) return allocator.dupe(u8, "/");
    const last = std.mem.lastIndexOfScalar(u8, path, '/') orelse return allocator.dupe(u8, "/");
    if (last == 0) return allocator.dupe(u8, "/");
    return allocator.dupe(u8, path[0..last]);
}

fn vfsBasename(path: []const u8) []const u8 {
    if (std.mem.eql(u8, path, "/")) return "/";
    const last = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[last + 1 ..];
}

fn vfsWatchFilename(watched_path: []const u8, changed_path: []const u8, recursive: bool) ?[]const u8 {
    if (std.mem.eql(u8, watched_path, changed_path)) return vfsBasename(changed_path);
    if (std.mem.eql(u8, watched_path, "/")) {
        if (changed_path.len <= 1 or changed_path[0] != '/') return null;
        const rest = changed_path[1..];
        if (!recursive and std.mem.indexOfScalar(u8, rest, '/') != null) return null;
        return rest;
    }
    if (!(std.mem.startsWith(u8, changed_path, watched_path) and changed_path.len > watched_path.len and changed_path[watched_path.len] == '/')) return null;
    const rest = changed_path[watched_path.len + 1 ..];
    if (rest.len == 0) return null;
    if (!recursive and std.mem.indexOfScalar(u8, rest, '/') != null) return null;
    return rest;
}

fn vfsNotify(handle: *VfsHandle, changed_path: []const u8, event_type: []const u8) void {
    for (handle.watchers.items) |watcher| {
        if (watcher.closed) continue;
        const filename = vfsWatchFilename(watcher.path, changed_path, watcher.recursive) orelse continue;
        const owned_type = handle.allocator.dupe(u8, event_type) catch continue;
        errdefer handle.allocator.free(owned_type);
        const owned_filename = handle.allocator.dupe(u8, filename) catch continue;
        watcher.events.append(.{ .event_type = owned_type, .filename = owned_filename }) catch {
            handle.allocator.free(owned_type);
            handle.allocator.free(owned_filename);
            continue;
        };
    }
}

fn vfsEnsureParentDir(handle: *VfsHandle, path: []const u8) !void {
    const parent = try vfsParentPath(handle.allocator, path);
    defer handle.allocator.free(parent);
    const entry = handle.entries.get(parent) orelse return error.ParentMissing;
    if (entry.kind != .dir) return error.ParentNotDir;
}

fn vfsPutEntry(handle: *VfsHandle, path: []const u8, entry: VfsEntry) !void {
    if (handle.entries.fetchRemove(path)) |old| {
        handle.allocator.free(old.key);
        var old_value = old.value;
        old_value.deinit(handle.allocator);
    }
    const key = try handle.allocator.dupe(u8, path);
    errdefer handle.allocator.free(key);
    try handle.entries.put(key, entry);
}

fn vfsCloneEntry(handle: *VfsHandle, entry: VfsEntry) !VfsEntry {
    return switch (entry.kind) {
        .dir => .{ .kind = .dir },
        .symlink => .{ .kind = .symlink, .data = try handle.allocator.dupe(u8, entry.data) },
        .file => .{ .kind = .file, .data = try handle.allocator.dupe(u8, entry.data) },
    };
}

fn vfsReplaceFileData(handle: *VfsHandle, path: []const u8, data: []u8) !void {
    try vfsPutEntry(handle, path, .{ .kind = .file, .data = data });
}

fn vfsEntryType(entry: VfsEntry) u32 {
    return switch (entry.kind) {
        .file => 1,
        .dir => 2,
        .symlink => 3,
    };
}

fn vfsHasChildren(handle: *VfsHandle, dir: []const u8) bool {
    var it = handle.entries.keyIterator();
    while (it.next()) |key_ptr| {
        const key = key_ptr.*;
        if (std.mem.eql(u8, key, dir)) continue;
        if (std.mem.eql(u8, dir, "/")) {
            if (key.len > 1 and key[0] == '/') return true;
        } else if (std.mem.startsWith(u8, key, dir) and key.len > dir.len and key[dir.len] == '/') return true;
    }
    return false;
}

fn vfsRemovePath(handle: *VfsHandle, path: []const u8, recursive: bool) !void {
    const entry = handle.entries.get(path) orelse return error.NotFound;
    if (std.mem.eql(u8, path, "/")) return error.Root;
    if (entry.kind == .dir and vfsHasChildren(handle, path) and !recursive) return error.DirNotEmpty;

    var keys = std.ArrayList([]const u8).init(handle.allocator);
    defer keys.deinit();
    var it = handle.entries.keyIterator();
    while (it.next()) |key_ptr| {
        const key = key_ptr.*;
        if (std.mem.eql(u8, key, path) or (recursive and std.mem.startsWith(u8, key, path) and key.len > path.len and key[path.len] == '/')) {
            try keys.append(key);
        }
    }
    for (keys.items) |key| {
        if (handle.entries.fetchRemove(key)) |removed| {
            handle.allocator.free(removed.key);
            var value = removed.value;
            value.deinit(handle.allocator);
        }
    }
}

pub export fn sa_node_plugin_vfs_new(out_vfs: ?*?*anyopaque) u32 {
    const handle = VfsHandle.init(std.heap.page_allocator) catch return fail();
    out_vfs.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_vfs_free(vfs_ptr: ?*anyopaque) u32 {
    if (vfsHandle(vfs_ptr)) |handle| handle.deinit();
    return 0;
}

pub export fn sa_node_plugin_vfs_mkdir(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const path = vfsResolve(handle, path_ptr.?[0..path_len]) catch return fail();
    defer handle.allocator.free(path);
    vfsEnsureParentDir(handle, path) catch return fail();
    vfsPutEntry(handle, path, .{ .kind = .dir }) catch return fail();
    vfsNotify(handle, path, "rename");
    return 0;
}

pub export fn sa_node_plugin_vfs_write_file(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const path = vfsResolve(handle, path_ptr.?[0..path_len]) catch return fail();
    defer handle.allocator.free(path);
    vfsEnsureParentDir(handle, path) catch return fail();
    const existed = handle.entries.contains(path);
    const data = handle.allocator.dupe(u8, data_ptr.?[0..data_len]) catch return fail();
    vfsPutEntry(handle, path, .{ .kind = .file, .data = data }) catch {
        handle.allocator.free(data);
        return fail();
    };
    vfsNotify(handle, path, if (existed) "change" else "rename");
    return 0;
}

pub export fn sa_node_plugin_vfs_append_file(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const path = vfsResolve(handle, path_ptr.?[0..path_len]) catch return fail();
    defer handle.allocator.free(path);
    vfsEnsureParentDir(handle, path) catch return fail();
    const suffix = data_ptr.?[0..data_len];
    if (handle.entries.get(path)) |entry| {
        if (entry.kind != .file) return fail();
        const data = handle.allocator.alloc(u8, entry.data.len + suffix.len) catch return fail();
        @memcpy(data[0..entry.data.len], entry.data);
        @memcpy(data[entry.data.len..], suffix);
        vfsPutEntry(handle, path, .{ .kind = .file, .data = data }) catch {
            handle.allocator.free(data);
            return fail();
        };
        vfsNotify(handle, path, "change");
        return 0;
    }
    const data = handle.allocator.dupe(u8, suffix) catch return fail();
    vfsPutEntry(handle, path, .{ .kind = .file, .data = data }) catch {
        handle.allocator.free(data);
        return fail();
    };
    vfsNotify(handle, path, "rename");
    return 0;
}

pub export fn sa_node_plugin_vfs_read_file(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const lookup = vfsLookup(handle, path_ptr.?[0..path_len], true, 0) catch return fail();
    defer handle.allocator.free(lookup.path);
    if (lookup.entry.kind != .file) return fail();
    return writeOwnedBytes(out_ptr, out_len, lookup.entry.data);
}

pub export fn sa_node_plugin_vfs_open(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, mode: u32, out_handle: ?*?*anyopaque) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const path = vfsResolve(handle, path_ptr.?[0..path_len]) catch return fail();
    errdefer handle.allocator.free(path);
    var flags = vfsFlagsFromMode(mode);
    if (!flags.readable and !flags.writable) flags.readable = true;

    if (handle.entries.get(path)) |entry| {
        if (flags.exclusive and flags.create) return fail();
        const lookup = if (entry.kind == .symlink) vfsLookup(handle, path, true, 0) catch return fail() else VfsLookup{ .path = handle.allocator.dupe(u8, path) catch return fail(), .entry = entry };
        defer handle.allocator.free(lookup.path);
        if (lookup.entry.kind != .file) return fail();
        if (flags.truncate) {
            const empty = handle.allocator.alloc(u8, 0) catch return fail();
            vfsReplaceFileData(handle, lookup.path, empty) catch {
                handle.allocator.free(empty);
                return fail();
            };
            vfsNotify(handle, lookup.path, "change");
        }
        handle.allocator.free(path);
        const owned_path = handle.allocator.dupe(u8, lookup.path) catch return fail();
        const file_handle = handle.allocator.create(VfsFileHandle) catch {
            handle.allocator.free(owned_path);
            return fail();
        };
        const current_entry = handle.entries.get(owned_path) orelse {
            handle.allocator.free(owned_path);
            handle.allocator.destroy(file_handle);
            return fail();
        };
        file_handle.* = .{ .vfs = handle, .path = owned_path, .position = if (flags.append) current_entry.data.len else 0, .flags = flags };
        out_handle.?.* = @ptrCast(file_handle);
        return 0;
    }

    if (!flags.create) return fail();
    vfsEnsureParentDir(handle, path) catch return fail();
    const empty = handle.allocator.alloc(u8, 0) catch return fail();
    vfsReplaceFileData(handle, path, empty) catch {
        handle.allocator.free(empty);
        return fail();
    };
    vfsNotify(handle, path, "rename");
    const file_handle = handle.allocator.create(VfsFileHandle) catch return fail();
    file_handle.* = .{ .vfs = handle, .path = path, .position = 0, .flags = flags };
    out_handle.?.* = @ptrCast(file_handle);
    return 0;
}

pub export fn sa_node_plugin_vfs_file_close(file_ptr: ?*anyopaque) u32 {
    const file = vfsFileHandle(file_ptr) orelse return fail();
    if (!file.closed) file.closed = true;
    file.deinit();
    return 0;
}

pub export fn sa_node_plugin_vfs_file_read(file_ptr: ?*anyopaque, buf_ptr: ?[*]u8, len: u64, position: u64, use_position: u32, out_n: ?*u64) u32 {
    const file = vfsFileHandle(file_ptr) orelse return fail();
    if (file.closed or !file.flags.readable) return fail();
    const entry = file.vfs.entries.get(file.path) orelse return fail();
    if (entry.kind != .file) return fail();
    const pos = if (use_position != 0) position else file.position;
    if (pos >= entry.data.len) {
        out_n.?.* = 0;
        return 0;
    }
    const n = @min(@as(usize, @intCast(len)), entry.data.len - @as(usize, @intCast(pos)));
    @memcpy(buf_ptr.?[0..n], entry.data[@as(usize, @intCast(pos)) .. @as(usize, @intCast(pos)) + n]);
    if (use_position == 0) file.position = pos + n;
    out_n.?.* = n;
    return 0;
}

pub export fn sa_node_plugin_vfs_file_write(file_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64, position: u64, use_position: u32, out_n: ?*u64) u32 {
    const file = vfsFileHandle(file_ptr) orelse return fail();
    if (file.closed or !file.flags.writable) return fail();
    const entry = file.vfs.entries.get(file.path) orelse return fail();
    if (entry.kind != .file) return fail();
    const write_pos: usize = if (file.flags.append) entry.data.len else @intCast(if (use_position != 0) position else file.position);
    const new_len = @max(entry.data.len, write_pos + @as(usize, @intCast(data_len)));
    const new_data = file.vfs.allocator.alloc(u8, new_len) catch return fail();
    @memset(new_data, 0);
    @memcpy(new_data[0..entry.data.len], entry.data);
    @memcpy(new_data[write_pos .. write_pos + @as(usize, @intCast(data_len))], data_ptr.?[0..data_len]);
    vfsReplaceFileData(file.vfs, file.path, new_data) catch {
        file.vfs.allocator.free(new_data);
        return fail();
    };
    vfsNotify(file.vfs, file.path, "change");
    if (use_position == 0 or file.flags.append) file.position = write_pos + data_len;
    out_n.?.* = data_len;
    return 0;
}

pub export fn sa_node_plugin_vfs_file_fstat_json(file_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const file = vfsFileHandle(file_ptr) orelse return fail();
    if (file.closed) return fail();
    const entry = file.vfs.entries.get(file.path) orelse return fail();
    var out = std.ArrayList(u8).init(file.vfs.allocator);
    defer out.deinit();
    vfsAppendStat(&out, file.path, entry) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_vfs_file_truncate(file_ptr: ?*anyopaque, len: u64) u32 {
    const file = vfsFileHandle(file_ptr) orelse return fail();
    if (file.closed or !file.flags.writable) return fail();
    const entry = file.vfs.entries.get(file.path) orelse return fail();
    if (entry.kind != .file) return fail();
    const new_len: usize = @intCast(len);
    const new_data = file.vfs.allocator.alloc(u8, new_len) catch return fail();
    @memset(new_data, 0);
    const copy_len = @min(entry.data.len, new_len);
    @memcpy(new_data[0..copy_len], entry.data[0..copy_len]);
    vfsReplaceFileData(file.vfs, file.path, new_data) catch {
        file.vfs.allocator.free(new_data);
        return fail();
    };
    vfsNotify(file.vfs, file.path, "change");
    if (file.position > len) file.position = len;
    return 0;
}

pub export fn sa_node_plugin_vfs_opendir(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, out_dir: ?*?*anyopaque) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const lookup = vfsLookup(handle, path_ptr.?[0..path_len], true, 0) catch return fail();
    defer handle.allocator.free(lookup.path);
    if (lookup.entry.kind != .dir) return fail();

    const dir = handle.allocator.create(VfsDirHandle) catch return fail();
    errdefer handle.allocator.destroy(dir);
    dir.* = .{ .allocator = handle.allocator, .path = handle.allocator.dupe(u8, lookup.path) catch return fail(), .entries = std.ArrayList(VfsDirEntryInfo).init(handle.allocator) };
    errdefer handle.allocator.free(dir.path);
    errdefer dir.entries.deinit();

    var it = handle.entries.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        if (std.mem.eql(u8, key, lookup.path)) continue;
        const rest = if (std.mem.eql(u8, lookup.path, "/")) key[1..] else blk: {
            if (!(std.mem.startsWith(u8, key, lookup.path) and key.len > lookup.path.len and key[lookup.path.len] == '/')) continue;
            break :blk key[lookup.path.len + 1 ..];
        };
        if (rest.len == 0 or std.mem.indexOfScalar(u8, rest, '/') != null) continue;
        dir.entries.append(.{ .name = handle.allocator.dupe(u8, rest) catch return fail(), .entry_type = vfsEntryType(entry.value_ptr.*) }) catch return fail();
    }
    std.mem.sort(VfsDirEntryInfo, dir.entries.items, {}, struct {
        fn lessThan(_: void, left: VfsDirEntryInfo, right: VfsDirEntryInfo) bool {
            return std.mem.lessThan(u8, left.name, right.name);
        }
    }.lessThan);
    out_dir.?.* = @ptrCast(dir);
    return 0;
}

pub export fn sa_node_plugin_vfs_dir_next(dir_ptr: ?*anyopaque, out_name_ptr: ?*?[*]const u8, out_name_len: ?*u64, out_entry_type: ?*u32) u32 {
    const dir = vfsDirHandle(dir_ptr) orelse return fail();
    if (dir.closed) return fail();
    if (dir.index >= dir.entries.items.len) {
        out_name_ptr.?.* = null;
        out_name_len.?.* = 0;
        out_entry_type.?.* = 0;
        return 0;
    }
    const entry = dir.entries.items[dir.index];
    dir.index += 1;
    out_entry_type.?.* = entry.entry_type;
    return writeOwnedBytes(out_name_ptr, out_name_len, entry.name);
}

pub export fn sa_node_plugin_vfs_dir_close(dir_ptr: ?*anyopaque) u32 {
    const dir = vfsDirHandle(dir_ptr) orelse return fail();
    dir.closed = true;
    dir.deinit();
    return 0;
}

pub export fn sa_node_plugin_vfs_dir_snapshot_json(dir_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const dir = vfsDirHandle(dir_ptr) orelse return fail();
    var out = std.ArrayList(u8).init(dir.allocator);
    defer out.deinit();
    out.writer().print("{{\"path\":", .{}) catch return fail();
    appendJsonString(&out, dir.path) catch return fail();
    out.writer().print(",\"closed\":{s},\"index\":{d},\"entries\":[", .{ if (dir.closed) "true" else "false", dir.index }) catch return fail();
    for (dir.entries.items, 0..) |entry, i| {
        if (i != 0) out.append(',') catch return fail();
        out.appendSlice("{\"name\":") catch return fail();
        appendJsonString(&out, entry.name) catch return fail();
        out.writer().print(",\"type\":{d}}}", .{entry.entry_type}) catch return fail();
    }
    out.appendSlice("]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_vfs_exists(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, out_bool: ?*u32) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const path = vfsResolve(handle, path_ptr.?[0..path_len]) catch return fail();
    defer handle.allocator.free(path);
    out_bool.?.* = if (handle.entries.contains(path)) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_vfs_unlink(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const path = vfsResolve(handle, path_ptr.?[0..path_len]) catch return fail();
    defer handle.allocator.free(path);
    const entry = handle.entries.get(path) orelse return fail();
    if (entry.kind != .file and entry.kind != .symlink) return fail();
    vfsRemovePath(handle, path, false) catch return fail();
    vfsNotify(handle, path, "rename");
    return 0;
}

pub export fn sa_node_plugin_vfs_rm(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, recursive: u32) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const path = vfsResolve(handle, path_ptr.?[0..path_len]) catch return fail();
    defer handle.allocator.free(path);
    vfsRemovePath(handle, path, recursive != 0) catch return fail();
    vfsNotify(handle, path, "rename");
    return 0;
}

pub export fn sa_node_plugin_vfs_rename(vfs_ptr: ?*anyopaque, old_ptr: ?[*]const u8, old_len: u64, new_ptr: ?[*]const u8, new_len: u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const old_path = vfsResolve(handle, old_ptr.?[0..old_len]) catch return fail();
    defer handle.allocator.free(old_path);
    const new_path = vfsResolve(handle, new_ptr.?[0..new_len]) catch return fail();
    defer handle.allocator.free(new_path);
    if (std.mem.eql(u8, old_path, "/") or std.mem.eql(u8, new_path, "/")) return fail();
    const root_entry = handle.entries.get(old_path) orelse return fail();
    vfsEnsureParentDir(handle, new_path) catch return fail();
    if (root_entry.kind == .dir and std.mem.startsWith(u8, new_path, old_path) and new_path.len > old_path.len and new_path[old_path.len] == '/') return fail();

    var old_keys = std.ArrayList([]const u8).init(handle.allocator);
    defer old_keys.deinit();
    var new_keys = std.ArrayList([]u8).init(handle.allocator);
    defer {
        for (new_keys.items) |key| handle.allocator.free(key);
        new_keys.deinit();
    }
    var cloned = std.ArrayList(VfsEntry).init(handle.allocator);
    defer {
        for (cloned.items) |*entry| entry.deinit(handle.allocator);
        cloned.deinit();
    }
    var it = handle.entries.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        if (std.mem.eql(u8, key, old_path) or (root_entry.kind == .dir and std.mem.startsWith(u8, key, old_path) and key.len > old_path.len and key[old_path.len] == '/')) {
            const suffix = key[old_path.len..];
            const target = std.fmt.allocPrint(handle.allocator, "{s}{s}", .{ new_path, suffix }) catch return fail();
            old_keys.append(key) catch {
                handle.allocator.free(target);
                return fail();
            };
            new_keys.append(target) catch {
                handle.allocator.free(target);
                return fail();
            };
            cloned.append(vfsCloneEntry(handle, entry.value_ptr.*) catch return fail()) catch return fail();
        }
    }
    for (old_keys.items) |key| {
        if (handle.entries.fetchRemove(key)) |removed| {
            handle.allocator.free(removed.key);
            var value = removed.value;
            value.deinit(handle.allocator);
        }
    }
    for (new_keys.items, cloned.items) |key, entry| {
        if (handle.entries.fetchRemove(key)) |old| {
            handle.allocator.free(old.key);
            var old_value = old.value;
            old_value.deinit(handle.allocator);
        }
        const moved_key = handle.allocator.dupe(u8, key) catch return fail();
        handle.entries.put(moved_key, entry) catch {
            handle.allocator.free(moved_key);
            return fail();
        };
    }
    cloned.clearRetainingCapacity();
    vfsNotify(handle, old_path, "rename");
    vfsNotify(handle, new_path, "rename");
    return 0;
}

pub export fn sa_node_plugin_vfs_copy_file(vfs_ptr: ?*anyopaque, src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const src = vfsResolve(handle, src_ptr.?[0..src_len]) catch return fail();
    defer handle.allocator.free(src);
    const dst = vfsResolve(handle, dst_ptr.?[0..dst_len]) catch return fail();
    defer handle.allocator.free(dst);
    const entry = handle.entries.get(src) orelse return fail();
    const existed = handle.entries.contains(dst);
    const source_entry = if (entry.kind == .symlink) blk: {
        const lookup = vfsLookup(handle, src, true, 0) catch return fail();
        defer handle.allocator.free(lookup.path);
        break :blk lookup.entry;
    } else entry;
    if (source_entry.kind != .file) return fail();
    vfsEnsureParentDir(handle, dst) catch return fail();
    const data = handle.allocator.dupe(u8, source_entry.data) catch return fail();
    vfsPutEntry(handle, dst, .{ .kind = .file, .data = data }) catch {
        handle.allocator.free(data);
        return fail();
    };
    vfsNotify(handle, dst, if (existed) "change" else "rename");
    return 0;
}

pub export fn sa_node_plugin_vfs_realpath(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const lookup = vfsLookup(handle, path_ptr.?[0..path_len], true, 0) catch return fail();
    defer handle.allocator.free(lookup.path);
    return writeOwnedBytes(out_ptr, out_len, lookup.path);
}

pub export fn sa_node_plugin_vfs_chdir(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const lookup = vfsLookup(handle, path_ptr.?[0..path_len], true, 0) catch return fail();
    defer handle.allocator.free(lookup.path);
    if (lookup.entry.kind != .dir) return fail();
    const owned = handle.allocator.dupe(u8, lookup.path) catch return fail();
    handle.allocator.free(handle.cwd);
    handle.cwd = owned;
    return 0;
}

pub export fn sa_node_plugin_vfs_symlink(vfs_ptr: ?*anyopaque, target_ptr: ?[*]const u8, target_len: u64, link_ptr: ?[*]const u8, link_len: u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const link = vfsResolve(handle, link_ptr.?[0..link_len]) catch return fail();
    defer handle.allocator.free(link);
    vfsEnsureParentDir(handle, link) catch return fail();
    const target = handle.allocator.dupe(u8, target_ptr.?[0..target_len]) catch return fail();
    vfsPutEntry(handle, link, .{ .kind = .symlink, .data = target }) catch {
        handle.allocator.free(target);
        return fail();
    };
    vfsNotify(handle, link, "rename");
    return 0;
}

pub export fn sa_node_plugin_vfs_readlink(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const lookup = vfsLookup(handle, path_ptr.?[0..path_len], false, 0) catch return fail();
    defer handle.allocator.free(lookup.path);
    if (lookup.entry.kind != .symlink) return fail();
    return writeOwnedBytes(out_ptr, out_len, lookup.entry.data);
}

pub export fn sa_node_plugin_vfs_cwd(vfs_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    return writeOwnedBytes(out_ptr, out_len, handle.cwd);
}

fn vfsAppendStat(out: *std.ArrayList(u8), path: []const u8, entry: VfsEntry) !void {
    try out.appendSlice("{\"path\":");
    try appendJsonString(out, path);
    try out.appendSlice(",\"type\":");
    try appendJsonString(out, switch (entry.kind) {
        .file => "file",
        .dir => "dir",
        .symlink => "symlink",
    });
    try out.writer().print(",\"isFile\":{s},\"isDirectory\":{s},\"isSymbolicLink\":{s},\"size\":{d}}}", .{
        if (entry.kind == .file) "true" else "false",
        if (entry.kind == .dir) "true" else "false",
        if (entry.kind == .symlink) "true" else "false",
        if (entry.kind == .file or entry.kind == .symlink) entry.data.len else 0,
    });
}

pub export fn sa_node_plugin_vfs_stat_json(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const lookup = vfsLookup(handle, path_ptr.?[0..path_len], true, 0) catch return fail();
    defer handle.allocator.free(lookup.path);
    var out = std.ArrayList(u8).init(handle.allocator);
    defer out.deinit();
    vfsAppendStat(&out, lookup.path, lookup.entry) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_vfs_lstat_json(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const lookup = vfsLookup(handle, path_ptr.?[0..path_len], false, 0) catch return fail();
    defer handle.allocator.free(lookup.path);
    var out = std.ArrayList(u8).init(handle.allocator);
    defer out.deinit();
    vfsAppendStat(&out, lookup.path, lookup.entry) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn vfsSortStrings(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

pub export fn sa_node_plugin_vfs_readdir(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const path = vfsResolve(handle, path_ptr.?[0..path_len]) catch return fail();
    defer handle.allocator.free(path);
    const dir_entry = handle.entries.get(path) orelse return fail();
    if (dir_entry.kind != .dir) return fail();
    var names = std.ArrayList([]const u8).init(handle.allocator);
    defer names.deinit();
    var it = handle.entries.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        if (std.mem.eql(u8, key, path)) continue;
        const rest = if (std.mem.eql(u8, path, "/")) key[1..] else blk: {
            if (!(std.mem.startsWith(u8, key, path) and key.len > path.len and key[path.len] == '/')) continue;
            break :blk key[path.len + 1 ..];
        };
        if (rest.len == 0 or std.mem.indexOfScalar(u8, rest, '/') != null) continue;
        names.append(rest) catch return fail();
    }
    std.mem.sort([]const u8, names.items, {}, vfsSortStrings);
    var out = std.ArrayList(u8).init(handle.allocator);
    defer out.deinit();
    out.append('[') catch return fail();
    for (names.items, 0..) |name, i| {
        if (i != 0) out.append(',') catch return fail();
        appendJsonString(&out, name) catch return fail();
    }
    out.append(']') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_vfs_watch(vfs_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, recursive: u32, out_watcher: ?*?*anyopaque) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    const lookup = vfsLookup(handle, path_ptr.?[0..path_len], false, 0) catch return fail();
    defer handle.allocator.free(lookup.path);
    const watcher = handle.allocator.create(VfsWatcherHandle) catch return fail();
    errdefer handle.allocator.destroy(watcher);
    const owned_path = handle.allocator.dupe(u8, lookup.path) catch return fail();
    errdefer handle.allocator.free(owned_path);
    watcher.* = .{ .vfs = handle, .path = owned_path, .recursive = recursive != 0, .events = std.ArrayList(VfsWatchEvent).init(handle.allocator) };
    handle.watchers.append(watcher) catch return fail();
    out_watcher.?.* = @ptrCast(watcher);
    return 0;
}

pub export fn sa_node_plugin_vfs_watcher_next(watcher_ptr: ?*anyopaque, out_event_ptr: ?*?[*]const u8, out_event_len: ?*u64, out_filename_ptr: ?*?[*]const u8, out_filename_len: ?*u64) u32 {
    const watcher = vfsWatcherHandle(watcher_ptr) orelse return fail();
    if (watcher.closed) return fail();
    if (watcher.events.items.len == 0) {
        out_event_ptr.?.* = null;
        out_event_len.?.* = 0;
        out_filename_ptr.?.* = null;
        out_filename_len.?.* = 0;
        return 0;
    }
    var event = watcher.events.orderedRemove(0);
    defer event.deinit(watcher.vfs.allocator);
    if (writeOwnedBytes(out_event_ptr, out_event_len, event.event_type) != 0) return fail();
    if (writeOwnedBytes(out_filename_ptr, out_filename_len, event.filename) != 0) return fail();
    return 0;
}

pub export fn sa_node_plugin_vfs_watcher_snapshot_json(watcher_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const watcher = vfsWatcherHandle(watcher_ptr) orelse return fail();
    var out = std.ArrayList(u8).init(watcher.vfs.allocator);
    defer out.deinit();
    out.appendSlice("{\"path\":") catch return fail();
    appendJsonString(&out, watcher.path) catch return fail();
    out.writer().print(",\"recursive\":{s},\"closed\":{s},\"queued\":{d},\"events\":[", .{ if (watcher.recursive) "true" else "false", if (watcher.closed) "true" else "false", watcher.events.items.len }) catch return fail();
    for (watcher.events.items, 0..) |event, i| {
        if (i != 0) out.append(',') catch return fail();
        out.appendSlice("{\"event\":") catch return fail();
        appendJsonString(&out, event.event_type) catch return fail();
        out.appendSlice(",\"filename\":") catch return fail();
        appendJsonString(&out, event.filename) catch return fail();
        out.append('}') catch return fail();
    }
    out.appendSlice("]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_vfs_watcher_close(watcher_ptr: ?*anyopaque) u32 {
    const watcher = vfsWatcherHandle(watcher_ptr) orelse return fail();
    watcher.closed = true;
    watcher.deinit(true);
    return 0;
}

pub export fn sa_node_plugin_vfs_snapshot_json(vfs_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = vfsHandle(vfs_ptr) orelse return fail();
    var keys = std.ArrayList([]const u8).init(handle.allocator);
    defer keys.deinit();
    var it = handle.entries.keyIterator();
    while (it.next()) |key_ptr| keys.append(key_ptr.*) catch return fail();
    std.mem.sort([]const u8, keys.items, {}, vfsSortStrings);
    var out = std.ArrayList(u8).init(handle.allocator);
    defer out.deinit();
    out.appendSlice("{\"provider\":\"memory\",\"readonly\":false,\"supportsSymlinks\":true,\"supportsWatch\":true,\"watchers\":") catch return fail();
    out.writer().print("{d},\"cwd\":", .{handle.watchers.items.len}) catch return fail();
    appendJsonString(&out, handle.cwd) catch return fail();
    out.appendSlice(",\"entries\":[") catch return fail();
    for (keys.items, 0..) |key, i| {
        if (i != 0) out.append(',') catch return fail();
        vfsAppendStat(&out, key, handle.entries.get(key).?) catch return fail();
    }
    out.appendSlice("]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_ffi_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "ffi", true, "dynamic library open/symbol lookup and common C ABI integer/string call helpers are exposed");
}

const FfiLibraryHandle = struct {
    lib: std.DynLib,
    fn deinit(self: *FfiLibraryHandle) void {
        self.lib.close();
        std.heap.page_allocator.destroy(self);
    }
};

const FfiFnI64_0 = *const fn () callconv(.c) i64;
const FfiFnI64_1 = *const fn (i64) callconv(.c) i64;
const FfiFnI64_2 = *const fn (i64, i64) callconv(.c) i64;
const FfiFnStrlen = *const fn ([*:0]const u8) callconv(.c) usize;
const FfiFnStringI64 = *const fn ([*:0]const u8, i64) callconv(.c) i64;
const FfiFnPtrString = *const fn ([*:0]const u8) callconv(.c) ?[*:0]const u8;

pub export fn sa_node_plugin_ffi_open(path_ptr: ?[*]const u8, path_len: u64, out_library: ?*?*anyopaque) u32 {
    const path = path_ptr.?[0..path_len];
    var lib = std.DynLib.open(path) catch return fail();
    const handle = std.heap.page_allocator.create(FfiLibraryHandle) catch {
        lib.close();
        return fail();
    };
    handle.* = .{ .lib = lib };
    out_library.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_ffi_close(library_ptr: ?*anyopaque) u32 {
    if (library_ptr) |ptr| {
        const handle: *FfiLibraryHandle = @ptrCast(@alignCast(ptr));
        handle.deinit();
    }
    return 0;
}

pub export fn sa_node_plugin_ffi_has_symbol(library_ptr: ?*anyopaque, symbol_ptr: ?[*]const u8, symbol_len: u64, out_bool: ?*u32) u32 {
    const handle: *FfiLibraryHandle = @ptrCast(@alignCast(library_ptr orelse return fail()));
    const symbol_z = std.heap.page_allocator.dupeZ(u8, symbol_ptr.?[0..symbol_len]) catch return fail();
    defer std.heap.page_allocator.free(symbol_z);
    out_bool.?.* = if (handle.lib.lookup(*const anyopaque, symbol_z)) |_| 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_ffi_call_i64_0(library_ptr: ?*anyopaque, symbol_ptr: ?[*]const u8, symbol_len: u64, out_value: ?*i64) u32 {
    const handle: *FfiLibraryHandle = @ptrCast(@alignCast(library_ptr orelse return fail()));
    const symbol_z = std.heap.page_allocator.dupeZ(u8, symbol_ptr.?[0..symbol_len]) catch return fail();
    defer std.heap.page_allocator.free(symbol_z);
    const func = handle.lib.lookup(FfiFnI64_0, symbol_z) orelse return fail();
    out_value.?.* = func();
    return 0;
}

pub export fn sa_node_plugin_ffi_call_i64_1(library_ptr: ?*anyopaque, symbol_ptr: ?[*]const u8, symbol_len: u64, a0: i64, out_value: ?*i64) u32 {
    const handle: *FfiLibraryHandle = @ptrCast(@alignCast(library_ptr orelse return fail()));
    const symbol_z = std.heap.page_allocator.dupeZ(u8, symbol_ptr.?[0..symbol_len]) catch return fail();
    defer std.heap.page_allocator.free(symbol_z);
    const func = handle.lib.lookup(FfiFnI64_1, symbol_z) orelse return fail();
    out_value.?.* = func(a0);
    return 0;
}

pub export fn sa_node_plugin_ffi_call_i64_2(library_ptr: ?*anyopaque, symbol_ptr: ?[*]const u8, symbol_len: u64, a0: i64, a1: i64, out_value: ?*i64) u32 {
    const handle: *FfiLibraryHandle = @ptrCast(@alignCast(library_ptr orelse return fail()));
    const symbol_z = std.heap.page_allocator.dupeZ(u8, symbol_ptr.?[0..symbol_len]) catch return fail();
    defer std.heap.page_allocator.free(symbol_z);
    const func = handle.lib.lookup(FfiFnI64_2, symbol_z) orelse return fail();
    out_value.?.* = func(a0, a1);
    return 0;
}

pub export fn sa_node_plugin_ffi_call_strlen(library_ptr: ?*anyopaque, symbol_ptr: ?[*]const u8, symbol_len: u64, value_ptr: ?[*]const u8, value_len: u64, out_value: ?*u64) u32 {
    const handle: *FfiLibraryHandle = @ptrCast(@alignCast(library_ptr orelse return fail()));
    const symbol_z = std.heap.page_allocator.dupeZ(u8, symbol_ptr.?[0..symbol_len]) catch return fail();
    defer std.heap.page_allocator.free(symbol_z);
    const value_z = std.heap.page_allocator.dupeZ(u8, value_ptr.?[0..value_len]) catch return fail();
    defer std.heap.page_allocator.free(value_z);
    const func = handle.lib.lookup(FfiFnStrlen, symbol_z) orelse return fail();
    out_value.?.* = @intCast(func(value_z.ptr));
    return 0;
}

pub export fn sa_node_plugin_ffi_call_string_i64(library_ptr: ?*anyopaque, symbol_ptr: ?[*]const u8, symbol_len: u64, value_ptr: ?[*]const u8, value_len: u64, a0: i64, out_value: ?*i64) u32 {
    const handle: *FfiLibraryHandle = @ptrCast(@alignCast(library_ptr orelse return fail()));
    const symbol_z = std.heap.page_allocator.dupeZ(u8, symbol_ptr.?[0..symbol_len]) catch return fail();
    defer std.heap.page_allocator.free(symbol_z);
    const value_z = std.heap.page_allocator.dupeZ(u8, value_ptr.?[0..value_len]) catch return fail();
    defer std.heap.page_allocator.free(value_z);
    const func = handle.lib.lookup(FfiFnStringI64, symbol_z) orelse return fail();
    out_value.?.* = func(value_z.ptr, a0);
    return 0;
}

pub export fn sa_node_plugin_ffi_call_ptr_string(library_ptr: ?*anyopaque, symbol_ptr: ?[*]const u8, symbol_len: u64, value_ptr: ?[*]const u8, value_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *FfiLibraryHandle = @ptrCast(@alignCast(library_ptr orelse return fail()));
    const symbol_z = std.heap.page_allocator.dupeZ(u8, symbol_ptr.?[0..symbol_len]) catch return fail();
    defer std.heap.page_allocator.free(symbol_z);
    const value_z = std.heap.page_allocator.dupeZ(u8, value_ptr.?[0..value_len]) catch return fail();
    defer std.heap.page_allocator.free(value_z);
    const func = handle.lib.lookup(FfiFnPtrString, symbol_z) orelse return fail();
    const result = func(value_z.ptr) orelse return fail();
    return writeOwnedBytes(out_ptr, out_len, std.mem.span(result));
}

pub export fn sa_node_plugin_sqlite_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "sqlite", true, "SQLite open/exec/query/prepare/bind/step/reset/finalize/backup, session/changeset, and SQLTagStore-style cache helpers are exposed through libsqlite3");
}

// --- SQLite native subset backed by libsqlite3 ---
const Sqlite3 = opaque {};
const Sqlite3Stmt = opaque {};
const Sqlite3Backup = opaque {};
const Sqlite3Session = opaque {};
const Sqlite3ChangesetIter = opaque {};

const Sqlite3OpenV2Fn = *const fn ([*:0]const u8, *?*Sqlite3, c_int, ?[*:0]const u8) callconv(.c) c_int;
const Sqlite3CloseFn = *const fn (?*Sqlite3) callconv(.c) c_int;
const Sqlite3ExecFn = *const fn (?*Sqlite3, [*:0]const u8, ?*const anyopaque, ?*anyopaque, ?*?[*:0]u8) callconv(.c) c_int;
const Sqlite3ErrmsgFn = *const fn (?*Sqlite3) callconv(.c) [*:0]const u8;
const Sqlite3PrepareV2Fn = *const fn (?*Sqlite3, [*:0]const u8, c_int, *?*Sqlite3Stmt, ?*?[*]const u8) callconv(.c) c_int;
const Sqlite3StepFn = *const fn (?*Sqlite3Stmt) callconv(.c) c_int;
const Sqlite3FinalizeFn = *const fn (?*Sqlite3Stmt) callconv(.c) c_int;
const Sqlite3ColumnCountFn = *const fn (?*Sqlite3Stmt) callconv(.c) c_int;
const Sqlite3ColumnNameFn = *const fn (?*Sqlite3Stmt, c_int) callconv(.c) [*:0]const u8;
const Sqlite3ColumnTypeFn = *const fn (?*Sqlite3Stmt, c_int) callconv(.c) c_int;
const Sqlite3ColumnTextFn = *const fn (?*Sqlite3Stmt, c_int) callconv(.c) ?[*:0]const u8;
const Sqlite3ColumnBlobFn = *const fn (?*Sqlite3Stmt, c_int) callconv(.c) ?*const anyopaque;
const Sqlite3ColumnBytesFn = *const fn (?*Sqlite3Stmt, c_int) callconv(.c) c_int;
const Sqlite3ColumnInt64Fn = *const fn (?*Sqlite3Stmt, c_int) callconv(.c) i64;
const Sqlite3ColumnDoubleFn = *const fn (?*Sqlite3Stmt, c_int) callconv(.c) f64;
const Sqlite3ChangesFn = *const fn (?*Sqlite3) callconv(.c) c_int;
const Sqlite3LastInsertRowidFn = *const fn (?*Sqlite3) callconv(.c) i64;
const Sqlite3LibversionFn = *const fn () callconv(.c) [*:0]const u8;
const Sqlite3BindInt64Fn = *const fn (?*Sqlite3Stmt, c_int, i64) callconv(.c) c_int;
const Sqlite3BindDoubleFn = *const fn (?*Sqlite3Stmt, c_int, f64) callconv(.c) c_int;
const Sqlite3BindTextFn = *const fn (?*Sqlite3Stmt, c_int, [*]const u8, c_int, ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int;
const Sqlite3BindBlobFn = *const fn (?*Sqlite3Stmt, c_int, [*]const u8, c_int, ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int;
const Sqlite3BindNullFn = *const fn (?*Sqlite3Stmt, c_int) callconv(.c) c_int;
const Sqlite3ResetFn = *const fn (?*Sqlite3Stmt) callconv(.c) c_int;
const Sqlite3ClearBindingsFn = *const fn (?*Sqlite3Stmt) callconv(.c) c_int;
const Sqlite3BackupInitFn = *const fn (?*Sqlite3, [*:0]const u8, ?*Sqlite3, [*:0]const u8) callconv(.c) ?*Sqlite3Backup;
const Sqlite3BackupStepFn = *const fn (?*Sqlite3Backup, c_int) callconv(.c) c_int;
const Sqlite3BackupFinishFn = *const fn (?*Sqlite3Backup) callconv(.c) c_int;
const Sqlite3BackupRemainingFn = *const fn (?*Sqlite3Backup) callconv(.c) c_int;
const Sqlite3BackupPagecountFn = *const fn (?*Sqlite3Backup) callconv(.c) c_int;
const Sqlite3FreeFn = *const fn (?*anyopaque) callconv(.c) void;
const Sqlite3SessionCreateFn = *const fn (?*Sqlite3, [*:0]const u8, *?*Sqlite3Session) callconv(.c) c_int;
const Sqlite3SessionAttachFn = *const fn (?*Sqlite3Session, ?[*:0]const u8) callconv(.c) c_int;
const Sqlite3SessionChangesetFn = *const fn (?*Sqlite3Session, *c_int, *?*anyopaque) callconv(.c) c_int;
const Sqlite3SessionPatchsetFn = *const fn (?*Sqlite3Session, *c_int, *?*anyopaque) callconv(.c) c_int;
const Sqlite3SessionDeleteFn = *const fn (?*Sqlite3Session) callconv(.c) void;
const Sqlite3SessionIsEmptyFn = *const fn (?*Sqlite3Session) callconv(.c) c_int;
const Sqlite3SessionMemoryUsedFn = *const fn (?*Sqlite3Session) callconv(.c) i64;
const Sqlite3ChangesetConflictFn = *const fn (?*anyopaque, c_int, ?*Sqlite3ChangesetIter) callconv(.c) c_int;
const Sqlite3ChangesetApplyFn = *const fn (?*Sqlite3, c_int, ?*anyopaque, ?*const fn (?*anyopaque, [*:0]const u8) callconv(.c) c_int, ?Sqlite3ChangesetConflictFn, ?*anyopaque) callconv(.c) c_int;

const SQLITE_OK = 0;
const SQLITE_ROW = 100;
const SQLITE_DONE = 101;
const SQLITE_OPEN_READWRITE = 0x00000002;
const SQLITE_OPEN_CREATE = 0x00000004;
const SQLITE_OPEN_URI = 0x00000040;
const SQLITE_NULL = 5;
const SQLITE_INTEGER = 1;
const SQLITE_FLOAT = 2;
const SQLITE_TEXT = 3;
const SQLITE_BLOB = 4;
const SQLITE_CHANGESET_ABORT = 2;
const SQLITE_TRANSIENT: ?*const fn (?*anyopaque) callconv(.c) void = @ptrFromInt(std.math.maxInt(usize));

const SqliteApi = struct {
    lib: std.DynLib,
    open_v2: Sqlite3OpenV2Fn,
    close: Sqlite3CloseFn,
    exec: Sqlite3ExecFn,
    errmsg: Sqlite3ErrmsgFn,
    prepare_v2: Sqlite3PrepareV2Fn,
    step: Sqlite3StepFn,
    finalize: Sqlite3FinalizeFn,
    column_count: Sqlite3ColumnCountFn,
    column_name: Sqlite3ColumnNameFn,
    column_type: Sqlite3ColumnTypeFn,
    column_text: Sqlite3ColumnTextFn,
    column_blob: Sqlite3ColumnBlobFn,
    column_bytes: Sqlite3ColumnBytesFn,
    column_int64: Sqlite3ColumnInt64Fn,
    column_double: Sqlite3ColumnDoubleFn,
    changes: Sqlite3ChangesFn,
    last_insert_rowid: Sqlite3LastInsertRowidFn,
    libversion: Sqlite3LibversionFn,
    bind_int64: Sqlite3BindInt64Fn,
    bind_double: Sqlite3BindDoubleFn,
    bind_text: Sqlite3BindTextFn,
    bind_blob: Sqlite3BindBlobFn,
    bind_null: Sqlite3BindNullFn,
    reset: Sqlite3ResetFn,
    clear_bindings: Sqlite3ClearBindingsFn,
    backup_init: Sqlite3BackupInitFn,
    backup_step: Sqlite3BackupStepFn,
    backup_finish: Sqlite3BackupFinishFn,
    backup_remaining: Sqlite3BackupRemainingFn,
    backup_pagecount: Sqlite3BackupPagecountFn,
    free: Sqlite3FreeFn,
    session_create: Sqlite3SessionCreateFn,
    session_attach: Sqlite3SessionAttachFn,
    session_changeset: Sqlite3SessionChangesetFn,
    session_patchset: Sqlite3SessionPatchsetFn,
    session_delete: Sqlite3SessionDeleteFn,
    session_isempty: Sqlite3SessionIsEmptyFn,
    session_memory_used: Sqlite3SessionMemoryUsedFn,
    changeset_apply: Sqlite3ChangesetApplyFn,
};

var sqlite_api: ?SqliteApi = null;
var sqlite_api_mutex = std.Thread.Mutex{};

fn loadSqliteApi() ?*SqliteApi {
    sqlite_api_mutex.lock();
    defer sqlite_api_mutex.unlock();
    if (sqlite_api) |*api| return api;
    const candidates = [_][]const u8{ "libsqlite3.so.0", "/lib/x86_64-linux-gnu/libsqlite3.so.0", "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0" };
    for (candidates) |candidate| {
        var lib = std.DynLib.open(candidate) catch continue;
        const open_v2 = lib.lookup(Sqlite3OpenV2Fn, "sqlite3_open_v2") orelse {
            lib.close();
            continue;
        };
        const close = lib.lookup(Sqlite3CloseFn, "sqlite3_close") orelse {
            lib.close();
            continue;
        };
        const exec = lib.lookup(Sqlite3ExecFn, "sqlite3_exec") orelse {
            lib.close();
            continue;
        };
        const errmsg = lib.lookup(Sqlite3ErrmsgFn, "sqlite3_errmsg") orelse {
            lib.close();
            continue;
        };
        const prepare_v2 = lib.lookup(Sqlite3PrepareV2Fn, "sqlite3_prepare_v2") orelse {
            lib.close();
            continue;
        };
        const step = lib.lookup(Sqlite3StepFn, "sqlite3_step") orelse {
            lib.close();
            continue;
        };
        const finalize = lib.lookup(Sqlite3FinalizeFn, "sqlite3_finalize") orelse {
            lib.close();
            continue;
        };
        const column_count = lib.lookup(Sqlite3ColumnCountFn, "sqlite3_column_count") orelse {
            lib.close();
            continue;
        };
        const column_name = lib.lookup(Sqlite3ColumnNameFn, "sqlite3_column_name") orelse {
            lib.close();
            continue;
        };
        const column_type = lib.lookup(Sqlite3ColumnTypeFn, "sqlite3_column_type") orelse {
            lib.close();
            continue;
        };
        const column_text = lib.lookup(Sqlite3ColumnTextFn, "sqlite3_column_text") orelse {
            lib.close();
            continue;
        };
        const column_blob = lib.lookup(Sqlite3ColumnBlobFn, "sqlite3_column_blob") orelse {
            lib.close();
            continue;
        };
        const column_bytes = lib.lookup(Sqlite3ColumnBytesFn, "sqlite3_column_bytes") orelse {
            lib.close();
            continue;
        };
        const column_int64 = lib.lookup(Sqlite3ColumnInt64Fn, "sqlite3_column_int64") orelse {
            lib.close();
            continue;
        };
        const column_double = lib.lookup(Sqlite3ColumnDoubleFn, "sqlite3_column_double") orelse {
            lib.close();
            continue;
        };
        const changes = lib.lookup(Sqlite3ChangesFn, "sqlite3_changes") orelse {
            lib.close();
            continue;
        };
        const last_insert_rowid = lib.lookup(Sqlite3LastInsertRowidFn, "sqlite3_last_insert_rowid") orelse {
            lib.close();
            continue;
        };
        const libversion = lib.lookup(Sqlite3LibversionFn, "sqlite3_libversion") orelse {
            lib.close();
            continue;
        };
        const bind_int64 = lib.lookup(Sqlite3BindInt64Fn, "sqlite3_bind_int64") orelse {
            lib.close();
            continue;
        };
        const bind_double = lib.lookup(Sqlite3BindDoubleFn, "sqlite3_bind_double") orelse {
            lib.close();
            continue;
        };
        const bind_text = lib.lookup(Sqlite3BindTextFn, "sqlite3_bind_text") orelse {
            lib.close();
            continue;
        };
        const bind_blob = lib.lookup(Sqlite3BindBlobFn, "sqlite3_bind_blob") orelse {
            lib.close();
            continue;
        };
        const bind_null = lib.lookup(Sqlite3BindNullFn, "sqlite3_bind_null") orelse {
            lib.close();
            continue;
        };
        const reset = lib.lookup(Sqlite3ResetFn, "sqlite3_reset") orelse {
            lib.close();
            continue;
        };
        const clear_bindings = lib.lookup(Sqlite3ClearBindingsFn, "sqlite3_clear_bindings") orelse {
            lib.close();
            continue;
        };
        const backup_init = lib.lookup(Sqlite3BackupInitFn, "sqlite3_backup_init") orelse {
            lib.close();
            continue;
        };
        const backup_step = lib.lookup(Sqlite3BackupStepFn, "sqlite3_backup_step") orelse {
            lib.close();
            continue;
        };
        const backup_finish = lib.lookup(Sqlite3BackupFinishFn, "sqlite3_backup_finish") orelse {
            lib.close();
            continue;
        };
        const backup_remaining = lib.lookup(Sqlite3BackupRemainingFn, "sqlite3_backup_remaining") orelse {
            lib.close();
            continue;
        };
        const backup_pagecount = lib.lookup(Sqlite3BackupPagecountFn, "sqlite3_backup_pagecount") orelse {
            lib.close();
            continue;
        };
        const sqlite_free = lib.lookup(Sqlite3FreeFn, "sqlite3_free") orelse {
            lib.close();
            continue;
        };
        const session_create = lib.lookup(Sqlite3SessionCreateFn, "sqlite3session_create") orelse {
            lib.close();
            continue;
        };
        const session_attach = lib.lookup(Sqlite3SessionAttachFn, "sqlite3session_attach") orelse {
            lib.close();
            continue;
        };
        const session_changeset = lib.lookup(Sqlite3SessionChangesetFn, "sqlite3session_changeset") orelse {
            lib.close();
            continue;
        };
        const session_patchset = lib.lookup(Sqlite3SessionPatchsetFn, "sqlite3session_patchset") orelse {
            lib.close();
            continue;
        };
        const session_delete = lib.lookup(Sqlite3SessionDeleteFn, "sqlite3session_delete") orelse {
            lib.close();
            continue;
        };
        const session_isempty = lib.lookup(Sqlite3SessionIsEmptyFn, "sqlite3session_isempty") orelse {
            lib.close();
            continue;
        };
        const session_memory_used = lib.lookup(Sqlite3SessionMemoryUsedFn, "sqlite3session_memory_used") orelse {
            lib.close();
            continue;
        };
        const changeset_apply = lib.lookup(Sqlite3ChangesetApplyFn, "sqlite3changeset_apply") orelse {
            lib.close();
            continue;
        };
        sqlite_api = .{ .lib = lib, .open_v2 = open_v2, .close = close, .exec = exec, .errmsg = errmsg, .prepare_v2 = prepare_v2, .step = step, .finalize = finalize, .column_count = column_count, .column_name = column_name, .column_type = column_type, .column_text = column_text, .column_blob = column_blob, .column_bytes = column_bytes, .column_int64 = column_int64, .column_double = column_double, .changes = changes, .last_insert_rowid = last_insert_rowid, .libversion = libversion, .bind_int64 = bind_int64, .bind_double = bind_double, .bind_text = bind_text, .bind_blob = bind_blob, .bind_null = bind_null, .reset = reset, .clear_bindings = clear_bindings, .backup_init = backup_init, .backup_step = backup_step, .backup_finish = backup_finish, .backup_remaining = backup_remaining, .backup_pagecount = backup_pagecount, .free = sqlite_free, .session_create = session_create, .session_attach = session_attach, .session_changeset = session_changeset, .session_patchset = session_patchset, .session_delete = session_delete, .session_isempty = session_isempty, .session_memory_used = session_memory_used, .changeset_apply = changeset_apply };
        return &sqlite_api.?;
    }
    return null;
}

const SqliteDbHandle = struct { db: ?*Sqlite3 };
const SqliteStmtHandle = struct { db: ?*Sqlite3, stmt: ?*Sqlite3Stmt };
const SqliteBackupHandle = struct {
    dest: ?*Sqlite3,
    backup: ?*Sqlite3Backup,
    finished: bool = false,
};
const SqliteSessionHandle = struct {
    session: ?*Sqlite3Session,
    closed: bool = false,
};

const SqliteTagEntry = struct {
    sql: []u8,
    stmt: ?*Sqlite3Stmt,
    last_used: u64,

    fn deinit(self: *SqliteTagEntry, api: *SqliteApi, allocator: std.mem.Allocator) void {
        _ = api.finalize(self.stmt);
        allocator.free(self.sql);
    }
};

const SqliteTagStoreHandle = struct {
    allocator: std.mem.Allocator,
    db: ?*Sqlite3,
    capacity: usize,
    clock: u64 = 0,
    entries: std.ArrayList(SqliteTagEntry),

    fn deinit(self: *SqliteTagStoreHandle, api: *SqliteApi) void {
        for (self.entries.items) |*entry| entry.deinit(api, self.allocator);
        self.entries.deinit();
        self.allocator.destroy(self);
    }
};

pub export fn sa_node_plugin_sqlite_version_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const version = std.mem.span(api.libversion());
    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    defer json.deinit();
    json.writer().print("{{\"sqlite\":", .{}) catch return fail();
    appendJsonString(&json, version) catch return fail();
    json.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, json.items);
}

pub export fn sa_node_plugin_sqlite_open(path_ptr: ?[*]const u8, path_len: u64, out_db: ?*?*anyopaque) u32 {
    const api = loadSqliteApi() orelse return fail();
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return fail();
    defer std.heap.page_allocator.free(path_z);
    var db: ?*Sqlite3 = null;
    if (api.open_v2(path_z.ptr, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, null) != SQLITE_OK) return fail();
    const handle = std.heap.page_allocator.create(SqliteDbHandle) catch return fail();
    handle.* = .{ .db = db };
    out_db.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_sqlite_close(db_ptr: ?*anyopaque) u32 {
    if (db_ptr) |ptr| {
        const api = loadSqliteApi() orelse return fail();
        const handle: *SqliteDbHandle = @ptrCast(@alignCast(ptr));
        _ = api.close(handle.db);
        std.heap.page_allocator.destroy(handle);
    }
    return 0;
}

pub export fn sa_node_plugin_sqlite_exec(db_ptr: ?*anyopaque, sql_ptr: ?[*]const u8, sql_len: u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteDbHandle = @ptrCast(@alignCast(db_ptr orelse return fail()));
    const sql_z = std.heap.page_allocator.dupeZ(u8, sql_ptr.?[0..sql_len]) catch return fail();
    defer std.heap.page_allocator.free(sql_z);
    return if (api.exec(handle.db, sql_z.ptr, null, null, null) == SQLITE_OK) 0 else fail();
}

fn sqliteAppendRow(api: *SqliteApi, stmt: ?*Sqlite3Stmt, out: *std.ArrayList(u8)) !void {
    try out.append('{');
    const cols = api.column_count(stmt);
    var i: c_int = 0;
    while (i < cols) : (i += 1) {
        if (i > 0) try out.append(',');
        try appendJsonString(out, std.mem.span(api.column_name(stmt, i)));
        try out.append(':');
        switch (api.column_type(stmt, i)) {
            SQLITE_INTEGER => try out.writer().print("{d}", .{api.column_int64(stmt, i)}),
            SQLITE_FLOAT => try out.writer().print("{d}", .{api.column_double(stmt, i)}),
            SQLITE_TEXT => {
                const text_ptr = api.column_text(stmt, i) orelse "";
                const len: usize = @intCast(api.column_bytes(stmt, i));
                try appendJsonString(out, text_ptr[0..len]);
            },
            SQLITE_BLOB => {
                const blob_ptr = api.column_blob(stmt, i) orelse {
                    try appendJsonString(out, "");
                    continue;
                };
                const len: usize = @intCast(api.column_bytes(stmt, i));
                const bytes: [*]const u8 = @ptrCast(blob_ptr);
                const enc_len = std.base64.standard.Encoder.calcSize(len);
                const enc = try std.heap.page_allocator.alloc(u8, enc_len);
                defer std.heap.page_allocator.free(enc);
                _ = std.base64.standard.Encoder.encode(enc, bytes[0..len]);
                try appendJsonString(out, enc);
            },
            SQLITE_NULL => try out.appendSlice("null"),
            else => try appendJsonString(out, ""),
        }
    }
    try out.append('}');
}

pub export fn sa_node_plugin_sqlite_query_json(db_ptr: ?*anyopaque, sql_ptr: ?[*]const u8, sql_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteDbHandle = @ptrCast(@alignCast(db_ptr orelse return fail()));
    const sql_z = std.heap.page_allocator.dupeZ(u8, sql_ptr.?[0..sql_len]) catch return fail();
    defer std.heap.page_allocator.free(sql_z);
    var stmt: ?*Sqlite3Stmt = null;
    if (api.prepare_v2(handle.db, sql_z.ptr, -1, &stmt, null) != SQLITE_OK) return fail();
    defer _ = api.finalize(stmt);
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.append('[') catch return fail();
    var first = true;
    while (true) {
        const rc = api.step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) return fail();
        if (!first) out.append(',') catch return fail();
        first = false;
        sqliteAppendRow(api, stmt, &out) catch return fail();
    }
    out.append(']') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_sqlite_prepare(db_ptr: ?*anyopaque, sql_ptr: ?[*]const u8, sql_len: u64, out_stmt: ?*?*anyopaque) u32 {
    const api = loadSqliteApi() orelse return fail();
    const db_handle: *SqliteDbHandle = @ptrCast(@alignCast(db_ptr orelse return fail()));
    const sql_z = std.heap.page_allocator.dupeZ(u8, sql_ptr.?[0..sql_len]) catch return fail();
    defer std.heap.page_allocator.free(sql_z);
    var stmt: ?*Sqlite3Stmt = null;
    if (api.prepare_v2(db_handle.db, sql_z.ptr, -1, &stmt, null) != SQLITE_OK) return fail();
    const handle = std.heap.page_allocator.create(SqliteStmtHandle) catch return fail();
    handle.* = .{ .db = db_handle.db, .stmt = stmt };
    out_stmt.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_sqlite_step_json(stmt_ptr: ?*anyopaque, out_ready: ?*u32, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteStmtHandle = @ptrCast(@alignCast(stmt_ptr orelse return fail()));
    const rc = api.step(handle.stmt);
    if (rc == SQLITE_DONE) {
        out_ready.?.* = 0;
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return 0;
    }
    if (rc != SQLITE_ROW) return fail();
    out_ready.?.* = 1;
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    sqliteAppendRow(api, handle.stmt, &out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn sqliteBindIndex(index: u64) ?c_int {
    if (index == 0 or index > std.math.maxInt(c_int)) return null;
    return @intCast(index);
}

pub export fn sa_node_plugin_sqlite_bind_int(stmt_ptr: ?*anyopaque, index: u64, value: i64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteStmtHandle = @ptrCast(@alignCast(stmt_ptr orelse return fail()));
    const idx = sqliteBindIndex(index) orelse return fail();
    return if (api.bind_int64(handle.stmt, idx, value) == SQLITE_OK) 0 else fail();
}

pub export fn sa_node_plugin_sqlite_bind_double(stmt_ptr: ?*anyopaque, index: u64, value: f64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteStmtHandle = @ptrCast(@alignCast(stmt_ptr orelse return fail()));
    const idx = sqliteBindIndex(index) orelse return fail();
    return if (api.bind_double(handle.stmt, idx, value) == SQLITE_OK) 0 else fail();
}

pub export fn sa_node_plugin_sqlite_bind_text(stmt_ptr: ?*anyopaque, index: u64, value_ptr: ?[*]const u8, value_len: u64) u32 {
    if (value_len > std.math.maxInt(c_int)) return fail();
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteStmtHandle = @ptrCast(@alignCast(stmt_ptr orelse return fail()));
    const idx = sqliteBindIndex(index) orelse return fail();
    const value = if (value_ptr) |ptr| ptr[0..value_len] else return fail();
    return if (api.bind_text(handle.stmt, idx, value.ptr, @intCast(value.len), SQLITE_TRANSIENT) == SQLITE_OK) 0 else fail();
}

pub export fn sa_node_plugin_sqlite_bind_blob(stmt_ptr: ?*anyopaque, index: u64, value_ptr: ?[*]const u8, value_len: u64) u32 {
    if (value_len > std.math.maxInt(c_int)) return fail();
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteStmtHandle = @ptrCast(@alignCast(stmt_ptr orelse return fail()));
    const idx = sqliteBindIndex(index) orelse return fail();
    const value = if (value_ptr) |ptr| ptr[0..value_len] else return fail();
    return if (api.bind_blob(handle.stmt, idx, value.ptr, @intCast(value.len), SQLITE_TRANSIENT) == SQLITE_OK) 0 else fail();
}

pub export fn sa_node_plugin_sqlite_bind_null(stmt_ptr: ?*anyopaque, index: u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteStmtHandle = @ptrCast(@alignCast(stmt_ptr orelse return fail()));
    const idx = sqliteBindIndex(index) orelse return fail();
    return if (api.bind_null(handle.stmt, idx) == SQLITE_OK) 0 else fail();
}

pub export fn sa_node_plugin_sqlite_reset(stmt_ptr: ?*anyopaque) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteStmtHandle = @ptrCast(@alignCast(stmt_ptr orelse return fail()));
    return if (api.reset(handle.stmt) == SQLITE_OK) 0 else fail();
}

pub export fn sa_node_plugin_sqlite_clear_bindings(stmt_ptr: ?*anyopaque) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteStmtHandle = @ptrCast(@alignCast(stmt_ptr orelse return fail()));
    return if (api.clear_bindings(handle.stmt) == SQLITE_OK) 0 else fail();
}

pub export fn sa_node_plugin_sqlite_finalize(stmt_ptr: ?*anyopaque) u32 {
    if (stmt_ptr) |ptr| {
        const api = loadSqliteApi() orelse return fail();
        const handle: *SqliteStmtHandle = @ptrCast(@alignCast(ptr));
        _ = api.finalize(handle.stmt);
        std.heap.page_allocator.destroy(handle);
    }
    return 0;
}

pub export fn sa_node_plugin_sqlite_changes(db_ptr: ?*anyopaque, out_changes: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteDbHandle = @ptrCast(@alignCast(db_ptr orelse return fail()));
    out_changes.?.* = @intCast(api.changes(handle.db));
    return 0;
}

pub export fn sa_node_plugin_sqlite_last_insert_rowid(db_ptr: ?*anyopaque, out_rowid: ?*i64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteDbHandle = @ptrCast(@alignCast(db_ptr orelse return fail()));
    out_rowid.?.* = api.last_insert_rowid(handle.db);
    return 0;
}

fn sqlitePagesArg(pages: u64) c_int {
    if (pages == 0 or pages > @as(u64, @intCast(std.math.maxInt(c_int)))) return -1;
    return @intCast(pages);
}

pub export fn sa_node_plugin_sqlite_backup_init(db_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, out_backup: ?*?*anyopaque) u32 {
    const api = loadSqliteApi() orelse return fail();
    const source: *SqliteDbHandle = @ptrCast(@alignCast(db_ptr orelse return fail()));
    const path_z = std.heap.page_allocator.dupeZ(u8, path_ptr.?[0..path_len]) catch return fail();
    defer std.heap.page_allocator.free(path_z);
    var dest: ?*Sqlite3 = null;
    if (api.open_v2(path_z.ptr, &dest, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, null) != SQLITE_OK) return fail();
    errdefer _ = api.close(dest);
    const backup = api.backup_init(dest, "main", source.db, "main") orelse return fail();
    const handle = std.heap.page_allocator.create(SqliteBackupHandle) catch return fail();
    handle.* = .{ .dest = dest, .backup = backup };
    out_backup.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_sqlite_backup_step(backup_ptr: ?*anyopaque, pages: u64, out_done: ?*u32, out_remaining: ?*u64, out_pagecount: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteBackupHandle = @ptrCast(@alignCast(backup_ptr orelse return fail()));
    if (handle.finished) return fail();
    const rc = api.backup_step(handle.backup, sqlitePagesArg(pages));
    out_remaining.?.* = @intCast(@max(api.backup_remaining(handle.backup), 0));
    out_pagecount.?.* = @intCast(@max(api.backup_pagecount(handle.backup), 0));
    if (rc == SQLITE_DONE) {
        out_done.?.* = 1;
        return 0;
    }
    if (rc == SQLITE_OK) {
        out_done.?.* = 0;
        return 0;
    }
    return fail();
}

pub export fn sa_node_plugin_sqlite_backup_remaining(backup_ptr: ?*anyopaque, out_remaining: ?*u64, out_pagecount: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const handle: *SqliteBackupHandle = @ptrCast(@alignCast(backup_ptr orelse return fail()));
    if (handle.finished) return fail();
    out_remaining.?.* = @intCast(@max(api.backup_remaining(handle.backup), 0));
    out_pagecount.?.* = @intCast(@max(api.backup_pagecount(handle.backup), 0));
    return 0;
}

pub export fn sa_node_plugin_sqlite_backup_finish(backup_ptr: ?*anyopaque) u32 {
    if (backup_ptr) |ptr| {
        const api = loadSqliteApi() orelse return fail();
        const handle: *SqliteBackupHandle = @ptrCast(@alignCast(ptr));
        if (!handle.finished) {
            _ = api.backup_finish(handle.backup);
            _ = api.close(handle.dest);
            handle.finished = true;
        }
        std.heap.page_allocator.destroy(handle);
    }
    return 0;
}

pub export fn sa_node_plugin_sqlite_backup_to_file(db_ptr: ?*anyopaque, path_ptr: ?[*]const u8, path_len: u64, pages_per_step: u64, out_pages: ?*u64) u32 {
    var backup_ptr: ?*anyopaque = null;
    if (sa_node_plugin_sqlite_backup_init(db_ptr, path_ptr, path_len, &backup_ptr) != 0) return fail();
    defer _ = sa_node_plugin_sqlite_backup_finish(backup_ptr);
    var done: u32 = 0;
    var remaining: u64 = 0;
    var pagecount: u64 = 0;
    while (done == 0) {
        if (sa_node_plugin_sqlite_backup_step(backup_ptr, pages_per_step, &done, &remaining, &pagecount) != 0) return fail();
    }
    out_pages.?.* = pagecount;
    return 0;
}

pub export fn sa_node_plugin_sqlite_session_create(db_ptr: ?*anyopaque, db_name_ptr: ?[*]const u8, db_name_len: u64, table_ptr: ?[*]const u8, table_len: u64, out_session: ?*?*anyopaque) u32 {
    const api = loadSqliteApi() orelse return fail();
    const db_handle: *SqliteDbHandle = @ptrCast(@alignCast(db_ptr orelse return fail()));
    const db_name = if (db_name_ptr) |ptr| ptr[0..db_name_len] else "main";
    const db_name_z = std.heap.page_allocator.dupeZ(u8, db_name) catch return fail();
    defer std.heap.page_allocator.free(db_name_z);

    var raw_session: ?*Sqlite3Session = null;
    if (api.session_create(db_handle.db, db_name_z.ptr, &raw_session) != SQLITE_OK) return fail();
    errdefer api.session_delete(raw_session);

    var table_z: ?[:0]u8 = null;
    defer if (table_z) |table| std.heap.page_allocator.free(table);
    const table_name: ?[*:0]const u8 = if (table_len == 0) null else blk: {
        const table = std.heap.page_allocator.dupeZ(u8, (table_ptr orelse return fail())[0..table_len]) catch return fail();
        table_z = table;
        break :blk table.ptr;
    };
    if (api.session_attach(raw_session, table_name) != SQLITE_OK) return fail();

    const handle = std.heap.page_allocator.create(SqliteSessionHandle) catch return fail();
    handle.* = .{ .session = raw_session };
    out_session.?.* = @ptrCast(handle);
    return 0;
}

fn sqliteSessionHandle(ptr: ?*anyopaque) ?*SqliteSessionHandle {
    const handle: *SqliteSessionHandle = @ptrCast(@alignCast(ptr orelse return null));
    if (handle.closed) return null;
    return handle;
}

fn sqliteWriteSessionBytes(session_ptr: ?*anyopaque, patchset: bool, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const session = sqliteSessionHandle(session_ptr) orelse return fail();
    var raw_len: c_int = 0;
    var raw_ptr: ?*anyopaque = null;
    const rc = if (patchset) api.session_patchset(session.session, &raw_len, &raw_ptr) else api.session_changeset(session.session, &raw_len, &raw_ptr);
    if (rc != SQLITE_OK) return fail();
    defer api.free(raw_ptr);
    if (raw_len < 0) return fail();
    const len: usize = @intCast(raw_len);
    const raw: [*]const u8 = if (raw_ptr) |ptr| @ptrCast(ptr) else {
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return 0;
    };
    return writeOwnedBytes(out_ptr, out_len, raw[0..len]);
}

pub export fn sa_node_plugin_sqlite_session_changeset(session_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sqliteWriteSessionBytes(session_ptr, false, out_ptr, out_len);
}

pub export fn sa_node_plugin_sqlite_session_patchset(session_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sqliteWriteSessionBytes(session_ptr, true, out_ptr, out_len);
}

pub export fn sa_node_plugin_sqlite_session_isempty(session_ptr: ?*anyopaque, out_empty: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const session = sqliteSessionHandle(session_ptr) orelse return fail();
    out_empty.?.* = if (api.session_isempty(session.session) != 0) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_sqlite_session_memory_used(session_ptr: ?*anyopaque, out_bytes: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const session = sqliteSessionHandle(session_ptr) orelse return fail();
    const bytes = api.session_memory_used(session.session);
    if (bytes < 0) return fail();
    out_bytes.?.* = @intCast(bytes);
    return 0;
}

pub export fn sa_node_plugin_sqlite_session_close(session_ptr: ?*anyopaque) u32 {
    if (session_ptr) |ptr| {
        const api = loadSqliteApi() orelse return fail();
        const handle: *SqliteSessionHandle = @ptrCast(@alignCast(ptr));
        if (!handle.closed) {
            api.session_delete(handle.session);
            handle.closed = true;
        }
        std.heap.page_allocator.destroy(handle);
    }
    return 0;
}

fn sqliteChangesetAbortConflict(_: ?*anyopaque, _: c_int, _: ?*Sqlite3ChangesetIter) callconv(.c) c_int {
    return SQLITE_CHANGESET_ABORT;
}

pub export fn sa_node_plugin_sqlite_apply_changeset(db_ptr: ?*anyopaque, changeset_ptr: ?[*]const u8, changeset_len: u64, out_applied: ?*u64) u32 {
    if (changeset_len > std.math.maxInt(c_int)) return fail();
    const api = loadSqliteApi() orelse return fail();
    const db_handle: *SqliteDbHandle = @ptrCast(@alignCast(db_ptr orelse return fail()));
    const bytes = if (changeset_ptr) |ptr| ptr[0..changeset_len] else return fail();
    const rc = api.changeset_apply(db_handle.db, @intCast(bytes.len), @ptrCast(@constCast(bytes.ptr)), null, sqliteChangesetAbortConflict, null);
    if (rc == SQLITE_OK) {
        out_applied.?.* = 1;
        return 0;
    }
    out_applied.?.* = 0;
    return fail();
}

fn sqliteTagStoreHandle(ptr: ?*anyopaque) ?*SqliteTagStoreHandle {
    return @ptrCast(@alignCast(ptr orelse return null));
}

fn sqliteBindJsonValue(api: *SqliteApi, stmt: ?*Sqlite3Stmt, index: usize, value: std.json.Value) !void {
    if (index == 0 or index > @as(usize, @intCast(std.math.maxInt(c_int)))) return error.InvalidIndex;
    const idx: c_int = @intCast(index);
    const rc = switch (value) {
        .null => api.bind_null(stmt, idx),
        .integer => |v| api.bind_int64(stmt, idx, v),
        .float => |v| api.bind_double(stmt, idx, v),
        .number_string => |v| blk: {
            const as_int = std.fmt.parseInt(i64, v, 10) catch null;
            if (as_int) |parsed| break :blk api.bind_int64(stmt, idx, parsed);
            const as_float = std.fmt.parseFloat(f64, v) catch return error.InvalidNumber;
            break :blk api.bind_double(stmt, idx, as_float);
        },
        .bool => |v| api.bind_int64(stmt, idx, if (v) 1 else 0),
        .string => |v| api.bind_text(stmt, idx, v.ptr, @intCast(v.len), SQLITE_TRANSIENT),
        else => return error.UnsupportedJsonValue,
    };
    if (rc != SQLITE_OK) return error.BindFailed;
}

fn sqliteBindJsonArray(api: *SqliteApi, stmt: ?*Sqlite3Stmt, params_json: []const u8) !void {
    if (params_json.len == 0) return;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, params_json, .{});
    defer parsed.deinit();
    if (parsed.value != .array) return error.InvalidParams;
    for (parsed.value.array.items, 0..) |value, i| try sqliteBindJsonValue(api, stmt, i + 1, value);
}

fn sqliteTagStoreGetStmt(store: *SqliteTagStoreHandle, api: *SqliteApi, sql: []const u8) !?*Sqlite3Stmt {
    store.clock +%= 1;
    for (store.entries.items) |*entry| {
        if (std.mem.eql(u8, entry.sql, sql)) {
            entry.last_used = store.clock;
            if (api.reset(entry.stmt) != SQLITE_OK) return error.ResetFailed;
            if (api.clear_bindings(entry.stmt) != SQLITE_OK) return error.ClearFailed;
            return entry.stmt;
        }
    }

    if (store.entries.items.len >= store.capacity and store.entries.items.len > 0) {
        var oldest_i: usize = 0;
        var oldest = store.entries.items[0].last_used;
        for (store.entries.items, 0..) |entry, i| {
            if (entry.last_used < oldest) {
                oldest = entry.last_used;
                oldest_i = i;
            }
        }
        var removed = store.entries.orderedRemove(oldest_i);
        removed.deinit(api, store.allocator);
    }

    const sql_z = try store.allocator.dupeZ(u8, sql);
    defer store.allocator.free(sql_z);
    var stmt: ?*Sqlite3Stmt = null;
    if (api.prepare_v2(store.db, sql_z.ptr, -1, &stmt, null) != SQLITE_OK) return error.PrepareFailed;
    errdefer _ = api.finalize(stmt);
    const sql_owned = try store.allocator.dupe(u8, sql);
    errdefer store.allocator.free(sql_owned);
    try store.entries.append(.{ .sql = sql_owned, .stmt = stmt, .last_used = store.clock });
    return stmt;
}

fn sqliteTagStoreQuery(store: *SqliteTagStoreHandle, sql: []const u8, params_json: []const u8, first_only: bool, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const stmt = sqliteTagStoreGetStmt(store, api, sql) catch return fail();
    sqliteBindJsonArray(api, stmt, params_json) catch return fail();
    var out = std.ArrayList(u8).init(store.allocator);
    defer out.deinit();
    if (!first_only) out.append('[') catch return fail();
    var first = true;
    while (true) {
        const rc = api.step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) return fail();
        if (first_only) {
            sqliteAppendRow(api, stmt, &out) catch return fail();
            return writeOwnedBytes(out_ptr, out_len, out.items);
        }
        if (!first) out.append(',') catch return fail();
        first = false;
        sqliteAppendRow(api, stmt, &out) catch return fail();
    }
    if (first_only) {
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return 0;
    }
    out.append(']') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_sqlite_tagstore_new(db_ptr: ?*anyopaque, capacity: u64, out_store: ?*?*anyopaque) u32 {
    const db_handle: *SqliteDbHandle = @ptrCast(@alignCast(db_ptr orelse return fail()));
    const allocator = std.heap.page_allocator;
    const store = allocator.create(SqliteTagStoreHandle) catch return fail();
    const cap: usize = @intCast(if (capacity == 0) 1000 else @min(capacity, 100_000));
    store.* = .{ .allocator = allocator, .db = db_handle.db, .capacity = cap, .entries = std.ArrayList(SqliteTagEntry).init(allocator) };
    out_store.?.* = @ptrCast(store);
    return 0;
}

pub export fn sa_node_plugin_sqlite_tagstore_all(store_ptr: ?*anyopaque, sql_ptr: ?[*]const u8, sql_len: u64, params_ptr: ?[*]const u8, params_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const store = sqliteTagStoreHandle(store_ptr) orelse return fail();
    const params = if (params_ptr) |ptr| ptr[0..params_len] else "[]";
    return sqliteTagStoreQuery(store, sql_ptr.?[0..sql_len], params, false, out_ptr, out_len);
}

pub export fn sa_node_plugin_sqlite_tagstore_get(store_ptr: ?*anyopaque, sql_ptr: ?[*]const u8, sql_len: u64, params_ptr: ?[*]const u8, params_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const store = sqliteTagStoreHandle(store_ptr) orelse return fail();
    const params = if (params_ptr) |ptr| ptr[0..params_len] else "[]";
    return sqliteTagStoreQuery(store, sql_ptr.?[0..sql_len], params, true, out_ptr, out_len);
}

pub export fn sa_node_plugin_sqlite_tagstore_run(store_ptr: ?*anyopaque, sql_ptr: ?[*]const u8, sql_len: u64, params_ptr: ?[*]const u8, params_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadSqliteApi() orelse return fail();
    const store = sqliteTagStoreHandle(store_ptr) orelse return fail();
    const params = if (params_ptr) |ptr| ptr[0..params_len] else "[]";
    const stmt = sqliteTagStoreGetStmt(store, api, sql_ptr.?[0..sql_len]) catch return fail();
    sqliteBindJsonArray(api, stmt, params) catch return fail();
    const rc = api.step(stmt);
    if (rc != SQLITE_DONE and rc != SQLITE_ROW) return fail();
    var out = std.ArrayList(u8).init(store.allocator);
    defer out.deinit();
    out.writer().print("{{\"changes\":{d},\"lastInsertRowid\":{d}}}", .{ api.changes(store.db), api.last_insert_rowid(store.db) }) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_sqlite_tagstore_snapshot_json(store_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const store = sqliteTagStoreHandle(store_ptr) orelse return fail();
    var out = std.ArrayList(u8).init(store.allocator);
    defer out.deinit();
    out.writer().print("{{\"capacity\":{d},\"size\":{d},\"sql\":[", .{ store.capacity, store.entries.items.len }) catch return fail();
    for (store.entries.items, 0..) |entry, i| {
        if (i != 0) out.append(',') catch return fail();
        appendJsonString(&out, entry.sql) catch return fail();
    }
    out.appendSlice("]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_sqlite_tagstore_clear(store_ptr: ?*anyopaque) u32 {
    const api = loadSqliteApi() orelse return fail();
    const store = sqliteTagStoreHandle(store_ptr) orelse return fail();
    for (store.entries.items) |*entry| entry.deinit(api, store.allocator);
    store.entries.clearRetainingCapacity();
    return 0;
}

pub export fn sa_node_plugin_sqlite_tagstore_free(store_ptr: ?*anyopaque) u32 {
    if (sqliteTagStoreHandle(store_ptr)) |store| {
        const api = loadSqliteApi() orelse return fail();
        store.deinit(api);
    }
    return 0;
}

pub export fn sa_node_plugin_tty_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"tty\":{\"isatty\":true}}");
}
pub export fn sa_node_plugin_diagnostics_channel_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"diagnostics_channel\":{\"supported\":true}}");
}
