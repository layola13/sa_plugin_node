const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const plugin_api = @import("plugin_api");
const base = @import("node_saasm_api.zig");
const ext = @import("node_saasm_api_ext.zig");
const linux = std.os.linux;
const posix = std.posix;

const SaSlice = extern struct {
    ptr: [*]const u8,
    len: u64,
};

extern fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern fn strerror(errnum: c_int) ?[*:0]const u8;

const UnsupportedStatus = @intFromEnum(plugin_api.AbiStatus.failed);

fn pluginRootDir() []const u8 {
    return build_options.plugin_root;
}

fn pluginManifestPath() []const u8 {
    return std.fmt.comptimePrint("{s}/sap.json", .{build_options.plugin_root});
}

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
var async_context_stack = std.ArrayListUnmanaged(AsyncContextFrame){};

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

fn envTruthy(name: []const u8) bool {
    const value = std.posix.getenv(name) orelse return false;
    if (value.len == 0) return false;
    if (std.mem.eql(u8, value, "0")) return false;
    return !std.ascii.eqlIgnoreCase(value, "false");
}

fn nodeOptionsHasFlag(flag: []const u8) bool {
    return std.mem.indexOf(u8, std.posix.getenv("NODE_OPTIONS") orelse "", flag) != null;
}

fn cloneOrNullTerminatedDup(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    return allocator.dupe(u8, text);
}

fn appendJsonFieldSeparator(out: *std.ArrayList(u8), first: *bool) !void {
    if (!first.*) try out.append(',');
    first.* = false;
}

fn appendJsonFieldValue(out: *std.ArrayList(u8), first: *bool, name: []const u8, value: std.json.Value) !void {
    try appendJsonFieldSeparator(out, first);
    try appendJsonString(out, name);
    try out.append(':');
    try std.json.stringify(value, .{}, out.writer());
}

fn appendJsonStringFieldValue(out: *std.ArrayList(u8), first: *bool, name: []const u8, value: []const u8) !void {
    try appendJsonFieldSeparator(out, first);
    try appendJsonString(out, name);
    try out.append(':');
    try appendJsonString(out, value);
}

fn appendJsonRawFieldValue(out: *std.ArrayList(u8), first: *bool, name: []const u8, raw_json: []const u8) !void {
    try appendJsonFieldSeparator(out, first);
    try appendJsonString(out, name);
    try out.append(':');
    try out.appendSlice(raw_json);
}

fn appendJsonIntFieldValue(out: *std.ArrayList(u8), first: *bool, name: []const u8, value: i64) !void {
    try appendJsonFieldSeparator(out, first);
    try appendJsonString(out, name);
    try out.append(':');
    try out.writer().print("{d}", .{value});
}

fn appendJsonObjectMembers(out: *std.ArrayList(u8), first: *bool, object: std.json.ObjectMap) !void {
    var it = object.iterator();
    while (it.next()) |entry| {
        try appendJsonFieldValue(out, first, entry.key_ptr.*, entry.value_ptr.*);
    }
}

fn appendOwnedStringArray(out: *std.ArrayList(u8), items: []const []u8) !void {
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

const AsyncContextFrame = struct {
    allocator: std.mem.Allocator,
    async_id: u64,
    trigger_async_id: u64,
    type_name: []u8,

    fn initFromHandle(allocator: std.mem.Allocator, handle: *const AsyncResourceHandle) !AsyncContextFrame {
        return .{
            .allocator = allocator,
            .async_id = handle.id,
            .trigger_async_id = handle.trigger_async_id,
            .type_name = try allocator.dupe(u8, handle.type_name),
        };
    }

    fn deinit(self: *AsyncContextFrame) void {
        self.allocator.free(self.type_name);
    }
};

fn asyncContextTrackingCurrent() ?*const AsyncContextFrame {
    if (async_context_stack.items.len == 0) return null;
    return &async_context_stack.items[async_context_stack.items.len - 1];
}

fn asyncContextTrackingClear() void {
    for (async_context_stack.items) |*frame| frame.deinit();
    async_context_stack.clearRetainingCapacity();
}

fn asyncContextTrackingWriteSnapshotJson(out: *std.ArrayList(u8)) !void {
    try out.appendSlice("{\"supported\":true,\"model\":\"explicit-native-stack\",\"depth\":");
    try out.writer().print("{d}", .{async_context_stack.items.len});
    try out.appendSlice(",\"executionAsyncId\":");
    if (asyncContextTrackingCurrent()) |frame| {
        try out.writer().print("{d}", .{frame.async_id});
    } else {
        try out.writer().print("{d}", .{async_resource_last_id});
    }
    try out.appendSlice(",\"triggerAsyncId\":");
    if (asyncContextTrackingCurrent()) |frame| {
        try out.writer().print("{d}", .{frame.trigger_async_id});
    } else {
        try out.appendSlice("0");
    }
    try out.appendSlice(",\"stack\":[");
    for (async_context_stack.items, 0..) |frame, i| {
        if (i != 0) try out.append(',');
        try out.appendSlice("{\"asyncId\":");
        try out.writer().print("{d}", .{frame.async_id});
        try out.appendSlice(",\"triggerAsyncId\":");
        try out.writer().print("{d}", .{frame.trigger_async_id});
        try out.appendSlice(",\"type\":");
        try appendJsonString(out, frame.type_name);
        try out.append('}');
    }
    try out.appendSlice("]}");
}

pub export fn sa_node_plugin_async_hooks_snapshot_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    asyncContextTrackingWriteSnapshotJson(&out) catch return fail();
    if (out.items.len > 1 and out.items[out.items.len - 1] == '}') {
        _ = out.pop();
    }
    out.appendSlice(",\"providers\":[]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

const async_hooks_export_names = [_][]const u8{
    "AsyncLocalStorage",
    "createHook",
    "executionAsyncId",
    "triggerAsyncId",
    "executionAsyncResource",
    "asyncWrapProviders",
    "AsyncResource",
};

pub export fn sa_node_plugin_async_hooks_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    if (sa_node_plugin_async_hooks_snapshot_json(&snapshot_ptr, &snapshot_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"async_hooks\",\"supported\":true,\"mode\":\"top-level-native-async-hooks-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &async_hooks_export_names) catch return fail();
    out.appendSlice(",\"snapshot\":") catch return fail();
    out.appendSlice((snapshot_ptr orelse return fail())[0..@intCast(snapshot_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"executionAsyncId\":true,\"triggerAsyncId\":true,\"AsyncResource\":true,\"asyncWrapProviders\":true,\"snapshot\":true,\"createHook\":false,\"executionAsyncResource\":false,\"AsyncLocalStorage\":false},\"capabilities\":[\"execution and trigger async id lookup\",\"explicit AsyncResource handle create, free, and snapshot helpers\",\"native async-context snapshot JSON\",\"empty asyncWrapProviders catalog metadata\"],\"limitations\":[\"no JavaScript hook callback registration or lifecycle dispatch\",\"no JavaScript executionAsyncResource object identity\",\"no AsyncLocalStorage store propagation semantics\",\"async state changes occur only through explicit native helpers rather than automatic host callback instrumentation\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_async_hooks_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &async_hooks_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_async_hooks_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"resourceModel\":\"explicit native AsyncResource handle with id, type, and triggerAsyncId metadata\",\"snapshotModel\":\"native async-context stack snapshot JSON\",\"providersModel\":\"empty provider catalog metadata\",\"hookModel\":\"not-modeled for JavaScript callback registration and dispatch\",\"asyncLocalStorageModel\":\"not-modeled\"}");
}

pub export fn sa_node_plugin_async_hooks_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"executionAsyncId\":{\"supported\":true,\"mode\":\"read current explicit native execution async id\"},\"triggerAsyncId\":{\"supported\":true,\"mode\":\"read current explicit native trigger async id\"},\"AsyncResource\":{\"supported\":true,\"mode\":\"explicit native AsyncResource handle with create/free/snapshot helpers\",\"limitations\":[\"not a JavaScript AsyncResource class instance\"]},\"asyncWrapProviders\":{\"supported\":true,\"mode\":\"static empty provider catalog metadata\"},\"snapshot\":{\"supported\":true,\"mode\":\"native async-context snapshot JSON\"},\"createHook\":{\"supported\":false,\"reason\":\"JavaScript async hook callback registration and dispatch are not modeled\"},\"executionAsyncResource\":{\"supported\":false,\"reason\":\"JavaScript executionAsyncResource object identity is not modeled\"},\"AsyncLocalStorage\":{\"supported\":false,\"reason\":\"AsyncLocalStorage store propagation semantics are not modeled in this facade\"}}");
}

pub export fn sa_node_plugin_stream_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"stream\",\"supported\":true,\"mode\":\"top-level-native-stream-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &stream_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"Readable\":false,\"Writable\":false,\"Duplex\":true,\"Transform\":true,\"PassThrough\":true,\"duplexPair\":true,\"pipeline\":true,\"finished\":true,\"compose\":true,\"destroy\":true,\"promises\":false,\"addAbortSignal\":false,\"setDefaultHighWaterMark\":false,\"getDefaultHighWaterMark\":false},\"capabilities\":[\"explicit native duplex, transform, passthrough, and composed stream handles\",\"pipeline and finished state JSON helpers\",\"explicit destroy helpers for stream handles\",\"duplex pair construction for connected native handles\"],\"limitations\":[\"no JavaScript Readable, Writable, Duplex, Transform, or PassThrough class instances\",\"no EventEmitter data, end, error, close, or drain lifecycle\",\"no stream.promises or addAbortSignal semantics\",\"default high-water-mark global tuning and prototype methods are not modeled\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_stream_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &stream_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_stream_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"handleModel\":\"explicit native stream handles with kind tags such as duplex, transform, passthrough, and composed\",\"pipelineModel\":\"native pipeline helper returns summary JSON rather than wiring JavaScript stream events\",\"finishedModel\":\"native finished helper returns snapshot JSON\",\"objectModel\":\"not-modeled for JavaScript stream class instances\",\"promisesModel\":\"not-modeled\"}");
}

pub export fn sa_node_plugin_stream_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"Readable\":{\"supported\":false,\"reason\":\"JavaScript Readable class instances and prototype semantics are not modeled\"},\"Writable\":{\"supported\":false,\"reason\":\"JavaScript Writable class instances and prototype semantics are not modeled\"},\"Duplex\":{\"supported\":true,\"mode\":\"explicit native duplex handle allocation\"},\"Transform\":{\"supported\":true,\"mode\":\"explicit native transform handle allocation\"},\"PassThrough\":{\"supported\":true,\"mode\":\"explicit native passthrough handle allocation\"},\"duplexPair\":{\"supported\":true,\"mode\":\"allocates two connected native duplex handles\"},\"pipeline\":{\"supported\":true,\"mode\":\"native pipeline summary JSON helper\",\"limitations\":[\"does not expose JavaScript callback or Promise completion semantics\"]},\"finished\":{\"supported\":true,\"mode\":\"native stream state snapshot JSON\"},\"compose\":{\"supported\":true,\"mode\":\"native composed stream handle helper\"},\"destroy\":{\"supported\":true,\"mode\":\"explicit native handle destroy helper\"},\"promises\":{\"supported\":false,\"reason\":\"stream.promises namespace and Promise object identity are not modeled\"},\"addAbortSignal\":{\"supported\":false,\"reason\":\"AbortSignal to stream cancellation wiring is not modeled\"},\"setDefaultHighWaterMark\":{\"supported\":false,\"reason\":\"global JavaScript stream high-water-mark tuning is not modeled\"},\"getDefaultHighWaterMark\":{\"supported\":false,\"reason\":\"global JavaScript stream high-water-mark tuning is not modeled\"}}");
}

pub export fn sa_node_plugin_readline_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"readline\",\"supported\":true,\"mode\":\"top-level-native-readline-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &readline_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"clearLine\":true,\"clearScreenDown\":true,\"cursorTo\":true,\"moveCursor\":true,\"emitKeypressEvents\":true,\"promises\":true,\"createInterface\":false,\"Interface\":false,\"completer\":false,\"historyEditing\":false},\"capabilities\":[\"terminal cursor and clear helpers over file descriptors\",\"emitKeypressEvents compatibility stub\",\"readline.promises explicit Interface handle with question, close, snapshot, and free helpers\"],\"limitations\":[\"no JavaScript readline.Interface class instances\",\"no callback-based createInterface or EventEmitter line lifecycle\",\"no completer, history editing, raw-mode line editor, or terminal redraw behavior\",\"promises support is limited to explicit native handle operations rather than JavaScript Promise/Interface objects\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_readline_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &readline_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_readline_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"cursorModel\":\"fd-based clear and cursor movement helpers\",\"promisesInterfaceModel\":\"explicit native Interface handle backed by buffered input text\",\"keypressModel\":\"emitKeypressEvents compatibility stub\",\"objectModel\":\"not-modeled for JavaScript Interface instances\"}");
}

pub export fn sa_node_plugin_readline_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"clearLine\":{\"supported\":true,\"mode\":\"fd-based ANSI clear-line helper\"},\"clearScreenDown\":{\"supported\":true,\"mode\":\"fd-based ANSI clear-screen-down helper\"},\"cursorTo\":{\"supported\":true,\"mode\":\"fd-based ANSI cursor positioning helper\"},\"moveCursor\":{\"supported\":true,\"mode\":\"fd-based ANSI relative cursor movement helper\"},\"emitKeypressEvents\":{\"supported\":true,\"mode\":\"compatibility stub with no event object production\"},\"promises\":{\"supported\":true,\"mode\":\"explicit native Interface handle with create/question/close/snapshot/free helpers\"},\"createInterface\":{\"supported\":false,\"reason\":\"callback-based JavaScript readline Interface creation and event lifecycle are not modeled; use the native promises Interface handle helpers instead\"},\"Interface\":{\"supported\":false,\"reason\":\"JavaScript readline Interface class instances are not modeled\"},\"completer\":{\"supported\":false,\"reason\":\"custom completion callbacks are not modeled\"},\"historyEditing\":{\"supported\":false,\"reason\":\"interactive line editing and history semantics are not modeled\"}}");
}

pub export fn sa_node_plugin_timers_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"timers\",\"supported\":true,\"mode\":\"top-level-native-timers-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &timers_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"setTimeout\":true,\"clearTimeout\":true,\"setImmediate\":true,\"clearImmediate\":true,\"setInterval\":true,\"clearInterval\":true,\"promises\":true,\"TimeoutObject\":false,\"ImmediateObject\":false,\"AbortSignal\":false,\"PromiseObjectIdentity\":false},\"capabilities\":[\"native timer id allocation for timeout, interval, and immediate helpers\",\"clear helpers over the native timer registry\",\"timers.promises setTimeout and setImmediate helpers returning already-resolved native buffers\",\"scheduler.wait and scheduler.yield helpers\",\"explicit timers.promises interval handle with next, return, snapshot, and free operations\"],\"limitations\":[\"no JavaScript Timeout or Immediate class instances\",\"no callback invocation or event-loop scheduling semantics beyond native id bookkeeping\",\"timers.promises does not return JavaScript Promise objects or async iterators\",\"AbortSignal cancellation wiring is not modeled\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_timers_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &timers_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_timers_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"timerModel\":\"native timer registry with numeric ids for timeout, interval, and immediate helpers\",\"promisesModel\":\"already-resolved native buffer helpers plus explicit interval handle operations\",\"schedulerModel\":\"native wait and yield helpers\",\"objectModel\":\"not-modeled for JavaScript Timeout/Immediate instances\"}");
}

pub export fn sa_node_plugin_timers_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"setTimeout\":{\"supported\":true,\"mode\":\"native timer id allocation with optional callback pointer bookkeeping\"},\"clearTimeout\":{\"supported\":true,\"mode\":\"native timer registry removal by id\"},\"setImmediate\":{\"supported\":true,\"mode\":\"native immediate id allocation\"},\"clearImmediate\":{\"supported\":true,\"mode\":\"native timer registry removal by id\"},\"setInterval\":{\"supported\":true,\"mode\":\"native interval id allocation with optional callback pointer bookkeeping\"},\"clearInterval\":{\"supported\":true,\"mode\":\"native timer registry removal by id\"},\"promises\":{\"supported\":true,\"mode\":\"native timers.promises helpers for timeout, immediate, scheduler, and explicit interval handles\",\"limitations\":[\"returns native buffers and explicit handles rather than JavaScript Promise or AsyncIterator objects\"]},\"TimeoutObject\":{\"supported\":false,\"reason\":\"JavaScript Timeout class instances and ref/unref methods are not modeled\"},\"ImmediateObject\":{\"supported\":false,\"reason\":\"JavaScript Immediate class instances are not modeled\"},\"AbortSignal\":{\"supported\":false,\"reason\":\"AbortSignal cancellation wiring is not modeled\"},\"PromiseObjectIdentity\":{\"supported\":false,\"reason\":\"timers.promises does not return JavaScript Promise object identity or microtask semantics\"}}");
}

pub export fn sa_node_plugin_console_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"console\",\"supported\":true,\"mode\":\"top-level-native-console-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &console_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"log\":true,\"info\":true,\"debug\":true,\"warn\":true,\"error\":true,\"dir\":true,\"dirxml\":true,\"table\":true,\"trace\":true,\"assert\":true,\"count\":true,\"countReset\":true,\"group\":true,\"groupCollapsed\":true,\"groupEnd\":true,\"time\":false,\"timeEnd\":false,\"timeLog\":true,\"timeStamp\":true,\"Console\":false},\"capabilities\":[\"global console-style stdout/stderr native text helpers\",\"native count and countReset label registry\",\"compatibility helpers for dir, dirxml, table, trace, and timeLog\",\"group, groupCollapsed, groupEnd, and timeStamp compatibility stubs\"],\"limitations\":[\"no JavaScript Console class instances or custom stream-backed console construction\",\"no inspect option, colorMode, or group indentation object-model parity\",\"time and timeEnd are not modeled; only timeLog metadata output is available\",\"formatting follows this plugin's native text helpers rather than exact Node util.format and inspector behavior\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_console_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &console_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_console_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"writeModel\":\"native stdout/stderr text output helpers\",\"counterModel\":\"native label registry shared by count and countReset\",\"groupModel\":\"status-only compatibility stubs without indentation stack semantics\",\"timingModel\":\"timeLog and timeStamp compatibility helpers without timer start/end registry\",\"objectModel\":\"not-modeled for JavaScript Console instances\"}");
}

pub export fn sa_node_plugin_console_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"log\":{\"supported\":true,\"mode\":\"native stdout text output helper via node base console ABI\"},\"info\":{\"supported\":true,\"mode\":\"native stdout text output helper\"},\"debug\":{\"supported\":true,\"mode\":\"native stdout text output helper\"},\"warn\":{\"supported\":true,\"mode\":\"native stderr text output helper\"},\"error\":{\"supported\":true,\"mode\":\"native stderr text output helper via node base console ABI\"},\"dir\":{\"supported\":true,\"mode\":\"native text output helper\"},\"dirxml\":{\"supported\":true,\"mode\":\"native text output helper\"},\"table\":{\"supported\":true,\"mode\":\"native text output helper\"},\"trace\":{\"supported\":true,\"mode\":\"native text output helper\"},\"assert\":{\"supported\":true,\"mode\":\"native conditional output helper\"},\"count\":{\"supported\":true,\"mode\":\"native label counter registry with string result output\"},\"countReset\":{\"supported\":true,\"mode\":\"native label counter reset\"},\"group\":{\"supported\":true,\"mode\":\"compatibility stub returning status only\"},\"groupCollapsed\":{\"supported\":true,\"mode\":\"compatibility stub returning status only\"},\"groupEnd\":{\"supported\":true,\"mode\":\"compatibility stub returning status only\"},\"time\":{\"supported\":false,\"reason\":\"timer start registry and JavaScript console timing object semantics are not modeled\"},\"timeEnd\":{\"supported\":false,\"reason\":\"timer completion registry and formatted elapsed-time output are not modeled\"},\"timeLog\":{\"supported\":true,\"mode\":\"native label plus payload text output helper\",\"limitations\":[\"does not depend on a prior time() registration\"]},\"timeStamp\":{\"supported\":true,\"mode\":\"native text output helper\"},\"Console\":{\"supported\":false,\"reason\":\"JavaScript Console class construction with custom streams and inspect options is not modeled\"},\"profile\":{\"supported\":false,\"reason\":\"inspector profiling integration is not modeled\"},\"clear\":{\"supported\":false,\"reason\":\"terminal clearing semantics are not exposed through the console facade\"}}");
}

pub export fn sa_node_plugin_events_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"events\",\"supported\":true,\"mode\":\"top-level-native-events-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &events_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"EventEmitter\":true,\"getEventListeners\":true,\"getMaxListeners\":true,\"setMaxListeners\":true,\"listenerCount\":true,\"errorMonitor\":false,\"captureRejections\":false,\"EventEmitterAsyncResource\":false,\"addAbortListener\":false,\"once\":false,\"on\":false},\"capabilities\":[\"explicit native EventEmitter handle allocation and free\",\"listener registration, prepend, once, remove, emit, and count helpers on native handles\",\"per-emitter max-listener metadata and event-listener snapshot JSON\",\"listenerCount and getEventListeners metadata over explicit native handles\"],\"limitations\":[\"top-level once() and on() Promise or AsyncIterator semantics are not modeled\",\"no JavaScript EventEmitter class/prototype objects, symbols, or thrown error behavior\",\"captureRejections, errorMonitor, EventEmitterAsyncResource, and addAbortListener require JavaScript function, Promise, AbortSignal, or async resource semantics\",\"listener callbacks are opaque native pointers rather than JavaScript functions\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_events_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &events_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_events_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"handleModel\":\"explicit native EventEmitter handle with listener arrays and per-listener once flags\",\"listenerModel\":\"opaque callback pointers stored on explicit native handles\",\"maxListenerModel\":\"per-emitter numeric max-listener metadata initialized to 10\",\"iterationModel\":\"listener snapshots returned as JSON arrays rather than live JavaScript arrays or iterators\",\"objectModel\":\"not-modeled for JavaScript EventEmitter class instances\"}");
}

pub export fn sa_node_plugin_events_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"EventEmitter\":{\"supported\":true,\"mode\":\"explicit native handle via create/on/once/off/emit/free helpers\",\"limitations\":[\"not exposed as a JavaScript class or prototype object\"]},\"getEventListeners\":{\"supported\":true,\"mode\":\"listener snapshot JSON for an explicit native handle and event name\"},\"getMaxListeners\":{\"supported\":true,\"mode\":\"reads stored max-listener metadata from an explicit native handle\"},\"setMaxListeners\":{\"supported\":true,\"mode\":\"writes stored max-listener metadata on an explicit native handle\",\"limitations\":[\"does not support EventTarget or global defaultMaxListeners mutation\"]},\"listenerCount\":{\"supported\":true,\"mode\":\"counts listeners for an explicit native handle and event name\"},\"errorMonitor\":{\"supported\":false,\"reason\":\"JavaScript symbol-keyed error monitoring semantics are not modeled\"},\"captureRejections\":{\"supported\":false,\"reason\":\"Promise rejection capture on JavaScript listeners is not modeled\"},\"EventEmitterAsyncResource\":{\"supported\":false,\"reason\":\"async resource backed EventEmitter subclass semantics are not modeled\"},\"addAbortListener\":{\"supported\":false,\"reason\":\"AbortSignal listener lifecycle and disposable return semantics are not modeled\"},\"once\":{\"supported\":false,\"reason\":\"top-level events.once() Promise semantics are not modeled; use explicit native emitter once-listener registration instead\"},\"on\":{\"supported\":false,\"reason\":\"top-level events.on() AsyncIterator semantics are not modeled; use explicit native emitter listener registration instead\"}}");
}

pub export fn sa_node_plugin_fs_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    if (sa_node_plugin_constants_json(&constants_ptr, &constants_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(constants_ptr, constants_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"fs\",\"supported\":true,\"mode\":\"top-level-native-fs-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &fs_export_names) catch return fail();
    out.appendSlice(",\"constants\":") catch return fail();
    out.appendSlice((constants_ptr orelse return fail())[0..@intCast(constants_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"access\":true,\"exists\":true,\"stat\":true,\"lstat\":true,\"readdir\":true,\"readFile\":true,\"writeFile\":true,\"mkdir\":true,\"rmdir\":true,\"rm\":true,\"unlink\":true,\"rename\":true,\"copyFile\":true,\"realpath\":true,\"readlink\":true,\"opendir\":true,\"open\":true,\"statfs\":true,\"glob\":true,\"promises\":true,\"constants\":true,\"cp\":false,\"watch\":false,\"watchFile\":false,\"unwatchFile\":false,\"ReadStream\":false,\"WriteStream\":false,\"Dir\":false,\"Dirent\":false,\"Stats\":false,\"openAsBlob\":false},\"capabilities\":[\"sync-style native file, directory, metadata, fd, link, glob, and statfs helpers\",\"fs.promises compatibility entry points returning already-resolved native results\",\"explicit opendir handle operations for directory iteration\",\"fs constants metadata through the native constants aggregate\"],\"limitations\":[\"no JavaScript ReadStream, WriteStream, Dir, Dirent, or Stats class instances\",\"no callback scheduling or event-emitter watch semantics\",\"promises returns already-resolved native results rather than JavaScript Promise objects\",\"cp, watch, watchFile, unwatchFile, and openAsBlob are not modeled at the top-level facade\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_fs_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &fs_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_fs_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"syncModel\":\"explicit native file and directory helpers returning immediate status plus buffers or scalars\",\"promisesModel\":\"fs.promises compatibility entry points returning already-resolved native results\",\"dirModel\":\"explicit opendir handle with next and free operations\",\"fdModel\":\"numeric file descriptors with explicit read/write/fstat/fsync/fdatasync/ftruncate/futimes helpers\",\"constantsModel\":\"native constants aggregate including fs access and copyfile flags\",\"objectModel\":\"not-modeled for JavaScript stream, Dir, Dirent, or Stats instances\"}");
}

pub export fn sa_node_plugin_fs_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"access\":{\"supported\":true,\"mode\":\"native existence and mode check helper returning boolean result\"},\"exists\":{\"supported\":true,\"mode\":\"native boolean existence helper\"},\"stat\":{\"supported\":true,\"mode\":\"native stat JSON helper\"},\"lstat\":{\"supported\":true,\"mode\":\"native lstat JSON helper\"},\"readdir\":{\"supported\":true,\"mode\":\"native directory listing JSON helper\"},\"readFile\":{\"supported\":true,\"mode\":\"native full-file read helper returning buffer\"},\"writeFile\":{\"supported\":true,\"mode\":\"native full-file write helper\"},\"mkdir\":{\"supported\":true,\"mode\":\"native mkdir helper with recursive flag\"},\"rmdir\":{\"supported\":true,\"mode\":\"native directory removal helper\"},\"rm\":{\"supported\":true,\"mode\":\"native remove helper with recursive flag\"},\"unlink\":{\"supported\":true,\"mode\":\"native unlink helper\"},\"rename\":{\"supported\":true,\"mode\":\"native rename helper\"},\"copyFile\":{\"supported\":true,\"mode\":\"native copy-file helper\"},\"realpath\":{\"supported\":true,\"mode\":\"native realpath helper returning resolved path text\"},\"readlink\":{\"supported\":true,\"mode\":\"native readlink helper returning target path text\"},\"opendir\":{\"supported\":true,\"mode\":\"explicit native directory handle with next and free operations\"},\"open\":{\"supported\":true,\"mode\":\"native open helper returning numeric file descriptor\"},\"statfs\":{\"supported\":true,\"mode\":\"native statfs JSON helper\"},\"glob\":{\"supported\":true,\"mode\":\"native glob helper returning matched path JSON\"},\"promises\":{\"supported\":true,\"mode\":\"fs.promises compatibility entry points over the same native operations\",\"limitations\":[\"returns already-resolved native results rather than JavaScript Promise object identity or microtask timing\"]},\"constants\":{\"supported\":true,\"mode\":\"native constants aggregate with fs access and copyfile flags\"},\"cp\":{\"supported\":false,\"reason\":\"recursive cp option handling is not exposed as a dedicated top-level helper\"},\"watch\":{\"supported\":false,\"reason\":\"FSWatcher event-emitter semantics are not modeled\"},\"watchFile\":{\"supported\":false,\"reason\":\"stat polling watcher semantics are not modeled\"},\"unwatchFile\":{\"supported\":false,\"reason\":\"stat polling watcher teardown semantics are not modeled\"},\"ReadStream\":{\"supported\":false,\"reason\":\"JavaScript ReadStream class instances are not modeled\"},\"WriteStream\":{\"supported\":false,\"reason\":\"JavaScript WriteStream class instances are not modeled\"},\"Dir\":{\"supported\":false,\"reason\":\"JavaScript Dir class instances are not modeled; use explicit native opendir handles instead\"},\"Dirent\":{\"supported\":false,\"reason\":\"JavaScript Dirent class instances are not modeled; directory entries are returned as JSON or scalar metadata\"},\"Stats\":{\"supported\":false,\"reason\":\"JavaScript Stats class instances are not modeled; stat data is returned as JSON\"},\"openAsBlob\":{\"supported\":false,\"reason\":\"Blob construction and stream-backed file blob semantics are not modeled\"}}");
}

pub export fn sa_node_plugin_crypto_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var hashes_ptr: ?[*]const u8 = null;
    var hashes_len: u64 = 0;
    if (ext.sa_node_plugin_crypto_get_hashes(&hashes_ptr, &hashes_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(hashes_ptr, hashes_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"crypto\",\"supported\":true,\"mode\":\"top-level-native-crypto-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &crypto_export_names) catch return fail();
    out.appendSlice(",\"hashes\":") catch return fail();
    out.appendSlice((hashes_ptr orelse return fail())[0..@intCast(hashes_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"randomBytes\":true,\"randomFill\":true,\"randomInt\":true,\"randomUUID\":true,\"createHash\":true,\"createHmac\":true,\"pbkdf2\":true,\"hkdf\":true,\"scrypt\":true,\"createCipheriv\":true,\"createDecipheriv\":true,\"sign\":true,\"verify\":true,\"generateKey\":true,\"getHashes\":true,\"timingSafeEqual\":true,\"webcrypto\":true,\"subtle\":true,\"generateKeyPair\":false,\"createPrivateKey\":false,\"createPublicKey\":false,\"createSecretKey\":false,\"KeyObject\":false,\"HashClass\":false,\"HmacClass\":false,\"Certificate\":false,\"X509Certificate\":false,\"secureHeapUsed\":false},\"capabilities\":[\"native random byte, UUID, integer, and fill helpers\",\"explicit native hash, HMAC, cipher, and decipher state handles\",\"PBKDF2, HKDF, scrypt, sign, verify, and symmetric key-generation helpers\",\"native hash catalog metadata and Web Crypto sync subset\"],\"limitations\":[\"no JavaScript Hash, Hmac, Cipheriv, Decipheriv, KeyObject, Certificate, or X509Certificate class instances\",\"no callback scheduling or Promise object identity for async-style Node crypto APIs\",\"generateKeyPair, asymmetric key object construction, and secure heap accounting are not modeled at the top-level facade\",\"webcrypto and subtle are exposed as native sync subsets rather than browser-compatible object graphs\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_crypto_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &crypto_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_crypto_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"randomModel\":\"native random byte, UUID, integer, and fill helpers\",\"hashModel\":\"one-shot hash plus explicit native hash and HMAC state handles\",\"cipherModel\":\"explicit native cipher and decipher state handles over supported symmetric algorithms\",\"keyModel\":\"raw byte buffers and explicit native web crypto key handles rather than JavaScript KeyObject instances\",\"webCryptoModel\":\"native sync subset for getRandomValues, randomUUID, subtle digest/import/generate/export/sign/verify/encrypt/decrypt\",\"objectModel\":\"not-modeled for JavaScript crypto class instances\"}");
}

pub export fn sa_node_plugin_crypto_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"randomBytes\":{\"supported\":true,\"mode\":\"native random byte buffer helper\"},\"randomFill\":{\"supported\":true,\"mode\":\"native in-place random fill helper\"},\"randomInt\":{\"supported\":true,\"mode\":\"native bounded random integer helper\"},\"randomUUID\":{\"supported\":true,\"mode\":\"native RFC4122 v4 UUID helper\"},\"createHash\":{\"supported\":true,\"mode\":\"explicit native hash state handle with update/final/free helpers\"},\"createHmac\":{\"supported\":true,\"mode\":\"explicit native HMAC state handle with update/final/free helpers\"},\"pbkdf2\":{\"supported\":true,\"mode\":\"native PBKDF2 helper\",\"limitations\":[\"returns derived key bytes directly rather than invoking a callback or returning a JavaScript Promise\"]},\"hkdf\":{\"supported\":true,\"mode\":\"native HKDF helper\"},\"scrypt\":{\"supported\":true,\"mode\":\"native scrypt helper\"},\"createCipheriv\":{\"supported\":true,\"mode\":\"explicit native cipher state handle with update/final/free helpers\"},\"createDecipheriv\":{\"supported\":true,\"mode\":\"explicit native decipher state handle with update/final/free helpers\"},\"sign\":{\"supported\":true,\"mode\":\"native Ed25519 sign helper over raw key bytes\"},\"verify\":{\"supported\":true,\"mode\":\"native Ed25519 verify helper over raw key bytes\"},\"generateKey\":{\"supported\":true,\"mode\":\"native random symmetric key bytes helper\"},\"getHashes\":{\"supported\":true,\"mode\":\"static hash catalog JSON\"},\"timingSafeEqual\":{\"supported\":true,\"mode\":\"native constant-time byte comparison helper\"},\"webcrypto\":{\"supported\":true,\"mode\":\"native sync Web Crypto subset\",\"limitations\":[\"not exposed as a full browser-compatible Crypto object graph\"]},\"subtle\":{\"supported\":true,\"mode\":\"native sync subset for digest/import/generate/export/sign/verify/encrypt/decrypt\",\"limitations\":[\"does not provide JavaScript Promise object identity or asynchronous timing\"]},\"generateKeyPair\":{\"supported\":false,\"reason\":\"Node key-pair generation and JavaScript KeyObject construction are not modeled\"},\"createPrivateKey\":{\"supported\":false,\"reason\":\"JavaScript KeyObject creation from PEM/DER/JWK is not modeled\"},\"createPublicKey\":{\"supported\":false,\"reason\":\"JavaScript KeyObject creation from PEM/DER/JWK is not modeled\"},\"createSecretKey\":{\"supported\":false,\"reason\":\"JavaScript KeyObject creation from secret key bytes is not modeled\"},\"KeyObject\":{\"supported\":false,\"reason\":\"JavaScript KeyObject class instances are not modeled\"},\"HashClass\":{\"supported\":false,\"reason\":\"JavaScript Hash class instances are not modeled; use explicit native handles instead\"},\"HmacClass\":{\"supported\":false,\"reason\":\"JavaScript Hmac class instances are not modeled; use explicit native handles instead\"},\"Certificate\":{\"supported\":false,\"reason\":\"legacy JavaScript Certificate helpers are not modeled\"},\"X509Certificate\":{\"supported\":false,\"reason\":\"JavaScript X509Certificate class instances are not modeled\"},\"secureHeapUsed\":{\"supported\":false,\"reason\":\"OpenSSL secure heap accounting is not modeled\"}}");
}

pub export fn sa_node_plugin_util_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"util\",\"supported\":true,\"mode\":\"top-level-native-util-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &util_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"callbackify\":true,\"promisify\":true,\"debuglog\":true,\"deprecate\":true,\"format\":true,\"styleText\":true,\"inherits\":true,\"inspect\":true,\"isDeepStrictEqual\":true,\"stripVTControlCharacters\":true,\"parseArgs\":true,\"diff\":true,\"MIMEType\":true,\"MIMEParams\":false,\"formatWithOptions\":false,\"getCallSites\":false,\"getSystemErrorMap\":false,\"getSystemErrorName\":false,\"getSystemErrorMessage\":false,\"TextDecoder\":false,\"TextEncoder\":false,\"types\":false,\"parseEnv\":false,\"setTraceSigInt\":false,\"transferableAbortSignal\":false,\"transferableAbortController\":false,\"aborted\":false},\"capabilities\":[\"native util.format and util.inspect style text and JSON formatting helpers\",\"native callbackify and promisify metadata wrappers plus deprecation and debuglog helpers\",\"native parseArgs, diff, MIME type lookup, styleText passthrough, and VT control stripping helpers\",\"deep strict equality and inheritance compatibility helpers without JavaScript prototype mutation semantics\"],\"limitations\":[\"no JavaScript class constructors or lazy property getters for TextEncoder, TextDecoder, MIMEParams, or util.types\",\"MIMEType is exposed as native path-to-media-type lookup metadata rather than a WHATWG MIMEType class instance\",\"formatWithOptions, parseEnv, getSystemErrorMap/Name/Message, getCallSites, setTraceSigInt, and abort-transfer helpers are not modeled\",\"callbackify and promisify expose native wrapper metadata rather than JavaScript function identity, callback timing, or Promise object semantics\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_util_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &util_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_util_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"formatModel\":\"native util.format and util.inspect helpers over JSON text and printf-style placeholders\",\"wrapModel\":\"callbackify and promisify return native wrapper metadata rather than JavaScript callable wrappers\",\"argModel\":\"parseArgs consumes JSON config and argv arrays and returns already-resolved values plus positionals JSON\",\"mimeModel\":\"MIMEType compatibility is modeled as filename/path media-type lookup JSON rather than WHATWG MIME classes\",\"deprecationModel\":\"native deprecation registry with explicit codes and messages\",\"objectModel\":\"not-modeled for JavaScript util.types, TextEncoder/TextDecoder, or MIMEType/MIMEParams class instances\"}");
}

pub export fn sa_node_plugin_util_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"callbackify\":{\"supported\":true,\"mode\":\"native metadata wrapper describing callbackified function intent\",\"limitations\":[\"does not return a JavaScript callable wrapper or nextTick rejection timing\"]},\"promisify\":{\"supported\":true,\"mode\":\"native metadata wrapper describing promisified function intent\",\"limitations\":[\"does not return a JavaScript Promise-returning wrapper function\"]},\"debuglog\":{\"supported\":true,\"mode\":\"NODE_DEBUG-aware native section metadata helper\"},\"deprecate\":{\"supported\":true,\"mode\":\"native deprecation registry keyed by code\",\"limitations\":[\"does not wrap JavaScript functions or emit process warning events\"]},\"format\":{\"supported\":true,\"mode\":\"native printf-style formatter over JSON argument arrays\"},\"styleText\":{\"supported\":true,\"mode\":\"native passthrough helper preserving input text\",\"limitations\":[\"ANSI style expansion and stream validation are not modeled\"]},\"inherits\":{\"supported\":true,\"mode\":\"native compatibility stub for inheritance intent\",\"limitations\":[\"does not mutate JavaScript prototypes\"]},\"inspect\":{\"supported\":true,\"mode\":\"native pretty-printed JSON formatter\",\"limitations\":[\"does not implement Node inspect custom hooks, colors, getters, or prototype traversal semantics\"]},\"isDeepStrictEqual\":{\"supported\":true,\"mode\":\"native JSON deep strict equality helper\"},\"stripVTControlCharacters\":{\"supported\":true,\"mode\":\"native VT control stripping helper\"},\"parseArgs\":{\"supported\":true,\"mode\":\"native JSON parseArgs subset for long --key=value options and positionals\",\"limitations\":[\"does not implement the full Node option schema, tokens, short-option, strict, or default-value behavior\"]},\"diff\":{\"supported\":true,\"mode\":\"native replace-or-empty diff summary helper\"},\"MIMEType\":{\"supported\":true,\"mode\":\"native filename/path to media-type lookup helper\",\"limitations\":[\"does not construct a WHATWG MIMEType class instance\"]},\"MIMEParams\":{\"supported\":false,\"reason\":\"WHATWG MIME parameter collection semantics are not modeled\"},\"formatWithOptions\":{\"supported\":false,\"reason\":\"inspect option bag handling is not modeled as a dedicated helper\"},\"getCallSites\":{\"supported\":false,\"reason\":\"JavaScript stack frame and source-map call-site inspection requires runtime integration\"},\"getSystemErrorMap\":{\"supported\":false,\"reason\":\"system error map exposure is not modeled in the util facade\"},\"getSystemErrorName\":{\"supported\":false,\"reason\":\"system error name lookup is not exposed through the util facade\"},\"getSystemErrorMessage\":{\"supported\":false,\"reason\":\"system error message lookup is not exposed through the util facade\"},\"TextDecoder\":{\"supported\":false,\"reason\":\"JavaScript TextDecoder class construction and decode semantics are not modeled in util\"},\"TextEncoder\":{\"supported\":false,\"reason\":\"JavaScript TextEncoder class construction and encode semantics are not modeled in util\"},\"types\":{\"supported\":false,\"reason\":\"util.types object and predicate catalog are not modeled\"},\"parseEnv\":{\"supported\":false,\"reason\":\"util.parseEnv is exposed through environment variable helpers, not the util top-level facade\"},\"setTraceSigInt\":{\"supported\":false,\"reason\":\"SIGINT trace integration is not modeled\"},\"transferableAbortSignal\":{\"supported\":false,\"reason\":\"AbortSignal transfer helpers require JavaScript object semantics\"},\"transferableAbortController\":{\"supported\":false,\"reason\":\"AbortController transfer helpers require JavaScript object semantics\"},\"aborted\":{\"supported\":false,\"reason\":\"abort state helper requires JavaScript AbortSignal semantics\"}}");
}

pub export fn sa_node_plugin_buffer_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"buffer\",\"supported\":true,\"mode\":\"top-level-native-buffer-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &buffer_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"transcode\":true,\"isUtf8\":true,\"isAscii\":true,\"atob\":true,\"btoa\":true,\"resolveObjectURL\":true,\"Buffer\":false,\"Buffer_byteLength\":true,\"Buffer_concat\":true,\"Blob\":false,\"File\":false,\"constants\":false,\"kMaxLength\":false,\"kStringMaxLength\":false,\"INSPECT_MAX_BYTES\":false},\"capabilities\":[\"native base64 helpers, ASCII and UTF-8 classification, and transcoding across common encodings\",\"native blob URL normalization through resolveObjectURL\",\"native byteLength and concat helpers exposed through the core buffer ABI\",\"top-level export-name and support metadata for the common public buffer surface\"],\"limitations\":[\"no JavaScript Buffer class instances, prototype methods, pooling, or Uint8Array subclass semantics\",\"no JavaScript Blob or File class instances or object URL store semantics\",\"buffer constants and mutable INSPECT_MAX_BYTES getter/setter semantics are not modeled\",\"Buffer static methods are available as native ABI helpers rather than through a live Buffer constructor export\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_buffer_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &buffer_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_buffer_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"textModel\":\"native base64 and encoding transcode helpers over raw byte slices\",\"classificationModel\":\"native UTF-8 and ASCII predicates over raw byte slices\",\"objectUrlModel\":\"resolveObjectURL strips the blob: wrapper to a native underlying URL string\",\"bufferStaticModel\":\"byteLength and concat are exposed as direct native helpers rather than through a JavaScript Buffer constructor\",\"objectModel\":\"not-modeled for JavaScript Buffer, Blob, or File class instances\"}");
}

pub export fn sa_node_plugin_buffer_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"transcode\":{\"supported\":true,\"mode\":\"native transcoding helper across utf8, utf16le, latin1, ascii, base64, base64url, and hex\"},\"isUtf8\":{\"supported\":true,\"mode\":\"native UTF-8 validation helper\"},\"isAscii\":{\"supported\":true,\"mode\":\"native ASCII validation helper\"},\"atob\":{\"supported\":true,\"mode\":\"native base64 decode helper returning text bytes\"},\"btoa\":{\"supported\":true,\"mode\":\"native base64 encode helper from text bytes\"},\"resolveObjectURL\":{\"supported\":true,\"mode\":\"native blob URL normalization helper\",\"limitations\":[\"does not consult a JavaScript blob URL registry or return Blob objects\"]},\"Buffer_byteLength\":{\"supported\":true,\"mode\":\"native byte-length helper over raw slices\"},\"Buffer_concat\":{\"supported\":true,\"mode\":\"native concatenation helper over explicit slice arrays\"},\"Buffer\":{\"supported\":false,\"reason\":\"JavaScript Buffer constructor, Uint8Array subclass identity, and prototype methods are not modeled\"},\"Blob\":{\"supported\":false,\"reason\":\"JavaScript Blob class instances are not modeled in the buffer facade\"},\"File\":{\"supported\":false,\"reason\":\"JavaScript File class instances are not modeled in the buffer facade\"},\"constants\":{\"supported\":false,\"reason\":\"buffer constants object and its exact Node numeric values are not modeled\"},\"kMaxLength\":{\"supported\":false,\"reason\":\"Node internal maximum Buffer length constant is not exposed\"},\"kStringMaxLength\":{\"supported\":false,\"reason\":\"Node internal maximum string length constant is not exposed\"},\"INSPECT_MAX_BYTES\":{\"supported\":false,\"reason\":\"mutable util.inspect Buffer truncation state is not modeled\"}}");
}

pub export fn sa_node_plugin_url_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"url\",\"supported\":true,\"mode\":\"top-level-native-url-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &url_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"parse\":true,\"format\":true,\"resolve\":true,\"URL\":true,\"URLSearchParams\":false,\"domainToASCII\":true,\"domainToUnicode\":true,\"pathToFileURL\":true,\"fileURLToPath\":true,\"fileURLToPathBuffer\":true,\"URLPattern\":false,\"urlToHttpOptions\":false,\"canParse\":true},\"capabilities\":[\"legacy-style native url.parse, url.format, and url.resolve helpers over JSON and string inputs\",\"explicit native URL handle creation plus href, protocol, host, and pathname getters\",\"native domainToASCII/domainToUnicode helpers via existing punycode conversion support\",\"native pathToFileURL, fileURLToPath, fileURLToPathBuffer, and canParse helpers\",\"top-level export-name and support metadata for the public url module surface\"],\"limitations\":[\"no WHATWG URLSearchParams, URLPattern, or live JavaScript URL class object graph semantics\",\"urlToHttpOptions is not exposed as a dedicated native helper\",\"parse/format/resolve and file URL helpers follow this plugin's native subset and do not claim full WHATWG object-model parity\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_url_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &url_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_url_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"legacyModel\":\"native url.parse, url.format, and url.resolve helpers over string and JSON inputs\",\"handleModel\":\"explicit native URL handle with href, protocol, host, and pathname getters plus free\",\"queryModel\":\"query strings remain embedded in parse and format text fields rather than separate URLSearchParams objects\",\"fileUrlModel\":\"native pathToFileURL plus fileURLToPath and fileURLToPathBuffer helpers over explicit text or byte buffers\",\"domainModel\":\"domainToASCII and domainToUnicode reuse the existing punycode conversion support\",\"objectModel\":\"not-modeled for WHATWG URLSearchParams, URLPattern, or JavaScript URL instance semantics beyond explicit native handle snapshots\"}");
}

pub export fn sa_node_plugin_url_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"parse\":{\"supported\":true,\"mode\":\"native legacy-style URL parse helper returning JSON fields\",\"limitations\":[\"does not emit Node deprecation warnings or parse query strings into querystring objects\"]},\"format\":{\"supported\":true,\"mode\":\"native URL format helper from JSON fields\"},\"resolve\":{\"supported\":true,\"mode\":\"native URL resolve helper combining base and relative inputs\"},\"URL\":{\"supported\":true,\"mode\":\"explicit native handle with href, protocol, host, pathname, and free operations\",\"limitations\":[\"does not expose full JavaScript URL property mutation, searchParams, or WHATWG serialization semantics\"]},\"URLSearchParams\":{\"supported\":false,\"reason\":\"WHATWG URLSearchParams object semantics are not modeled\"},\"domainToASCII\":{\"supported\":true,\"mode\":\"native domain-to-ASCII helper reusing punycode conversion support\"},\"domainToUnicode\":{\"supported\":true,\"mode\":\"native domain-to-Unicode helper reusing punycode conversion support\"},\"pathToFileURL\":{\"supported\":true,\"mode\":\"native absolute path to file:// URL helper\",\"limitations\":[\"follows host path resolution and percent-encoding subset rather than full WHATWG URL object semantics\"]},\"fileURLToPath\":{\"supported\":true,\"mode\":\"native file:// URL to path text helper\",\"limitations\":[\"supports absolute file URLs only in the current native subset\"]},\"fileURLToPathBuffer\":{\"supported\":true,\"mode\":\"native file:// URL to raw path buffer helper\",\"limitations\":[\"supports absolute file URLs only in the current native subset\"]},\"URLPattern\":{\"supported\":false,\"reason\":\"WHATWG URLPattern class semantics are not modeled\"},\"urlToHttpOptions\":{\"supported\":false,\"reason\":\"conversion from WHATWG URL objects to HTTP options is not exposed as a dedicated helper\"},\"canParse\":{\"supported\":true,\"mode\":\"native parseability predicate using direct URL parse or base-plus-resolve checks\"}}");
}

pub export fn sa_node_plugin_process_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"process\",\"supported\":true,\"mode\":\"top-level-native-process-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &process_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"pid\":true,\"ppid\":true,\"cwd\":true,\"uptime\":true,\"hrtime\":true,\"memoryUsage\":true,\"argv\":true,\"versions\":true,\"env\":true,\"getuid\":true,\"getgid\":true,\"kill\":true,\"resourceUsage\":true,\"availableMemory\":true,\"constrainedMemory\":true,\"features\":true,\"exit\":true,\"arch\":false,\"platform\":false,\"release\":false,\"version\":false,\"versionsObjectIdentity\":false,\"stdin\":false,\"stdout\":false,\"stderr\":false,\"nextTick\":false,\"emitWarning\":false,\"dlopen\":false,\"umask\":false,\"chdir\":false},\"capabilities\":[\"native process identity, cwd, uptime, hrtime, argv, versions, env, uid, and gid helpers\",\"native process memory usage, resourceUsage, availableMemory, constrainedMemory, and features JSON helpers\",\"real POSIX signal delivery through kill helpers and explicit process exit\",\"top-level export-name and support metadata for the public process surface\"],\"limitations\":[\"no JavaScript EventEmitter process object semantics, warning events, or nextTick queue integration\",\"no live stdin/stdout/stderr stream objects or process.channel/message IPC behavior\",\"arch, platform, release, version, dlopen, umask, and chdir are not exposed as dedicated native helpers in this facade\",\"versions and env are exposed through explicit JSON and getter/setter helpers rather than live JavaScript object identity\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_process_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &process_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_process_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"identityModel\":\"native pid, ppid, uid, gid, cwd, uptime, argv, and versions helpers\",\"memoryModel\":\"native memoryUsage, resourceUsage, availableMemory, constrainedMemory, and features JSON snapshots\",\"signalModel\":\"real POSIX kill helpers by numeric or named signal plus explicit exit\",\"envModel\":\"explicit process env get, set, delete, and snapshot helpers rather than a live JavaScript proxy object\",\"objectModel\":\"not-modeled for EventEmitter process object semantics, stdio stream instances, or nextTick queues\"}");
}

pub export fn sa_node_plugin_process_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"pid\":{\"supported\":true,\"mode\":\"native process pid helper\"},\"ppid\":{\"supported\":true,\"mode\":\"native parent pid helper\"},\"cwd\":{\"supported\":true,\"mode\":\"native cwd string helper\"},\"uptime\":{\"supported\":true,\"mode\":\"native process uptime helper in seconds\"},\"hrtime\":{\"supported\":true,\"mode\":\"native monotonic hrtime bigint helper\"},\"memoryUsage\":{\"supported\":true,\"mode\":\"native process memory usage JSON snapshot\"},\"argv\":{\"supported\":true,\"mode\":\"native argv JSON snapshot\"},\"versions\":{\"supported\":true,\"mode\":\"native versions JSON snapshot\",\"limitations\":[\"not exposed as a live JavaScript process.versions object\"]},\"env\":{\"supported\":true,\"mode\":\"explicit native env get, set, delete, and snapshot helpers\",\"limitations\":[\"not exposed as a live JavaScript process.env proxy object\"]},\"getuid\":{\"supported\":true,\"mode\":\"native uid helper\"},\"getgid\":{\"supported\":true,\"mode\":\"native gid helper\"},\"kill\":{\"supported\":true,\"mode\":\"real POSIX signal delivery by numeric or named signal\"},\"resourceUsage\":{\"supported\":true,\"mode\":\"native getrusage-based JSON snapshot\"},\"availableMemory\":{\"supported\":true,\"mode\":\"native host and cgroup-aware available-memory helper\"},\"constrainedMemory\":{\"supported\":true,\"mode\":\"native cgroup memory limit helper\"},\"features\":{\"supported\":true,\"mode\":\"native build capability JSON snapshot\"},\"exit\":{\"supported\":true,\"mode\":\"explicit native process exit helper\",\"limitations\":[\"terminates the host process immediately rather than coordinating JavaScript exit events\"]},\"arch\":{\"supported\":false,\"reason\":\"process.arch string is not exposed as a dedicated helper in the current native ABI\"},\"platform\":{\"supported\":false,\"reason\":\"process.platform string is not exposed as a dedicated helper in the current native ABI\"},\"release\":{\"supported\":false,\"reason\":\"process.release metadata is not exposed as a dedicated helper in the current native ABI\"},\"version\":{\"supported\":false,\"reason\":\"process.version string is not exposed as a dedicated helper in the current native ABI\"},\"stdin\":{\"supported\":false,\"reason\":\"live stdin stream object semantics are not modeled\"},\"stdout\":{\"supported\":false,\"reason\":\"live stdout stream object semantics are not modeled\"},\"stderr\":{\"supported\":false,\"reason\":\"live stderr stream object semantics are not modeled\"},\"nextTick\":{\"supported\":false,\"reason\":\"JavaScript nextTick queue semantics require runtime integration\"},\"emitWarning\":{\"supported\":false,\"reason\":\"JavaScript warning event and Error object semantics are not modeled\"},\"dlopen\":{\"supported\":false,\"reason\":\"process.dlopen and native module loader semantics are not modeled\"},\"umask\":{\"supported\":false,\"reason\":\"process.umask is not exposed as a dedicated helper in the current native ABI\"},\"chdir\":{\"supported\":false,\"reason\":\"process.chdir is not exposed as a dedicated helper in the current native ABI\"}}");
}

pub export fn sa_node_plugin_os_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"os\",\"supported\":true,\"mode\":\"top-level-native-os-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &os_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"arch\":true,\"availableParallelism\":true,\"cpus\":true,\"endianness\":true,\"freemem\":true,\"getPriority\":true,\"homedir\":true,\"hostname\":true,\"loadavg\":true,\"machine\":true,\"networkInterfaces\":true,\"platform\":true,\"release\":true,\"setPriority\":true,\"tmpdir\":true,\"totalmem\":true,\"type\":true,\"uptime\":true,\"userInfo\":true,\"version\":true,\"constants\":true,\"devNull\":false,\"EOL\":false},\"capabilities\":[\"native CPU, memory, load average, uptime, and network-interface snapshots\",\"native platform, arch, release, type, version, machine, hostname, tmpdir, homedir, and endianness helpers\",\"native os.constants aggregate plus process-priority get/set helpers\",\"top-level export-name and support metadata for the public os module surface\"],\"limitations\":[\"devNull and EOL are not exposed as dedicated native helpers in this facade\",\"platform and arch follow the plugin's native host reporting rather than Node's exact cross-build target matrix semantics\",\"cpus and networkInterfaces return snapshot JSON rather than live JavaScript object graphs or typed class instances\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_os_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &os_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_os_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"snapshotModel\":\"native JSON snapshots for cpus, networkInterfaces, userInfo, and os.constants\",\"identityModel\":\"native platform, arch, release, type, version, machine, hostname, tmpdir, homedir, and endianness helpers\",\"resourceModel\":\"native totalmem, freemem, loadavg, uptime, availableParallelism, and priority helpers\",\"constantsModel\":\"native os.constants aggregate including signals, errno, priority, and dlopen fields\",\"objectModel\":\"not-modeled for live JavaScript getter properties or frozen constants objects beyond returned JSON snapshots\"}");
}

pub export fn sa_node_plugin_os_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"arch\":{\"supported\":true,\"mode\":\"native host arch string helper\"},\"availableParallelism\":{\"supported\":true,\"mode\":\"native available parallelism helper\"},\"cpus\":{\"supported\":true,\"mode\":\"native CPU snapshot JSON helper\"},\"endianness\":{\"supported\":true,\"mode\":\"native endianness helper returning LE or BE\"},\"freemem\":{\"supported\":true,\"mode\":\"native free-memory helper\"},\"getPriority\":{\"supported\":true,\"mode\":\"native POSIX getpriority helper\"},\"homedir\":{\"supported\":true,\"mode\":\"native home-directory helper\"},\"hostname\":{\"supported\":true,\"mode\":\"native hostname helper\"},\"loadavg\":{\"supported\":true,\"mode\":\"native load-average helper\"},\"machine\":{\"supported\":true,\"mode\":\"native uname machine helper\"},\"networkInterfaces\":{\"supported\":true,\"mode\":\"native network-interface snapshot JSON helper\"},\"platform\":{\"supported\":true,\"mode\":\"native host platform string helper\"},\"release\":{\"supported\":true,\"mode\":\"native OS release helper\"},\"setPriority\":{\"supported\":true,\"mode\":\"native POSIX setpriority helper\",\"limitations\":[\"subject to host permission constraints and priority range validation\"]},\"tmpdir\":{\"supported\":true,\"mode\":\"native temp-directory helper\"},\"totalmem\":{\"supported\":true,\"mode\":\"native total-memory helper\"},\"type\":{\"supported\":true,\"mode\":\"native OS type helper\"},\"uptime\":{\"supported\":true,\"mode\":\"native system uptime helper\"},\"userInfo\":{\"supported\":true,\"mode\":\"native user-info JSON helper\"},\"version\":{\"supported\":true,\"mode\":\"native uname version helper\"},\"constants\":{\"supported\":true,\"mode\":\"native os.constants JSON aggregate\"},\"devNull\":{\"supported\":false,\"reason\":\"os.devNull path constant is not exposed as a dedicated helper in the current native ABI\"},\"EOL\":{\"supported\":false,\"reason\":\"os.EOL constant is not exposed as a dedicated helper in the current native ABI\"}}");
}

pub export fn sa_node_plugin_path_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"path\",\"supported\":true,\"mode\":\"top-level-native-path-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &path_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"join\":true,\"resolve\":true,\"normalize\":true,\"basename\":true,\"dirname\":true,\"extname\":true,\"isAbsolute\":true,\"relative\":true,\"format\":true,\"parse\":true,\"sep\":true,\"delimiter\":true,\"matchesGlob\":true,\"posix\":false,\"win32\":false,\"toNamespacedPath\":false},\"capabilities\":[\"native path join, resolve, normalize, basename, dirname, extname, and isAbsolute helpers\",\"native relative, format, parse, sep, delimiter, and matchesGlob helpers\",\"top-level export-name and support metadata for the public path module surface\"],\"limitations\":[\"no separate path.posix or path.win32 namespace objects with platform-specific method tables\",\"toNamespacedPath and Windows namespace path semantics are not exposed as dedicated native helpers\",\"normalization and resolution follow the host-native std.fs.path behavior rather than Node's full cross-platform edge-case matrix\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_path_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &path_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_path_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"joinModel\":\"native std.fs.path join and resolve helpers over explicit slice arrays\",\"analysisModel\":\"native normalize, basename, dirname, extname, isAbsolute, relative, format, and parse helpers\",\"separatorModel\":\"native sep and delimiter helpers reflect the host path platform surface\",\"globModel\":\"matchesGlob is exposed as a native boolean helper\",\"objectModel\":\"not-modeled for path.posix and path.win32 namespace objects or Windows namespaced path semantics\"}");
}

pub export fn sa_node_plugin_path_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"join\":{\"supported\":true,\"mode\":\"native std.fs.path join helper over explicit slice arrays\"},\"resolve\":{\"supported\":true,\"mode\":\"native std.fs.path resolve helper over explicit slice arrays\"},\"normalize\":{\"supported\":true,\"mode\":\"native path normalization helper\",\"limitations\":[\"uses host-native path resolution semantics\"]},\"basename\":{\"supported\":true,\"mode\":\"native basename helper with optional extension stripping\"},\"dirname\":{\"supported\":true,\"mode\":\"native dirname helper\"},\"extname\":{\"supported\":true,\"mode\":\"native extension helper\"},\"isAbsolute\":{\"supported\":true,\"mode\":\"native absolute-path predicate\"},\"relative\":{\"supported\":true,\"mode\":\"native relative-path helper over resolved inputs\"},\"format\":{\"supported\":true,\"mode\":\"native path format helper from JSON path parts\"},\"parse\":{\"supported\":true,\"mode\":\"native path parse helper returning JSON parts\"},\"sep\":{\"supported\":true,\"mode\":\"native path separator helper\"},\"delimiter\":{\"supported\":true,\"mode\":\"native path delimiter helper\"},\"matchesGlob\":{\"supported\":true,\"mode\":\"native glob-match boolean helper\"},\"posix\":{\"supported\":false,\"reason\":\"path.posix namespace object is not modeled as a distinct method table\"},\"win32\":{\"supported\":false,\"reason\":\"path.win32 namespace object is not modeled as a distinct method table\"},\"toNamespacedPath\":{\"supported\":false,\"reason\":\"Windows namespaced path conversion helper is not exposed in the current native ABI\"}}");
}

pub export fn sa_node_plugin_querystring_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"querystring\",\"supported\":true,\"mode\":\"top-level-native-querystring-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &querystring_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"escape\":true,\"unescape\":true,\"parse\":true,\"stringify\":true,\"encode\":true,\"decode\":true,\"unescapeBuffer\":true},\"capabilities\":[\"native percent-encoding escape and unescape helpers for query string text\",\"native parse and stringify helpers between query strings and flat JSON objects\",\"native unescapeBuffer-style byte helper through explicit buffer-returning ABI\",\"top-level export-name and support metadata for the public querystring module surface\"],\"limitations\":[\"parse and stringify operate on flat key-value objects and do not model full Node custom separator, repeated-key array coercion, or prototype pollution guards\",\"unescapeBuffer returns raw bytes through the native ABI rather than a JavaScript Buffer instance\",\"encode and decode are aliases over stringify and parse metadata rather than distinct implementations\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_querystring_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &querystring_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_querystring_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"escapeModel\":\"native percent-encoding escape and unescape helpers over query text\",\"parseModel\":\"native query-string parse helper returning flat JSON object fields\",\"stringifyModel\":\"native flat JSON object stringify helper producing key=value pairs\",\"bufferModel\":\"unescapeBuffer returns raw bytes through an explicit buffer helper\",\"objectModel\":\"not-modeled for JavaScript Buffer instances, repeated-key array coercion, or custom separator option bags\"}");
}

pub export fn sa_node_plugin_querystring_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"escape\":{\"supported\":true,\"mode\":\"native percent-encoding escape helper\"},\"unescape\":{\"supported\":true,\"mode\":\"native percent-decoding helper with plus-to-space handling\"},\"parse\":{\"supported\":true,\"mode\":\"native query-string parse helper returning a flat JSON object\",\"limitations\":[\"does not model repeated-key arrays, custom separators, or maxKeys options\"]},\"stringify\":{\"supported\":true,\"mode\":\"native flat JSON object stringify helper\",\"limitations\":[\"does not model custom separators, nested objects, or repeated-key array expansion semantics\"]},\"encode\":{\"supported\":true,\"mode\":\"alias metadata over stringify helper\"},\"decode\":{\"supported\":true,\"mode\":\"alias metadata over parse helper\"},\"unescapeBuffer\":{\"supported\":true,\"mode\":\"native raw-byte percent-decoding helper\",\"limitations\":[\"returns bytes through the native ABI rather than a JavaScript Buffer instance\"]}}");
}

pub export fn sa_node_plugin_punycode_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"punycode\",\"supported\":true,\"mode\":\"top-level-native-punycode-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &punycode_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"encode\":true,\"decode\":true,\"toASCII\":true,\"toUnicode\":true,\"ucs2\":false,\"version\":false},\"capabilities\":[\"native punycode encode and decode helpers over UTF-8 text\",\"native IDNA-style toASCII and toUnicode helpers through the existing libidn2-backed ABI\",\"top-level export-name and support metadata for the public punycode module surface\"],\"limitations\":[\"no punycode.ucs2 namespace helpers for JavaScript UTF-16 code-unit arrays\",\"no top-level version constant export in this native facade\",\"encode and decode operate on explicit native string buffers and do not model JavaScript exception identity or deprecated warning emission\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_punycode_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &punycode_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_punycode_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"encodeModel\":\"native punycode encode helper over explicit UTF-8 input text\",\"decodeModel\":\"native punycode decode helper returning UTF-8 text\",\"domainModel\":\"toASCII and toUnicode use the existing libidn2-backed domain conversion helpers\",\"objectModel\":\"not-modeled for punycode.ucs2 namespace objects, version constant exports, or JavaScript deprecation-warning side effects\"}");
}

pub export fn sa_node_plugin_punycode_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"encode\":{\"supported\":true,\"mode\":\"native punycode encode helper over UTF-8 text\"},\"decode\":{\"supported\":true,\"mode\":\"native punycode decode helper returning UTF-8 text\"},\"toASCII\":{\"supported\":true,\"mode\":\"native libidn2-backed domain-to-ASCII helper\",\"limitations\":[\"depends on libidn2 availability at runtime\"]},\"toUnicode\":{\"supported\":true,\"mode\":\"native libidn2-backed domain-to-Unicode helper\",\"limitations\":[\"depends on libidn2 availability at runtime\"]},\"ucs2\":{\"supported\":false,\"reason\":\"JavaScript UTF-16 code-unit array helpers are not modeled in the current native ABI\"},\"version\":{\"supported\":false,\"reason\":\"the deprecated punycode module version constant is not exposed as a dedicated native export\"}}");
}

pub export fn sa_node_plugin_string_decoder_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"string_decoder\",\"supported\":true,\"mode\":\"top-level-native-string-decoder-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &string_decoder_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"StringDecoder\":true,\"write\":true,\"end\":false,\"text\":false,\"lastChar\":false,\"lastNeed\":false,\"lastTotal\":false},\"capabilities\":[\"native explicit StringDecoder handle allocation and free\",\"native write helper that preserves incomplete UTF-8 multibyte sequences across chunks\",\"top-level export-name and support metadata for the public string_decoder module surface\"],\"limitations\":[\"only the explicit native handle plus write/free subset is exposed\",\"end, text, lastChar, lastNeed, and lastTotal JavaScript instance semantics are not modeled\",\"encoding selection and broader non-UTF-8 codec families are not exposed as configurable JavaScript constructor behavior\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_string_decoder_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &string_decoder_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_string_decoder_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"handleModel\":\"explicit native StringDecoder handle allocated with create() and released with free()\",\"writeModel\":\"native write helper accumulates incomplete UTF-8 multibyte sequences between chunks\",\"encodingModel\":\"current native implementation exposes a fixed UTF-8-oriented decoder subset rather than full JavaScript encoding selection\",\"objectModel\":\"not-modeled for JavaScript constructor instances, prototype getters, or end/text methods\"}");
}

pub export fn sa_node_plugin_string_decoder_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"StringDecoder\":{\"supported\":true,\"mode\":\"explicit native handle with create, write, and free operations\"},\"write\":{\"supported\":true,\"mode\":\"native chunk decoder with incomplete UTF-8 sequence buffering\"},\"end\":{\"supported\":false,\"reason\":\"flush semantics for pending buffered bytes are not exposed as a dedicated helper in the current native ABI\"},\"text\":{\"supported\":false,\"reason\":\"legacy text(buf, offset) instance helper is not modeled\"},\"lastChar\":{\"supported\":false,\"reason\":\"JavaScript getter exposing the buffered incomplete character bytes is not modeled\"},\"lastNeed\":{\"supported\":false,\"reason\":\"JavaScript getter exposing missing byte count is not modeled\"},\"lastTotal\":{\"supported\":false,\"reason\":\"JavaScript getter exposing buffered plus missing byte count is not modeled\"}}");
}

pub export fn sa_node_plugin_zlib_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"zlib\",\"supported\":true,\"mode\":\"top-level-native-zlib-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &zlib_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"gzipSync\":true,\"gunzipSync\":true,\"deflateSync\":true,\"inflateSync\":true,\"deflateRawSync\":true,\"inflateRawSync\":true,\"unzipSync\":true,\"brotliCompressSync\":true,\"brotliDecompressSync\":true,\"zstdCompressSync\":true,\"zstdDecompressSync\":true,\"crc32\":true,\"createGzip\":false,\"createGunzip\":false,\"createDeflate\":false,\"createInflate\":false,\"createDeflateRaw\":false,\"createInflateRaw\":false,\"createUnzip\":false,\"createBrotliCompress\":false,\"createBrotliDecompress\":false,\"createZstdCompress\":false,\"createZstdDecompress\":false,\"gzip\":false,\"gunzip\":false,\"deflate\":false,\"inflate\":false,\"deflateRaw\":false,\"inflateRaw\":false,\"unzip\":false,\"brotliCompress\":false,\"brotliDecompress\":false,\"zstdCompress\":false,\"zstdDecompress\":false,\"constants\":false,\"codes\":false},\"capabilities\":[\"native synchronous gzip, gunzip, deflate, inflate, raw-deflate, raw-inflate, and unzip helpers\",\"native synchronous Brotli and Zstd compress and decompress helpers plus CRC32\",\"top-level export-name and support metadata for the public zlib module surface\"],\"limitations\":[\"no JavaScript Transform stream classes or create* constructor helpers\",\"callback-style asynchronous convenience methods are not modeled; this facade exposes synchronous native helpers only\",\"constants and codes objects are not exposed as dedicated native top-level exports in the current ABI\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_zlib_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &zlib_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_zlib_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"syncModel\":\"native synchronous byte-buffer helpers for gzip, gunzip, deflate, inflate, raw deflate/inflate, unzip, Brotli, and Zstd\",\"checksumModel\":\"native CRC32 helper over explicit byte slices\",\"codecModel\":\"gzip/gunzip and zlib deflate/inflate use std.compress while Brotli and Zstd use dynamically loaded system libraries when available\",\"objectModel\":\"not-modeled for JavaScript Transform stream classes, create* constructors, callback-style async methods, or constants/codes objects\"}");
}

pub export fn sa_node_plugin_zlib_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"gzipSync\":{\"supported\":true,\"mode\":\"native synchronous gzip helper\"},\"gunzipSync\":{\"supported\":true,\"mode\":\"native synchronous gunzip helper\"},\"deflateSync\":{\"supported\":true,\"mode\":\"native synchronous zlib-deflate helper\"},\"inflateSync\":{\"supported\":true,\"mode\":\"native synchronous zlib-inflate helper\"},\"deflateRawSync\":{\"supported\":true,\"mode\":\"native synchronous raw-deflate helper\"},\"inflateRawSync\":{\"supported\":true,\"mode\":\"native synchronous raw-inflate helper\"},\"unzipSync\":{\"supported\":true,\"mode\":\"native synchronous gzip-or-zlib unzip helper\"},\"brotliCompressSync\":{\"supported\":true,\"mode\":\"native synchronous Brotli compress helper\",\"limitations\":[\"depends on Brotli system library availability at runtime\"]},\"brotliDecompressSync\":{\"supported\":true,\"mode\":\"native synchronous Brotli decompress helper\",\"limitations\":[\"depends on Brotli system library availability at runtime\"]},\"zstdCompressSync\":{\"supported\":true,\"mode\":\"native synchronous Zstd compress helper\",\"limitations\":[\"depends on Zstd system library availability at runtime\"]},\"zstdDecompressSync\":{\"supported\":true,\"mode\":\"native synchronous Zstd decompress helper\",\"limitations\":[\"depends on Zstd system library availability at runtime\"]},\"crc32\":{\"supported\":true,\"mode\":\"native CRC32 helper\"},\"createGzip\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createGunzip\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createDeflate\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createInflate\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createDeflateRaw\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createInflateRaw\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createUnzip\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createBrotliCompress\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createBrotliDecompress\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createZstdCompress\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"createZstdDecompress\":{\"supported\":false,\"reason\":\"JavaScript Transform stream constructors are not modeled\"},\"gzip\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"gunzip\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"deflate\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"inflate\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"deflateRaw\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"inflateRaw\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"unzip\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"brotliCompress\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"brotliDecompress\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"zstdCompress\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"zstdDecompress\":{\"supported\":false,\"reason\":\"callback-style asynchronous convenience helpers are not modeled\"},\"constants\":{\"supported\":false,\"reason\":\"zlib constants are not exposed as a dedicated native object snapshot in the current ABI\"},\"codes\":{\"supported\":false,\"reason\":\"zlib code-name lookup table is not exposed as a dedicated native object snapshot in the current ABI\"}}");
}

pub export fn sa_node_plugin_async_hooks_execution_async_id(out_id: ?*u64) u32 {
    out_id.?.* = if (asyncContextTrackingCurrent()) |frame| frame.async_id else async_resource_last_id;
    return 0;
}

pub export fn sa_node_plugin_async_hooks_trigger_async_id(out_id: ?*u64) u32 {
    out_id.?.* = if (asyncContextTrackingCurrent()) |frame| frame.trigger_async_id else 0;
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
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"async_context_tracking\",\"supported\":true,\"mode\":\"explicit-native-stack\",\"capabilities\":[\"async resource handle integration\",\"explicit enter and exit\",\"execution and trigger async id lookup\",\"stack depth and snapshot JSON\",\"reset current native stack\"],\"limitations\":[\"no automatic propagation across host callbacks\",\"no JavaScript AsyncLocalStorage or promise hook semantics\",\"context changes occur only through explicit native enter/exit helpers\"],\"depth\":") catch return fail();
    out.writer().print("{d}", .{async_context_stack.items.len}) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn assertBuildFailureJson(actual: []const u8, expected: []const u8, operator: []const u8, message: ?[]const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var diff_ptr: ?[*]const u8 = null;
    var diff_len: u64 = 0;
    if (ext.sa_node_plugin_util_diff(actual.ptr, actual.len, expected.ptr, expected.len, operator.ptr, operator.len, &diff_ptr, &diff_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(diff_ptr, diff_len);

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"name\":\"AssertionError\",\"code\":\"ERR_ASSERTION\",\"actual\":") catch return fail();
    out.appendSlice(actual) catch return fail();
    out.appendSlice(",\"expected\":") catch return fail();
    out.appendSlice(expected) catch return fail();
    out.appendSlice(",\"operator\":") catch return fail();
    appendJsonString(&out, operator) catch return fail();
    out.appendSlice(",\"generatedMessage\":") catch return fail();
    out.appendSlice(if (message == null or message.?.len == 0) "true" else "false") catch return fail();
    out.appendSlice(",\"message\":") catch return fail();
    if (message) |text| {
        appendJsonString(&out, text) catch return fail();
    } else {
        appendJsonString(&out, "Assertion failed") catch return fail();
    }
    out.appendSlice(",\"diff\":") catch return fail();
    out.appendSlice((diff_ptr orelse return fail())[0..@intCast(diff_len)]) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_assert_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"assert\",\"supported\":true,\"mode\":\"top-level-native-assert-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &assert_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"ok\":true,\"equal\":true,\"strictEqual\":true,\"deepStrictEqual\":true,\"fail\":true,\"strict\":true,\"AssertionError\":true,\"Assert\":false,\"throws\":false,\"rejects\":false},\"capabilities\":[\"ok/equal/strictEqual style result checks\",\"deepStrictEqual via existing util JSON comparison\",\"AssertionError JSON payloads with diff metadata\",\"strict Assert options snapshot metadata\",\"top-level export-name and support metadata for the public assert module surface\"],\"limitations\":[\"no JavaScript throw/catch integration\",\"no Promise/rejects callback semantics\",\"results are explicit status codes and JSON diagnostics\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_assert_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &assert_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_assert_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"resultModel\":\"native assert helpers return explicit success bits plus optional AssertionError JSON payloads\",\"comparisonModel\":\"equal and strictEqual compare explicit text slices while deepStrictEqual delegates to the existing util JSON comparator\",\"strictModel\":\"strict Assert configuration is exposed as snapshot metadata rather than a JavaScript Assert instance\",\"objectModel\":\"not-modeled for JavaScript throw/catch behavior, callback helpers, Promise assertions, or Assert class instances\"}");
}

pub export fn sa_node_plugin_assert_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"ok\":{\"supported\":true,\"mode\":\"native truthy check returning explicit ok bit and optional AssertionError JSON\"},\"equal\":{\"supported\":true,\"mode\":\"native loose-text equality helper\"},\"strictEqual\":{\"supported\":true,\"mode\":\"native strict-text equality helper\"},\"deepStrictEqual\":{\"supported\":true,\"mode\":\"native deep equality helper using util JSON comparison\"},\"fail\":{\"supported\":true,\"mode\":\"native AssertionError JSON builder\"},\"strict\":{\"supported\":true,\"mode\":\"strict Assert config snapshot metadata\",\"limitations\":[\"not a live JavaScript assert.strict function table\"]},\"AssertionError\":{\"supported\":true,\"mode\":\"AssertionError-style JSON payloads with diff metadata\",\"limitations\":[\"not a JavaScript Error subclass instance\"]},\"Assert\":{\"supported\":false,\"reason\":\"JavaScript Assert class construction and method binding semantics are not modeled\"},\"throws\":{\"supported\":false,\"reason\":\"callback exception capture semantics are not modeled without a JS runtime\"},\"rejects\":{\"supported\":false,\"reason\":\"Promise rejection assertions are not modeled\"}} ");
}

pub export fn sa_node_plugin_assert_ok(value: u64, message_ptr: ?[*]const u8, message_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64, out_ok: ?*u64) u32 {
    const message = if (message_len == 0) null else (message_ptr orelse return fail())[0..message_len];
    out_ok.?.* = if (value != 0) 1 else 0;
    if (value != 0) return writeOwnedString(out_ptr, out_len, "null");
    return assertBuildFailureJson("false", "true", "==", message, out_ptr, out_len);
}

pub export fn sa_node_plugin_assert_equal(actual_ptr: ?[*]const u8, actual_len: u64, expected_ptr: ?[*]const u8, expected_len: u64, strict: u32, message_ptr: ?[*]const u8, message_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64, out_ok: ?*u64) u32 {
    const actual = if (actual_ptr) |ptr| ptr[0..actual_len] else "null";
    const expected = if (expected_ptr) |ptr| ptr[0..expected_len] else "null";
    const message = if (message_len == 0) null else (message_ptr orelse return fail())[0..message_len];
    const equal = if (strict != 0) std.mem.eql(u8, actual, expected) else blk: {
        const trimmed_actual = std.mem.trim(u8, actual, " \t\r\n");
        const trimmed_expected = std.mem.trim(u8, expected, " \t\r\n");
        break :blk std.mem.eql(u8, trimmed_actual, trimmed_expected);
    };
    out_ok.?.* = if (equal) 1 else 0;
    if (equal) return writeOwnedString(out_ptr, out_len, "null");
    return assertBuildFailureJson(actual, expected, if (strict != 0) "strictEqual" else "equal", message, out_ptr, out_len);
}

pub export fn sa_node_plugin_assert_deep_strict_equal(actual_ptr: ?[*]const u8, actual_len: u64, expected_ptr: ?[*]const u8, expected_len: u64, message_ptr: ?[*]const u8, message_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64, out_ok: ?*u64) u32 {
    const actual = if (actual_ptr) |ptr| ptr[0..actual_len] else "null";
    const expected = if (expected_ptr) |ptr| ptr[0..expected_len] else "null";
    const message = if (message_len == 0) null else (message_ptr orelse return fail())[0..message_len];
    var deep_equal: u64 = 0;
    if (base.sa_node_plugin_util_is_deep_strict_equal(actual.ptr, actual.len, expected.ptr, expected.len, &deep_equal) != 0) return fail();
    out_ok.?.* = deep_equal;
    if (deep_equal != 0) return writeOwnedString(out_ptr, out_len, "null");
    return assertBuildFailureJson(actual, expected, "deepStrictEqual", message, out_ptr, out_len);
}

pub export fn sa_node_plugin_assert_fail_json(message_ptr: ?[*]const u8, message_len: u64, actual_ptr: ?[*]const u8, actual_len: u64, expected_ptr: ?[*]const u8, expected_len: u64, operator_ptr: ?[*]const u8, operator_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const message = if (message_len == 0) null else (message_ptr orelse return fail())[0..message_len];
    const actual = if (actual_ptr) |ptr| ptr[0..actual_len] else "null";
    const expected = if (expected_ptr) |ptr| ptr[0..expected_len] else "null";
    const operator = if (operator_len == 0) "fail" else (operator_ptr orelse return fail())[0..operator_len];
    return assertBuildFailureJson(actual, expected, operator, message, out_ptr, out_len);
}

pub export fn sa_node_plugin_assert_strict_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"strict\":true,\"diff\":\"simple\",\"skipPrototype\":false,\"alias\":[\"strictEqual\",\"deepStrictEqual\",\"notStrictEqual\",\"notDeepStrictEqual\"]}");
}

pub export fn sa_node_plugin_constants_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var os_ptr: ?[*]const u8 = null;
    var os_len: u64 = 0;
    if (ext.sa_node_plugin_os_constants(&os_ptr, &os_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(os_ptr, os_len);

    var crypto_ptr: ?[*]const u8 = null;
    var crypto_len: u64 = 0;
    if (ext.sa_node_plugin_crypto_get_hashes(&crypto_ptr, &crypto_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(crypto_ptr, crypto_len);

    const os_json = (os_ptr orelse return fail())[0..@intCast(os_len)];
    var os_parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, os_json, .{}) catch return fail();
    defer os_parsed.deinit();
    if (os_parsed.value != .object) return fail();

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.append('{') catch return fail();
    var first = true;
    const os_object = os_parsed.value.object;
    inline for ([_][]const u8{ "dlopen", "errno", "priority", "signals", "uv" }) |group_name| {
        if (os_object.get(group_name)) |group| {
            if (group == .object) {
                appendJsonObjectMembers(&out, &first, group.object) catch return fail();
            }
        }
    }
    appendJsonIntFieldValue(&out, &first, "F_OK", 0) catch return fail();
    appendJsonIntFieldValue(&out, &first, "R_OK", 4) catch return fail();
    appendJsonIntFieldValue(&out, &first, "W_OK", 2) catch return fail();
    appendJsonIntFieldValue(&out, &first, "X_OK", 1) catch return fail();
    appendJsonIntFieldValue(&out, &first, "COPYFILE_EXCL", 1) catch return fail();
    appendJsonIntFieldValue(&out, &first, "COPYFILE_FICLONE", 2) catch return fail();
    appendJsonIntFieldValue(&out, &first, "COPYFILE_FICLONE_FORCE", 4) catch return fail();
    appendJsonStringFieldValue(&out, &first, "DEFAULT_ENCODING", "buffer") catch return fail();
    appendJsonRawFieldValue(&out, &first, "CRYPTO_HASHES", (crypto_ptr orelse return fail())[0..@intCast(crypto_len)]) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_constants_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"constants\",\"supported\":true,\"mode\":\"top-level-native-constants-facade\",\"exports\":") catch return fail();
    constantsAppendExportNamesJson(&out) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"osConstants\":true,\"fsAccessFlags\":true,\"fsCopyFileFlags\":true,\"cryptoHashes\":true,\"frozenObject\":false},\"sources\":[\"os.constants\",\"fs access/copyfile flags\",\"crypto hash catalog metadata\"],\"limitations\":[\"not a frozen JavaScript object\",\"exports JSON rather than property descriptors\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn constantsAppendExportNamesJson(out: *std.ArrayList(u8)) !void {
    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    if (sa_node_plugin_constants_json(&constants_ptr, &constants_len) != 0) return error.Unexpected;
    defer _ = base.sa_node_plugin_free_buffer(constants_ptr, constants_len);
    const constants_json = (constants_ptr orelse return error.Unexpected)[0..@intCast(constants_len)];
    var parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, constants_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.Unexpected;
    try out.append('[');
    var first = true;
    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        if (!first) try out.append(',');
        first = false;
        try appendJsonString(out, entry.key_ptr.*);
    }
    try out.append(']');
}

pub export fn sa_node_plugin_constants_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    constantsAppendExportNamesJson(&out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_constants_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"aggregationModel\":\"native constants object assembled from os.constants, fs flag constants, and crypto hash catalog metadata\",\"exportModel\":\"exports JSON lists the currently aggregated property names rather than a hand-maintained static table\",\"objectModel\":\"not-modeled for frozen JavaScript property descriptors or lazy getter semantics\"}");
}

pub export fn sa_node_plugin_constants_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"osConstants\":{\"supported\":true,\"mode\":\"native flattened os.constants groups including signals, errno, priority, dlopen, and uv values\"},\"fsAccessFlags\":{\"supported\":true,\"mode\":\"native F_OK, R_OK, W_OK, and X_OK integer constants\"},\"fsCopyFileFlags\":{\"supported\":true,\"mode\":\"native COPYFILE_* integer constants\"},\"cryptoHashes\":{\"supported\":true,\"mode\":\"CRYPTO_HASHES property exported as the current native hash catalog array\"},\"frozenObject\":{\"supported\":false,\"reason\":\"the facade returns JSON snapshots rather than a frozen JavaScript constants object\"}} ");
}

pub export fn sa_node_plugin_sys_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"sys\",\"supported\":true,\"mode\":\"top-level-native-sys-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &sys_export_names) catch return fail();
    out.appendSlice(",\"aliasTarget\":\"util\",\"deprecationCode\":\"DEP0025\",\"featureSupport\":{\"format\":true,\"inspect\":true,\"debuglog\":true,\"legacyAlias\":true,\"inherits\":false},\"limitations\":[\"only a narrow deprecated util alias subset is exposed\",\"no runtime warning event emission or full util namespace parity\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_sys_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &sys_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_sys_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"aliasModel\":\"deprecated native alias wrapper over a narrow util subset\",\"deprecationModel\":\"DEP0025 metadata is exposed explicitly through sys status and deprecation JSON helpers\",\"objectModel\":\"not-modeled for full util namespace parity, warning events, or JavaScript module identity semantics\"}");
}

pub export fn sa_node_plugin_sys_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"format\":{\"supported\":true,\"mode\":\"native wrapper over util.format\"},\"inspect\":{\"supported\":true,\"mode\":\"native wrapper over util.inspect\"},\"debuglog\":{\"supported\":true,\"mode\":\"native wrapper over util.debuglog\"},\"legacyAlias\":{\"supported\":true,\"mode\":\"explicit deprecated alias metadata targeting util\"},\"inherits\":{\"supported\":false,\"reason\":\"full legacy sys alias surface is not modeled beyond the current wrapper subset\"}} ");
}

pub export fn sa_node_plugin_sys_deprecation_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"code\":\"DEP0025\",\"type\":\"DeprecationWarning\",\"message\":\"sys is deprecated. Use `node:util` instead.\",\"runtimeWarningEmitted\":false}");
}

pub export fn sa_node_plugin_sys_format(format_ptr: ?[*]const u8, format_len: u64, args_json_ptr: ?[*]const u8, args_json_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_util_format(format_ptr, format_len, args_json_ptr, args_json_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_sys_inspect(json_ptr: ?[*]const u8, json_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_util_inspect(json_ptr, json_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_sys_debuglog(section_ptr: ?[*]const u8, section_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return ext.sa_node_plugin_util_debuglog(section_ptr, section_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_async_context_tracking_snapshot_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    asyncContextTrackingWriteSnapshotJson(&out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_async_context_tracking_enter(handle_ptr: ?*anyopaque, out_depth: ?*u64) u32 {
    const handle: *AsyncResourceHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    const frame = AsyncContextFrame.initFromHandle(std.heap.page_allocator, handle) catch return fail();
    async_context_stack.append(std.heap.page_allocator, frame) catch {
        var frame_mut = frame;
        frame_mut.deinit();
        return fail();
    };
    out_depth.?.* = async_context_stack.items.len;
    return 0;
}

pub export fn sa_node_plugin_async_context_tracking_exit(out_async_id: ?*u64, out_popped: ?*u64) u32 {
    if (async_context_stack.items.len == 0) {
        out_async_id.?.* = 0;
        out_popped.?.* = 0;
        return 0;
    }
    var frame = async_context_stack.pop().?;
    defer frame.deinit();
    out_async_id.?.* = frame.async_id;
    out_popped.?.* = 1;
    return 0;
}

pub export fn sa_node_plugin_async_context_tracking_execution_async_id(out_id: ?*u64) u32 {
    out_id.?.* = if (asyncContextTrackingCurrent()) |frame| frame.async_id else async_resource_last_id;
    return 0;
}

pub export fn sa_node_plugin_async_context_tracking_trigger_async_id(out_id: ?*u64) u32 {
    out_id.?.* = if (asyncContextTrackingCurrent()) |frame| frame.trigger_async_id else 0;
    return 0;
}

pub export fn sa_node_plugin_async_context_tracking_depth(out_depth: ?*u64) u32 {
    out_depth.?.* = async_context_stack.items.len;
    return 0;
}

pub export fn sa_node_plugin_async_context_tracking_reset() u32 {
    asyncContextTrackingClear();
    return 0;
}

const CommandLineOptionsConfig = struct {
    allocator: std.mem.Allocator,
    argv: std.ArrayList([]u8),
    node_options_tokens: std.ArrayList([]u8),
    env_files: std.ArrayList([]u8),
    optional_env_files: std.ArrayList([]u8),
    conditions: std.ArrayList([]u8),
    preload_modules: std.ArrayList([]u8),
    inspect_flags: std.ArrayList([]u8),
    saw_node_options: bool = false,
    saw_argv: bool = false,

    fn init(allocator: std.mem.Allocator) CommandLineOptionsConfig {
        return .{
            .allocator = allocator,
            .argv = std.ArrayList([]u8).init(allocator),
            .node_options_tokens = std.ArrayList([]u8).init(allocator),
            .env_files = std.ArrayList([]u8).init(allocator),
            .optional_env_files = std.ArrayList([]u8).init(allocator),
            .conditions = std.ArrayList([]u8).init(allocator),
            .preload_modules = std.ArrayList([]u8).init(allocator),
            .inspect_flags = std.ArrayList([]u8).init(allocator),
        };
    }

    fn freeItems(allocator: std.mem.Allocator, list: *std.ArrayList([]u8)) void {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    fn deinit(self: *CommandLineOptionsConfig) void {
        CommandLineOptionsConfig.freeItems(self.allocator, &self.argv);
        CommandLineOptionsConfig.freeItems(self.allocator, &self.node_options_tokens);
        CommandLineOptionsConfig.freeItems(self.allocator, &self.env_files);
        CommandLineOptionsConfig.freeItems(self.allocator, &self.optional_env_files);
        CommandLineOptionsConfig.freeItems(self.allocator, &self.conditions);
        CommandLineOptionsConfig.freeItems(self.allocator, &self.preload_modules);
        CommandLineOptionsConfig.freeItems(self.allocator, &self.inspect_flags);
    }
};

fn commandLineOptionsPush(list: *std.ArrayList([]u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try list.append(try allocator.dupe(u8, value));
}

fn commandLineOptionsFlagValue(token: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, token, prefix)) return null;
    if (token.len <= prefix.len or token[prefix.len] != '=') return null;
    return token[prefix.len + 1 ..];
}

fn commandLineOptionsInspectPrefix(token: []const u8) bool {
    return std.mem.eql(u8, token, "--inspect") or
        std.mem.startsWith(u8, token, "--inspect=") or
        std.mem.eql(u8, token, "--inspect-brk") or
        std.mem.startsWith(u8, token, "--inspect-brk=") or
        std.mem.eql(u8, token, "--inspect-wait") or
        std.mem.startsWith(u8, token, "--inspect-wait=");
}

fn commandLineOptionsParseToken(config: *CommandLineOptionsConfig, token: []const u8, next: ?[]const u8, from_node_options: bool) !bool {
    if (from_node_options) {
        try commandLineOptionsPush(&config.node_options_tokens, config.allocator, token);
    }
    if (commandLineOptionsFlagValue(token, "--env-file")) |value| {
        try commandLineOptionsPush(&config.env_files, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "--env-file") and next != null) {
        if (from_node_options) try commandLineOptionsPush(&config.node_options_tokens, config.allocator, next.?);
        try commandLineOptionsPush(&config.env_files, config.allocator, next.?);
        return true;
    }
    if (commandLineOptionsFlagValue(token, "--env-file-if-exists")) |value| {
        try commandLineOptionsPush(&config.optional_env_files, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "--env-file-if-exists") and next != null) {
        if (from_node_options) try commandLineOptionsPush(&config.node_options_tokens, config.allocator, next.?);
        try commandLineOptionsPush(&config.optional_env_files, config.allocator, next.?);
        return true;
    }
    if (commandLineOptionsFlagValue(token, "--require")) |value| {
        try commandLineOptionsPush(&config.preload_modules, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "--require") and next != null) {
        if (from_node_options) try commandLineOptionsPush(&config.node_options_tokens, config.allocator, next.?);
        try commandLineOptionsPush(&config.preload_modules, config.allocator, next.?);
        return true;
    }
    if (commandLineOptionsFlagValue(token, "-r")) |value| {
        try commandLineOptionsPush(&config.preload_modules, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "-r") and next != null) {
        if (from_node_options) try commandLineOptionsPush(&config.node_options_tokens, config.allocator, next.?);
        try commandLineOptionsPush(&config.preload_modules, config.allocator, next.?);
        return true;
    }
    if (commandLineOptionsFlagValue(token, "--conditions")) |value| {
        try commandLineOptionsPush(&config.conditions, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "--conditions") and next != null) {
        if (from_node_options) try commandLineOptionsPush(&config.node_options_tokens, config.allocator, next.?);
        try commandLineOptionsPush(&config.conditions, config.allocator, next.?);
        return true;
    }
    if (commandLineOptionsFlagValue(token, "-C")) |value| {
        try commandLineOptionsPush(&config.conditions, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "-C") and next != null) {
        if (from_node_options) try commandLineOptionsPush(&config.node_options_tokens, config.allocator, next.?);
        try commandLineOptionsPush(&config.conditions, config.allocator, next.?);
        return true;
    }
    if (commandLineOptionsInspectPrefix(token)) {
        try commandLineOptionsPush(&config.inspect_flags, config.allocator, token);
        return false;
    }
    return false;
}

fn commandLineOptionsParseNodeOptions(config: *CommandLineOptionsConfig) !void {
    const options = std.posix.getenv("NODE_OPTIONS") orelse return;
    config.saw_node_options = true;
    var tokens = std.mem.tokenizeAny(u8, options, " \t\r\n");
    var pending: ?[]const u8 = tokens.next();
    while (pending) |token| {
        const next = tokens.next();
        const consumed_next = try commandLineOptionsParseToken(config, token, next, true);
        pending = if (consumed_next) tokens.next() else next;
    }
}

fn commandLineOptionsParseArgv(config: *CommandLineOptionsConfig) !void {
    const allocator = config.allocator;
    const argv = std.process.argsAlloc(allocator) catch return;
    defer std.process.argsFree(allocator, argv);
    if (argv.len == 0) return;
    config.saw_argv = true;
    for (argv) |arg| {
        try commandLineOptionsPush(&config.argv, allocator, arg);
    }
    if (argv.len <= 1) return;
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const consumed_next = try commandLineOptionsParseToken(config, argv[i], if (i + 1 < argv.len) argv[i + 1] else null, false);
        if (consumed_next) i += 1;
    }
}

fn commandLineOptionsReadConfig(allocator: std.mem.Allocator) !CommandLineOptionsConfig {
    var config = CommandLineOptionsConfig.init(allocator);
    errdefer config.deinit();
    try commandLineOptionsParseNodeOptions(&config);
    try commandLineOptionsParseArgv(&config);
    return config;
}

fn commandLineOptionsHasFlagInternal(flag: []const u8) bool {
    var config = commandLineOptionsReadConfig(std.heap.page_allocator) catch return false;
    defer config.deinit();

    if (config.saw_node_options) {
        for (config.node_options_tokens.items) |token| {
            if (std.mem.eql(u8, token, flag)) return true;
            if (std.mem.startsWith(u8, token, flag) and token.len > flag.len and token[flag.len] == '=') return true;
        }
    }
    if (config.saw_argv) {
        for (config.argv.items[1..]) |token| {
            if (std.mem.eql(u8, token, flag)) return true;
            if (std.mem.startsWith(u8, token, flag) and token.len > flag.len and token[flag.len] == '=') return true;
        }
    }
    return false;
}

fn commandLineOptionsWriteStatusJson(config: *const CommandLineOptionsConfig, out: *std.ArrayList(u8)) !void {
    try out.appendSlice("{\"module\":\"command_line_options\",\"supported\":true,\"mode\":\"native-process-env\",\"argvSource\":\"std.process.args\",\"nodeOptionsParsing\":\"whitespace-tokenized\",\"nodeOptionsPresent\":");
    try out.appendSlice(if (config.saw_node_options) "true" else "false");
    try out.appendSlice(",\"argvPresent\":");
    try out.appendSlice(if (config.saw_argv) "true" else "false");
    try out.appendSlice(",\"saPluginDev\":");
    try out.appendSlice(if (std.posix.getenv("SA_PLUGIN_DEV") != null) "true" else "false");
    try appendEnvStringField(out, "nodeOptions", "NODE_OPTIONS");
    try out.appendSlice(",\"argv\":");
    try appendOwnedStringArray(out, config.argv.items);
    try out.appendSlice(",\"nodeOptionsTokens\":");
    try appendOwnedStringArray(out, config.node_options_tokens.items);
    try out.appendSlice(",\"envFiles\":");
    try appendOwnedStringArray(out, config.env_files.items);
    try out.appendSlice(",\"optionalEnvFiles\":");
    try appendOwnedStringArray(out, config.optional_env_files.items);
    try out.appendSlice(",\"preloadModules\":");
    try appendOwnedStringArray(out, config.preload_modules.items);
    try out.appendSlice(",\"conditions\":");
    try appendOwnedStringArray(out, config.conditions.items);
    try out.appendSlice(",\"inspectFlags\":");
    try appendOwnedStringArray(out, config.inspect_flags.items);
    try out.appendSlice(",\"recognizedFamilies\":[\"--inspect*\",\"--require/-r\",\"--conditions/-C\",\"--env-file\",\"--env-file-if-exists\",\"--input-type\",\"--experimental-*\",\"--trace-*\"],\"capabilities\":[\"host argv snapshot\",\"NODE_OPTIONS token snapshot\",\"preload/env-file/conditions/inspect flag introspection\"],\"limitations\":[\"flags are reported for host and tooling compatibility only\",\"no V8 or JavaScript loader flags are executed by this native plugin\",\"NODE_OPTIONS parsing is whitespace-based and does not emulate shell quoting\"]}");
}

pub export fn sa_node_plugin_command_line_options_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var config = commandLineOptionsReadConfig(std.heap.page_allocator) catch return fail();
    defer config.deinit();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    commandLineOptionsWriteStatusJson(&config, &out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_command_line_options_argv_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var config = commandLineOptionsReadConfig(std.heap.page_allocator) catch return fail();
    defer config.deinit();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendOwnedStringArray(&out, config.argv.items) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_command_line_options_node_options_tokens_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var config = commandLineOptionsReadConfig(std.heap.page_allocator) catch return fail();
    defer config.deinit();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendOwnedStringArray(&out, config.node_options_tokens.items) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_command_line_options_env_files_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var config = commandLineOptionsReadConfig(std.heap.page_allocator) catch return fail();
    defer config.deinit();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"required\":") catch return fail();
    appendOwnedStringArray(&out, config.env_files.items) catch return fail();
    out.appendSlice(",\"optional\":") catch return fail();
    appendOwnedStringArray(&out, config.optional_env_files.items) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_command_line_options_has_flag(flag_ptr: ?[*]const u8, flag_len: u64, out_bool: ?*u64) u32 {
    const flag = if (flag_len == 0) return fail() else (flag_ptr orelse return fail())[0..flag_len];
    out_bool.?.* = if (commandLineOptionsHasFlagInternal(flag)) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_debugger_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "debugger", false, "debugger protocol is not modeled");
}

const DeprecatedEntry = struct {
    code: []u8,
    message: []u8,
    count: u64,

    fn deinit(self: *DeprecatedEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        allocator.free(self.message);
        allocator.destroy(self);
    }
};

var deprecated_mutex = std.Thread.Mutex{};
var deprecated_registry = std.StringHashMap(*DeprecatedEntry).init(std.heap.page_allocator);

fn deprecatedPendingEnabledInternal() bool {
    return nodeOptionsHasFlag("--pending-deprecation") or envTruthy("NODE_PENDING_DEPRECATION");
}

fn deprecatedNoDeprecationInternal() bool {
    return nodeOptionsHasFlag("--no-deprecation");
}

fn deprecatedTraceDeprecationInternal() bool {
    return nodeOptionsHasFlag("--trace-deprecation");
}

fn deprecatedThrowDeprecationInternal() bool {
    return nodeOptionsHasFlag("--throw-deprecation");
}

fn deprecatedNoWarningsInternal() bool {
    return nodeOptionsHasFlag("--no-warnings") or envTruthy("NODE_NO_WARNINGS");
}

fn deprecatedAppendFlagsObject(out: *std.ArrayList(u8)) !void {
    try out.appendSlice("{\"pendingDeprecation\":");
    try out.appendSlice(if (deprecatedPendingEnabledInternal()) "true" else "false");
    try out.appendSlice(",\"noDeprecation\":");
    try out.appendSlice(if (deprecatedNoDeprecationInternal()) "true" else "false");
    try out.appendSlice(",\"traceDeprecation\":");
    try out.appendSlice(if (deprecatedTraceDeprecationInternal()) "true" else "false");
    try out.appendSlice(",\"throwDeprecation\":");
    try out.appendSlice(if (deprecatedThrowDeprecationInternal()) "true" else "false");
    try out.appendSlice(",\"noWarnings\":");
    try out.appendSlice(if (deprecatedNoWarningsInternal()) "true" else "false");
    try out.append('}');
}

fn deprecatedRegisteredCount() u64 {
    deprecated_mutex.lock();
    defer deprecated_mutex.unlock();
    return deprecated_registry.count();
}

pub export fn sa_node_plugin_deprecated_flags_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    deprecatedAppendFlagsObject(&out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_deprecated_clear() u32 {
    deprecated_mutex.lock();
    defer deprecated_mutex.unlock();
    var it = deprecated_registry.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.*.deinit(std.heap.page_allocator);
    }
    deprecated_registry.clearRetainingCapacity();
    return 0;
}

pub export fn sa_node_plugin_deprecated_has(code_ptr: ?[*]const u8, code_len: u64, out_bool: ?*u64) u32 {
    const code = if (code_len == 0) "" else (code_ptr orelse return fail())[0..code_len];
    deprecated_mutex.lock();
    defer deprecated_mutex.unlock();
    out_bool.?.* = if (deprecated_registry.contains(code)) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_deprecated_record_json(code_ptr: ?[*]const u8, code_len: u64, msg_ptr: ?[*]const u8, msg_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const code = if (code_len == 0) return fail() else (code_ptr orelse return fail())[0..code_len];
    const message = if (msg_len == 0) "" else (msg_ptr orelse return fail())[0..msg_len];
    const allocator = std.heap.page_allocator;

    var first_occurrence = false;
    var count: u64 = 0;
    var stored_message: []const u8 = "";

    deprecated_mutex.lock();
    defer deprecated_mutex.unlock();

    if (deprecated_registry.get(code)) |entry| {
        entry.count += 1;
        count = entry.count;
        stored_message = entry.message;
    } else {
        const entry = allocator.create(DeprecatedEntry) catch return fail();
        entry.* = .{
            .code = allocator.dupe(u8, code) catch {
                allocator.destroy(entry);
                return fail();
            },
            .message = allocator.dupe(u8, message) catch {
                allocator.free(entry.code);
                allocator.destroy(entry);
                return fail();
            },
            .count = 1,
        };
        deprecated_registry.put(entry.code, entry) catch {
            entry.deinit(allocator);
            return fail();
        };
        first_occurrence = true;
        count = 1;
        stored_message = entry.message;
    }

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"code\":") catch return fail();
    appendJsonString(&out, code) catch return fail();
    out.appendSlice(",\"message\":") catch return fail();
    appendJsonString(&out, stored_message) catch return fail();
    out.writer().print(",\"count\":{d},\"firstOccurrence\":{s},\"shouldEmit\":{s},\"flags\":", .{
        count,
        if (first_occurrence) "true" else "false",
        if (!deprecatedNoDeprecationInternal() and !deprecatedNoWarningsInternal() and first_occurrence) "true" else "false",
    }) catch return fail();
    deprecatedAppendFlagsObject(&out) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_deprecated_snapshot_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    deprecated_mutex.lock();
    defer deprecated_mutex.unlock();

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"flags\":") catch return fail();
    deprecatedAppendFlagsObject(&out) catch return fail();
    out.writer().print(",\"registeredCount\":{d},\"entries\":[", .{deprecated_registry.count()}) catch return fail();

    var first = true;
    var it = deprecated_registry.iterator();
    while (it.next()) |entry| {
        if (!first) out.append(',') catch return fail();
        first = false;
        out.appendSlice("{\"code\":") catch return fail();
        appendJsonString(&out, entry.value_ptr.*.code) catch return fail();
        out.appendSlice(",\"message\":") catch return fail();
        appendJsonString(&out, entry.value_ptr.*.message) catch return fail();
        out.writer().print(",\"count\":{d}}}", .{entry.value_ptr.*.count}) catch return fail();
    }

    out.appendSlice("]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_deprecated_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"deprecated\",\"supported\":true,\"mode\":\"native-registry\",\"registeredCount\":") catch return fail();
    out.writer().print("{d}", .{deprecatedRegisteredCount()}) catch return fail();
    out.appendSlice(",\"flags\":") catch return fail();
    deprecatedAppendFlagsObject(&out) catch return fail();
    out.appendSlice(",\"capabilities\":[\"util.deprecate-style registry\",\"idempotent deprecation codes\",\"deprecation flag introspection\",\"snapshot and clear helpers\"],\"limitations\":[\"no JavaScript wrapper invocation semantics\",\"no process warning events or warning listeners\",\"registry tracks native deprecation metadata only\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_environment_variables_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var env_map = std.process.getEnvMap(std.heap.page_allocator) catch return fail();
    defer env_map.deinit();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"environment_variables\",\"supported\":true,\"mode\":\"native-process-env\",\"entryCount\":") catch return fail();
    out.writer().print("{d}", .{env_map.count()}) catch return fail();
    out.appendSlice(",\"hasNodeOptions\":") catch return fail();
    out.appendSlice(if (std.posix.getenv("NODE_OPTIONS") != null) "true" else "false") catch return fail();
    appendEnvStringField(&out, "nodeOptions", "NODE_OPTIONS") catch return fail();
    out.appendSlice(",\"capabilities\":[\"host environment snapshot\",\"single-variable lookup\",\"dotenv parse and load helpers\"],\"limitations\":[\"no JavaScript process.env object proxy semantics\",\"no per-Worker environment copies\",\"loadEnvFile follows native host environment behavior and ignores NODE_OPTIONS entries from dotenv content\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn environmentVariablesAppendObject(out: *std.ArrayList(u8), map: *const std.process.EnvMap) !void {
    try out.append('{');
    var it = map.iterator();
    var first = true;
    while (it.next()) |entry| {
        if (!first) try out.append(',');
        first = false;
        try appendJsonString(out, entry.key_ptr.*);
        try out.append(':');
        try appendJsonString(out, entry.value_ptr.*);
    }
    try out.append('}');
}

fn environmentVariablesIsValidName(name: []const u8) bool {
    if (name.len == 0) return false;
    const first = name[0];
    if (!(std.ascii.isAlphabetic(first) or first == '_')) return false;
    for (name[1..]) |ch| {
        if (!(std.ascii.isAlphanumeric(ch) or ch == '_')) return false;
    }
    return true;
}

fn environmentVariablesTrimSpaces(bytes: []const u8) []const u8 {
    return std.mem.trim(u8, bytes, " \t\n\r");
}

fn environmentVariablesExpandDoubleQuotedNewlines(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (value[i] == '\\' and i + 1 < value.len and value[i + 1] == 'n') {
            try out.append('\n');
            i += 1;
            continue;
        }
        try out.append(value[i]);
    }
    return out.toOwnedSlice();
}

fn environmentVariablesFindClosingQuote(bytes: []const u8, quote: u8) ?usize {
    if (bytes.len == 0 or bytes[0] != quote) return null;
    var i: usize = 1;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == quote) return i;
    }
    return null;
}

fn environmentVariablesStoreInsertOwned(store: *std.StringHashMap([]u8), allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
    const owned_key = try allocator.dupe(u8, key);
    errdefer allocator.free(owned_key);
    const owned_value = try allocator.dupe(u8, value);
    errdefer allocator.free(owned_value);
    const gop = try store.getOrPut(owned_key);
    if (gop.found_existing) {
        allocator.free(owned_key);
        allocator.free(gop.value_ptr.*);
        gop.value_ptr.* = owned_value;
        return;
    }
    gop.value_ptr.* = owned_value;
}

fn environmentVariablesStoreDeinit(store: *std.StringHashMap([]u8), allocator: std.mem.Allocator) void {
    var it = store.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.*);
    }
    store.deinit();
}

fn environmentVariablesParseContent(allocator: std.mem.Allocator, content_in: []const u8) !std.StringHashMap([]u8) {
    var store = std.StringHashMap([]u8).init(allocator);
    errdefer environmentVariablesStoreDeinit(&store, allocator);

    const normalized = try std.mem.replaceOwned(u8, allocator, content_in, "\r", "");
    defer allocator.free(normalized);

    var content = environmentVariablesTrimSpaces(normalized);
    while (content.len > 0) {
        if (content[0] == '\n' or content[0] == '#') {
            if (std.mem.indexOfScalar(u8, content, '\n')) |newline| {
                content = content[newline + 1 ..];
                continue;
            }
            break;
        }

        const equal_or_newline = std.mem.indexOfAny(u8, content, "=\n") orelse break;
        if (content[equal_or_newline] == '\n') {
            content = environmentVariablesTrimSpaces(content[equal_or_newline + 1 ..]);
            continue;
        }

        var key = environmentVariablesTrimSpaces(content[0..equal_or_newline]);
        content = content[equal_or_newline + 1 ..];
        if (key.len == 0) {
            content = environmentVariablesTrimSpaces(content);
            continue;
        }
        if (std.mem.startsWith(u8, key, "export ")) {
            key = environmentVariablesTrimSpaces(key[7..]);
        }
        if (!environmentVariablesIsValidName(key)) {
            if (std.mem.indexOfScalar(u8, content, '\n')) |newline| {
                content = environmentVariablesTrimSpaces(content[newline + 1 ..]);
                continue;
            }
            break;
        }

        if (content.len == 0 or content[0] == '\n') {
            try environmentVariablesStoreInsertOwned(&store, allocator, key, "");
            content = if (content.len == 0) content else environmentVariablesTrimSpaces(content[1..]);
            continue;
        }

        content = environmentVariablesTrimSpaces(content);
        if (content.len == 0) {
            try environmentVariablesStoreInsertOwned(&store, allocator, key, "");
            break;
        }

        if (content[0] == '"') {
            if (environmentVariablesFindClosingQuote(content, '"')) |closing| {
                const raw = content[1..closing];
                const expanded = try environmentVariablesExpandDoubleQuotedNewlines(allocator, raw);
                defer allocator.free(expanded);
                try environmentVariablesStoreInsertOwned(&store, allocator, key, expanded);
                if (std.mem.indexOfScalarPos(u8, content, closing + 1, '\n')) |newline| {
                    content = environmentVariablesTrimSpaces(content[newline + 1 ..]);
                } else {
                    break;
                }
                continue;
            }
        }

        if (content[0] == '\'' or content[0] == '"' or content[0] == '`') {
            const quote = content[0];
            if (environmentVariablesFindClosingQuote(content, quote)) |closing| {
                try environmentVariablesStoreInsertOwned(&store, allocator, key, content[1..closing]);
                if (std.mem.indexOfScalarPos(u8, content, closing + 1, '\n')) |newline| {
                    content = environmentVariablesTrimSpaces(content[newline + 1 ..]);
                } else {
                    break;
                }
                continue;
            }

            if (std.mem.indexOfScalar(u8, content, '\n')) |newline| {
                try environmentVariablesStoreInsertOwned(&store, allocator, key, content[0..newline]);
                content = environmentVariablesTrimSpaces(content[newline + 1 ..]);
            } else {
                try environmentVariablesStoreInsertOwned(&store, allocator, key, content);
                break;
            }
            continue;
        }

        if (std.mem.indexOfScalar(u8, content, '\n')) |newline| {
            var value = content[0..newline];
            if (std.mem.indexOfScalar(u8, value, '#')) |hash| {
                value = value[0..hash];
            }
            try environmentVariablesStoreInsertOwned(&store, allocator, key, environmentVariablesTrimSpaces(value));
            content = environmentVariablesTrimSpaces(content[newline + 1 ..]);
        } else {
            var value = content;
            if (std.mem.indexOfScalar(u8, value, '#')) |hash| {
                value = value[0..hash];
            }
            try environmentVariablesStoreInsertOwned(&store, allocator, key, environmentVariablesTrimSpaces(value));
            break;
        }
    }

    return store;
}

fn environmentVariablesAppendStoreObject(out: *std.ArrayList(u8), store: *const std.StringHashMap([]u8)) !void {
    try out.append('{');
    var it = store.iterator();
    var first = true;
    while (it.next()) |entry| {
        if (!first) try out.append(',');
        first = false;
        try appendJsonString(out, entry.key_ptr.*);
        try out.append(':');
        try appendJsonString(out, entry.value_ptr.*);
    }
    try out.append('}');
}

pub export fn sa_node_plugin_environment_variables_snapshot_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var env_map = std.process.getEnvMap(std.heap.page_allocator) catch return fail();
    defer env_map.deinit();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    environmentVariablesAppendObject(&out, &env_map) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_environment_variables_has(name_ptr: ?[*]const u8, name_len: u64, out_bool: ?*u64) u32 {
    const name = if (name_len == 0) return fail() else (name_ptr orelse return fail())[0..name_len];
    out_bool.?.* = if (std.posix.getenv(name) != null) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_environment_variables_get_json(name_ptr: ?[*]const u8, name_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const name = if (name_len == 0) return fail() else (name_ptr orelse return fail())[0..name_len];
    if (std.posix.getenv(name)) |value| {
        return writeJsonValue(out_ptr, out_len, value);
    }
    return writeOwnedString(out_ptr, out_len, "null");
}

pub export fn sa_node_plugin_environment_variables_parse_env_json(content_ptr: ?[*]const u8, content_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const content = if (content_len == 0) "" else (content_ptr orelse return fail())[0..content_len];
    var store = environmentVariablesParseContent(std.heap.page_allocator, content) catch return fail();
    defer environmentVariablesStoreDeinit(&store, std.heap.page_allocator);
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    environmentVariablesAppendStoreObject(&out, &store) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_environment_variables_load_env_file_json(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const path = if (path_len == 0) ".env" else (path_ptr orelse return fail())[0..path_len];
    const allocator = std.heap.page_allocator;
    var file = if (std.fs.path.isAbsolute(path))
        std.fs.openFileAbsolute(path, .{}) catch return fail()
    else
        std.fs.cwd().openFile(path, .{}) catch return fail();
    defer file.close();

    const content = file.readToEndAlloc(allocator, 1024 * 1024) catch return fail();
    defer allocator.free(content);

    var store = environmentVariablesParseContent(allocator, content) catch return fail();
    defer environmentVariablesStoreDeinit(&store, allocator);

    var loaded_count: u64 = 0;
    var skipped_count: u64 = 0;
    var it = store.iterator();
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "NODE_OPTIONS")) {
            skipped_count += 1;
            continue;
        }
        if (std.posix.getenv(entry.key_ptr.*) != null) {
            skipped_count += 1;
            continue;
        }
        const key_z = std.fmt.allocPrintZ(allocator, "{s}", .{entry.key_ptr.*}) catch return fail();
        defer allocator.free(key_z);
        const value_z = std.fmt.allocPrintZ(allocator, "{s}", .{entry.value_ptr.*}) catch return fail();
        defer allocator.free(value_z);
        if (setenv(key_z.ptr, value_z.ptr, 1) != 0) return fail();
        loaded_count += 1;
    }

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"path\":") catch return fail();
    appendJsonString(&out, path) catch return fail();
    out.appendSlice(",\"loaded\":") catch return fail();
    out.writer().print("{d}", .{loaded_count}) catch return fail();
    out.appendSlice(",\"skipped\":") catch return fail();
    out.writer().print("{d}", .{skipped_count}) catch return fail();
    out.appendSlice(",\"entries\":") catch return fail();
    environmentVariablesAppendStoreObject(&out, &store) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

const ErrorCodeEntry = struct {
    name: []const u8,
    number: i32,
};

const node_error_codes = [_][]const u8{
    "ERR_INVALID_ARG_TYPE",
    "ERR_INVALID_ARG_VALUE",
    "ERR_OUT_OF_RANGE",
    "ERR_SYSTEM_ERROR",
};

const common_system_error_names = [_][]const u8{
    "ENOENT",
    "EACCES",
    "ECONNREFUSED",
    "ECONNRESET",
    "ETIMEDOUT",
};

const system_error_codes = [_]ErrorCodeEntry{
    .{ .name = "E2BIG", .number = 7 },
    .{ .name = "EACCES", .number = 13 },
    .{ .name = "EADDRINUSE", .number = 98 },
    .{ .name = "EADDRNOTAVAIL", .number = 99 },
    .{ .name = "EAFNOSUPPORT", .number = 97 },
    .{ .name = "EAGAIN", .number = 11 },
    .{ .name = "EALREADY", .number = 114 },
    .{ .name = "EBADF", .number = 9 },
    .{ .name = "EBUSY", .number = 16 },
    .{ .name = "ECANCELED", .number = 125 },
    .{ .name = "ECONNABORTED", .number = 103 },
    .{ .name = "ECONNREFUSED", .number = 111 },
    .{ .name = "ECONNRESET", .number = 104 },
    .{ .name = "EEXIST", .number = 17 },
    .{ .name = "EHOSTUNREACH", .number = 113 },
    .{ .name = "EINPROGRESS", .number = 115 },
    .{ .name = "EINTR", .number = 4 },
    .{ .name = "EINVAL", .number = 22 },
    .{ .name = "EIO", .number = 5 },
    .{ .name = "EISCONN", .number = 106 },
    .{ .name = "EISDIR", .number = 21 },
    .{ .name = "EMFILE", .number = 24 },
    .{ .name = "ENAMETOOLONG", .number = 36 },
    .{ .name = "ENETDOWN", .number = 100 },
    .{ .name = "ENETRESET", .number = 102 },
    .{ .name = "ENETUNREACH", .number = 101 },
    .{ .name = "ENOENT", .number = 2 },
    .{ .name = "ENOMEM", .number = 12 },
    .{ .name = "ENOSPC", .number = 28 },
    .{ .name = "ENOTCONN", .number = 107 },
    .{ .name = "ENOTDIR", .number = 20 },
    .{ .name = "ENOTEMPTY", .number = 39 },
    .{ .name = "ENOTSOCK", .number = 88 },
    .{ .name = "ENOTSUP", .number = 95 },
    .{ .name = "EPERM", .number = 1 },
    .{ .name = "EPIPE", .number = 32 },
    .{ .name = "EPROTONOSUPPORT", .number = 93 },
    .{ .name = "EPROTOTYPE", .number = 91 },
    .{ .name = "ERANGE", .number = 34 },
    .{ .name = "EROFS", .number = 30 },
    .{ .name = "ESRCH", .number = 3 },
    .{ .name = "ETIMEDOUT", .number = 110 },
};

fn errorsLookupSystemName(errnum: i32) []const u8 {
    for (system_error_codes) |entry| {
        if (entry.number == errnum) return entry.name;
    }
    return "UNKNOWN";
}

fn errorsSystemMessage(errnum: i32) []const u8 {
    const msg_z = strerror(@intCast(errnum)) orelse return "unknown error";
    return std.mem.span(msg_z);
}

fn errorsAppendQuotedField(out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    try out.appendSlice(",\"");
    try out.appendSlice(name);
    try out.appendSlice("\":");
    try appendJsonString(out, value);
}

fn errorsAppendQuotedMessage(out: *std.ArrayList(u8), name: []const u8, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(std.heap.page_allocator, fmt, args);
    defer std.heap.page_allocator.free(text);
    try errorsAppendQuotedField(out, name, text);
}

fn errorsBuildSystemErrorJson(out: *std.ArrayList(u8), errnum: i32, syscall: []const u8, path: ?[]const u8, dest: ?[]const u8) !void {
    const code = errorsLookupSystemName(errnum);
    const message = errorsSystemMessage(errnum);
    try out.appendSlice("{\"code\":");
    try appendJsonString(out, code);
    try out.appendSlice(",\"errno\":");
    try out.writer().print("{d}", .{errnum});
    try errorsAppendQuotedField(out, "message", message);
    try errorsAppendQuotedField(out, "syscall", syscall);
    if (path) |file_path| {
        if (dest) |dest_path| {
            try errorsAppendQuotedMessage(out, "summary", "{s}: {s}, {s} '{s}' -> '{s}'", .{ code, message, syscall, file_path, dest_path });
        } else {
            try errorsAppendQuotedMessage(out, "summary", "{s}: {s}, {s} '{s}'", .{ code, message, syscall, file_path });
        }
    } else {
        try errorsAppendQuotedMessage(out, "summary", "{s}: {s}, {s}", .{ code, message, syscall });
    }
    try out.appendSlice(",\"path\":");
    if (path) |file_path| {
        try appendJsonString(out, file_path);
    } else {
        try out.appendSlice("null");
    }
    try out.appendSlice(",\"dest\":");
    if (dest) |dest_path| {
        try appendJsonString(out, dest_path);
    } else {
        try out.appendSlice("null");
    }
    try out.append('}');
}

pub export fn sa_node_plugin_errors_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"errors\",\"supported\":true,\"mode\":\"native-error-codes\",\"nodeCodes\":") catch return fail();
    appendStringArray(&out, &node_error_codes) catch return fail();
    out.appendSlice(",\"commonSystemCodes\":") catch return fail();
    appendStringArray(&out, &common_system_error_names) catch return fail();
    out.appendSlice(",\"systemCodeCount\":") catch return fail();
    out.writer().print("{d}", .{system_error_codes.len}) catch return fail();
    out.appendSlice(",\"capabilities\":[\"system errno lookup\",\"native system error JSON\",\"common argument validation diagnostic JSON\"],\"limitations\":[\"no JavaScript Error subclass prototypes\",\"no stack capture or cause chaining\",\"native APIs return status codes and JSON diagnostics\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_errors_codes_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"node\":") catch return fail();
    appendStringArray(&out, &node_error_codes) catch return fail();
    out.appendSlice(",\"system\":{") catch return fail();
    for (system_error_codes, 0..) |entry, i| {
        if (i != 0) out.append(',') catch return fail();
        appendJsonString(&out, entry.name) catch return fail();
        out.append(':') catch return fail();
        out.writer().print("{d}", .{entry.number}) catch return fail();
    }
    out.appendSlice("}}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_errors_get_system_error_name(errnum: i64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, errorsLookupSystemName(@intCast(errnum)));
}

pub export fn sa_node_plugin_errors_get_system_error_message(errnum: i64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, errorsSystemMessage(@intCast(errnum)));
}

pub export fn sa_node_plugin_errors_system_error_json(errnum: i64, syscall_ptr: ?[*]const u8, syscall_len: u64, path_ptr: ?[*]const u8, path_len: u64, dest_ptr: ?[*]const u8, dest_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const syscall = if (syscall_len == 0) "unknown" else (syscall_ptr orelse return fail())[0..syscall_len];
    const path = if (path_len == 0) null else (path_ptr orelse return fail())[0..path_len];
    const dest = if (dest_len == 0) null else (dest_ptr orelse return fail())[0..dest_len];
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    errorsBuildSystemErrorJson(&out, @intCast(errnum), syscall, path, dest) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_errors_invalid_arg_type_json(name_ptr: ?[*]const u8, name_len: u64, expected_ptr: ?[*]const u8, expected_len: u64, actual_type_ptr: ?[*]const u8, actual_type_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const name = if (name_len == 0) return fail() else (name_ptr orelse return fail())[0..name_len];
    const expected = if (expected_len == 0) return fail() else (expected_ptr orelse return fail())[0..expected_len];
    const actual_type = if (actual_type_len == 0) return fail() else (actual_type_ptr orelse return fail())[0..actual_type_len];
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"code\":\"ERR_INVALID_ARG_TYPE\",\"name\":") catch return fail();
    appendJsonString(&out, name) catch return fail();
    out.appendSlice(",\"expected\":") catch return fail();
    appendJsonString(&out, expected) catch return fail();
    out.appendSlice(",\"actualType\":") catch return fail();
    appendJsonString(&out, actual_type) catch return fail();
    errorsAppendQuotedMessage(&out, "message", "The '{s}' argument must be of type {s}. Received type {s}", .{ name, expected, actual_type }) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_errors_invalid_arg_value_json(name_ptr: ?[*]const u8, name_len: u64, value_ptr: ?[*]const u8, value_len: u64, reason_ptr: ?[*]const u8, reason_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const name = if (name_len == 0) return fail() else (name_ptr orelse return fail())[0..name_len];
    const value = if (value_len == 0) "" else (value_ptr orelse return fail())[0..value_len];
    const reason = if (reason_len == 0) "is invalid" else (reason_ptr orelse return fail())[0..reason_len];
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"code\":\"ERR_INVALID_ARG_VALUE\",\"name\":") catch return fail();
    appendJsonString(&out, name) catch return fail();
    out.appendSlice(",\"value\":") catch return fail();
    appendJsonString(&out, value) catch return fail();
    out.appendSlice(",\"reason\":") catch return fail();
    appendJsonString(&out, reason) catch return fail();
    errorsAppendQuotedMessage(&out, "message", "The argument '{s}' {s}. Received {s}", .{ name, reason, value }) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_errors_out_of_range_json(name_ptr: ?[*]const u8, name_len: u64, range_ptr: ?[*]const u8, range_len: u64, received_ptr: ?[*]const u8, received_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const name = if (name_len == 0) return fail() else (name_ptr orelse return fail())[0..name_len];
    const range = if (range_len == 0) return fail() else (range_ptr orelse return fail())[0..range_len];
    const received = if (received_len == 0) "" else (received_ptr orelse return fail())[0..received_len];
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"code\":\"ERR_OUT_OF_RANGE\",\"name\":") catch return fail();
    appendJsonString(&out, name) catch return fail();
    out.appendSlice(",\"range\":") catch return fail();
    appendJsonString(&out, range) catch return fail();
    out.appendSlice(",\"received\":") catch return fail();
    appendJsonString(&out, received) catch return fail();
    errorsAppendQuotedMessage(&out, "message", "The value of '{s}' is out of range. It must be {s}. Received {s}", .{ name, range, received }) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

const internationalization_supported_encodings = [_][]const u8{
    "utf-8",
    "utf8",
    "utf-16le",
    "utf16le",
    "ucs-2",
    "ucs2",
    "latin1",
    "binary",
    "ascii",
    "base64",
    "base64url",
    "hex",
};

fn internationalizationFlagValue(token: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, token, prefix)) return null;
    if (token.len <= prefix.len or token[prefix.len] != '=') return null;
    return token[prefix.len + 1 ..];
}

fn internationalizationOwnedLocale(allocator: std.mem.Allocator) ![]u8 {
    if (std.posix.getenv("LC_ALL")) |value| return allocator.dupe(u8, value);
    if (std.posix.getenv("LC_CTYPE")) |value| return allocator.dupe(u8, value);
    if (std.posix.getenv("LANG")) |value| return allocator.dupe(u8, value);
    return allocator.dupe(u8, "C");
}

fn internationalizationConfiguredIcuDataDir(allocator: std.mem.Allocator) ?[]u8 {
    const argv = std.process.argsAlloc(allocator) catch return null;
    defer std.process.argsFree(allocator, argv);
    if (argv.len > 1) {
        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            if (internationalizationFlagValue(argv[i], "--icu-data-dir")) |value| {
                return allocator.dupe(u8, value) catch null;
            }
            if (std.mem.eql(u8, argv[i], "--icu-data-dir") and i + 1 < argv.len) {
                return allocator.dupe(u8, argv[i + 1]) catch null;
            }
        }
    }

    const node_options = std.posix.getenv("NODE_OPTIONS") orelse return null;
    var tokens = std.mem.tokenizeAny(u8, node_options, " \t\r\n");
    var pending: ?[]const u8 = tokens.next();
    while (pending) |token| {
        const next = tokens.next();
        if (internationalizationFlagValue(token, "--icu-data-dir")) |value| {
            return allocator.dupe(u8, value) catch null;
        }
        if (std.mem.eql(u8, token, "--icu-data-dir") and next != null) {
            return allocator.dupe(u8, next.?) catch null;
        }
        pending = next;
    }
    return null;
}

fn internationalizationHasEncodingInternal(name: []const u8) bool {
    for (internationalization_supported_encodings) |entry| {
        if (std.ascii.eqlIgnoreCase(entry, name)) return true;
    }
    return false;
}

fn internationalizationWriteConfigJson(out: *std.ArrayList(u8)) !void {
    const allocator = std.heap.page_allocator;
    const locale = try internationalizationOwnedLocale(allocator);
    defer allocator.free(locale);
    const icu_data_dir = internationalizationConfiguredIcuDataDir(allocator);
    defer if (icu_data_dir) |value| allocator.free(value);

    try out.appendSlice("{\"icu\":false,\"effectiveLocale\":");
    try appendJsonString(out, locale);
    try out.appendSlice(",\"defaultEncoding\":\"utf-8\"");
    try appendEnvStringField(out, "lang", "LANG");
    try appendEnvStringField(out, "lcAll", "LC_ALL");
    try appendEnvStringField(out, "lcCtype", "LC_CTYPE");
    try appendEnvStringField(out, "timezone", "TZ");
    try appendEnvStringField(out, "nodeIcuData", "NODE_ICU_DATA");
    try out.appendSlice(",\"icuDataDirFlag\":");
    if (icu_data_dir) |value| {
        try appendJsonString(out, value);
    } else {
        try out.appendSlice("null");
    }
    try out.appendSlice(",\"icuConfigured\":");
    try out.appendSlice(if (std.posix.getenv("NODE_ICU_DATA") != null or icu_data_dir != null) "true" else "false");
    try out.appendSlice(",\"supportedEncodings\":");
    try appendStringArray(out, &internationalization_supported_encodings);
    try out.append('}');
}

pub export fn sa_node_plugin_internationalization_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"internationalization\",\"supported\":true,\"mode\":\"locale-env-and-unicode-primitives\",\"icu\":false") catch return fail();
    appendEnvStringField(&out, "lang", "LANG") catch return fail();
    appendEnvStringField(&out, "lcAll", "LC_ALL") catch return fail();
    appendEnvStringField(&out, "lcCtype", "LC_CTYPE") catch return fail();
    appendEnvStringField(&out, "timezone", "TZ") catch return fail();
    appendEnvStringField(&out, "nodeIcuData", "NODE_ICU_DATA") catch return fail();
    const icu_data_dir = internationalizationConfiguredIcuDataDir(std.heap.page_allocator);
    defer if (icu_data_dir) |value| std.heap.page_allocator.free(value);
    out.appendSlice(",\"icuDataDirFlag\":") catch return fail();
    if (icu_data_dir) |value| {
        appendJsonString(&out, value) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"encoding\":\"utf-8\",\"capabilities\":[\"UTF-8 string/byte conversion\",\"TextEncoder/TextDecoder compatible helpers\",\"locale and timezone discovery from process environment\",\"NODE_ICU_DATA and --icu-data-dir configuration introspection\",\"encoding support queries\"],\"limitations\":[\"full ICU collation/date/number formatting is not bundled\",\"Intl JavaScript constructors are outside this native plugin surface\",\"ICU configuration is reported but does not imply bundled Intl runtime support\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_internationalization_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    internationalizationWriteConfigJson(&out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_internationalization_effective_locale_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const locale = internationalizationOwnedLocale(std.heap.page_allocator) catch return fail();
    defer std.heap.page_allocator.free(locale);
    return writeJsonValue(out_ptr, out_len, locale);
}

pub export fn sa_node_plugin_internationalization_supported_encodings_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &internationalization_supported_encodings) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_internationalization_has_encoding(name_ptr: ?[*]const u8, name_len: u64, out_bool: ?*u64) u32 {
    const name = if (name_len == 0) return fail() else (name_ptr orelse return fail())[0..name_len];
    out_bool.?.* = if (internationalizationHasEncodingInternal(name)) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_internationalization_has_icu_config(out_bool: ?*u64) u32 {
    const icu_data_dir = internationalizationConfiguredIcuDataDir(std.heap.page_allocator);
    defer if (icu_data_dir) |value| std.heap.page_allocator.free(value);
    out_bool.?.* = if (std.posix.getenv("NODE_ICU_DATA") != null or icu_data_dir != null) 1 else 0;
    return 0;
}

const iterable_stream_types = [_][]const u8{
    "Readable",
    "Writable",
    "Duplex",
    "Transform",
    "PassThrough",
    "WebReadableStream",
    "WebWritableStream",
    "WebTransformStream",
};

const iterable_stream_capabilities = [_][]const u8{
    "native stream handles",
    "pipeline state tracking",
    "finished/destroyed state tracking",
    "compose state tracking",
    "web stream read/write/enqueue helpers",
    "classic and web stream bridge metadata",
};

const iterable_stream_bridge_ops = [_][]const u8{
    "stream.readable_new",
    "stream.writable_new",
    "stream.duplex_new",
    "stream.transform_new",
    "stream.passthrough_new",
    "stream.pipeline",
    "stream.finished",
    "stream.compose",
    "web_streams.readable_new",
    "web_streams.writable_new",
    "web_streams.transform_new",
    "web_streams.enqueue",
    "web_streams.write",
    "web_streams.read",
    "web_streams.snapshot_json",
    "web_streams.close",
};

fn iterableStreamsHasValue(items: []const []const u8, name: []const u8) bool {
    for (items) |item| {
        if (std.ascii.eqlIgnoreCase(item, name)) return true;
    }
    return false;
}

fn iterableStreamsWriteBridgeJson(out: *std.ArrayList(u8)) !void {
    try out.appendSlice("{\"mode\":\"poll-read-byte-iterators\",\"classic\":{");
    try out.appendSlice("\"readableNew\":true,\"writableNew\":true,\"duplexNew\":true,\"transformNew\":true,\"passthroughNew\":true,\"pipeline\":true,\"finished\":true,\"compose\":true");
    try out.appendSlice("},\"web\":{");
    try out.appendSlice("\"readableNew\":true,\"writableNew\":true,\"transformNew\":true,\"enqueue\":true,\"write\":true,\"read\":true,\"snapshot\":true,\"close\":true");
    try out.appendSlice("},\"asyncIterator\":false,\"iteratorProtocol\":\"explicit native read/poll\",\"bridgeOps\":");
    try appendStringArray(out, &iterable_stream_bridge_ops);
    try out.append('}');
}

pub export fn sa_node_plugin_iterable_streams_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"iterable_streams\",\"supported\":true,\"mode\":\"poll-read-byte-iterators\",\"streamTypes\":") catch return fail();
    appendStringArray(&out, &iterable_stream_types) catch return fail();
    out.appendSlice(",\"capabilities\":") catch return fail();
    appendStringArray(&out, &iterable_stream_capabilities) catch return fail();
    out.appendSlice(",\"bridge\":") catch return fail();
    iterableStreamsWriteBridgeJson(&out) catch return fail();
    out.appendSlice(",\"limitations\":[\"no JavaScript Symbol.asyncIterator callbacks\",\"Readable.from()/fromWeb()/toWeb() object-model semantics are not emulated\",\"iteration is exposed through explicit native read/poll helpers\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_iterable_streams_stream_types_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &iterable_stream_types) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_iterable_streams_capabilities_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &iterable_stream_capabilities) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_iterable_streams_bridge_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    iterableStreamsWriteBridgeJson(&out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_iterable_streams_has_stream_type(name_ptr: ?[*]const u8, name_len: u64, out_bool: ?*u64) u32 {
    const name = if (name_len == 0) return fail() else (name_ptr orelse return fail())[0..name_len];
    out_bool.?.* = if (iterableStreamsHasValue(&iterable_stream_types, name)) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_iterable_streams_has_capability(name_ptr: ?[*]const u8, name_len: u64, out_bool: ?*u64) u32 {
    const name = if (name_len == 0) return fail() else (name_ptr orelse return fail())[0..name_len];
    out_bool.?.* = if (iterableStreamsHasValue(&iterable_stream_capabilities, name) or iterableStreamsHasValue(&iterable_stream_bridge_ops, name)) 1 else 0;
    return 0;
}

const permissions_available_flags = [_][]const u8{
    "--allow-fs-read",
    "--allow-fs-write",
    "--allow-addons",
    "--allow-child-process",
    "--allow-net",
    "--allow-inspector",
    "--allow-wasi",
    "--allow-worker",
    "--allow-ffi",
};

fn permissionsNodeOptions() []const u8 {
    return std.posix.getenv("NODE_OPTIONS") orelse "";
}

fn permissionsIsAuditModeInternal() bool {
    return std.mem.indexOf(u8, permissionsNodeOptions(), "--permission-audit") != null;
}

fn permissionsIsEnabledInternal() bool {
    const options = permissionsNodeOptions();
    return std.mem.indexOf(u8, options, "--permission") != null or std.mem.indexOf(u8, options, "--permission-audit") != null;
}

fn permissionsReadManifestJson(allocator: std.mem.Allocator) ![]u8 {
    const manifest_path = pluginManifestPath();
    var file = if (std.fs.path.isAbsolute(manifest_path))
        std.fs.openFileAbsolute(manifest_path, .{}) catch return error.ManifestNotFound
    else
        std.fs.cwd().openFile(manifest_path, .{}) catch return error.ManifestNotFound;
    defer file.close();
    return file.readToEndAlloc(allocator, 1024 * 1024);
}

fn permissionsNormalizePathAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(path)) return allocator.dupe(u8, path);
    if (std.fs.path.isAbsolute(pluginRootDir())) {
        return std.fs.path.resolve(allocator, &.{ pluginRootDir(), path });
    }
    return std.fs.path.resolve(allocator, &.{ pluginRootDir(), path });
}

fn permissionsExpandProjectPathAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, path, "$PROJECT")) return allocator.dupe(u8, path);
    const root = if (std.fs.path.isAbsolute(pluginRootDir()))
        try allocator.dupe(u8, pluginRootDir())
    else
        try std.fs.path.resolve(allocator, &.{pluginRootDir()});
    defer allocator.free(root);
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ root, path[8..] });
}

fn permissionsPathMatches(allocator: std.mem.Allocator, declared_path: []const u8, reference: []const u8) bool {
    const expanded = permissionsExpandProjectPathAlloc(allocator, declared_path) catch return false;
    defer allocator.free(expanded);
    const normalized_ref = permissionsNormalizePathAlloc(allocator, reference) catch return false;
    defer allocator.free(normalized_ref);

    if (std.mem.endsWith(u8, expanded, "/**")) {
        const root_path = expanded[0 .. expanded.len - 3];
        if (std.mem.eql(u8, normalized_ref, root_path)) return true;
        return normalized_ref.len > root_path.len and std.mem.startsWith(u8, normalized_ref, root_path) and normalized_ref[root_path.len] == '/';
    }

    return std.mem.eql(u8, normalized_ref, expanded);
}

fn permissionsEnvMatches(pattern: []const u8, reference: []const u8) bool {
    if (std.mem.endsWith(u8, pattern, "*")) {
        return std.mem.startsWith(u8, reference, pattern[0 .. pattern.len - 1]);
    }
    return std.mem.eql(u8, pattern, reference);
}

fn permissionsHasFs(allocator: std.mem.Allocator, permissions: std.json.Value, scope: []const u8, reference: ?[]const u8) bool {
    const fs_value = permissions.object.get("fs") orelse return false;
    if (fs_value != .array) return false;
    const op = if (std.mem.eql(u8, scope, "fs")) null else scope[3..];
    for (fs_value.array.items) |item| {
        if (item != .object) continue;
        const item_op = item.object.get("op") orelse continue;
        const item_path = item.object.get("path") orelse continue;
        if (item_op != .string or item_path != .string) continue;
        if (op) |needed| {
            if (!std.mem.eql(u8, item_op.string, needed)) continue;
        }
        if (reference) |ref| {
            if (!permissionsPathMatches(allocator, item_path.string, ref)) continue;
        }
        return true;
    }
    return false;
}

fn permissionsHasNet(permissions: std.json.Value, reference: ?[]const u8) bool {
    const net_value = permissions.object.get("net") orelse return false;
    if (net_value != .array) return false;
    if (reference == null) return net_value.array.items.len > 0;
    for (net_value.array.items) |item| {
        if (item != .object) continue;
        const url_value = item.object.get("url") orelse continue;
        if (url_value != .string) continue;
        if (std.mem.eql(u8, url_value.string, reference.?)) return true;
    }
    return false;
}

fn permissionsHasEnv(permissions: std.json.Value, reference: ?[]const u8) bool {
    const env_value = permissions.object.get("env") orelse return false;
    if (env_value != .array) return false;
    if (reference == null) return env_value.array.items.len > 0;
    for (env_value.array.items) |item| {
        if (item != .string) continue;
        if (permissionsEnvMatches(item.string, reference.?)) return true;
    }
    return false;
}

fn permissionsHasProcess(permissions: std.json.Value, scope: []const u8, reference: ?[]const u8) bool {
    const process_value = permissions.object.get("process") orelse return false;
    if (process_value != .object) return false;
    if (std.mem.eql(u8, scope, "child") or std.mem.eql(u8, scope, "child_process") or std.mem.eql(u8, scope, "process.spawn")) {
        const spawn_value = process_value.object.get("spawn") orelse return false;
        return spawn_value == .bool and spawn_value.bool;
    }
    if (std.mem.eql(u8, scope, "process.exec")) {
        const exec_value = process_value.object.get("exec") orelse return false;
        if (exec_value != .array) return false;
        if (reference == null) return exec_value.array.items.len > 0;
        for (exec_value.array.items) |item| {
            if (item != .object) continue;
            const path_value = item.object.get("path") orelse continue;
            if (path_value != .string) continue;
            if (std.mem.eql(u8, path_value.string, reference.?)) return true;
        }
    }
    return false;
}

fn permissionsHasDeclared(scope: []const u8, reference: ?[]const u8) bool {
    const allocator = std.heap.page_allocator;
    const json_text = permissionsReadManifestJson(allocator) catch return false;
    defer allocator.free(json_text);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch return false;
    defer parsed.deinit();
    const permissions = parsed.value.object.get("permissions") orelse return false;
    if (permissions != .object) return false;

    if (std.mem.eql(u8, scope, "fs") or std.mem.eql(u8, scope, "fs.read") or std.mem.eql(u8, scope, "fs.write") or std.mem.eql(u8, scope, "fs.create") or std.mem.eql(u8, scope, "fs.delete") or std.mem.eql(u8, scope, "fs.metadata")) {
        return permissionsHasFs(allocator, permissions, scope, reference);
    }
    if (std.mem.eql(u8, scope, "net")) return permissionsHasNet(permissions, reference);
    if (std.mem.eql(u8, scope, "env")) return permissionsHasEnv(permissions, reference);
    if (std.mem.eql(u8, scope, "child") or std.mem.eql(u8, scope, "child_process") or std.mem.eql(u8, scope, "process.spawn") or std.mem.eql(u8, scope, "process.exec")) {
        return permissionsHasProcess(permissions, scope, reference);
    }
    return false;
}

pub export fn sa_node_plugin_permissions_is_enabled(out_bool: ?*u64) u32 {
    out_bool.?.* = if (permissionsIsEnabledInternal()) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_permissions_is_audit_mode(out_bool: ?*u64) u32 {
    out_bool.?.* = if (permissionsIsAuditModeInternal()) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_permissions_available_flags_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &permissions_available_flags) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_permissions_declared_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    const json_text = permissionsReadManifestJson(allocator) catch return fail();
    defer allocator.free(json_text);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch return fail();
    defer parsed.deinit();
    const permissions = parsed.value.object.get("permissions") orelse return fail();
    return writeJsonValue(out_ptr, out_len, permissions);
}

pub export fn sa_node_plugin_permissions_has(scope_ptr: ?[*]const u8, scope_len: u64, reference_ptr: ?[*]const u8, reference_len: u64, out_bool: ?*u64) u32 {
    const scope = if (scope_len == 0) "" else (scope_ptr orelse return fail())[0..scope_len];
    const reference = if (reference_len == 0) null else (reference_ptr orelse return fail())[0..reference_len];
    out_bool.?.* = if (permissionsHasDeclared(scope, reference)) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_permissions_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const dev_mode = std.posix.getenv("SA_PLUGIN_DEV") != null;
    var flags_ptr: ?[*]const u8 = null;
    var flags_len: u64 = 0;
    if (sa_node_plugin_permissions_available_flags_json(&flags_ptr, &flags_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(flags_ptr, flags_len);

    var declared_ptr: ?[*]const u8 = null;
    var declared_len: u64 = 0;
    if (sa_node_plugin_permissions_declared_json(&declared_ptr, &declared_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(declared_ptr, declared_len);

    const flags = if (flags_ptr) |ptr| ptr[0..@intCast(flags_len)] else "[]";
    const declared = if (declared_ptr) |ptr| ptr[0..@intCast(declared_len)] else "null";
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"permissions\",\"supported\":true,\"model\":\"sa-plugin-manifest\",\"sandboxEnforced\":false,\"devMode\":") catch return fail();
    out.appendSlice(if (dev_mode) "true" else "false") catch return fail();
    out.appendSlice(",\"enabled\":") catch return fail();
    out.appendSlice(if (permissionsIsEnabledInternal()) "true" else "false") catch return fail();
    out.appendSlice(",\"auditMode\":") catch return fail();
    out.appendSlice(if (permissionsIsAuditModeInternal()) "true" else "false") catch return fail();
    out.appendSlice(",\"availableFlags\":") catch return fail();
    out.appendSlice(flags) catch return fail();
    out.appendSlice(",\"declared\":") catch return fail();
    out.appendSlice(declared) catch return fail();
    out.appendSlice(",\"limitations\":[\"Node --permission runtime flags are not enforced by this plugin\",\"has() reports declared manifest allowances rather than runtime interception state\",\"host sandbox and sap.json are authoritative\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

const ReplBuiltinCommand = struct {
    name: []const u8,
    help: []const u8,
};

const repl_builtin_commands = [_]ReplBuiltinCommand{
    .{ .name = "break", .help = "clear buffered continuation input" },
    .{ .name = "clear", .help = "alias of .break for native sessions" },
    .{ .name = "help", .help = "list available dot commands" },
    .{ .name = "history", .help = "return current line history" },
};

const repl_export_names = [_][]const u8{
    "start",
    "REPLServer",
    "Recoverable",
};

const ReplCommand = struct {
    name: []u8,
    help: []u8,
};

const ReplSession = struct {
    allocator: std.mem.Allocator,
    prompt: []u8,
    continuation_prompt: []u8,
    buffer: std.ArrayList(u8),
    history: std.ArrayList([]u8),
    commands: std.ArrayList(ReplCommand),
    terminal: bool,
    use_colors: bool,
    closed: bool = false,
    eval_count: u64 = 0,

    fn init(allocator: std.mem.Allocator, prompt: []const u8) !*ReplSession {
        const session = try allocator.create(ReplSession);
        errdefer allocator.destroy(session);
        session.* = .{
            .allocator = allocator,
            .prompt = try allocator.dupe(u8, if (prompt.len == 0) "node> " else prompt),
            .continuation_prompt = try allocator.dupe(u8, "... "),
            .buffer = std.ArrayList(u8).init(allocator),
            .history = std.ArrayList([]u8).init(allocator),
            .commands = std.ArrayList(ReplCommand).init(allocator),
            .terminal = replIsTerminal(),
            .use_colors = replShouldUseColors(),
        };
        return session;
    }

    fn deinit(self: *ReplSession) void {
        self.allocator.free(self.prompt);
        self.allocator.free(self.continuation_prompt);
        self.buffer.deinit();
        for (self.history.items) |item| self.allocator.free(item);
        self.history.deinit();
        for (self.commands.items) |item| {
            self.allocator.free(item.name);
            self.allocator.free(item.help);
        }
        self.commands.deinit();
        self.allocator.destroy(self);
    }

    fn setPrompt(self: *ReplSession, prompt: []const u8) !void {
        self.allocator.free(self.prompt);
        self.prompt = try self.allocator.dupe(u8, if (prompt.len == 0) "node> " else prompt);
    }

    fn appendHistory(self: *ReplSession, line: []const u8) !void {
        try self.history.append(try self.allocator.dupe(u8, line));
    }

    fn defineCommand(self: *ReplSession, name: []const u8, help: []const u8) !void {
        for (self.commands.items) |*command| {
            if (std.mem.eql(u8, command.name, name)) {
                self.allocator.free(command.help);
                command.help = try self.allocator.dupe(u8, help);
                return;
            }
        }
        try self.commands.append(.{
            .name = try self.allocator.dupe(u8, name),
            .help = try self.allocator.dupe(u8, help),
        });
    }
};

fn replIsTerminal() bool {
    return posix.isatty(0) and posix.isatty(1);
}

fn replShouldUseColors() bool {
    if (std.posix.getenv("NO_COLOR") != null) return false;
    if (std.posix.getenv("FORCE_COLOR")) |value| return !std.mem.eql(u8, value, "0");
    const term = std.posix.getenv("TERM") orelse return replIsTerminal();
    if (std.mem.eql(u8, term, "dumb")) return false;
    return replIsTerminal();
}

fn replFindCommand(session: *const ReplSession, name: []const u8) ?*const ReplCommand {
    for (session.commands.items) |*command| {
        if (std.mem.eql(u8, command.name, name)) return command;
    }
    return null;
}

fn replAppendCommandsJson(out: *std.ArrayList(u8), session: *const ReplSession) !void {
    try out.append('[');
    var first = true;
    for (repl_builtin_commands) |command| {
        if (!first) try out.append(',');
        first = false;
        try out.appendSlice("{\"name\":\".");
        try out.appendSlice(command.name);
        try out.appendSlice("\",\"help\":");
        try appendJsonString(out, command.help);
        try out.appendSlice(",\"builtin\":true}");
    }
    for (session.commands.items) |command| {
        if (!first) try out.append(',');
        first = false;
        try out.appendSlice("{\"name\":\".");
        try out.appendSlice(command.name);
        try out.appendSlice("\",\"help\":");
        try appendJsonString(out, command.help);
        try out.appendSlice(",\"builtin\":false}");
    }
    try out.append(']');
}

fn replWriteHistoryJson(session: *const ReplSession, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendOwnedStringArray(&out, session.history.items) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn replWriteSnapshotJson(session: *const ReplSession, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"prompt\":") catch return fail();
    appendJsonString(&out, session.prompt) catch return fail();
    out.appendSlice(",\"continuationPrompt\":") catch return fail();
    appendJsonString(&out, session.continuation_prompt) catch return fail();
    out.appendSlice(",\"terminal\":") catch return fail();
    out.appendSlice(if (session.terminal) "true" else "false") catch return fail();
    out.appendSlice(",\"useColors\":") catch return fail();
    out.appendSlice(if (session.use_colors) "true" else "false") catch return fail();
    out.appendSlice(",\"closed\":") catch return fail();
    out.appendSlice(if (session.closed) "true" else "false") catch return fail();
    out.appendSlice(",\"evalCount\":") catch return fail();
    out.writer().print("{d}", .{session.eval_count}) catch return fail();
    out.appendSlice(",\"historySize\":") catch return fail();
    out.writer().print("{d}", .{session.history.items.len}) catch return fail();
    out.appendSlice(",\"bufferedInput\":") catch return fail();
    appendJsonString(&out, session.buffer.items) catch return fail();
    out.appendSlice(",\"commands\":") catch return fail();
    replAppendCommandsJson(&out, session) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn replWriteEvalResultJson(session: *ReplSession, line: []const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const trimmed = std.mem.trim(u8, line, " \t");
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();

    if (trimmed.len == 0) {
        out.appendSlice("{\"type\":\"empty\",\"executed\":false}") catch return fail();
        return writeOwnedBytes(out_ptr, out_len, out.items);
    }

    if (trimmed[0] == '.') {
        const body = trimmed[1..];
        const space_index = std.mem.indexOfAny(u8, body, " \t");
        const command_name = if (space_index) |idx| body[0..idx] else body;
        const argument = if (space_index) |idx| std.mem.trim(u8, body[idx + 1 ..], " \t") else "";

        if (std.mem.eql(u8, command_name, "help")) {
            out.appendSlice("{\"type\":\"help\",\"executed\":false,\"commands\":") catch return fail();
            replAppendCommandsJson(&out, session) catch return fail();
            out.append('}') catch return fail();
            return writeOwnedBytes(out_ptr, out_len, out.items);
        }
        if (std.mem.eql(u8, command_name, "history")) {
            out.appendSlice("{\"type\":\"history\",\"executed\":false,\"entries\":") catch return fail();
            appendOwnedStringArray(&out, session.history.items) catch return fail();
            out.append('}') catch return fail();
            return writeOwnedBytes(out_ptr, out_len, out.items);
        }
        if (std.mem.eql(u8, command_name, "break") or std.mem.eql(u8, command_name, "clear")) {
            session.buffer.clearRetainingCapacity();
            out.appendSlice("{\"type\":\"control\",\"command\":\".") catch return fail();
            out.appendSlice(command_name) catch return fail();
            out.appendSlice("\",\"executed\":false,\"bufferedInput\":\"\",\"cleared\":true}") catch return fail();
            return writeOwnedBytes(out_ptr, out_len, out.items);
        }
        if (replFindCommand(session, command_name)) |command| {
            out.appendSlice("{\"type\":\"command\",\"executed\":false,\"name\":\".") catch return fail();
            out.appendSlice(command.name) catch return fail();
            out.appendSlice("\",\"help\":") catch return fail();
            appendJsonString(&out, command.help) catch return fail();
            out.appendSlice(",\"argument\":") catch return fail();
            appendJsonString(&out, argument) catch return fail();
            out.append('}') catch return fail();
            return writeOwnedBytes(out_ptr, out_len, out.items);
        }
        out.appendSlice("{\"type\":\"unknown-command\",\"executed\":false,\"name\":\".") catch return fail();
        out.appendSlice(command_name) catch return fail();
        out.appendSlice("\"}") catch return fail();
        return writeOwnedBytes(out_ptr, out_len, out.items);
    }

    if (line.len > 0 and line[line.len - 1] == '\\') {
        session.buffer.appendSlice(line[0 .. line.len - 1]) catch return fail();
        session.buffer.append('\n') catch return fail();
        out.appendSlice("{\"type\":\"buffer\",\"executed\":false,\"continued\":true,\"bufferedInput\":") catch return fail();
        appendJsonString(&out, session.buffer.items) catch return fail();
        out.append('}') catch return fail();
        return writeOwnedBytes(out_ptr, out_len, out.items);
    }

    if (session.buffer.items.len != 0) {
        session.buffer.appendSlice(line) catch return fail();
        out.appendSlice("{\"type\":\"input\",\"executed\":false,\"submitted\":true,\"source\":") catch return fail();
        appendJsonString(&out, session.buffer.items) catch return fail();
        out.appendSlice(",\"jsRuntime\":false}") catch return fail();
        session.buffer.clearRetainingCapacity();
        return writeOwnedBytes(out_ptr, out_len, out.items);
    }

    out.appendSlice("{\"type\":\"input\",\"executed\":false,\"submitted\":true,\"source\":") catch return fail();
    appendJsonString(&out, line) catch return fail();
    out.appendSlice(",\"jsRuntime\":false}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_repl_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"repl\",\"supported\":true,\"mode\":\"top-level-native-repl-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &repl_export_names) catch return fail();
    out.appendSlice(",\"defaultConfig\":{\"terminal\":") catch return fail();
    out.appendSlice(if (replIsTerminal()) "true" else "false") catch return fail();
    out.appendSlice(",\"useColors\":") catch return fail();
    out.appendSlice(if (replShouldUseColors()) "true" else "false") catch return fail();
    out.appendSlice(",\"prompt\":\"node> \",\"continuationPrompt\":\"... \",\"builtinCommands\":[\".help\",\".break\",\".clear\",\".history\"]},\"featureSupport\":{\"start\":true,\"REPLServer\":false,\"Recoverable\":false,\"prompt\":true,\"history\":true,\"defineCommand\":true,\"bufferedInput\":true,\"jsEvaluation\":false,\"completion\":false,\"contextObject\":false,\"requireInjection\":false},\"capabilities\":[\"explicit REPL session handles\",\"prompt and continuation prompt metadata\",\"dot-command registry and help listing\",\"line history and buffered continuation input\",\"native eval-line routing without JavaScript execution\"],\"limitations\":[\"no vm or V8-backed JavaScript evaluation\",\"no context object, completion engine, or require injection\",\"multiline continuation uses explicit trailing backslash buffering rather than JavaScript syntax recovery\",\"top-level start metadata maps to native session allocation rather than a live stream-bound REPLServer instance\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_repl_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &repl_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_repl_default_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"prompt\":\"node> \",\"continuationPrompt\":\"... \",\"terminal\":") catch return fail();
    out.appendSlice(if (replIsTerminal()) "true" else "false") catch return fail();
    out.appendSlice(",\"useColors\":") catch return fail();
    out.appendSlice(if (replShouldUseColors()) "true" else "false") catch return fail();
    out.appendSlice(",\"builtinCommands\":[\".help\",\".break\",\".clear\",\".history\"],\"sessionModel\":\"explicit native handle\"}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_repl_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"start\":{\"supported\":true,\"mode\":\"allocate native REPL session handle with prompt metadata\"},\"REPLServer\":{\"supported\":false,\"reason\":\"JavaScript REPLServer stream-bound EventEmitter objects are not modeled\"},\"Recoverable\":{\"supported\":false,\"reason\":\"JavaScript Recoverable error class identity is not modeled\"},\"prompt\":{\"supported\":true,\"mode\":\"native prompt and continuation prompt metadata\"},\"history\":{\"supported\":true,\"mode\":\"native history JSON snapshot\"},\"defineCommand\":{\"supported\":true,\"mode\":\"native dot-command registry\"},\"bufferedInput\":{\"supported\":true,\"mode\":\"explicit trailing-backslash multiline buffer\"},\"jsEvaluation\":{\"supported\":false,\"reason\":\"vm or V8-backed JavaScript evaluation is out of scope\"},\"completion\":{\"supported\":false,\"reason\":\"syntax-aware completion engine is not modeled\"},\"contextObject\":{\"supported\":false,\"reason\":\"mutable JavaScript evaluation context objects are not modeled\"},\"requireInjection\":{\"supported\":false,\"reason\":\"module loader and require injection are not modeled\"}}");
}

pub export fn sa_node_plugin_repl_create_session(prompt_ptr: ?[*]const u8, prompt_len: u64, out_session: ?*?*anyopaque) u32 {
    const prompt = if (prompt_ptr) |ptr| ptr[0..prompt_len] else "";
    const session = ReplSession.init(std.heap.page_allocator, prompt) catch return fail();
    out_session.?.* = @ptrCast(session);
    return 0;
}

pub export fn sa_node_plugin_repl_set_prompt(session_ptr: ?*anyopaque, prompt_ptr: ?[*]const u8, prompt_len: u64) u32 {
    const session: *ReplSession = @ptrCast(@alignCast(session_ptr orelse return fail()));
    const prompt = if (prompt_ptr) |ptr| ptr[0..prompt_len] else "";
    session.setPrompt(prompt) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_repl_define_command(session_ptr: ?*anyopaque, name_ptr: ?[*]const u8, name_len: u64, help_ptr: ?[*]const u8, help_len: u64) u32 {
    const session: *ReplSession = @ptrCast(@alignCast(session_ptr orelse return fail()));
    const name = if (name_ptr) |ptr| ptr[0..name_len] else return fail();
    const help = if (help_ptr) |ptr| ptr[0..help_len] else "";
    session.defineCommand(name, help) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_repl_eval_line(session_ptr: ?*anyopaque, line_ptr: ?[*]const u8, line_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const session: *ReplSession = @ptrCast(@alignCast(session_ptr orelse return fail()));
    if (session.closed) return fail();
    const raw_line = if (line_ptr) |ptr| ptr[0..line_len] else "";
    const line = std.mem.trimRight(u8, raw_line, "\r\n");
    session.eval_count += 1;
    if (line.len != 0) session.appendHistory(line) catch return fail();
    return replWriteEvalResultJson(session, line, out_ptr, out_len);
}

pub export fn sa_node_plugin_repl_history_json(session_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const session: *ReplSession = @ptrCast(@alignCast(session_ptr orelse return fail()));
    return replWriteHistoryJson(session, out_ptr, out_len);
}

pub export fn sa_node_plugin_repl_snapshot_json(session_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const session: *ReplSession = @ptrCast(@alignCast(session_ptr orelse return fail()));
    return replWriteSnapshotJson(session, out_ptr, out_len);
}

pub export fn sa_node_plugin_repl_close(session_ptr: ?*anyopaque) u32 {
    const session: *ReplSession = @ptrCast(@alignCast(session_ptr orelse return fail()));
    session.closed = true;
    return 0;
}

pub export fn sa_node_plugin_repl_free(session_ptr: ?*anyopaque) u32 {
    if (session_ptr) |ptr| {
        const session: *ReplSession = @ptrCast(@alignCast(ptr));
        session.deinit();
    }
    return 0;
}

const test_runner_builtin_reporters = [_][]const u8{ "spec", "tap", "dot", "junit", "lcov" };
const test_module_export_names = [_][]const u8{
    "test",
    "it",
    "suite",
    "describe",
    "before",
    "after",
    "beforeEach",
    "afterEach",
    "run",
    "getTestContext",
    "assert",
    "mock",
    "snapshot",
};

const TestRunnerConfig = struct {
    allocator: std.mem.Allocator,
    coverage: bool = false,
    watch: bool = false,
    only: bool = false,
    force_exit: bool = false,
    concurrency: ?u64 = null,
    timeout: ?u64 = null,
    isolation: ?[]u8 = null,
    rerun_failures_path: ?[]u8 = null,
    reporters: std.ArrayList([]u8),
    reporter_destinations: std.ArrayList([]u8),
    saw_node_options: bool = false,
    saw_argv: bool = false,

    fn init(allocator: std.mem.Allocator) TestRunnerConfig {
        return .{
            .allocator = allocator,
            .reporters = std.ArrayList([]u8).init(allocator),
            .reporter_destinations = std.ArrayList([]u8).init(allocator),
        };
    }

    fn deinit(self: *TestRunnerConfig) void {
        for (self.reporters.items) |item| self.allocator.free(item);
        self.reporters.deinit();
        for (self.reporter_destinations.items) |item| self.allocator.free(item);
        self.reporter_destinations.deinit();
        if (self.isolation) |value| self.allocator.free(value);
        if (self.rerun_failures_path) |value| self.allocator.free(value);
    }
};

fn testRunnerFlagValue(token: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, token, prefix)) return null;
    if (token.len <= prefix.len or token[prefix.len] != '=') return null;
    return token[prefix.len + 1 ..];
}

fn testRunnerConfigPush(list: *std.ArrayList([]u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try list.append(try allocator.dupe(u8, value));
}

fn testRunnerConfigSetOwned(slot: *?[]u8, allocator: std.mem.Allocator, value: []const u8) !void {
    if (slot.*) |existing| allocator.free(existing);
    slot.* = try allocator.dupe(u8, value);
}

fn testRunnerParseToken(config: *TestRunnerConfig, token: []const u8, next: ?[]const u8) !bool {
    if (std.mem.eql(u8, token, "--experimental-test-coverage")) {
        config.coverage = true;
        return false;
    }
    if (std.mem.eql(u8, token, "--watch")) {
        config.watch = true;
        return false;
    }
    if (std.mem.eql(u8, token, "--test-only")) {
        config.only = true;
        return false;
    }
    if (std.mem.eql(u8, token, "--test-force-exit")) {
        config.force_exit = true;
        return false;
    }
    if (testRunnerFlagValue(token, "--test-concurrency")) |value| {
        config.concurrency = std.fmt.parseInt(u64, value, 10) catch config.concurrency;
        return false;
    }
    if (std.mem.eql(u8, token, "--test-concurrency") and next != null) {
        config.concurrency = std.fmt.parseInt(u64, next.?, 10) catch config.concurrency;
        return true;
    }
    if (testRunnerFlagValue(token, "--test-timeout")) |value| {
        config.timeout = std.fmt.parseInt(u64, value, 10) catch config.timeout;
        return false;
    }
    if (std.mem.eql(u8, token, "--test-timeout") and next != null) {
        config.timeout = std.fmt.parseInt(u64, next.?, 10) catch config.timeout;
        return true;
    }
    if (testRunnerFlagValue(token, "--test-isolation")) |value| {
        try testRunnerConfigSetOwned(&config.isolation, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "--test-isolation") and next != null) {
        try testRunnerConfigSetOwned(&config.isolation, config.allocator, next.?);
        return true;
    }
    if (testRunnerFlagValue(token, "--test-reporter")) |value| {
        try testRunnerConfigPush(&config.reporters, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "--test-reporter") and next != null) {
        try testRunnerConfigPush(&config.reporters, config.allocator, next.?);
        return true;
    }
    if (testRunnerFlagValue(token, "--test-reporter-destination")) |value| {
        try testRunnerConfigPush(&config.reporter_destinations, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "--test-reporter-destination") and next != null) {
        try testRunnerConfigPush(&config.reporter_destinations, config.allocator, next.?);
        return true;
    }
    if (testRunnerFlagValue(token, "--test-rerun-failures")) |value| {
        try testRunnerConfigSetOwned(&config.rerun_failures_path, config.allocator, value);
        return false;
    }
    if (std.mem.eql(u8, token, "--test-rerun-failures") and next != null) {
        try testRunnerConfigSetOwned(&config.rerun_failures_path, config.allocator, next.?);
        return true;
    }
    return false;
}

fn testRunnerParseNodeOptions(config: *TestRunnerConfig) !void {
    const options = std.posix.getenv("NODE_OPTIONS") orelse return;
    config.saw_node_options = true;
    var tokens = std.mem.tokenizeAny(u8, options, " \t\r\n");
    var pending: ?[]const u8 = tokens.next();
    while (pending) |token| {
        const next = tokens.next();
        const consumed_next = try testRunnerParseToken(config, token, next);
        pending = if (consumed_next) tokens.next() else next;
    }
}

fn testRunnerParseArgv(config: *TestRunnerConfig) !void {
    const allocator = config.allocator;
    const argv = std.process.argsAlloc(allocator) catch return;
    defer std.process.argsFree(allocator, argv);
    if (argv.len <= 1) return;
    config.saw_argv = true;
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const consumed_next = try testRunnerParseToken(config, argv[i], if (i + 1 < argv.len) argv[i + 1] else null);
        if (consumed_next) i += 1;
    }
}

fn testRunnerReadConfig(allocator: std.mem.Allocator) !TestRunnerConfig {
    var config = TestRunnerConfig.init(allocator);
    errdefer config.deinit();
    try testRunnerParseNodeOptions(&config);
    try testRunnerParseArgv(&config);
    if (config.reporters.items.len == 0) {
        try testRunnerConfigPush(&config.reporters, allocator, "spec");
    }
    if (config.isolation == null) {
        try testRunnerConfigSetOwned(&config.isolation, allocator, "process");
    }
    return config;
}

fn testRunnerAppendOwnedStringArray(out: *std.ArrayList(u8), items: []const []u8) !void {
    try out.append('[');
    for (items, 0..) |item, i| {
        if (i != 0) try out.append(',');
        try appendJsonString(out, item);
    }
    try out.append(']');
}

fn testRunnerWriteConfigJson(config: *const TestRunnerConfig, out: *std.ArrayList(u8)) !void {
    try out.appendSlice("{\"coverage\":");
    try out.appendSlice(if (config.coverage) "true" else "false");
    try out.appendSlice(",\"watch\":");
    try out.appendSlice(if (config.watch) "true" else "false");
    try out.appendSlice(",\"only\":");
    try out.appendSlice(if (config.only) "true" else "false");
    try out.appendSlice(",\"forceExit\":");
    try out.appendSlice(if (config.force_exit) "true" else "false");
    try out.appendSlice(",\"concurrency\":");
    if (config.concurrency) |value| {
        try out.writer().print("{d}", .{value});
    } else {
        try out.appendSlice("null");
    }
    try out.appendSlice(",\"timeout\":");
    if (config.timeout) |value| {
        try out.writer().print("{d}", .{value});
    } else {
        try out.appendSlice("null");
    }
    try out.appendSlice(",\"isolation\":");
    if (config.isolation) |value| {
        try appendJsonString(out, value);
    } else {
        try out.appendSlice("null");
    }
    try out.appendSlice(",\"rerunFailuresPath\":");
    if (config.rerun_failures_path) |value| {
        try appendJsonString(out, value);
    } else {
        try out.appendSlice("null");
    }
    try out.appendSlice(",\"reporters\":");
    try testRunnerAppendOwnedStringArray(out, config.reporters.items);
    try out.appendSlice(",\"reporterDestinations\":");
    try testRunnerAppendOwnedStringArray(out, config.reporter_destinations.items);
    try out.appendSlice(",\"source\":{\"nodeOptions\":");
    try out.appendSlice(if (config.saw_node_options) "true" else "false");
    try out.appendSlice(",\"argv\":");
    try out.appendSlice(if (config.saw_argv) "true" else "false");
    try out.appendSlice("}}");
}

pub export fn sa_node_plugin_test_runner_builtin_reporters_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &test_runner_builtin_reporters) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_test_runner_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var config = testRunnerReadConfig(allocator) catch return fail();
    defer config.deinit();
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    testRunnerWriteConfigJson(&config, &out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_test_runner_has_builtin_reporter(name_ptr: ?[*]const u8, name_len: u64, out_bool: ?*u64) u32 {
    const name = if (name_len == 0) "" else (name_ptr orelse return fail())[0..name_len];
    for (test_runner_builtin_reporters) |reporter| {
        if (std.mem.eql(u8, reporter, name)) {
            out_bool.?.* = 1;
            return 0;
        }
    }
    out_bool.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_test_runner_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var config = testRunnerReadConfig(allocator) catch return fail();
    defer config.deinit();
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"test_runner\",\"supported\":true,\"backend\":\"sa test\",\"mode\":\"sync-native-config-introspection\",\"builtinReporters\":") catch return fail();
    appendStringArray(&out, &test_runner_builtin_reporters) catch return fail();
    out.appendSlice(",\"config\":") catch return fail();
    testRunnerWriteConfigJson(&config, &out) catch return fail();
    out.appendSlice(",\"capabilities\":[\"built-in reporter metadata\",\"host argv and NODE_OPTIONS test flag introspection\",\"coverage/watch/only/isolation/concurrency/timeout snapshot\"],\"limitations\":[\"no JavaScript callback scheduling\",\"no TAP or TestsStream object model\",\"NODE_OPTIONS parsing is whitespace-based and does not emulate shell quoting\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_test_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var config = testRunnerReadConfig(allocator) catch return fail();
    defer config.deinit();
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"test\",\"supported\":true,\"backend\":\"sa test\",\"mode\":\"top-level-native-test-module\",\"exports\":") catch return fail();
    appendStringArray(&out, &test_module_export_names) catch return fail();
    out.appendSlice(",\"aliases\":{\"describe\":\"suite\",\"it\":\"test\"},\"reporters\":") catch return fail();
    appendStringArray(&out, &test_runner_builtin_reporters) catch return fail();
    out.appendSlice(",\"config\":") catch return fail();
    testRunnerWriteConfigJson(&config, &out) catch return fail();
    out.appendSlice(",\"assert\":{\"module\":\"assert\",\"supported\":true,\"register\":false,\"reason\":\"native assert compatibility helpers are exposed separately without node:test registration callbacks\"},\"mock\":{\"supported\":false,\"reason\":\"MockTracker and JavaScript function interception are not modeled\"},\"snapshot\":{\"supported\":false,\"reason\":\"snapshot serializer hooks and path resolution callbacks are not modeled\"},\"capabilities\":[\"top-level export and alias metadata\",\"built-in reporter metadata\",\"host argv and NODE_OPTIONS test flag introspection\",\"separate assert compatibility integration metadata\"],\"limitations\":[\"no JavaScript callback scheduling or subtest execution\",\"no TestContext, Suite, or MockTracker object model\",\"no snapshot serializer/path hook callbacks\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_test_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &test_module_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_test_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var config = testRunnerReadConfig(allocator) catch return fail();
    defer config.deinit();
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"backend\":\"sa test\",\"aliasModel\":{\"describe\":\"suite\",\"it\":\"test\"},\"reporters\":") catch return fail();
    appendStringArray(&out, &test_runner_builtin_reporters) catch return fail();
    out.appendSlice(",\"runnerConfig\":") catch return fail();
    testRunnerWriteConfigJson(&config, &out) catch return fail();
    out.appendSlice(",\"objectModel\":\"not-modeled for JavaScript TestContext, Suite, MockTracker, or snapshot serializer objects\"}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_test_reporters_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_test_runner_builtin_reporters_json(out_ptr, out_len);
}

pub export fn sa_node_plugin_test_assert_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"module\":\"assert\",\"supported\":true,\"register\":false,\"ok\":true,\"equal\":true,\"deepStrictEqual\":true,\"fail\":true,\"reason\":\"native assert compatibility helpers are available, but node:test assert.register callbacks are not modeled\"}");
}

pub export fn sa_node_plugin_test_property_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"mock\":{\"supported\":false,\"reason\":\"MockTracker and JS interception are not modeled\"},\"snapshot\":{\"supported\":false,\"reason\":\"snapshot serializer and resolve path callbacks are not modeled\"},\"getTestContext\":{\"supported\":false,\"reason\":\"JavaScript TestContext objects are not modeled\"},\"run\":{\"supported\":false,\"reason\":\"node:test run() callback/object model is not modeled; use sa test and test_runner metadata instead\"}}");
}

pub export fn sa_node_plugin_test_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"test\":{\"supported\":true,\"mode\":\"native top-level metadata for sa test integration\"},\"suite\":{\"supported\":true,\"mode\":\"describe alias metadata only\"},\"describe\":{\"supported\":true,\"mode\":\"alias of suite metadata\"},\"it\":{\"supported\":true,\"mode\":\"alias of test metadata\"},\"assert\":") catch return fail();
    out.appendSlice("{\"supported\":true,\"register\":false,\"reason\":\"native assert compatibility helpers are available, but node:test assert.register callbacks are not modeled\"}") catch return fail();
    out.appendSlice(",\"mock\":{\"supported\":false,\"reason\":\"MockTracker and JS interception are not modeled\"},\"snapshot\":{\"supported\":false,\"reason\":\"snapshot serializer and resolve path callbacks are not modeled\"},\"getTestContext\":{\"supported\":false,\"reason\":\"JavaScript TestContext objects are not modeled\"},\"run\":{\"supported\":false,\"reason\":\"node:test run() callback/object model is not modeled; use sa test and test_runner metadata instead\"}}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

// --- Domain ---
const DomainHandle = struct {
    allocator: std.mem.Allocator,
    id: u64,
    members: std.ArrayList(?*anyopaque),
    disposed: bool = false,

    fn init(allocator: std.mem.Allocator, id: u64) !*DomainHandle {
        const handle = try allocator.create(DomainHandle);
        handle.* = .{
            .allocator = allocator,
            .id = id,
            .members = std.ArrayList(?*anyopaque).init(allocator),
            .disposed = false,
        };
        return handle;
    }

    fn deinit(self: *DomainHandle) void {
        self.members.deinit();
        self.allocator.destroy(self);
    }
};

var domain_next_id: u64 = 1;
var domain_active: ?*DomainHandle = null;
var domain_stack = std.ArrayList(*DomainHandle).init(std.heap.page_allocator);

const domain_export_names = [_][]const u8{
    "Domain",
    "create",
    "createDomain",
    "active",
    "_stack",
};

fn domainHandle(domain_ptr: ?*anyopaque) ?*DomainHandle {
    return if (domain_ptr) |ptr| @ptrCast(@alignCast(ptr)) else null;
}

fn domainSyncActive() void {
    domain_active = if (domain_stack.items.len == 0) null else domain_stack.items[domain_stack.items.len - 1];
}

fn domainRemoveFromStack(domain: *DomainHandle, remove_all: bool) void {
    var i: usize = 0;
    while (i < domain_stack.items.len) {
        if (domain_stack.items[i] == domain) {
            _ = domain_stack.orderedRemove(i);
            if (!remove_all) break;
            continue;
        }
        i += 1;
    }
    domainSyncActive();
}

fn domainLastIndexOf(domain: *DomainHandle) ?usize {
    var i = domain_stack.items.len;
    while (i > 0) {
        i -= 1;
        if (domain_stack.items[i] == domain) return i;
    }
    return null;
}

fn domainStackDepthFor(domain: *DomainHandle) u64 {
    var count: u64 = 0;
    for (domain_stack.items) |entry| {
        if (entry == domain) count += 1;
    }
    return count;
}

fn domainSnapshotJson(domain: *DomainHandle, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"id\":") catch return fail();
    out.writer().print("{d}", .{domain.id}) catch return fail();
    out.appendSlice(",\"disposed\":") catch return fail();
    out.appendSlice(if (domain.disposed) "true" else "false") catch return fail();
    out.appendSlice(",\"active\":") catch return fail();
    out.appendSlice(if (domain_active == domain) "true" else "false") catch return fail();
    out.appendSlice(",\"stackDepth\":") catch return fail();
    out.writer().print("{d}", .{domainStackDepthFor(domain)}) catch return fail();
    out.appendSlice(",\"memberCount\":") catch return fail();
    out.writer().print("{d}", .{domain.members.items.len}) catch return fail();
    out.appendSlice(",\"members\":[") catch return fail();
    for (domain.members.items, 0..) |member, i| {
        if (i != 0) out.append(',') catch return fail();
        if (member) |ptr| {
            out.writer().print("{d}", .{@intFromPtr(ptr)}) catch return fail();
        } else {
            out.appendSlice("0") catch return fail();
        }
    }
    out.appendSlice("]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_domain_create(out_domain: ?*?*anyopaque) u32 {
    const handle = DomainHandle.init(std.heap.page_allocator, domain_next_id) catch return fail();
    domain_next_id += 1;
    out_domain.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_domain_add(domain_ptr: ?*anyopaque, member_ptr: ?*anyopaque) u32 {
    const domain = domainHandle(domain_ptr) orelse return fail();
    if (domain.disposed) return fail();
    for (domain.members.items) |member| {
        if (member == member_ptr) return 0;
    }
    domain.members.append(member_ptr) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_domain_remove(domain_ptr: ?*anyopaque, member_ptr: ?*anyopaque) u32 {
    const domain = domainHandle(domain_ptr) orelse return fail();
    if (domain.disposed) return fail();
    var i: usize = 0;
    while (i < domain.members.items.len) : (i += 1) {
        if (domain.members.items[i] == member_ptr) {
            _ = domain.members.orderedRemove(i);
            break;
        }
    }
    return 0;
}

pub export fn sa_node_plugin_domain_enter(domain_ptr: ?*anyopaque) u32 {
    const domain = domainHandle(domain_ptr) orelse return fail();
    if (domain.disposed) return fail();
    domain_stack.append(domain) catch return fail();
    domainSyncActive();
    return 0;
}

pub export fn sa_node_plugin_domain_exit(domain_ptr: ?*anyopaque) u32 {
    const domain = domainHandle(domain_ptr) orelse return fail();
    const index = domainLastIndexOf(domain) orelse return 0;
    domain_stack.shrinkRetainingCapacity(index);
    domainSyncActive();
    return 0;
}

pub export fn sa_node_plugin_domain_dispose(domain_ptr: ?*anyopaque) u32 {
    const domain = domainHandle(domain_ptr) orelse return fail();
    domain.disposed = true;
    domain.members.clearRetainingCapacity();
    domainRemoveFromStack(domain, true);
    return 0;
}

pub export fn sa_node_plugin_domain_get_active(out_domain: ?*?*anyopaque) u32 {
    out_domain.?.* = if (domain_active) |domain| @ptrCast(domain) else null;
    return 0;
}

pub export fn sa_node_plugin_domain_member_count(domain_ptr: ?*anyopaque, out_count: ?*u64) u32 {
    const domain = domainHandle(domain_ptr) orelse return fail();
    out_count.?.* = domain.members.items.len;
    return 0;
}

pub export fn sa_node_plugin_domain_snapshot_json(domain_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const domain = domainHandle(domain_ptr) orelse return fail();
    return domainSnapshotJson(domain, out_ptr, out_len);
}

pub export fn sa_node_plugin_domain_free(domain_ptr: ?*anyopaque) u32 {
    if (domain_ptr) |ptr| {
        const domain: *DomainHandle = @ptrCast(@alignCast(ptr));
        domainRemoveFromStack(domain, true);
        domain.deinit();
    }
    return 0;
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

const perf_hooks_export_names = [_][]const u8{
    "Performance",
    "PerformanceEntry",
    "PerformanceMark",
    "PerformanceMeasure",
    "PerformanceObserver",
    "PerformanceObserverEntryList",
    "PerformanceResourceTiming",
    "monitorEventLoopDelay",
    "eventLoopUtilization",
    "timerify",
    "createHistogram",
    "performance",
    "constants",
};

const perf_hooks_supported_entry_types = [_][]const u8{
    "mark",
    "measure",
    "function",
};

fn perfHooksConstantsJson() []const u8 {
    return "{\"NODE_PERFORMANCE_GC_MAJOR\":1,\"NODE_PERFORMANCE_GC_MINOR\":2,\"NODE_PERFORMANCE_GC_INCREMENTAL\":4,\"NODE_PERFORMANCE_GC_WEAKCB\":8,\"NODE_PERFORMANCE_GC_FLAGS_NO\":0,\"NODE_PERFORMANCE_GC_FLAGS_CONSTRUCT_RETAINED\":2,\"NODE_PERFORMANCE_GC_FLAGS_FORCED\":4,\"NODE_PERFORMANCE_GC_FLAGS_SYNCHRONOUS_PHANTOM_PROCESSING\":8,\"NODE_PERFORMANCE_GC_FLAGS_ALL_AVAILABLE_GARBAGE\":16,\"NODE_PERFORMANCE_GC_FLAGS_ALL_EXTERNAL_MEMORY\":32,\"NODE_PERFORMANCE_GC_FLAGS_SCHEDULE_IDLE\":64}";
}

pub export fn sa_node_plugin_perf_hooks_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var now_ms: f64 = 0;
    if (sa_node_plugin_perf_hooks_now_ms(&now_ms) != 0) return fail();
    var origin_ms: f64 = 0;
    if (sa_node_plugin_perf_hooks_time_origin_ms(&origin_ms) != 0) return fail();

    var elu_ptr: ?[*]const u8 = null;
    var elu_len: u64 = 0;
    if (ext.sa_node_plugin_perf_hooks_event_loop_utilization(&elu_ptr, &elu_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(elu_ptr, elu_len);

    var entries_ptr: ?[*]const u8 = null;
    var entries_len: u64 = 0;
    if (sa_node_plugin_perf_hooks_entries_json(&entries_ptr, &entries_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(entries_ptr, entries_len);

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"perf_hooks\",\"supported\":true,\"mode\":\"top-level-native-perf-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &perf_hooks_export_names) catch return fail();
    out.appendSlice(",\"supportedEntryTypes\":") catch return fail();
    appendStringArray(&out, &perf_hooks_supported_entry_types) catch return fail();
    out.appendSlice(",\"performance\":{\"now\":true,\"timeOrigin\":true,\"mark\":true,\"measure\":true,\"getEntries\":true,\"eventLoopUtilization\":true},\"helpers\":{\"createHistogram\":true,\"timerify\":true,\"monitorEventLoopDelay\":true},\"runtime\":{\"nowMs\":") catch return fail();
    out.writer().print("{d}", .{now_ms}) catch return fail();
    out.appendSlice(",\"timeOriginMs\":") catch return fail();
    out.writer().print("{d}", .{origin_ms}) catch return fail();
    out.appendSlice(",\"entries\":") catch return fail();
    out.appendSlice((entries_ptr orelse return fail())[0..@intCast(entries_len)]) catch return fail();
    out.appendSlice(",\"eventLoopUtilization\":") catch return fail();
    out.appendSlice((elu_ptr orelse return fail())[0..@intCast(elu_len)]) catch return fail();
    out.appendSlice(",\"constants\":") catch return fail();
    out.appendSlice(perfHooksConstantsJson()) catch return fail();
    out.appendSlice("},\"featureSupport\":{\"PerformanceObserver\":false,\"PerformanceObserverEntryList\":false,\"PerformanceResourceTiming\":false,\"PerformanceEntryClass\":false,\"PerformanceClass\":false,\"performanceNow\":true,\"performanceTimeOrigin\":true,\"performanceMark\":true,\"performanceMeasure\":true,\"performanceEntries\":true,\"eventLoopUtilization\":true,\"createHistogram\":true,\"timerify\":true,\"monitorEventLoopDelay\":true,\"constants\":true},\"limitations\":[\"Performance, PerformanceEntry, PerformanceMark, PerformanceMeasure, PerformanceObserver, and PerformanceResourceTiming JavaScript class instances are not modeled\",\"monitorEventLoopDelay is exposed as a histogram-handle compatibility path over explicit native sampling records rather than an autonomous event-loop probe\",\"timerify records native timer ids only and does not wrap JavaScript functions or emit observer callbacks\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_perf_hooks_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &perf_hooks_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_perf_hooks_supported_entry_types_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &perf_hooks_supported_entry_types) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_perf_hooks_constants_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, perfHooksConstantsJson());
}

pub export fn sa_node_plugin_perf_hooks_performance_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var now_ms: f64 = 0;
    if (sa_node_plugin_perf_hooks_now_ms(&now_ms) != 0) return fail();
    var origin_ms: f64 = 0;
    if (sa_node_plugin_perf_hooks_time_origin_ms(&origin_ms) != 0) return fail();
    var elu_ptr: ?[*]const u8 = null;
    var elu_len: u64 = 0;
    if (ext.sa_node_plugin_perf_hooks_event_loop_utilization(&elu_ptr, &elu_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(elu_ptr, elu_len);

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"nowMs\":") catch return fail();
    out.writer().print("{d}", .{now_ms}) catch return fail();
    out.appendSlice(",\"timeOriginMs\":") catch return fail();
    out.writer().print("{d}", .{origin_ms}) catch return fail();
    out.appendSlice(",\"eventLoopUtilization\":") catch return fail();
    out.appendSlice((elu_ptr orelse return fail())[0..@intCast(elu_len)]) catch return fail();
    out.appendSlice(",\"supportedEntryTypes\":") catch return fail();
    appendStringArray(&out, &perf_hooks_supported_entry_types) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_perf_hooks_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"Performance\":{\"supported\":false,\"reason\":\"JavaScript Performance class instances are not modeled\"},\"PerformanceEntry\":{\"supported\":false,\"reason\":\"JavaScript PerformanceEntry instances are not modeled\"},\"PerformanceMark\":{\"supported\":false,\"reason\":\"JavaScript PerformanceMark instances are not modeled\"},\"PerformanceMeasure\":{\"supported\":false,\"reason\":\"JavaScript PerformanceMeasure instances are not modeled\"},\"PerformanceObserver\":{\"supported\":false,\"reason\":\"observer callback dispatch and buffering are not modeled\"},\"PerformanceObserverEntryList\":{\"supported\":false,\"reason\":\"observer entry list objects are not modeled\"},\"PerformanceResourceTiming\":{\"supported\":false,\"reason\":\"resource timing objects are not modeled\"},\"performance.now\":{\"supported\":true,\"mode\":\"native monotonic milliseconds since process facade origin\"},\"performance.timeOrigin\":{\"supported\":true,\"mode\":\"native process facade origin timestamp\"},\"performance.mark\":{\"supported\":true,\"mode\":\"named native mark registry\"},\"performance.measure\":{\"supported\":true,\"mode\":\"named native mark delta calculation\"},\"performance.getEntries\":{\"supported\":true,\"mode\":\"JSON snapshot via entries_json\"},\"eventLoopUtilization\":{\"supported\":true,\"mode\":\"native process CPU and wall clock estimate JSON\"},\"createHistogram\":{\"supported\":true,\"mode\":\"native histogram handle\"},\"monitorEventLoopDelay\":{\"supported\":true,\"mode\":\"histogram handle compatibility subset\",\"limitations\":[\"no autonomous background sampling\",\"no resolution scheduler\"]},\"timerify\":{\"supported\":true,\"mode\":\"native timer registration id only\",\"limitations\":[\"does not wrap JavaScript functions\",\"does not emit PerformanceObserver function entries\"]},\"constants\":{\"supported\":true,\"mode\":\"static perf_hooks constant catalog\"}}");
}

// --- Report ---
const report_export_names = [_][]const u8{
    "writeReport",
    "getReport",
    "directory",
    "filename",
    "compact",
    "excludeNetwork",
    "signal",
    "reportOnFatalError",
    "reportOnSignal",
    "reportOnUncaughtException",
    "excludeEnv",
};

pub export fn sa_node_plugin_report_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var report_ptr: ?[*]const u8 = null;
    var report_len: u64 = 0;
    if (sa_node_plugin_report_get_json(&report_ptr, &report_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(report_ptr, report_len);

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"report\",\"supported\":true,\"mode\":\"top-level-native-report-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &report_export_names) catch return fail();
    out.appendSlice(",\"sampleReport\":") catch return fail();
    out.appendSlice((report_ptr orelse return fail())[0..@intCast(report_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"writeReport\":true,\"getReport\":true,\"directory\":false,\"filename\":false,\"compact\":false,\"excludeNetwork\":false,\"signal\":false,\"reportOnFatalError\":false,\"reportOnSignal\":false,\"reportOnUncaughtException\":false,\"excludeEnv\":false},\"capabilities\":[\"generate native diagnostic report JSON snapshot\",\"write report JSON to explicit absolute or resolved file path\",\"report current pid/ppid/cwd/platform/arch metadata\"],\"limitations\":[\"no JavaScript process.report object with live getters and setters\",\"no signal-triggered, fatal-error, or uncaught-exception automatic report hooks\",\"no compact, excludeNetwork, or excludeEnv toggles\",\"writeReport persists the native JSON snapshot only and does not accept JavaScript Error objects\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
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

pub export fn sa_node_plugin_report_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &report_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_report_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"defaultFilename\":\"sa-report.json\",\"pathResolution\":\"relative paths resolve against cwd before write\",\"writeReport\":{\"supported\":true,\"mode\":\"write native diagnostic snapshot to explicit file path\"},\"getReport\":{\"supported\":true,\"mode\":\"return native diagnostic snapshot JSON\"},\"liveProperties\":{\"directory\":false,\"filename\":false,\"compact\":false,\"excludeNetwork\":false,\"signal\":false,\"reportOnFatalError\":false,\"reportOnSignal\":false,\"reportOnUncaughtException\":false,\"excludeEnv\":false}}");
}

pub export fn sa_node_plugin_report_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"writeReport\":{\"supported\":true,\"mode\":\"write explicit-path diagnostic JSON file\",\"limitations\":[\"does not accept JavaScript Error objects\",\"does not classify API vs signal vs fatal error origins\"]},\"getReport\":{\"supported\":true,\"mode\":\"return current native diagnostic JSON snapshot\"},\"directory\":{\"supported\":false,\"reason\":\"mutable process.report output directory state is not modeled\"},\"filename\":{\"supported\":false,\"reason\":\"mutable process.report filename state is not modeled\"},\"compact\":{\"supported\":false,\"reason\":\"compact formatting toggle is not modeled\"},\"excludeNetwork\":{\"supported\":false,\"reason\":\"network elision toggle is not modeled\"},\"signal\":{\"supported\":false,\"reason\":\"signal-triggered report configuration is not modeled\"},\"reportOnFatalError\":{\"supported\":false,\"reason\":\"fatal-error automatic reporting requires runtime exception integration\"},\"reportOnSignal\":{\"supported\":false,\"reason\":\"signal-triggered automatic reporting is not modeled\"},\"reportOnUncaughtException\":{\"supported\":false,\"reason\":\"uncaught-exception automatic reporting requires runtime exception integration\"},\"excludeEnv\":{\"supported\":false,\"reason\":\"environment elision toggle is not modeled\"}}");
}

// --- SEA ---
pub export fn sa_node_plugin_sea_is_sea(out_bool: ?*u32) u32 {
    return writeOwnedBool(out_bool, std.posix.getenv("SA_NODE_SEA_ASSETS") != null or std.posix.getenv("SA_NODE_SEA_ASSET_DIR") != null);
}

const sea_export_names = [_][]const u8{
    "isSea",
    "getAsset",
    "getRawAsset",
    "getAssetAsBlob",
    "getAssetKeys",
};

fn seaProviderConfigJson(out: *std.ArrayList(u8)) !void {
    var is_sea: u32 = 0;
    if (sa_node_plugin_sea_is_sea(&is_sea) != 0) return error.Unexpected;

    var keys_ptr: ?[*]const u8 = null;
    var keys_len: u64 = 0;
    if (sa_node_plugin_sea_asset_keys_json(&keys_ptr, &keys_len) != 0) return error.Unexpected;
    defer _ = base.sa_node_plugin_free_buffer(keys_ptr, keys_len);

    try out.appendSlice("{\"isSea\":");
    try out.appendSlice(if (is_sea != 0) "true" else "false");
    try out.appendSlice(",\"assetKeys\":");
    try out.appendSlice((keys_ptr orelse return error.Unexpected)[0..@intCast(keys_len)]);
    try appendEnvStringField(out, "assetsEnv", "SA_NODE_SEA_ASSETS");
    try appendEnvStringField(out, "assetDir", "SA_NODE_SEA_ASSET_DIR");
    try out.appendSlice(",\"provider\":");
    if (std.posix.getenv("SA_NODE_SEA_ASSETS") != null) {
        try appendJsonString(out, "environment-json");
    } else if (std.posix.getenv("SA_NODE_SEA_ASSET_DIR") != null) {
        try appendJsonString(out, "filesystem-directory");
    } else {
        try out.appendSlice("null");
    }
    try out.append('}');
}

pub export fn sa_node_plugin_sea_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"sea\",\"supported\":true,\"mode\":\"top-level-sea-asset-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &sea_export_names) catch return fail();
    out.appendSlice(",\"config\":") catch return fail();
    seaProviderConfigJson(&out) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"isSea\":true,\"getAsset\":true,\"getRawAsset\":true,\"getAssetAsBlob\":true,\"getAssetKeys\":true,\"TextDecoderSemantics\":false,\"BlobClass\":false,\"singleExecutableBinaryEmbedding\":false},\"limitations\":[\"SEA data is sourced from environment JSON or a host directory rather than from an embedded single-executable blob\",\"getAssetAsBlob returns a readable native blob-like stream handle rather than a JavaScript Blob instance\",\"getAsset encoding support is limited to the native utf8/base64/hex compatibility paths implemented by this plugin\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_sea_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &sea_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_sea_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    seaProviderConfigJson(&out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_sea_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"isSea\":{\"supported\":true,\"mode\":\"environment or directory backed SEA detection\"},\"getAsset\":{\"supported\":true,\"mode\":\"native asset lookup plus utf8/base64/hex encoding compatibility\"},\"getRawAsset\":{\"supported\":true,\"mode\":\"native byte lookup\"},\"getAssetAsBlob\":{\"supported\":true,\"mode\":\"readable native blob-like handle\",\"limitations\":[\"not a JavaScript Blob instance\"]},\"getAssetKeys\":{\"supported\":true,\"mode\":\"environment JSON keys or directory file listing\"},\"singleExecutableBinaryEmbedding\":{\"supported\":false,\"reason\":\"embedded SEA binary blob parsing is not modeled; use environment or directory backed assets\"},\"TextDecoderSemantics\":{\"supported\":false,\"reason\":\"full JavaScript TextDecoder error handling and label aliases are not modeled\"},\"Blob\":{\"supported\":false,\"reason\":\"JavaScript Blob class instances are not modeled\"}}");
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

pub export fn sa_node_plugin_trace_events_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"trace_events\",\"supported\":true,\"mode\":\"top-level-native-trace-events-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &trace_events_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"createTracing\":true,\"getEnabledCategories\":true,\"Tracing\":false},\"capabilities\":[\"explicit native tracing handle allocation with stored category string\",\"enable and disable state toggling on explicit tracing handles\",\"enabled-categories snapshot JSON from explicit tracing handles\"],\"limitations\":[\"no JavaScript Tracing class instances or custom inspect behavior\",\"category validation follows this plugin's explicit string handle model rather than Node internal CategorySet semantics\",\"global process trace state, warnings, and internal trace buffer integration are not modeled\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_trace_events_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &trace_events_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_trace_events_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"handleModel\":\"explicit native tracing handle with category string and enabled boolean\",\"categoryModel\":\"comma-delimited category text stored per handle\",\"stateModel\":\"per-handle enable and disable toggles only\",\"objectModel\":\"not-modeled for JavaScript Tracing class instances\"}");
}

pub export fn sa_node_plugin_trace_events_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"createTracing\":{\"supported\":true,\"mode\":\"allocates an explicit native tracing handle from category text\",\"limitations\":[\"does not return a JavaScript Tracing class instance\"]},\"getEnabledCategories\":{\"supported\":true,\"mode\":\"returns the stored category string for an explicit native tracing handle\"},\"Tracing\":{\"supported\":false,\"reason\":\"JavaScript Tracing class construction, getters, and custom inspect behavior are not modeled\"},\"enable\":{\"supported\":true,\"mode\":\"sets the explicit native handle enabled flag\"},\"disable\":{\"supported\":true,\"mode\":\"clears the explicit native handle enabled flag\"},\"warnings\":{\"supported\":false,\"reason\":\"enabled Tracing object leak warnings and process.emitWarning integration are not modeled\"},\"globalTraceState\":{\"supported\":false,\"reason\":\"Node internal process-wide trace category state and backend integration are not modeled\"}}");
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

const worker_threads_export_names = [_][]const u8{
    "isInternalThread",
    "isMainThread",
    "SHARE_ENV",
    "resourceLimits",
    "setEnvironmentData",
    "getEnvironmentData",
    "threadId",
    "threadName",
    "Worker",
    "MessagePort",
    "MessageChannel",
    "markAsUncloneable",
    "markAsUntransferable",
    "isMarkedAsUntransferable",
    "moveMessagePortToContext",
    "receiveMessageOnPort",
    "BroadcastChannel",
    "postMessageToThread",
    "parentPort",
    "workerData",
    "locks",
};

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
    const allocator = std.heap.page_allocator;
    var limits_ptr: ?[*]const u8 = null;
    var limits_len: u64 = 0;
    if (sa_node_plugin_worker_threads_resource_limits_json(&limits_ptr, &limits_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(limits_ptr, limits_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"worker_threads\",\"supported\":true,\"mode\":\"top-level-main-thread-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &worker_threads_export_names) catch return fail();
    out.appendSlice(",\"runtime\":{\"isMainThread\":true,\"isInternalThread\":false,\"threadId\":0,\"threadName\":\"main\",\"parentPort\":null,\"workerData\":null,\"shareEnv\":true},\"resourceLimits\":") catch return fail();
    out.appendSlice((limits_ptr orelse return fail())[0..@intCast(limits_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"MessageChannel\":true,\"MessagePort\":true,\"receiveMessageOnPort\":true,\"postMessageToThread\":true,\"setEnvironmentData\":true,\"getEnvironmentData\":true,\"Worker\":false,\"BroadcastChannel\":false,\"locks\":false,\"moveMessagePortToContext\":false,\"markAsUncloneable\":false,\"markAsUntransferable\":false,\"isMarkedAsUntransferable\":false},\"limitations\":[\"no Worker constructor or background JavaScript execution\",\"no BroadcastChannel, LockManager, or structured-clone transfer registry\",\"message ports are native queue handles rather than EventTarget objects\",\"postMessageToThread only targets the main native thread mailbox compatibility path\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_worker_threads_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &worker_threads_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_worker_threads_share_env_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"SHARE_ENV\":true,\"mode\":\"host-environment-shared\",\"reason\":\"this native facade runs in a single host environment and environment data is shared explicitly\"}");
}

pub export fn sa_node_plugin_worker_threads_parent_port_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "null");
}

pub export fn sa_node_plugin_worker_threads_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"Worker\":{\"supported\":false,\"reason\":\"background JavaScript workers are not modeled\"},\"BroadcastChannel\":{\"supported\":false,\"reason\":\"cross-thread broadcast channels are not modeled\"},\"locks\":{\"supported\":false,\"reason\":\"LockManager coordination is not modeled\"},\"moveMessagePortToContext\":{\"supported\":false,\"reason\":\"vm context transfer is not modeled without a JS runtime\"},\"markAsUncloneable\":{\"supported\":false,\"reason\":\"JS object identity and structured clone hooks are not modeled\"},\"markAsUntransferable\":{\"supported\":false,\"reason\":\"transfer registries for JS object wrappers are not modeled\"},\"isMarkedAsUntransferable\":{\"supported\":false,\"reason\":\"transfer registries for JS object wrappers are not modeled\"},\"MessageChannel\":{\"supported\":true,\"mode\":\"native queue handles\"},\"MessagePort\":{\"supported\":true,\"mode\":\"native queue handles\"},\"receiveMessageOnPort\":{\"supported\":true,\"mode\":\"immediate native dequeue\"},\"postMessageToThread\":{\"supported\":true,\"mode\":\"main-thread mailbox compatibility path\"}}");
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
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"child_process\",\"supported\":true,\"mode\":\"top-level-native-child-process-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &child_process_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"exec\":true,\"execFile\":true,\"execFileSync\":true,\"execSync\":true,\"fork\":true,\"spawn\":true,\"spawnSync\":true,\"ChildProcess\":false,\"_forkChild\":false,\"ipc\":false,\"streamingStdio\":false,\"abortSignal\":false},\"capabilities\":[\"real subprocess execution for exec, execFile, spawn, spawnSync, and fork-style helpers\",\"argv-vector parsing compatible with SA argument slices\",\"pid reporting for spawned and forked processes\",\"captured stdout JSON for synchronous execution helpers\",\"process_exec-backed structured sync exec JSON with code, stdout, and stderr\"],\"limitations\":[\"no JavaScript ChildProcess class instances or EventEmitter lifecycle\",\"no streaming stdio object model, IPC channels, or message events\",\"exec and spawn helpers expose explicit pid or captured-buffer results rather than live process objects\",\"_forkChild internal bootstrap and AbortSignal wiring are not modeled\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

const child_process_export_names = [_][]const u8{
    "_forkChild",
    "ChildProcess",
    "exec",
    "execFile",
    "execFileSync",
    "execSync",
    "fork",
    "spawn",
    "spawnSync",
};

pub export fn sa_node_plugin_child_process_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &child_process_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_child_process_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"execModel\":\"real subprocess execution with captured stdout or structured stdout/stderr JSON helpers\",\"spawnModel\":\"real subprocess spawn returning pid only\",\"forkModel\":\"spawns external node executable with module path and args when available\",\"stdioModel\":\"captured sync stdout buffers only; no live JavaScript stream objects\",\"objectModel\":\"not-modeled for JavaScript ChildProcess instances\"}");
}

pub export fn sa_node_plugin_child_process_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"exec\":{\"supported\":true,\"mode\":\"real subprocess shell execution with pid output and captured stdout buffer\",\"limitations\":[\"no live ChildProcess object or callback/event lifecycle\"]},\"execFile\":{\"supported\":true,\"mode\":\"real subprocess execution from argv-vector input with captured stdout buffer\"},\"execFileSync\":{\"supported\":true,\"mode\":\"sync execFile compatibility over the same captured stdout helper\"},\"execSync\":{\"supported\":true,\"mode\":\"process_exec-backed structured JSON containing code, stdout, and stderr\"},\"fork\":{\"supported\":true,\"mode\":\"spawns external node executable with module path and args and returns pid\",\"limitations\":[\"requires node to be present on PATH\",\"no IPC channel or message passing\"]},\"spawn\":{\"supported\":true,\"mode\":\"real subprocess spawn returning pid only\",\"limitations\":[\"no stdio stream handles or process object lifecycle\"]},\"spawnSync\":{\"supported\":true,\"mode\":\"real subprocess spawn with captured stdout buffer\"},\"ChildProcess\":{\"supported\":false,\"reason\":\"JavaScript ChildProcess class instances and EventEmitter semantics are not modeled\"},\"_forkChild\":{\"supported\":false,\"reason\":\"Node internal child bootstrap helper is not exposed as a public native ABI helper\"},\"ipc\":{\"supported\":false,\"reason\":\"Node child-process IPC channels, send/receive messaging, and serialization modes are not modeled\"},\"streamingStdio\":{\"supported\":false,\"reason\":\"live stdin/stdout/stderr stream objects are not modeled in this facade\"},\"abortSignal\":{\"supported\":false,\"reason\":\"AbortSignal integration and cancellation semantics are not modeled\"}}");
}

// --- Cluster ---
const cluster_sched_none: u64 = 1;
const cluster_sched_rr: u64 = 2;

var cluster_scheduling_policy: u64 = cluster_sched_rr;

const cluster_export_names = [_][]const u8{
    "isPrimary",
    "isMaster",
    "isWorker",
    "SCHED_NONE",
    "SCHED_RR",
    "schedulingPolicy",
    "setupPrimary",
    "setupMaster",
    "fork",
    "settings",
    "Worker",
    "worker",
    "workers",
    "disconnect",
};

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

const QuicEndpointHandle = struct {
    allocator: std.mem.Allocator,
    socket: ?*anyopaque,
    family: u32,
    server: bool,
    closed: bool = false,
    bound: bool = false,
    connected: bool = false,
    has_ref: bool = true,
    local_host: []u8,
    local_port: u16,
    remote_host: []u8,
    remote_port: u16,
    alpn: []u8,
    cc: []u8,
    idle_timeout_ms: u64,

    fn deinit(self: *QuicEndpointHandle) void {
        if (!self.closed and self.socket != null) {
            _ = base.sa_node_plugin_dgram_close(self.socket);
        }
        self.allocator.free(self.local_host);
        self.allocator.free(self.remote_host);
        self.allocator.free(self.alpn);
        self.allocator.free(self.cc);
        self.allocator.destroy(self);
    }
};

const QuicSessionHandle = struct {
    allocator: std.mem.Allocator,
    endpoint: *QuicEndpointHandle,
    authority: []u8,
    path: []u8,
    method: []u8,
    closed: bool = false,

    fn deinit(self: *QuicSessionHandle) void {
        self.allocator.free(self.authority);
        self.allocator.free(self.path);
        self.allocator.free(self.method);
        self.allocator.destroy(self);
    }
};

fn quicEndpointHandle(ptr: ?*anyopaque) ?*QuicEndpointHandle {
    if (ptr == null) return null;
    return @ptrCast(@alignCast(ptr));
}

fn quicSessionHandle(ptr: ?*anyopaque) ?*QuicSessionHandle {
    if (ptr == null) return null;
    return @ptrCast(@alignCast(ptr));
}

fn quicNormalizeCc(cc: []const u8) ?[]const u8 {
    if (cc.len == 0) return "cubic";
    if (std.ascii.eqlIgnoreCase(cc, "reno")) return "reno";
    if (std.ascii.eqlIgnoreCase(cc, "cubic")) return "cubic";
    if (std.ascii.eqlIgnoreCase(cc, "bbr")) return "bbr";
    return null;
}

fn quicNormalizeAlpn(alpn: []const u8) ?[]const u8 {
    if (alpn.len == 0) return "h3";
    if (std.mem.eql(u8, alpn, "h3")) return "h3";
    if (std.mem.eql(u8, alpn, "h3-29")) return "h3-29";
    return null;
}

fn quicCreateEndpoint(family: u32, server: bool, local_host: []const u8, local_port: u64, remote_host: []const u8, remote_port: u64, alpn: []const u8, cc: []const u8, idle_timeout_ms: u64, out_endpoint: ?*?*anyopaque) u32 {
    if (family != 4 and family != 6) return fail();
    if (local_port > std.math.maxInt(u16) or remote_port > std.math.maxInt(u16)) return fail();
    const allocator = std.heap.page_allocator;
    const norm_alpn = quicNormalizeAlpn(alpn) orelse return fail();
    const norm_cc = quicNormalizeCc(cc) orelse return fail();
    const socket = if (family == 6) base.sa_node_plugin_dgram_create_udp6() else base.sa_node_plugin_dgram_create();
    if (socket == null) return fail();
    errdefer _ = base.sa_node_plugin_dgram_close(socket);

    if (server or local_host.len != 0 or local_port != 0) {
        const bind_host = if (local_host.len == 0) (if (family == 6) "::" else "0.0.0.0") else local_host;
        if (base.sa_node_plugin_dgram_bind(socket, bind_host.ptr, bind_host.len, local_port) != 0) return fail();
    }
    if (!server and remote_host.len != 0) {
        if (base.sa_node_plugin_dgram_connect(socket, remote_host.ptr, remote_host.len, remote_port) != 0) return fail();
    }

    const handle = allocator.create(QuicEndpointHandle) catch return fail();
    errdefer allocator.destroy(handle);
    handle.* = .{
        .allocator = allocator,
        .socket = socket,
        .family = family,
        .server = server,
        .bound = server or local_host.len != 0 or local_port != 0,
        .connected = !server and remote_host.len != 0,
        .local_host = allocator.dupe(u8, local_host) catch return fail(),
        .local_port = @intCast(local_port),
        .remote_host = allocator.dupe(u8, remote_host) catch return fail(),
        .remote_port = @intCast(remote_port),
        .alpn = allocator.dupe(u8, norm_alpn) catch return fail(),
        .cc = allocator.dupe(u8, norm_cc) catch return fail(),
        .idle_timeout_ms = idle_timeout_ms,
    };
    out_endpoint.?.* = @ptrCast(handle);
    return 0;
}

fn quicWriteEndpointSnapshot(handle: *QuicEndpointHandle, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(handle.allocator);
    defer out.deinit();
    out.appendSlice("{\"family\":") catch return fail();
    out.writer().print("{d}", .{handle.family}) catch return fail();
    out.appendSlice(",\"server\":") catch return fail();
    out.appendSlice(if (handle.server) "true" else "false") catch return fail();
    out.appendSlice(",\"closed\":") catch return fail();
    out.appendSlice(if (handle.closed) "true" else "false") catch return fail();
    out.appendSlice(",\"bound\":") catch return fail();
    out.appendSlice(if (handle.bound) "true" else "false") catch return fail();
    out.appendSlice(",\"connected\":") catch return fail();
    out.appendSlice(if (handle.connected) "true" else "false") catch return fail();
    out.appendSlice(",\"hasRef\":") catch return fail();
    out.appendSlice(if (handle.has_ref) "true" else "false") catch return fail();
    out.appendSlice(",\"alpn\":") catch return fail();
    appendJsonString(&out, handle.alpn) catch return fail();
    out.appendSlice(",\"cc\":") catch return fail();
    appendJsonString(&out, handle.cc) catch return fail();
    out.writer().print(",\"idleTimeoutMs\":{d}", .{handle.idle_timeout_ms}) catch return fail();
    out.appendSlice(",\"localHost\":") catch return fail();
    appendJsonString(&out, handle.local_host) catch return fail();
    out.writer().print(",\"localPort\":{d}", .{handle.local_port}) catch return fail();
    out.appendSlice(",\"remoteHost\":") catch return fail();
    appendJsonString(&out, handle.remote_host) catch return fail();
    out.writer().print(",\"remotePort\":{d}", .{handle.remote_port}) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn quicWriteSessionSnapshot(handle: *QuicSessionHandle, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(handle.allocator);
    defer out.deinit();
    out.appendSlice("{\"closed\":") catch return fail();
    out.appendSlice(if (handle.closed) "true" else "false") catch return fail();
    out.appendSlice(",\"authority\":") catch return fail();
    appendJsonString(&out, handle.authority) catch return fail();
    out.appendSlice(",\"path\":") catch return fail();
    appendJsonString(&out, handle.path) catch return fail();
    out.appendSlice(",\"method\":") catch return fail();
    appendJsonString(&out, handle.method) catch return fail();
    out.appendSlice(",\"alpn\":") catch return fail();
    appendJsonString(&out, handle.endpoint.alpn) catch return fail();
    out.appendSlice(",\"cc\":") catch return fail();
    appendJsonString(&out, handle.endpoint.cc) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_quic_create_endpoint(family: u32, host_ptr: ?[*]const u8, host_len: u64, port: u64, alpn_ptr: ?[*]const u8, alpn_len: u64, cc_ptr: ?[*]const u8, cc_len: u64, idle_timeout_ms: u64, out_endpoint: ?*?*anyopaque) u32 {
    const host = if (host_ptr) |ptr| ptr[0..host_len] else "";
    const alpn = if (alpn_ptr) |ptr| ptr[0..alpn_len] else "";
    const cc = if (cc_ptr) |ptr| ptr[0..cc_len] else "";
    return quicCreateEndpoint(family, false, host, port, "", 0, alpn, cc, idle_timeout_ms, out_endpoint);
}

pub export fn sa_node_plugin_quic_connect(family: u32, remote_host_ptr: ?[*]const u8, remote_host_len: u64, remote_port: u64, local_host_ptr: ?[*]const u8, local_host_len: u64, local_port: u64, alpn_ptr: ?[*]const u8, alpn_len: u64, cc_ptr: ?[*]const u8, cc_len: u64, idle_timeout_ms: u64, out_endpoint: ?*?*anyopaque) u32 {
    const remote_host = (remote_host_ptr orelse return fail())[0..remote_host_len];
    if (remote_host.len == 0) return fail();
    const local_host = if (local_host_ptr) |ptr| ptr[0..local_host_len] else "";
    const alpn = if (alpn_ptr) |ptr| ptr[0..alpn_len] else "";
    const cc = if (cc_ptr) |ptr| ptr[0..cc_len] else "";
    return quicCreateEndpoint(family, false, local_host, local_port, remote_host, remote_port, alpn, cc, idle_timeout_ms, out_endpoint);
}

pub export fn sa_node_plugin_quic_listen(family: u32, host_ptr: ?[*]const u8, host_len: u64, port: u64, alpn_ptr: ?[*]const u8, alpn_len: u64, cc_ptr: ?[*]const u8, cc_len: u64, idle_timeout_ms: u64, out_endpoint: ?*?*anyopaque) u32 {
    const host = if (host_ptr) |ptr| ptr[0..host_len] else "";
    const alpn = if (alpn_ptr) |ptr| ptr[0..alpn_len] else "";
    const cc = if (cc_ptr) |ptr| ptr[0..cc_len] else "";
    return quicCreateEndpoint(family, true, host, port, "", 0, alpn, cc, idle_timeout_ms, out_endpoint);
}

pub export fn sa_node_plugin_quic_endpoint_snapshot_json(endpoint_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = quicEndpointHandle(endpoint_ptr) orelse return fail();
    return quicWriteEndpointSnapshot(handle, out_ptr, out_len);
}

pub export fn sa_node_plugin_quic_endpoint_address_json(endpoint_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = quicEndpointHandle(endpoint_ptr) orelse return fail();
    if (handle.closed or handle.socket == null) return fail();
    return base.sa_node_plugin_dgram_address(handle.socket, out_ptr, out_len);
}

pub export fn sa_node_plugin_quic_endpoint_remote_address_json(endpoint_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = quicEndpointHandle(endpoint_ptr) orelse return fail();
    if (handle.closed or handle.socket == null or !handle.connected) return fail();
    return base.sa_node_plugin_dgram_remote_address(handle.socket, out_ptr, out_len);
}

pub export fn sa_node_plugin_quic_endpoint_ref(endpoint_ptr: ?*anyopaque) u32 {
    const handle = quicEndpointHandle(endpoint_ptr) orelse return fail();
    if (handle.closed or handle.socket == null) return fail();
    handle.has_ref = true;
    return base.sa_node_plugin_dgram_ref(handle.socket);
}

pub export fn sa_node_plugin_quic_endpoint_unref(endpoint_ptr: ?*anyopaque) u32 {
    const handle = quicEndpointHandle(endpoint_ptr) orelse return fail();
    if (handle.closed or handle.socket == null) return fail();
    handle.has_ref = false;
    return base.sa_node_plugin_dgram_unref(handle.socket);
}

pub export fn sa_node_plugin_quic_endpoint_has_ref(endpoint_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const handle = quicEndpointHandle(endpoint_ptr) orelse return fail();
    if (handle.closed or handle.socket == null) return fail();
    return base.sa_node_plugin_dgram_has_ref(handle.socket, out_bool);
}

pub export fn sa_node_plugin_quic_endpoint_close(endpoint_ptr: ?*anyopaque) u32 {
    const handle = quicEndpointHandle(endpoint_ptr) orelse return fail();
    if (handle.closed) return 0;
    handle.closed = true;
    if (handle.socket != null) {
        const socket = handle.socket;
        handle.socket = null;
        return base.sa_node_plugin_dgram_close(socket);
    }
    return 0;
}

pub export fn sa_node_plugin_quic_endpoint_free(endpoint_ptr: ?*anyopaque) u32 {
    if (quicEndpointHandle(endpoint_ptr)) |handle| handle.deinit();
    return 0;
}

pub export fn sa_node_plugin_http3_create_session(endpoint_ptr: ?*anyopaque, authority_ptr: ?[*]const u8, authority_len: u64, path_ptr: ?[*]const u8, path_len: u64, method_ptr: ?[*]const u8, method_len: u64, out_session: ?*?*anyopaque) u32 {
    const endpoint = quicEndpointHandle(endpoint_ptr) orelse return fail();
    if (endpoint.closed or endpoint.socket == null) return fail();
    const allocator = std.heap.page_allocator;
    const authority = if (authority_ptr) |ptr| ptr[0..authority_len] else "";
    const path = if (path_ptr) |ptr| ptr[0..path_len] else "/";
    const method = if (method_ptr) |ptr| ptr[0..method_len] else "GET";
    const handle = allocator.create(QuicSessionHandle) catch return fail();
    errdefer allocator.destroy(handle);
    handle.* = .{
        .allocator = allocator,
        .endpoint = endpoint,
        .authority = allocator.dupe(u8, authority) catch return fail(),
        .path = allocator.dupe(u8, path) catch return fail(),
        .method = allocator.dupe(u8, method) catch return fail(),
    };
    out_session.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_http3_session_snapshot_json(session_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = quicSessionHandle(session_ptr) orelse return fail();
    return quicWriteSessionSnapshot(handle, out_ptr, out_len);
}

pub export fn sa_node_plugin_http3_session_send_datagram(session_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const handle = quicSessionHandle(session_ptr) orelse return fail();
    if (handle.closed or handle.endpoint.closed or handle.endpoint.socket == null or !handle.endpoint.connected) return fail();
    return base.sa_node_plugin_dgram_send_connected(handle.endpoint.socket, data_ptr, data_len);
}

pub export fn sa_node_plugin_http3_session_recv_datagram(session_ptr: ?*anyopaque, max_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64, out_host_ptr: ?*?[*]const u8, out_host_len: ?*u64, out_port: ?*u64) u32 {
    const handle = quicSessionHandle(session_ptr) orelse return fail();
    if (handle.closed or handle.endpoint.closed or handle.endpoint.socket == null) return fail();
    return base.sa_node_plugin_dgram_recv(handle.endpoint.socket, max_len, out_ptr, out_len, out_host_ptr, out_host_len, out_port);
}

pub export fn sa_node_plugin_http3_session_close(session_ptr: ?*anyopaque) u32 {
    const handle = quicSessionHandle(session_ptr) orelse return fail();
    handle.closed = true;
    return 0;
}

pub export fn sa_node_plugin_http3_session_free(session_ptr: ?*anyopaque) u32 {
    if (quicSessionHandle(session_ptr)) |handle| handle.deinit();
    return 0;
}

pub export fn sa_node_plugin_dtls_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "dtls", true, "native UDP endpoint/session metadata and datagram transport helpers are exposed; DTLS handshake and record-layer crypto are not modeled");
}

pub export fn sa_node_plugin_dtls_connect(family: u32, remote_host_ptr: ?[*]const u8, remote_host_len: u64, remote_port: u64, local_host_ptr: ?[*]const u8, local_host_len: u64, local_port: u64, out_endpoint: ?*?*anyopaque) u32 {
    return sa_node_plugin_quic_connect(family, remote_host_ptr, remote_host_len, remote_port, local_host_ptr, local_host_len, local_port, "dtls".ptr, 4, "reno".ptr, 4, 0, out_endpoint);
}

pub export fn sa_node_plugin_dtls_listen(family: u32, host_ptr: ?[*]const u8, host_len: u64, port: u64, out_endpoint: ?*?*anyopaque) u32 {
    return sa_node_plugin_quic_listen(family, host_ptr, host_len, port, "dtls".ptr, 4, "reno".ptr, 4, 0, out_endpoint);
}

pub export fn sa_node_plugin_dtls_endpoint_snapshot_json(endpoint_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_quic_endpoint_snapshot_json(endpoint_ptr, out_ptr, out_len);
}

pub export fn sa_node_plugin_dtls_send(endpoint_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const handle = quicEndpointHandle(endpoint_ptr) orelse return fail();
    if (handle.closed or handle.socket == null or !handle.connected) return fail();
    return base.sa_node_plugin_dgram_send_connected(handle.socket, data_ptr, data_len);
}

pub export fn sa_node_plugin_dtls_recv(endpoint_ptr: ?*anyopaque, max_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64, out_host_ptr: ?*?[*]const u8, out_host_len: ?*u64, out_port: ?*u64) u32 {
    const handle = quicEndpointHandle(endpoint_ptr) orelse return fail();
    if (handle.closed or handle.socket == null) return fail();
    return base.sa_node_plugin_dgram_recv(handle.socket, max_len, out_ptr, out_len, out_host_ptr, out_host_len, out_port);
}

pub export fn sa_node_plugin_dtls_close(endpoint_ptr: ?*anyopaque) u32 {
    return sa_node_plugin_quic_endpoint_close(endpoint_ptr);
}

pub export fn sa_node_plugin_dtls_free(endpoint_ptr: ?*anyopaque) u32 {
    return sa_node_plugin_quic_endpoint_free(endpoint_ptr);
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

const http2_export_names = [_][]const u8{
    "connect",
    "constants",
    "createServer",
    "createSecureServer",
    "getDefaultSettings",
    "getPackedSettings",
    "getUnpackedSettings",
    "performServerHandshake",
    "sensitiveHeaders",
    "Http2ServerRequest",
    "Http2ServerResponse",
};

const http_export_names = [_][]const u8{
    "_connectionListener",
    "METHODS",
    "STATUS_CODES",
    "Agent",
    "ClientRequest",
    "IncomingMessage",
    "OutgoingMessage",
    "Server",
    "ServerResponse",
    "createServer",
    "validateHeaderName",
    "validateHeaderValue",
    "get",
    "request",
    "setMaxIdleHTTPParsers",
    "maxHeaderSize",
    "globalAgent",
    "WebSocket",
};

const https_export_names = [_][]const u8{
    "Agent",
    "globalAgent",
    "Server",
    "createServer",
    "get",
    "request",
};

const tls_export_names = [_][]const u8{
    "CLIENT_RENEG_LIMIT",
    "CLIENT_RENEG_WINDOW",
    "DEFAULT_CIPHERS",
    "DEFAULT_ECDH_CURVE",
    "DEFAULT_MIN_VERSION",
    "DEFAULT_MAX_VERSION",
    "getCiphers",
    "rootCertificates",
    "getCACertificates",
    "setDefaultCACertificates",
    "convertALPNProtocols",
    "checkServerIdentity",
    "createSecureContext",
    "SecureContext",
    "TLSSocket",
    "Server",
    "createServer",
    "connect",
};

const dgram_export_names = [_][]const u8{
    "createSocket",
    "Socket",
};

const stream_export_names = [_][]const u8{
    "isDestroyed",
    "isDisturbed",
    "isErrored",
    "isReadable",
    "isWritable",
    "Readable",
    "Writable",
    "Duplex",
    "Transform",
    "PassThrough",
    "duplexPair",
    "pipeline",
    "addAbortSignal",
    "finished",
    "destroy",
    "compose",
    "setDefaultHighWaterMark",
    "getDefaultHighWaterMark",
    "promises",
    "Stream",
};

const readline_export_names = [_][]const u8{
    "Interface",
    "clearLine",
    "clearScreenDown",
    "createInterface",
    "cursorTo",
    "emitKeypressEvents",
    "moveCursor",
    "promises",
};

const console_export_names = [_][]const u8{
    "Console",
    "log",
    "info",
    "debug",
    "warn",
    "error",
    "dir",
    "dirxml",
    "table",
    "trace",
    "assert",
    "count",
    "countReset",
    "group",
    "groupCollapsed",
    "groupEnd",
    "time",
    "timeEnd",
    "timeLog",
    "timeStamp",
};

const events_export_names = [_][]const u8{
    "EventEmitter",
    "EventEmitterAsyncResource",
    "addAbortListener",
    "captureRejectionSymbol",
    "captureRejections",
    "defaultMaxListeners",
    "errorMonitor",
    "getEventListeners",
    "getMaxListeners",
    "listenerCount",
    "on",
    "once",
    "setMaxListeners",
    "usingDomains",
};

const trace_events_export_names = [_][]const u8{
    "createTracing",
    "getEnabledCategories",
    "Tracing",
};

const fs_export_names = [_][]const u8{
    "access",
    "copyFile",
    "cp",
    "createReadStream",
    "createWriteStream",
    "Dir",
    "Dirent",
    "exists",
    "glob",
    "lstat",
    "mkdir",
    "open",
    "openAsBlob",
    "opendir",
    "promises",
    "readFile",
    "readdir",
    "readlink",
    "realpath",
    "rename",
    "rm",
    "rmdir",
    "stat",
    "statfs",
    "Stats",
    "symlink",
    "truncate",
    "unlink",
    "unwatchFile",
    "utimes",
    "watch",
    "watchFile",
    "writeFile",
    "constants",
};

const crypto_export_names = [_][]const u8{
    "Certificate",
    "Cipheriv",
    "Decipheriv",
    "Hash",
    "Hmac",
    "KeyObject",
    "X509Certificate",
    "createCipheriv",
    "createDecipheriv",
    "createHash",
    "createHmac",
    "createPrivateKey",
    "createPublicKey",
    "createSecretKey",
    "generateKey",
    "generateKeyPair",
    "getHashes",
    "hkdf",
    "pbkdf2",
    "randomBytes",
    "randomFill",
    "randomInt",
    "randomUUID",
    "scrypt",
    "secureHeapUsed",
    "sign",
    "subtle",
    "timingSafeEqual",
    "verify",
    "webcrypto",
};

const util_export_names = [_][]const u8{
    "MIMEParams",
    "MIMEType",
    "TextDecoder",
    "TextEncoder",
    "aborted",
    "callbackify",
    "debug",
    "debuglog",
    "deprecate",
    "diff",
    "format",
    "formatWithOptions",
    "getCallSites",
    "getSystemErrorMap",
    "getSystemErrorMessage",
    "getSystemErrorName",
    "inherits",
    "inspect",
    "isDeepStrictEqual",
    "parseArgs",
    "parseEnv",
    "promisify",
    "setTraceSigInt",
    "stripVTControlCharacters",
    "styleText",
    "toUSVString",
    "transferableAbortController",
    "transferableAbortSignal",
    "types",
};

const buffer_export_names = [_][]const u8{
    "Blob",
    "Buffer",
    "File",
    "INSPECT_MAX_BYTES",
    "atob",
    "btoa",
    "constants",
    "isAscii",
    "isUtf8",
    "kMaxLength",
    "kStringMaxLength",
    "resolveObjectURL",
    "transcode",
};

const url_export_names = [_][]const u8{
    "URL",
    "URLPattern",
    "URLSearchParams",
    "canParse",
    "domainToASCII",
    "domainToUnicode",
    "fileURLToPath",
    "fileURLToPathBuffer",
    "format",
    "parse",
    "pathToFileURL",
    "resolve",
    "urlToHttpOptions",
};

const process_export_names = [_][]const u8{
    "arch",
    "argv",
    "availableMemory",
    "chdir",
    "constrainedMemory",
    "cwd",
    "dlopen",
    "emitWarning",
    "env",
    "exit",
    "features",
    "getgid",
    "getuid",
    "hrtime",
    "kill",
    "memoryUsage",
    "nextTick",
    "pid",
    "platform",
    "ppid",
    "release",
    "resourceUsage",
    "stderr",
    "stdin",
    "stdout",
    "umask",
    "uptime",
    "version",
    "versions",
};

const os_export_names = [_][]const u8{
    "EOL",
    "arch",
    "availableParallelism",
    "constants",
    "cpus",
    "devNull",
    "endianness",
    "freemem",
    "getPriority",
    "homedir",
    "hostname",
    "loadavg",
    "machine",
    "networkInterfaces",
    "platform",
    "release",
    "setPriority",
    "tmpdir",
    "totalmem",
    "type",
    "uptime",
    "userInfo",
    "version",
};

const path_export_names = [_][]const u8{
    "basename",
    "delimiter",
    "dirname",
    "extname",
    "format",
    "isAbsolute",
    "join",
    "matchesGlob",
    "normalize",
    "parse",
    "posix",
    "relative",
    "resolve",
    "sep",
    "toNamespacedPath",
    "win32",
};

const querystring_export_names = [_][]const u8{
    "decode",
    "encode",
    "escape",
    "parse",
    "stringify",
    "unescape",
    "unescapeBuffer",
};

const punycode_export_names = [_][]const u8{
    "decode",
    "encode",
    "toASCII",
    "toUnicode",
    "ucs2",
    "version",
};

const string_decoder_export_names = [_][]const u8{
    "StringDecoder",
};

const assert_export_names = [_][]const u8{
    "AssertionError",
    "Assert",
    "deepStrictEqual",
    "equal",
    "fail",
    "ok",
    "rejects",
    "strict",
    "strictEqual",
    "throws",
};

const sys_export_names = [_][]const u8{
    "debuglog",
    "format",
    "inspect",
    "inherits",
};

const zlib_export_names = [_][]const u8{
    "brotliCompress",
    "brotliCompressSync",
    "brotliDecompress",
    "brotliDecompressSync",
    "codes",
    "constants",
    "createBrotliCompress",
    "createBrotliDecompress",
    "createDeflate",
    "createDeflateRaw",
    "createGunzip",
    "createGzip",
    "createInflate",
    "createInflateRaw",
    "createUnzip",
    "createZstdCompress",
    "createZstdDecompress",
    "crc32",
    "deflate",
    "deflateRaw",
    "deflateRawSync",
    "deflateSync",
    "gunzip",
    "gunzipSync",
    "gzip",
    "gzipSync",
    "inflate",
    "inflateRaw",
    "inflateRawSync",
    "inflateSync",
    "unzip",
    "unzipSync",
    "zstdCompress",
    "zstdCompressSync",
    "zstdDecompress",
    "zstdDecompressSync",
};

const timers_export_names = [_][]const u8{
    "setTimeout",
    "clearTimeout",
    "setImmediate",
    "clearImmediate",
    "setInterval",
    "clearInterval",
    "promises",
};

const net_export_names = [_][]const u8{
    "_createServerHandle",
    "_normalizeArgs",
    "BlockList",
    "SocketAddress",
    "connect",
    "createConnection",
    "createServer",
    "isIP",
    "isIPv4",
    "isIPv6",
    "Server",
    "Socket",
    "Stream",
    "getDefaultAutoSelectFamily",
    "setDefaultAutoSelectFamily",
    "getDefaultAutoSelectFamilyAttemptTimeout",
    "setDefaultAutoSelectFamilyAttemptTimeout",
};

const dns_export_names = [_][]const u8{
    "lookup",
    "lookupService",
    "Resolver",
    "getDefaultResultOrder",
    "setDefaultResultOrder",
    "setServers",
    "getServers",
    "resolve",
    "resolve4",
    "resolve6",
    "resolveAny",
    "resolveCaa",
    "resolveCname",
    "resolveMx",
    "resolveNaptr",
    "resolveNs",
    "resolvePtr",
    "resolveSoa",
    "resolveSrv",
    "resolveTxt",
    "resolveTlsa",
    "reverse",
    "ADDRCONFIG",
    "ALL",
    "V4MAPPED",
    "NODATA",
    "FORMERR",
    "SERVFAIL",
    "NOTFOUND",
    "NOTIMP",
    "REFUSED",
    "BADQUERY",
    "BADNAME",
    "BADFAMILY",
    "BADRESP",
    "CONNREFUSED",
    "TIMEOUT",
    "EOF",
    "FILE",
    "NOMEM",
    "DESTRUCTION",
    "BADSTR",
    "BADFLAGS",
    "NONAME",
    "BADHINTS",
    "NOTINITIALIZED",
    "LOADIPHLPAPI",
    "ADDRGETNETWORKPARAMS",
    "CANCELLED",
    "promises",
};

// --- Status-only compatibility shims ---
pub export fn sa_node_plugin_cluster_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    var primary_ptr: ?[*]const u8 = null;
    var primary_len: u64 = 0;
    if (clusterPrimarySnapshotJson(&primary_ptr, &primary_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(primary_ptr, primary_len);

    out.appendSlice("{\"module\":\"cluster\",\"supported\":true,\"mode\":\"top-level-native-cluster-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &cluster_export_names) catch return fail();
    out.appendSlice(",\"isPrimary\":true,\"isMaster\":true,\"isWorker\":false,\"schedulingPolicy\":") catch return fail();
    out.writer().print("{d}", .{cluster_scheduling_policy}) catch return fail();
    out.appendSlice(",\"constants\":{\"SCHED_NONE\":1,\"SCHED_RR\":2},\"settings\":") catch return fail();
    out.appendSlice((primary_ptr orelse return fail())[0..@intCast(primary_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"setupPrimary\":true,\"setupMaster\":true,\"fork\":true,\"disconnect\":false,\"WorkerClass\":false,\"workerProperty\":false,\"workersMap\":false,\"send\":true,\"kill\":true,\"wait\":true,\"sharedServerHandles\":false,\"internalSerialization\":false},\"capabilities\":[\"setupPrimary and setupMaster config metadata\",\"fork subprocess worker handles\",\"stdin/stdout message exchange\",\"worker pid/alive/connected snapshot\",\"worker disconnect/kill/wait/free\"],\"limitations\":[\"no JavaScript EventEmitter primary or worker object model\",\"no shared libuv server handle distribution\",\"no Node internal IPC framing or structured serialization\",\"workers and worker are exposed as metadata only, not live JavaScript objects\",\"disconnect is only available on explicit native worker handles, not as a top-level cluster object method\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_cluster_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &cluster_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_cluster_primary_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return clusterPrimarySnapshotJson(out_ptr, out_len);
}

pub export fn sa_node_plugin_cluster_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"isPrimary\":{\"supported\":true,\"mode\":\"always true in the primary native process\"},\"isMaster\":{\"supported\":true,\"mode\":\"legacy alias of isPrimary\"},\"isWorker\":{\"supported\":true,\"mode\":\"always false in the primary native process\"},\"SCHED_NONE\":{\"supported\":true,\"value\":1},\"SCHED_RR\":{\"supported\":true,\"value\":2},\"schedulingPolicy\":{\"supported\":true,\"mode\":\"native stored policy metadata\"},\"setupPrimary\":{\"supported\":true,\"mode\":\"store exec/args/cwd/env metadata for native forks\"},\"setupMaster\":{\"supported\":true,\"mode\":\"alias of setupPrimary for legacy cluster API naming\"},\"fork\":{\"supported\":true,\"mode\":\"spawn subprocess worker handle with stdin/stdout pipes\"},\"settings\":{\"supported\":true,\"mode\":\"returns stored primary config snapshot JSON\"},\"Worker\":{\"supported\":false,\"reason\":\"JavaScript Worker class construction and EventEmitter prototype semantics are not modeled\"},\"worker\":{\"supported\":false,\"reason\":\"current-process worker object identity is not modeled\"},\"workers\":{\"supported\":false,\"reason\":\"live worker registry object map is not modeled\"},\"disconnect\":{\"supported\":false,\"reason\":\"top-level cluster disconnect across worker registry is not modeled; explicit worker handles can disconnect individually\"},\"send\":{\"supported\":true,\"mode\":\"stdin write on explicit worker handle\"},\"receiveMessage\":{\"supported\":true,\"mode\":\"stdout read on explicit worker handle\"},\"sharedServerHandles\":{\"supported\":false,\"reason\":\"shared libuv server distribution is not modeled\"},\"internalSerialization\":{\"supported\":false,\"reason\":\"Node cluster internal IPC framing and advancedHandle passing are not modeled\"}}");
}

pub export fn sa_node_plugin_domain_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"domain\",\"supported\":true,\"mode\":\"top-level-native-domain-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &domain_export_names) catch return fail();
    out.appendSlice(",\"active\":") catch return fail();
    if (domain_active) |active| {
        var active_ptr: ?[*]const u8 = null;
        var active_len: u64 = 0;
        if (domainSnapshotJson(active, &active_ptr, &active_len) != 0) return fail();
        defer _ = base.sa_node_plugin_free_buffer(active_ptr, active_len);
        out.appendSlice((active_ptr orelse return fail())[0..@intCast(active_len)]) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"stackDepth\":") catch return fail();
    out.writer().print("{d}", .{domain_stack.items.len}) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"Domain\":true,\"create\":true,\"createDomain\":true,\"active\":true,\"_stack\":true,\"enter\":true,\"exit\":true,\"dispose\":true,\"bind\":false,\"intercept\":false,\"run\":false,\"disposeEvent\":false,\"asyncPropagation\":false},\"capabilities\":[\"create native domain handles\",\"enter and exit explicit domain stack\",\"member registry add/remove/count\",\"active domain snapshot and stack-depth metadata\",\"snapshot, dispose, and free\"],\"limitations\":[\"no JavaScript EventEmitter inheritance or process.domain mutation hooks\",\"no bind/intercept callback wrapping or run() callback execution helper\",\"no uncaught exception capture callback integration\",\"no async_hooks, Promise, or timer callback domain propagation\",\"_stack is exposed as metadata rather than a live JavaScript array\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_domain_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &domain_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_domain_active_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (domain_active) |active| return domainSnapshotJson(active, out_ptr, out_len);
    return writeOwnedString(out_ptr, out_len, "null");
}

pub export fn sa_node_plugin_domain_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"Domain\":{\"supported\":true,\"mode\":\"native domain handle\",\"operations\":[\"add\",\"remove\",\"enter\",\"exit\",\"dispose\",\"snapshot\",\"free\"]},\"create\":{\"supported\":true,\"mode\":\"allocate native domain handle\"},\"createDomain\":{\"supported\":true,\"mode\":\"alias of create\"},\"active\":{\"supported\":true,\"mode\":\"returns current active native domain snapshot or null\"},\"_stack\":{\"supported\":true,\"mode\":\"stack-depth metadata via status and domain snapshots\",\"limitations\":[\"not a live JavaScript array export\",\"entries are explicit native handles only\"]},\"bind\":{\"supported\":false,\"reason\":\"callback wrapping requires JavaScript function objects and invocation hooks\"},\"intercept\":{\"supported\":false,\"reason\":\"error-first callback interception requires JavaScript callback wrappers\"},\"run\":{\"supported\":false,\"reason\":\"run() callback execution semantics are not modeled without a JS runtime\"},\"EventEmitterInheritance\":{\"supported\":false,\"reason\":\"Domain is not exposed as a JavaScript EventEmitter subclass\"},\"uncaughtExceptionCapture\":{\"supported\":false,\"reason\":\"process uncaught exception capture integration is not modeled\"},\"asyncPropagation\":{\"supported\":false,\"reason\":\"automatic propagation across async_hooks, Promise, and timer callbacks is not modeled\"}}");
}

const module_builtin_modules = [_][]const u8{
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "dtls",
    "events",
    "ffi",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "quic",
    "readline",
    "repl",
    "sea",
    "sqlite",
    "stream",
    "string_decoder",
    "sys",
    "test",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "vfs",
    "wasi",
    "worker_threads",
    "zlib",
};

const module_export_names = [_][]const u8{
    "builtinModules",
    "constants",
    "enableCompileCache",
    "findPackageJSON",
    "flushCompileCache",
    "getCompileCacheDir",
    "getSourceMapsSupport",
    "setSourceMapsSupport",
    "globalPaths",
    "isBuiltin",
    "createRequire",
    "register",
    "registerHooks",
    "runMain",
    "syncBuiltinESMExports",
    "stripTypeScriptTypes",
    "findSourceMap",
    "SourceMap",
};

var module_compile_cache_enabled = false;
var module_compile_cache_dir: ?[]u8 = null;
var module_source_maps_initialized = false;
var module_source_maps_enabled = false;
var module_source_maps_node_modules = false;
var module_source_maps_generated_code = false;

fn moduleInitSourceMapsSupport() void {
    if (module_source_maps_initialized) return;
    module_source_maps_initialized = true;
    module_source_maps_enabled = nodeOptionsHasFlag("--enable-source-maps");
    module_source_maps_node_modules = false;
    module_source_maps_generated_code = false;
}

fn moduleCompileCacheDisabled() bool {
    return envTruthy("NODE_DISABLE_COMPILE_CACHE");
}

fn moduleCompileCacheStatusConstantsJson() []const u8 {
    return "{\"FAILED\":0,\"ENABLED\":1,\"ALREADY_ENABLED\":2,\"DISABLED\":3}";
}

fn moduleResolveCompileCacheDir(allocator: std.mem.Allocator) ![]u8 {
    if (module_compile_cache_dir) |dir| return cloneOrNullTerminatedDup(allocator, dir);
    const resolved = if (std.posix.getenv("NODE_COMPILE_CACHE")) |configured|
        try allocator.dupe(u8, configured)
    else if (std.posix.getenv("XDG_CACHE_HOME")) |xdg|
        try std.fs.path.join(allocator, &[_][]const u8{ xdg, "sa_plugin_node", "compile-cache" })
    else if (std.posix.getenv("HOME")) |home|
        try std.fs.path.join(allocator, &[_][]const u8{ home, ".cache", "sa_plugin_node", "compile-cache" })
    else
        try allocator.dupe(u8, "/tmp/sa_plugin_node-compile-cache");
    module_compile_cache_dir = resolved;
    return cloneOrNullTerminatedDup(allocator, resolved);
}

fn moduleEnsureDir(path: []const u8) !void {
    if (std.fs.path.isAbsolute(path)) {
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        const sub = std.mem.trimLeft(u8, path, "/");
        if (sub.len == 0) return;
        try root.makePath(sub);
        return;
    }
    try std.fs.cwd().makePath(path);
}

fn moduleWriteCompileCacheResultJson(status_code: u64, directory: ?[]const u8, message: ?[]const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"status\":") catch return fail();
    out.writer().print("{d}", .{status_code}) catch return fail();
    out.appendSlice(",\"directory\":") catch return fail();
    if (directory) |dir| {
        appendJsonString(&out, dir) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"message\":") catch return fail();
    if (message) |text| {
        appendJsonString(&out, text) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn moduleWriteSourceMapsSupportJson(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    moduleInitSourceMapsSupport();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"enabled\":") catch return fail();
    out.appendSlice(if (module_source_maps_enabled) "true" else "false") catch return fail();
    out.appendSlice(",\"nodeModules\":") catch return fail();
    out.appendSlice(if (module_source_maps_node_modules) "true" else "false") catch return fail();
    out.appendSlice(",\"generatedCode\":") catch return fail();
    out.appendSlice(if (module_source_maps_generated_code) "true" else "false") catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

fn moduleAppendGlobalPaths(out: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
    try out.append('[');
    var first = true;
    if (std.posix.getenv("NODE_PATH")) |node_path| {
        const delimiter: u8 = if (builtin.os.tag == .windows) ';' else ':';
        var parts = std.mem.splitScalar(u8, node_path, delimiter);
        while (parts.next()) |part| {
            if (part.len == 0) continue;
            try appendJsonFieldSeparator(out, &first);
            try appendJsonString(out, part);
        }
    }
    if (std.posix.getenv("HOME")) |home| {
        const user_modules = try std.fs.path.join(allocator, &[_][]const u8{ home, ".node_modules" });
        defer allocator.free(user_modules);
        try appendJsonFieldSeparator(out, &first);
        try appendJsonString(out, user_modules);
        const user_libraries = try std.fs.path.join(allocator, &[_][]const u8{ home, ".node_libraries" });
        defer allocator.free(user_libraries);
        try appendJsonFieldSeparator(out, &first);
        try appendJsonString(out, user_libraries);
    }
    try appendJsonFieldSeparator(out, &first);
    try appendJsonString(out, "/usr/local/lib/node");
    try out.append(']');
}

fn moduleAbsolutePath(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(input)) return allocator.dupe(u8, input);
    const cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);
    return std.fs.path.join(allocator, &[_][]const u8{ cwd, input });
}

fn moduleFindPackageJsonPath(allocator: std.mem.Allocator, input: []const u8) !?[]u8 {
    const absolute = try moduleAbsolutePath(allocator, input);
    defer allocator.free(absolute);

    var current = blk: {
        if (std.fs.openDirAbsolute(absolute, .{})) |opened_dir| {
            var dir = opened_dir;
            dir.close();
            break :blk try allocator.dupe(u8, absolute);
        } else |_| {}
        const dirname = std.fs.path.dirname(absolute) orelse return null;
        break :blk try allocator.dupe(u8, dirname);
    };
    errdefer allocator.free(current);

    while (true) {
        const candidate = try std.fs.path.join(allocator, &[_][]const u8{ current, "package.json" });
        errdefer allocator.free(candidate);
        if (std.fs.accessAbsolute(candidate, .{})) |_| {
            const real = std.fs.realpathAlloc(allocator, candidate) catch candidate;
            if (real.ptr != candidate.ptr) allocator.free(candidate);
            allocator.free(current);
            return real;
        } else |_| {}
        const parent = std.fs.path.dirname(current) orelse break;
        if (std.mem.eql(u8, parent, current)) break;
        const next = try allocator.dupe(u8, parent);
        allocator.free(current);
        current = next;
    }
    allocator.free(current);
    return null;
}

pub export fn sa_node_plugin_module_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var source_maps_ptr: ?[*]const u8 = null;
    var source_maps_len: u64 = 0;
    if (moduleWriteSourceMapsSupportJson(&source_maps_ptr, &source_maps_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(source_maps_ptr, source_maps_len);
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"module\",\"supported\":true,\"mode\":\"top-level-native-module-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &module_export_names) catch return fail();
    out.appendSlice(",\"builtinModules\":") catch return fail();
    appendStringArray(&out, &module_builtin_modules) catch return fail();
    out.appendSlice(",\"constants\":{\"compileCacheStatus\":") catch return fail();
    out.appendSlice(moduleCompileCacheStatusConstantsJson()) catch return fail();
    out.appendSlice("},\"compileCache\":{\"enabled\":") catch return fail();
    out.appendSlice(if (module_compile_cache_enabled) "true" else "false") catch return fail();
    out.appendSlice(",\"disabledByEnv\":") catch return fail();
    out.appendSlice(if (moduleCompileCacheDisabled()) "true" else "false") catch return fail();
    out.appendSlice(",\"directory\":") catch return fail();
    if (module_compile_cache_dir) |dir| {
        appendJsonString(&out, dir) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice("},\"sourceMapsSupport\":") catch return fail();
    out.appendSlice((source_maps_ptr orelse return fail())[0..@intCast(source_maps_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"findPackageJSON\":true,\"builtinModules\":true,\"globalPaths\":true,\"isBuiltin\":true,\"enableCompileCache\":true,\"flushCompileCache\":true,\"getCompileCacheDir\":true,\"getSourceMapsSupport\":true,\"setSourceMapsSupport\":true,\"createRequire\":false,\"register\":false,\"registerHooks\":false,\"runMain\":false,\"syncBuiltinESMExports\":false,\"findSourceMap\":false,\"SourceMap\":false,\"stripTypeScriptTypes\":false},\"limitations\":[\"no CommonJS or ESM loader execution semantics\",\"no createRequire/register/registerHooks/runMain integration\",\"no SourceMap object model or findSourceMap cache\",\"stripTypeScriptTypes is not yet modeled; use external tooling before feeding TypeScript to this plugin\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_module_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &module_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_module_builtin_modules_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &module_builtin_modules) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_module_constants_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"compileCacheStatus\":{\"FAILED\":0,\"ENABLED\":1,\"ALREADY_ENABLED\":2,\"DISABLED\":3}}");
}

pub export fn sa_node_plugin_module_global_paths_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    moduleAppendGlobalPaths(&out, std.heap.page_allocator) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_module_is_builtin(name_ptr: ?[*]const u8, name_len: u64, out_bool: ?*u64) u32 {
    const name = if (name_len == 0) "" else (name_ptr orelse return fail())[0..name_len];
    const bare = if (std.mem.startsWith(u8, name, "node:")) name[5..] else name;
    for (module_builtin_modules) |entry| {
        if (std.mem.eql(u8, bare, entry)) {
            out_bool.?.* = 1;
            return 0;
        }
    }
    out_bool.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_module_find_package_json(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const input = if (path_len == 0) "." else (path_ptr orelse return fail())[0..path_len];
    const found = moduleFindPackageJsonPath(std.heap.page_allocator, input) catch return fail();
    defer if (found) |path| std.heap.page_allocator.free(path);
    if (found) |path| {
        var out = std.ArrayList(u8).init(std.heap.page_allocator);
        defer out.deinit();
        appendJsonString(&out, path) catch return fail();
        return writeOwnedBytes(out_ptr, out_len, out.items);
    }
    return writeOwnedString(out_ptr, out_len, "null");
}

pub export fn sa_node_plugin_module_enable_compile_cache_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (moduleCompileCacheDisabled()) return moduleWriteCompileCacheResultJson(3, module_compile_cache_dir, "disabled by NODE_DISABLE_COMPILE_CACHE", out_ptr, out_len);
    if (module_compile_cache_enabled) return moduleWriteCompileCacheResultJson(2, module_compile_cache_dir, "already enabled", out_ptr, out_len);
    const dir = moduleResolveCompileCacheDir(std.heap.page_allocator) catch return fail();
    defer std.heap.page_allocator.free(dir);
    moduleEnsureDir(dir) catch return moduleWriteCompileCacheResultJson(0, dir, "failed to create compile cache directory", out_ptr, out_len);
    module_compile_cache_enabled = true;
    return moduleWriteCompileCacheResultJson(1, dir, null, out_ptr, out_len);
}

pub export fn sa_node_plugin_module_flush_compile_cache_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (!module_compile_cache_enabled) return writeOwnedString(out_ptr, out_len, "{\"flushed\":false,\"directory\":null,\"entries\":0,\"reason\":\"compile cache not enabled\"}");
    return moduleWriteCompileCacheResultJson(1, module_compile_cache_dir, "flush is a metadata-only no-op for this native module facade", out_ptr, out_len);
}

pub export fn sa_node_plugin_module_get_compile_cache_dir_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (!module_compile_cache_enabled) return writeOwnedString(out_ptr, out_len, "null");
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendJsonString(&out, module_compile_cache_dir orelse return fail()) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_module_get_source_maps_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return moduleWriteSourceMapsSupportJson(out_ptr, out_len);
}

pub export fn sa_node_plugin_module_set_source_maps_support(enabled: u64, node_modules: u64, generated_code: u64) u32 {
    module_source_maps_initialized = true;
    module_source_maps_enabled = enabled != 0;
    module_source_maps_node_modules = node_modules != 0;
    module_source_maps_generated_code = generated_code != 0;
    return 0;
}

pub export fn sa_node_plugin_module_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"createRequire\":{\"supported\":false,\"reason\":\"CommonJS loader instances are not modeled\"},\"register\":{\"supported\":false,\"reason\":\"ESM loader registration hooks are not modeled\"},\"registerHooks\":{\"supported\":false,\"reason\":\"ESM hook chaining is not modeled\"},\"runMain\":{\"supported\":false,\"reason\":\"Node main-module bootstrap is not modeled\"},\"syncBuiltinESMExports\":{\"supported\":false,\"reason\":\"builtin ESM/CJS export synchronization is not modeled\"},\"findSourceMap\":{\"supported\":false,\"reason\":\"source map cache lookup is not modeled\"},\"SourceMap\":{\"supported\":false,\"reason\":\"SourceMap object construction is not modeled\"},\"stripTypeScriptTypes\":{\"supported\":false,\"reason\":\"TypeScript syntax stripping is not yet modeled in this native facade\"}}");
}

pub export fn sa_node_plugin_module_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var source_maps_ptr: ?[*]const u8 = null;
    var source_maps_len: u64 = 0;
    if (moduleWriteSourceMapsSupportJson(&source_maps_ptr, &source_maps_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(source_maps_ptr, source_maps_len);
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"builtinModuleModel\":\"builtinModules is exported as a native static name list\",\"compileCacheModel\":{\"enabled\":") catch return fail();
    out.appendSlice(if (module_compile_cache_enabled) "true" else "false") catch return fail();
    out.appendSlice(",\"disabledByEnv\":") catch return fail();
    out.appendSlice(if (moduleCompileCacheDisabled()) "true" else "false") catch return fail();
    out.appendSlice(",\"directory\":") catch return fail();
    if (module_compile_cache_dir) |dir| {
        appendJsonString(&out, dir) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice("},\"sourceMapsSupport\":") catch return fail();
    out.appendSlice((source_maps_ptr orelse return fail())[0..@intCast(source_maps_len)]) catch return fail();
    out.appendSlice(",\"objectModel\":\"not-modeled for CommonJS or ESM loader execution, SourceMap class instances, or main-module bootstrap semantics\"}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

const inspector_export_names = [_][]const u8{
    "open",
    "close",
    "url",
    "waitForDebugger",
    "console",
    "Session",
    "Network",
    "NetworkResources",
    "DOMStorage",
};

const InspectorConfigSnapshot = struct {
    allocator: std.mem.Allocator,
    enabled: bool,
    allowed: bool,
    host: []const u8,
    port: u16,
    flag: ?[]const u8,
    kind: ?[]const u8,
    wait_for_debugger: bool,
    break_first_line: bool,

    fn deinit(self: *InspectorConfigSnapshot) void {
        self.allocator.free(self.host);
        if (self.flag) |flag| self.allocator.free(flag);
    }
};

fn inspectorAllowedInternal() bool {
    return !permissionsIsEnabledInternal() or nodeOptionsHasFlag("--allow-inspector");
}

fn inspectorParsePort(text: []const u8) ?u16 {
    if (text.len == 0) return null;
    const port = std.fmt.parseInt(u16, text, 10) catch return null;
    return port;
}

fn inspectorApplyEndpointValue(snapshot: *InspectorConfigSnapshot, value: []const u8) void {
    if (value.len == 0) return;
    if (inspectorParsePort(value)) |port| {
        snapshot.port = port;
        return;
    }

    if (value[0] == '[') {
        if (std.mem.indexOfScalar(u8, value, ']')) |close_index| {
            snapshot.host = value[1..close_index];
            if (close_index + 1 < value.len and value[close_index + 1] == ':') {
                if (inspectorParsePort(value[close_index + 2 ..])) |port| snapshot.port = port;
            }
            return;
        }
    }

    const colon_count = std.mem.count(u8, value, ":");
    if (colon_count == 1) {
        if (std.mem.lastIndexOfScalar(u8, value, ':')) |colon_index| {
            const host = value[0..colon_index];
            const port_text = value[colon_index + 1 ..];
            if (host.len != 0) {
                if (inspectorParsePort(port_text)) |port| {
                    snapshot.host = host;
                    snapshot.port = port;
                    return;
                }
            }
        }
    }

    snapshot.host = value;
}

fn inspectorConfigSnapshot(allocator: std.mem.Allocator) !InspectorConfigSnapshot {
    var config = try commandLineOptionsReadConfig(allocator);
    defer config.deinit();

    var snapshot = InspectorConfigSnapshot{
        .allocator = allocator,
        .enabled = config.inspect_flags.items.len != 0,
        .allowed = inspectorAllowedInternal(),
        .host = try allocator.dupe(u8, "127.0.0.1"),
        .port = 9229,
        .flag = null,
        .kind = null,
        .wait_for_debugger = false,
        .break_first_line = false,
    };
    errdefer snapshot.deinit();
    if (config.inspect_flags.items.len == 0) return snapshot;

    const flag = config.inspect_flags.items[config.inspect_flags.items.len - 1];
    snapshot.flag = try allocator.dupe(u8, flag);
    if (std.mem.startsWith(u8, flag, "--inspect-brk")) {
        snapshot.kind = "inspect-brk";
        snapshot.wait_for_debugger = true;
        snapshot.break_first_line = true;
    } else if (std.mem.startsWith(u8, flag, "--inspect-wait")) {
        snapshot.kind = "inspect-wait";
        snapshot.wait_for_debugger = true;
    } else {
        snapshot.kind = "inspect";
    }

    if (std.mem.indexOfScalar(u8, flag, '=')) |eq_index| {
        const endpoint = flag[eq_index + 1 ..];
        var host = snapshot.host;
        var port = snapshot.port;
        var temp = InspectorConfigSnapshot{
            .allocator = allocator,
            .enabled = snapshot.enabled,
            .allowed = snapshot.allowed,
            .host = host,
            .port = port,
            .flag = snapshot.flag,
            .kind = snapshot.kind,
            .wait_for_debugger = snapshot.wait_for_debugger,
            .break_first_line = snapshot.break_first_line,
        };
        inspectorApplyEndpointValue(&temp, endpoint);
        host = temp.host;
        port = temp.port;
        if (host.ptr != snapshot.host.ptr) {
            const owned_host = try allocator.dupe(u8, host);
            snapshot.allocator.free(snapshot.host);
            snapshot.host = owned_host;
        }
        snapshot.port = port;
    }
    return snapshot;
}

pub export fn sa_node_plugin_inspector_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var snapshot = inspectorConfigSnapshot(std.heap.page_allocator) catch return fail();
    defer snapshot.deinit();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"inspector\",\"supported\":true,\"mode\":\"top-level-config-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &inspector_export_names) catch return fail();
    out.appendSlice(",\"enabled\":") catch return fail();
    out.appendSlice(if (snapshot.enabled) "true" else "false") catch return fail();
    out.appendSlice(",\"allowed\":") catch return fail();
    out.appendSlice(if (snapshot.allowed) "true" else "false") catch return fail();
    out.appendSlice(",\"permissionModelEnabled\":") catch return fail();
    out.appendSlice(if (permissionsIsEnabledInternal()) "true" else "false") catch return fail();
    out.appendSlice(",\"permissionAuditMode\":") catch return fail();
    out.appendSlice(if (permissionsIsAuditModeInternal()) "true" else "false") catch return fail();
    out.appendSlice(",\"configuredHost\":") catch return fail();
    appendJsonString(&out, snapshot.host) catch return fail();
    out.appendSlice(",\"configuredPort\":") catch return fail();
    out.writer().print("{d}", .{snapshot.port}) catch return fail();
    out.appendSlice(",\"waitForDebugger\":") catch return fail();
    out.appendSlice(if (snapshot.wait_for_debugger) "true" else "false") catch return fail();
    out.appendSlice(",\"breakFirstLine\":") catch return fail();
    out.appendSlice(if (snapshot.break_first_line) "true" else "false") catch return fail();
    out.appendSlice(",\"featureSupport\":{\"urlMetadata\":true,\"open\":false,\"close\":false,\"waitForDebugger\":false,\"console\":false,\"Session\":false,\"Network\":false,\"NetworkResources\":false,\"DOMStorage\":false},\"limitations\":[\"live inspector activation and the Chrome DevTools Protocol are not modeled\",\"url metadata is derived from host CLI flags only and does not imply an active backend\",\"Session, console, Network, NetworkResources, and DOMStorage object models require a JavaScript runtime\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_inspector_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &inspector_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_inspector_is_enabled(out_bool: ?*u64) u32 {
    var snapshot = inspectorConfigSnapshot(std.heap.page_allocator) catch return fail();
    defer snapshot.deinit();
    out_bool.?.* = if (snapshot.enabled) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_inspector_is_allowed(out_bool: ?*u64) u32 {
    out_bool.?.* = if (inspectorAllowedInternal()) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_inspector_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var config = commandLineOptionsReadConfig(allocator) catch return fail();
    defer config.deinit();
    var snapshot = inspectorConfigSnapshot(allocator) catch return fail();
    defer snapshot.deinit();

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"enabled\":") catch return fail();
    out.appendSlice(if (snapshot.enabled) "true" else "false") catch return fail();
    out.appendSlice(",\"allowed\":") catch return fail();
    out.appendSlice(if (snapshot.allowed) "true" else "false") catch return fail();
    out.appendSlice(",\"inspectFlags\":") catch return fail();
    appendOwnedStringArray(&out, config.inspect_flags.items) catch return fail();
    out.appendSlice(",\"selectedFlag\":") catch return fail();
    if (snapshot.flag) |flag| {
        appendJsonString(&out, flag) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"kind\":") catch return fail();
    if (snapshot.kind) |kind| {
        appendJsonString(&out, kind) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"host\":") catch return fail();
    appendJsonString(&out, snapshot.host) catch return fail();
    out.appendSlice(",\"port\":") catch return fail();
    out.writer().print("{d}", .{snapshot.port}) catch return fail();
    out.appendSlice(",\"waitForDebugger\":") catch return fail();
    out.appendSlice(if (snapshot.wait_for_debugger) "true" else "false") catch return fail();
    out.appendSlice(",\"breakFirstLine\":") catch return fail();
    out.appendSlice(if (snapshot.break_first_line) "true" else "false") catch return fail();
    out.appendSlice(",\"permissionModelEnabled\":") catch return fail();
    out.appendSlice(if (permissionsIsEnabledInternal()) "true" else "false") catch return fail();
    out.appendSlice(",\"permissionAuditMode\":") catch return fail();
    out.appendSlice(if (permissionsIsAuditModeInternal()) "true" else "false") catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_inspector_url_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var snapshot = inspectorConfigSnapshot(std.heap.page_allocator) catch return fail();
    defer snapshot.deinit();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"active\":false,\"configured\":") catch return fail();
    out.appendSlice(if (snapshot.enabled) "true" else "false") catch return fail();
    out.appendSlice(",\"url\":null,\"host\":") catch return fail();
    if (snapshot.enabled) {
        appendJsonString(&out, snapshot.host) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"port\":") catch return fail();
    if (snapshot.enabled) {
        out.writer().print("{d}", .{snapshot.port}) catch return fail();
    } else {
        out.appendSlice("null") catch return fail();
    }
    out.appendSlice(",\"reason\":\"live WebSocket inspector URLs require an active backend session id; this facade only reports host CLI configuration\"}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_inspector_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"open\":{\"supported\":false,\"reason\":\"activating a live inspector backend is not modeled\"},\"close\":{\"supported\":false,\"reason\":\"closing a live inspector backend is not modeled\"},\"url\":{\"supported\":true,\"mode\":\"configured host/port metadata only\",\"liveBackendRequired\":true},\"waitForDebugger\":{\"supported\":false,\"reason\":\"blocking for debugger attach requires a live inspector backend\"},\"console\":{\"supported\":false,\"reason\":\"inspector console frontend hooks are not modeled\"},\"Session\":{\"supported\":false,\"reason\":\"Chrome DevTools Protocol sessions are not modeled\"},\"Network\":{\"supported\":false,\"reason\":\"frontend protocol event emission is not modeled\"},\"NetworkResources\":{\"supported\":false,\"reason\":\"frontend network resource bridging is not modeled\"},\"DOMStorage\":{\"supported\":false,\"reason\":\"frontend DOMStorage protocol event emission is not modeled\"}}");
}

pub export fn sa_node_plugin_http_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var methods_ptr: ?[*]const u8 = null;
    var methods_len: u64 = 0;
    if (sa_node_plugin_http_methods_json(&methods_ptr, &methods_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(methods_ptr, methods_len);

    var status_codes_ptr: ?[*]const u8 = null;
    var status_codes_len: u64 = 0;
    if (sa_node_plugin_http_status_codes_json(&status_codes_ptr, &status_codes_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(status_codes_ptr, status_codes_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"http\",\"supported\":true,\"mode\":\"top-level-native-http1-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &http_export_names) catch return fail();
    out.appendSlice(",\"methods\":") catch return fail();
    out.appendSlice((methods_ptr orelse return fail())[0..@intCast(methods_len)]) catch return fail();
    out.appendSlice(",\"statusCodes\":") catch return fail();
    out.appendSlice((status_codes_ptr orelse return fail())[0..@intCast(status_codes_len)]) catch return fail();
    out.appendSlice(",\"maxHeaderSize\":16384,\"maxIdleHTTPParsers\":") catch return fail();
    out.writer().print("{d}", .{http_max_idle_parsers}) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"request\":true,\"get\":true,\"createServer\":true,\"validateHeaderName\":true,\"validateHeaderValue\":true,\"setMaxIdleHTTPParsers\":true,\"METHODS\":true,\"STATUS_CODES\":true,\"maxHeaderSize\":true,\"ClientRequest\":false,\"IncomingMessage\":false,\"OutgoingMessage\":false,\"Server\":false,\"ServerResponse\":false,\"Agent\":false,\"globalAgent\":false,\"WebSocket\":false},\"capabilities\":[\"HTTP/1 request and get JSON helpers\",\"explicit native client/request/response handles\",\"explicit native server/request/response handles\",\"header validation helpers\",\"HTTP metadata for methods, status codes, and max header size\",\"WebSocket bridge helpers through explicit native handles\"],\"limitations\":[\"no JavaScript ClientRequest, IncomingMessage, OutgoingMessage, Server, or ServerResponse class instances\",\"request and get return completed native response JSON rather than asynchronous event emitter objects\",\"no Agent or globalAgent object model\",\"WebSocket is available through explicit bridge helpers rather than the top-level undici WebSocket class export\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
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

pub export fn sa_node_plugin_http_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &http_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_http_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var methods_ptr: ?[*]const u8 = null;
    var methods_len: u64 = 0;
    if (sa_node_plugin_http_methods_json(&methods_ptr, &methods_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(methods_ptr, methods_len);

    var status_codes_ptr: ?[*]const u8 = null;
    var status_codes_len: u64 = 0;
    if (sa_node_plugin_http_status_codes_json(&status_codes_ptr, &status_codes_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(status_codes_ptr, status_codes_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"maxHeaderSize\":16384,\"maxIdleHTTPParsers\":") catch return fail();
    out.writer().print("{d}", .{http_max_idle_parsers}) catch return fail();
    out.appendSlice(",\"methods\":") catch return fail();
    out.appendSlice((methods_ptr orelse return fail())[0..@intCast(methods_len)]) catch return fail();
    out.appendSlice(",\"statusCodes\":") catch return fail();
    out.appendSlice((status_codes_ptr orelse return fail())[0..@intCast(status_codes_len)]) catch return fail();
    out.appendSlice(",\"requestModel\":\"one-shot completed-response JSON or explicit native client handles\",\"serverModel\":\"explicit native server/request/response handles\",\"agentModel\":\"not-modeled\",\"websocketModel\":\"explicit bridge handle helpers outside the top-level WebSocket class export\"}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_http_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"_connectionListener\":{\"supported\":false,\"reason\":\"Node internal connection listener hooks are not modeled as a public JS callback export\"},\"METHODS\":{\"supported\":true,\"mode\":\"static method name array JSON\"},\"STATUS_CODES\":{\"supported\":true,\"mode\":\"static status code catalog JSON\"},\"request\":{\"supported\":true,\"mode\":\"one-shot completed-response JSON helper and explicit native client/request handles\",\"limitations\":[\"no JavaScript ClientRequest event emitter object\",\"no callback scheduling or implicit streaming lifecycle\"]},\"get\":{\"supported\":true,\"mode\":\"one-shot completed-response JSON helper\",\"limitations\":[\"returns native response JSON rather than a JavaScript request object\"]},\"createServer\":{\"supported\":true,\"mode\":\"explicit native server/request/response handles\",\"limitations\":[\"no JavaScript Server event emitter object\",\"accept/respond flow is explicit through native handles\"]},\"validateHeaderName\":{\"supported\":true,\"mode\":\"native RFC token validation\"},\"validateHeaderValue\":{\"supported\":true,\"mode\":\"native visible-ASCII and tab validation\"},\"setMaxIdleHTTPParsers\":{\"supported\":true,\"mode\":\"native stored parser-pool limit metadata\"},\"maxHeaderSize\":{\"supported\":true,\"mode\":\"static native max header size metadata\"},\"Agent\":{\"supported\":false,\"reason\":\"JavaScript Agent pooling objects are not modeled\"},\"globalAgent\":{\"supported\":false,\"reason\":\"global Agent object identity is not modeled\"},\"ClientRequest\":{\"supported\":false,\"reason\":\"JavaScript ClientRequest class instances are not modeled\"},\"IncomingMessage\":{\"supported\":false,\"reason\":\"JavaScript IncomingMessage class instances are not modeled\"},\"OutgoingMessage\":{\"supported\":false,\"reason\":\"JavaScript OutgoingMessage class instances are not modeled\"},\"Server\":{\"supported\":false,\"reason\":\"JavaScript Server class instances are not modeled\"},\"ServerResponse\":{\"supported\":false,\"reason\":\"JavaScript ServerResponse class instances are not modeled\"},\"WebSocket\":{\"supported\":false,\"reason\":\"the top-level undici WebSocket class export is not modeled; use explicit native WebSocket bridge helpers instead\"}}");
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
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"https\",\"supported\":true,\"mode\":\"top-level-native-https-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &https_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"request\":true,\"get\":true,\"Agent\":false,\"globalAgent\":false,\"Server\":false,\"createServer\":false},\"capabilities\":[\"HTTPS request and get one-shot JSON helpers\",\"TLS-backed client requests through the HTTP client bridge\"],\"limitations\":[\"no JavaScript Agent, globalAgent, or Server object model\",\"no HTTPS createServer listener support at the top-level facade\",\"request and get return completed native response JSON rather than asynchronous ClientRequest objects\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_https_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &https_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_https_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"requestModel\":\"one-shot completed-response JSON helpers\",\"transport\":\"HTTP client bridge over native TLS when available in the build\",\"agentModel\":\"not-modeled\",\"serverModel\":\"not-modeled at the https top-level facade\"}");
}

pub export fn sa_node_plugin_https_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"request\":{\"supported\":true,\"mode\":\"one-shot completed-response JSON helper over the native HTTP/TLS bridge\",\"limitations\":[\"no JavaScript ClientRequest event emitter object\",\"no callback scheduling or streaming event lifecycle\"]},\"get\":{\"supported\":true,\"mode\":\"one-shot completed-response JSON helper over the native HTTP/TLS bridge\",\"limitations\":[\"returns native response JSON rather than a JavaScript request object\"]},\"Agent\":{\"supported\":false,\"reason\":\"JavaScript HTTPS Agent pooling objects are not modeled\"},\"globalAgent\":{\"supported\":false,\"reason\":\"global HTTPS Agent object identity is not modeled\"},\"Server\":{\"supported\":false,\"reason\":\"JavaScript HTTPS Server class instances are not modeled\"},\"createServer\":{\"supported\":false,\"reason\":\"HTTPS server listener and JavaScript event-emitter semantics are not modeled at the top-level facade\"}}");
}

pub export fn sa_node_plugin_http2_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var defaults_ptr: ?[*]const u8 = null;
    var defaults_len: u64 = 0;
    if (sa_node_plugin_http2_get_default_settings_json(&defaults_ptr, &defaults_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(defaults_ptr, defaults_len);

    var sensitive_ptr: ?[*]const u8 = null;
    var sensitive_len: u64 = 0;
    if (sa_node_plugin_http2_sensitive_headers(&sensitive_ptr, &sensitive_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(sensitive_ptr, sensitive_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"http2\",\"supported\":true,\"mode\":\"top-level-native-http2-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &http2_export_names) catch return fail();
    out.appendSlice(",\"nghttp2Available\":") catch return fail();
    out.appendSlice(if (loadNghttp2Api() != null) "true" else "false") catch return fail();
    out.appendSlice(",\"defaultSettings\":") catch return fail();
    out.appendSlice((defaults_ptr orelse return fail())[0..@intCast(defaults_len)]) catch return fail();
    out.appendSlice(",\"sensitiveHeaders\":") catch return fail();
    out.appendSlice((sensitive_ptr orelse return fail())[0..@intCast(sensitive_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"connect\":true,\"constants\":true,\"getDefaultSettings\":true,\"getPackedSettings\":true,\"getUnpackedSettings\":true,\"sensitiveHeaders\":true,\"createServer\":false,\"createSecureServer\":false,\"performServerHandshake\":false,\"Http2ServerRequest\":false,\"Http2ServerResponse\":false,\"pushStreams\":false},\"capabilities\":[\"HTTP/2 constants metadata\",\"default settings metadata\",\"packed and unpacked settings helpers\",\"sensitive header metadata\",\"cleartext prior-knowledge client request helper\"],\"limitations\":[\"no server, session, or stream object model\",\"no TLS ALPN or secure HTTP/2 server support\",\"no push streams, priorities, or lifecycle events\",\"connect maps to the explicit h2c client helper rather than a live ClientHttp2Session object\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_http2_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &http2_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_http2_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var defaults_ptr: ?[*]const u8 = null;
    var defaults_len: u64 = 0;
    if (sa_node_plugin_http2_get_default_settings_json(&defaults_ptr, &defaults_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(defaults_ptr, defaults_len);

    var sensitive_ptr: ?[*]const u8 = null;
    var sensitive_len: u64 = 0;
    if (sa_node_plugin_http2_sensitive_headers(&sensitive_ptr, &sensitive_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(sensitive_ptr, sensitive_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"defaultSettings\":") catch return fail();
    out.appendSlice((defaults_ptr orelse return fail())[0..@intCast(defaults_len)]) catch return fail();
    out.appendSlice(",\"sensitiveHeaders\":") catch return fail();
    out.appendSlice((sensitive_ptr orelse return fail())[0..@intCast(sensitive_len)]) catch return fail();
    out.appendSlice(",\"transport\":\"cleartext prior-knowledge h2c client helper\",\"nghttp2Available\":") catch return fail();
    out.appendSlice(if (loadNghttp2Api() != null) "true" else "false") catch return fail();
    out.appendSlice(",\"serverSupport\":false,\"tlsAlpnSupport\":false,\"sessionModel\":\"not-modeled\"}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_http2_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"connect\":{\"supported\":true,\"mode\":\"explicit cleartext h2c client request helper\",\"limitations\":[\"no persistent ClientHttp2Session object\",\"no per-stream lifecycle events\"]},\"constants\":{\"supported\":true,\"mode\":\"static constant catalog JSON\"},\"getDefaultSettings\":{\"supported\":true,\"mode\":\"default settings JSON\"},\"getPackedSettings\":{\"supported\":true,\"mode\":\"RFC wire-format settings encoder\"},\"getUnpackedSettings\":{\"supported\":true,\"mode\":\"RFC wire-format settings decoder\"},\"sensitiveHeaders\":{\"supported\":true,\"mode\":\"static sensitive header metadata\"},\"createServer\":{\"supported\":false,\"reason\":\"HTTP/2 server session and stream object model are not modeled\"},\"createSecureServer\":{\"supported\":false,\"reason\":\"TLS ALPN and secure HTTP/2 server support are not modeled\"},\"performServerHandshake\":{\"supported\":false,\"reason\":\"live server-side handshake state is not modeled\"},\"Http2ServerRequest\":{\"supported\":false,\"reason\":\"JavaScript request object instances are not modeled\"},\"Http2ServerResponse\":{\"supported\":false,\"reason\":\"JavaScript response object instances are not modeled\"},\"pushStreams\":{\"supported\":false,\"reason\":\"HTTP/2 push stream lifecycle is not modeled\"}}");
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
    const allocator = std.heap.page_allocator;

    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    if (ext.sa_node_plugin_tls_default_constants_json(&constants_ptr, &constants_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(constants_ptr, constants_len);

    var ciphers_ptr: ?[*]const u8 = null;
    var ciphers_len: u64 = 0;
    if (ext.sa_node_plugin_tls_get_ciphers_json(&ciphers_ptr, &ciphers_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(ciphers_ptr, ciphers_len);

    var root_ptr: ?[*]const u8 = null;
    var root_len: u64 = 0;
    if (ext.sa_node_plugin_tls_root_certificates_json(&root_ptr, &root_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(root_ptr, root_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"tls\",\"supported\":true,\"mode\":\"top-level-native-tls-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &tls_export_names) catch return fail();
    out.appendSlice(",\"constants\":") catch return fail();
    out.appendSlice((constants_ptr orelse return fail())[0..@intCast(constants_len)]) catch return fail();
    out.appendSlice(",\"ciphers\":") catch return fail();
    out.appendSlice((ciphers_ptr orelse return fail())[0..@intCast(ciphers_len)]) catch return fail();
    out.appendSlice(",\"rootCertificates\":") catch return fail();
    out.appendSlice((root_ptr orelse return fail())[0..@intCast(root_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"getCiphers\":true,\"rootCertificates\":true,\"getCACertificates\":true,\"setDefaultCACertificates\":true,\"convertALPNProtocols\":true,\"createSecureContext\":true,\"connect\":true,\"checkServerIdentity\":false,\"SecureContext\":false,\"TLSSocket\":false,\"Server\":false,\"createServer\":false},\"capabilities\":[\"default TLS constant metadata\",\"native cipher catalog and detailed metadata\",\"native system/default/extra CA certificate snapshots\",\"SecureContext create/snapshot/free handles\",\"TLS client connect/write/read/close plus protocol/cipher/address/timeout/ref metadata\",\"ALPN wire-format conversion helper\"],\"limitations\":[\"no JavaScript TLSSocket, SecureContext, or Server class instances\",\"no HTTPS/TLS server listener object model at the top-level tls facade\",\"checkServerIdentity hostname validation semantics are not modeled as a public top-level helper\",\"connect returns explicit native socket handles rather than JavaScript event-emitter objects\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_tls_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &tls_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_tls_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    if (ext.sa_node_plugin_tls_default_constants_json(&constants_ptr, &constants_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(constants_ptr, constants_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"defaults\":") catch return fail();
    out.appendSlice((constants_ptr orelse return fail())[0..@intCast(constants_len)]) catch return fail();
    out.appendSlice(",\"caModel\":\"native system/default/extra certificate snapshot helpers\",\"secureContextModel\":\"explicit native SecureContext handle\",\"socketModel\":\"explicit native TLS client handle\",\"serverModel\":\"not-modeled at the tls top-level facade\"}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_tls_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"CLIENT_RENEG_LIMIT\":{\"supported\":true,\"mode\":\"static constant metadata value 3\"},\"CLIENT_RENEG_WINDOW\":{\"supported\":true,\"mode\":\"static constant metadata value 600\"},\"DEFAULT_CIPHERS\":{\"supported\":true,\"mode\":\"static default cipher string metadata\"},\"DEFAULT_ECDH_CURVE\":{\"supported\":true,\"mode\":\"static default ECDH curve string metadata\"},\"DEFAULT_MIN_VERSION\":{\"supported\":true,\"mode\":\"static default minimum TLS version metadata\"},\"DEFAULT_MAX_VERSION\":{\"supported\":true,\"mode\":\"static default maximum TLS version metadata\"},\"getCiphers\":{\"supported\":true,\"mode\":\"native cipher list and detailed metadata JSON\"},\"rootCertificates\":{\"supported\":true,\"mode\":\"native system root certificate PEM array JSON snapshot\"},\"getCACertificates\":{\"supported\":true,\"mode\":\"native default/system/bundled/extra CA certificate PEM array JSON snapshot\"},\"setDefaultCACertificates\":{\"supported\":true,\"mode\":\"replace native default CA PEM bundle used by this facade\"},\"convertALPNProtocols\":{\"supported\":true,\"mode\":\"encode JSON protocol array into TLS ALPN wire format\"},\"createSecureContext\":{\"supported\":true,\"mode\":\"explicit native SecureContext handle with snapshot/free helpers\"},\"connect\":{\"supported\":true,\"mode\":\"explicit native TLS client socket handle\",\"limitations\":[\"no JavaScript TLSSocket event emitter object\",\"operations are exposed through explicit native read/write/close/state helpers\"]},\"checkServerIdentity\":{\"supported\":false,\"reason\":\"Node's JavaScript hostname/certificate validation helper is not exposed as a separate top-level ABI helper\"},\"SecureContext\":{\"supported\":false,\"reason\":\"JavaScript SecureContext class instances are not modeled; use explicit native handles instead\"},\"TLSSocket\":{\"supported\":false,\"reason\":\"JavaScript TLSSocket class instances are not modeled; use explicit native handles instead\"},\"Server\":{\"supported\":false,\"reason\":\"JavaScript TLS Server class instances are not modeled\"},\"createServer\":{\"supported\":false,\"reason\":\"TLS server listener and JavaScript event-emitter semantics are not modeled at the top-level facade\"}}");
}

pub export fn sa_node_plugin_dgram_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"dgram\",\"supported\":true,\"mode\":\"top-level-native-dgram-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &dgram_export_names) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"createSocket\":true,\"Socket\":false,\"udp4\":true,\"udp6\":true,\"bind\":true,\"send\":true,\"recv\":true,\"connect\":true,\"disconnect\":true,\"address\":true,\"remoteAddress\":true,\"ref\":true,\"unref\":true,\"hasRef\":true,\"multicast\":true,\"blockList\":true},\"capabilities\":[\"UDP4 and UDP6 socket create/bind/send/recv/close\",\"connected UDP send and disconnect\",\"local and remote address metadata\",\"broadcast, TTL, buffer, queue, and multicast controls\",\"send and receive blocklist filtering\",\"native ref and unref state\"],\"limitations\":[\"no JavaScript Socket EventEmitter class instances\",\"receive and send flows use explicit native socket handles rather than callback events\",\"queue metrics report this plugin's synchronous UDP send model rather than libuv request queues\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_dgram_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &dgram_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_dgram_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"socketModel\":\"explicit native UDP socket handle\",\"families\":[\"udp4\",\"udp6\"],\"queueModel\":\"synchronous send completion with queue size/count reported as 0\",\"blockListModel\":\"copied native send and receive blocklist rules\"}");
}

pub export fn sa_node_plugin_dgram_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"createSocket\":{\"supported\":true,\"mode\":\"allocate explicit native UDP socket handle for udp4 or udp6\"},\"Socket\":{\"supported\":false,\"reason\":\"JavaScript dgram Socket EventEmitter class instances are not modeled\"},\"bind\":{\"supported\":true,\"mode\":\"explicit native bind on UDP socket handle\"},\"send\":{\"supported\":true,\"mode\":\"explicit native sendto or connected send on UDP socket handle\"},\"recv\":{\"supported\":true,\"mode\":\"explicit native recvfrom with host and port outputs\"},\"connect\":{\"supported\":true,\"mode\":\"native UDP connect storing peer on explicit handle\"},\"disconnect\":{\"supported\":true,\"mode\":\"native UDP disconnect on explicit handle\"},\"address\":{\"supported\":true,\"mode\":\"local socket address JSON snapshot\"},\"remoteAddress\":{\"supported\":true,\"mode\":\"connected peer address JSON snapshot\"},\"ref\":{\"supported\":true,\"mode\":\"native has_ref state toggle\"},\"unref\":{\"supported\":true,\"mode\":\"native has_ref state toggle\"},\"hasRef\":{\"supported\":true,\"mode\":\"native has_ref state query\"},\"setBroadcast\":{\"supported\":true,\"mode\":\"sets SO_BROADCAST\"},\"setTTL\":{\"supported\":true,\"mode\":\"sets IPv4 TTL\"},\"setMulticastTTL\":{\"supported\":true,\"mode\":\"sets IPv4 multicast TTL\"},\"setMulticastLoopback\":{\"supported\":true,\"mode\":\"sets IPv4 multicast loopback\"},\"setMulticastInterface\":{\"supported\":true,\"mode\":\"sets IPv4 multicast interface\"},\"setMulticastInterface6\":{\"supported\":true,\"mode\":\"sets IPv6 multicast interface index\"},\"setMulticastHops6\":{\"supported\":true,\"mode\":\"sets IPv6 multicast hops\"},\"setMulticastLoopback6\":{\"supported\":true,\"mode\":\"sets IPv6 multicast loopback\"},\"membership\":{\"supported\":true,\"mode\":\"IPv4 and IPv6 multicast membership controls, including IPv4 source-specific membership\"},\"bufferSizing\":{\"supported\":true,\"mode\":\"native SO_RCVBUF and SO_SNDBUF configuration and queries\"},\"sendQueueMetrics\":{\"supported\":true,\"mode\":\"reports 0 for this synchronous UDP send model\"},\"blockList\":{\"supported\":true,\"mode\":\"native copied send and receive blocklist rules\"}}");
}

pub export fn sa_node_plugin_net_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var auto_select_family: u64 = 0;
    if (ext.sa_node_plugin_net_get_default_auto_select_family(&auto_select_family) != 0) return fail();
    var auto_select_timeout: u64 = 0;
    if (ext.sa_node_plugin_net_get_default_auto_select_family_attempt_timeout(&auto_select_timeout) != 0) return fail();

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"net\",\"supported\":true,\"mode\":\"top-level-native-net-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &net_export_names) catch return fail();
    out.appendSlice(",\"defaults\":{\"autoSelectFamily\":") catch return fail();
    out.appendSlice(if (auto_select_family != 0) "true" else "false") catch return fail();
    out.appendSlice(",\"autoSelectFamilyAttemptTimeout\":") catch return fail();
    out.writer().print("{d}", .{auto_select_timeout}) catch return fail();
    out.appendSlice("},\"featureSupport\":{\"connect\":true,\"createConnection\":true,\"createServer\":true,\"isIP\":true,\"isIPv4\":true,\"isIPv6\":true,\"BlockList\":true,\"SocketAddress\":true,\"getDefaultAutoSelectFamily\":true,\"setDefaultAutoSelectFamily\":true,\"getDefaultAutoSelectFamilyAttemptTimeout\":true,\"setDefaultAutoSelectFamilyAttemptTimeout\":true,\"Server\":false,\"Socket\":false,\"Stream\":false,\"_createServerHandle\":false,\"_normalizeArgs\":false},\"capabilities\":[\"TCP and Unix socket connect/listen/accept/read/write/end helpers\",\"socket and server address, timeout, buffer, ref, readyState, and byte-counter metadata\",\"SocketAddress and BlockList native handles\",\"TCP connect blocklist filtering and createConnection/createServer convenience helpers\",\"default auto-select-family setting metadata and setters\"],\"limitations\":[\"no JavaScript Server, Socket, or Stream class instances\",\"no EventEmitter callback object model for sockets or servers\",\"_createServerHandle and _normalizeArgs internal JavaScript helpers are not modeled\",\"createConnection and createServer return explicit native handles rather than JavaScript objects\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_net_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &net_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_net_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var auto_select_family: u64 = 0;
    if (ext.sa_node_plugin_net_get_default_auto_select_family(&auto_select_family) != 0) return fail();
    var auto_select_timeout: u64 = 0;
    if (ext.sa_node_plugin_net_get_default_auto_select_family_attempt_timeout(&auto_select_timeout) != 0) return fail();

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"socketModel\":\"explicit native TCP or Unix socket handle\",\"serverModel\":\"explicit native listener handle\",\"blockListModel\":\"explicit native BlockList handle\",\"socketAddressModel\":\"explicit native SocketAddress handle\",\"defaultAutoSelectFamily\":") catch return fail();
    out.appendSlice(if (auto_select_family != 0) "true" else "false") catch return fail();
    out.appendSlice(",\"defaultAutoSelectFamilyAttemptTimeout\":") catch return fail();
    out.writer().print("{d}", .{auto_select_timeout}) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_net_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"connect\":{\"supported\":true,\"mode\":\"explicit native TCP or Unix socket connect helper\"},\"createConnection\":{\"supported\":true,\"mode\":\"alias of native connect helper returning explicit socket handle\"},\"createServer\":{\"supported\":true,\"mode\":\"native listener handle on an ephemeral port\",\"limitations\":[\"returns explicit native listener handle rather than a JavaScript Server object\"]},\"isIP\":{\"supported\":true,\"mode\":\"native IP parser returning 0, 4, or 6\"},\"isIPv4\":{\"supported\":true,\"mode\":\"native IPv4 parser boolean helper\"},\"isIPv6\":{\"supported\":true,\"mode\":\"native IPv6 parser boolean helper\"},\"BlockList\":{\"supported\":true,\"mode\":\"explicit native BlockList handle with add/check/rules helpers\"},\"SocketAddress\":{\"supported\":true,\"mode\":\"explicit native SocketAddress handle with parse/address/family/port/flowlabel/json helpers\"},\"getDefaultAutoSelectFamily\":{\"supported\":true,\"mode\":\"read native default setting metadata\"},\"setDefaultAutoSelectFamily\":{\"supported\":true,\"mode\":\"write native default setting metadata\"},\"getDefaultAutoSelectFamilyAttemptTimeout\":{\"supported\":true,\"mode\":\"read native default timeout metadata\"},\"setDefaultAutoSelectFamilyAttemptTimeout\":{\"supported\":true,\"mode\":\"write native default timeout metadata\"},\"Server\":{\"supported\":false,\"reason\":\"JavaScript Server class instances are not modeled; use explicit native listener handles instead\"},\"Socket\":{\"supported\":false,\"reason\":\"JavaScript Socket class instances are not modeled; use explicit native socket handles instead\"},\"Stream\":{\"supported\":false,\"reason\":\"legacy JavaScript Stream alias semantics are not modeled\"},\"_createServerHandle\":{\"supported\":false,\"reason\":\"Node internal JavaScript server-handle helper is not exposed as a public native ABI helper\"},\"_normalizeArgs\":{\"supported\":false,\"reason\":\"Node internal JavaScript argument normalization helper is not modeled\"}}");
}

pub export fn sa_node_plugin_dns_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    if (ext.sa_node_plugin_dns_constants_json(&constants_ptr, &constants_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(constants_ptr, constants_len);

    var servers_ptr: ?[*]const u8 = null;
    var servers_len: u64 = 0;
    if (ext.sa_node_plugin_dns_get_servers(&servers_ptr, &servers_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(servers_ptr, servers_len);

    var order_ptr: ?[*]const u8 = null;
    var order_len: u64 = 0;
    if (ext.sa_node_plugin_dns_get_default_result_order(&order_ptr, &order_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(order_ptr, order_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"dns\",\"supported\":true,\"mode\":\"top-level-native-dns-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &dns_export_names) catch return fail();
    out.appendSlice(",\"defaults\":{\"resultOrder\":") catch return fail();
    out.appendSlice((order_ptr orelse return fail())[0..@intCast(order_len)]) catch return fail();
    out.appendSlice(",\"servers\":") catch return fail();
    out.appendSlice((servers_ptr orelse return fail())[0..@intCast(servers_len)]) catch return fail();
    out.appendSlice("},\"constants\":") catch return fail();
    out.appendSlice((constants_ptr orelse return fail())[0..@intCast(constants_len)]) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"lookup\":true,\"lookupService\":true,\"Resolver\":true,\"getDefaultResultOrder\":true,\"setDefaultResultOrder\":true,\"setServers\":true,\"getServers\":true,\"resolve\":true,\"resolve4\":true,\"resolve6\":true,\"resolveAny\":true,\"resolveCaa\":true,\"resolveCname\":true,\"resolveMx\":true,\"resolveNaptr\":true,\"resolveNs\":true,\"resolvePtr\":true,\"resolveSoa\":true,\"resolveSrv\":true,\"resolveTxt\":true,\"resolveTlsa\":true,\"reverse\":true,\"promises\":true,\"ADDRCONFIG\":true,\"ALL\":true,\"V4MAPPED\":true,\"errorCodes\":true,\"cAresChannelSemantics\":false,\"JavaScriptCallbackSemantics\":false,\"JavaScriptPromiseObjectIdentity\":false},\"capabilities\":[\"OS resolver lookup and lookupService helpers\",\"global resolver server configuration and default result-order helpers\",\"resolver-backed RRtype queries for A, AAAA, ANY, CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SRV, TXT, and TLSA\",\"explicit native Resolver handles with independent server lists, local bind addresses, cancel counters, and snapshot JSON\",\"dns.promises namespace compatibility over already-resolved native buffers\",\"Node-style lookup flag and error-code constant metadata\"],\"limitations\":[\"no JavaScript callback scheduling or Promise object identity\",\"no JavaScript Resolver class instances; use explicit native handles instead\",\"full c-ares channel behavior such as search domains, retries, and in-flight cancellation is not modeled\",\"results and errors follow the plugin's synchronous native resolver model rather than Node's event-loop timing semantics\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_dns_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &dns_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_dns_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;

    var servers_ptr: ?[*]const u8 = null;
    var servers_len: u64 = 0;
    if (ext.sa_node_plugin_dns_get_servers(&servers_ptr, &servers_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(servers_ptr, servers_len);

    var order_ptr: ?[*]const u8 = null;
    var order_len: u64 = 0;
    if (ext.sa_node_plugin_dns_get_default_result_order(&order_ptr, &order_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(order_ptr, order_len);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"resolverModel\":\"explicit native Resolver handle with setServers/getServers/setLocalAddress/cancel/resolve/reverse/snapshot helpers\",\"lookupModel\":\"synchronous native OS resolver JSON helpers\",\"promisesModel\":\"dns.promises names return already-resolved native buffers rather than JavaScript Promise objects\",\"customServerModel\":\"resolver handles can issue UDP DNS queries to configured servers\",\"defaultResultOrder\":") catch return fail();
    out.appendSlice((order_ptr orelse return fail())[0..@intCast(order_len)]) catch return fail();
    out.appendSlice(",\"defaultServers\":") catch return fail();
    out.appendSlice((servers_ptr orelse return fail())[0..@intCast(servers_len)]) catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_dns_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"lookup\":{\"supported\":true,\"mode\":\"synchronous native OS resolver lookup JSON\",\"limitations\":[\"no JavaScript callback scheduling semantics\"]},\"lookupService\":{\"supported\":true,\"mode\":\"native reverse service lookup JSON\"},\"Resolver\":{\"supported\":true,\"mode\":\"explicit native Resolver handle with independent server lists, bind addresses, cancel counters, and snapshot JSON\",\"limitations\":[\"not a JavaScript Resolver class instance\"]},\"getDefaultResultOrder\":{\"supported\":true,\"mode\":\"read native dns default result-order setting\"},\"setDefaultResultOrder\":{\"supported\":true,\"mode\":\"write native dns default result-order setting\"},\"setServers\":{\"supported\":true,\"mode\":\"replace the global resolver server list for subsequent native lookups\"},\"getServers\":{\"supported\":true,\"mode\":\"read the global resolver server list as JSON\"},\"resolve\":{\"supported\":true,\"mode\":\"native RRtype-dispatched resolve helper\"},\"resolve4\":{\"supported\":true,\"mode\":\"native A record lookup\"},\"resolve6\":{\"supported\":true,\"mode\":\"native AAAA record lookup\"},\"resolveAny\":{\"supported\":true,\"mode\":\"native ANY record lookup\"},\"resolveCaa\":{\"supported\":true,\"mode\":\"native CAA record lookup\"},\"resolveCname\":{\"supported\":true,\"mode\":\"native CNAME record lookup\"},\"resolveMx\":{\"supported\":true,\"mode\":\"native MX record lookup\"},\"resolveNaptr\":{\"supported\":true,\"mode\":\"native NAPTR record lookup\"},\"resolveNs\":{\"supported\":true,\"mode\":\"native NS record lookup\"},\"resolvePtr\":{\"supported\":true,\"mode\":\"native PTR record lookup\"},\"resolveSoa\":{\"supported\":true,\"mode\":\"native SOA record lookup\"},\"resolveSrv\":{\"supported\":true,\"mode\":\"native SRV record lookup\"},\"resolveTxt\":{\"supported\":true,\"mode\":\"native TXT record lookup\"},\"resolveTlsa\":{\"supported\":true,\"mode\":\"native TLSA record lookup\"},\"reverse\":{\"supported\":true,\"mode\":\"native reverse DNS lookup\"},\"promises\":{\"supported\":true,\"mode\":\"dns.promises namespace over already-resolved native buffers\",\"limitations\":[\"no JavaScript Promise object identity or microtask scheduling\"]},\"ADDRCONFIG\":{\"supported\":true,\"mode\":\"static lookup hint constant metadata\"},\"ALL\":{\"supported\":true,\"mode\":\"static lookup hint constant metadata\"},\"V4MAPPED\":{\"supported\":true,\"mode\":\"static lookup hint constant metadata\"},\"errorCodes\":{\"supported\":true,\"mode\":\"static Node-style DNS error code catalog JSON\"},\"cAresChannelSemantics\":{\"supported\":false,\"reason\":\"full c-ares search domain, retry, rotation, and in-flight cancellation behavior is not modeled\"},\"JavaScriptCallbackSemantics\":{\"supported\":false,\"reason\":\"callback scheduling and request object identity are not modeled\"},\"JavaScriptPromiseObjectIdentity\":{\"supported\":false,\"reason\":\"dns.promises returns already-resolved native buffers rather than JavaScript Promise objects\"}}");
}

const wasi_supported_versions = [_][]const u8{ "unstable", "preview1" };
const wasi_import_module_names = [_][]const u8{ "wasi_unstable", "wasi_snapshot_preview1" };

fn wasiVersion() []const u8 {
    return std.posix.getenv("SA_NODE_WASI_VERSION") orelse "preview1";
}

fn wasiBindingName(version: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, version, "unstable")) return "wasi_unstable";
    if (std.mem.eql(u8, version, "preview1")) return "wasi_snapshot_preview1";
    return null;
}

fn wasiReadJsonConfig(allocator: std.mem.Allocator, env_name: []const u8, default_json: []const u8, expected_kind: std.meta.Tag(std.json.Value)) ![]u8 {
    const json_text = std.process.getEnvVarOwned(allocator, env_name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return allocator.dupe(u8, default_json),
        else => return err,
    };
    defer allocator.free(json_text);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();
    if (parsed.value != expected_kind) return error.InvalidWasiConfig;

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try std.json.stringify(parsed.value, .{}, out.writer());
    return out.toOwnedSlice();
}

fn wasiReturnOnExit() bool {
    const value = std.posix.getenv("SA_NODE_WASI_RETURN_ON_EXIT") orelse return true;
    if (value.len == 0) return true;
    if (std.mem.eql(u8, value, "0")) return false;
    return !std.ascii.eqlIgnoreCase(value, "false");
}

fn wasiStdioFd(name: []const u8, default_value: u64) u64 {
    const value = std.posix.getenv(name) orelse return default_value;
    return std.fmt.parseInt(u64, value, 10) catch default_value;
}

fn wasiExperimentalFlag() bool {
    return nodeOptionsHasFlag("--experimental-wasi-unstable-preview1");
}

fn wasiAllowedInternal() bool {
    return !permissionsIsEnabledInternal() or nodeOptionsHasFlag("--allow-wasi");
}

pub export fn sa_node_plugin_wasi_supported_versions_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &wasi_supported_versions) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_wasi_import_modules_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &wasi_import_module_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_wasi_is_allowed(out_bool: ?*u64) u32 {
    out_bool.?.* = if (wasiAllowedInternal()) 1 else 0;
    return 0;
}

const wasi_export_names = [_][]const u8{
    "WASI",
};

pub export fn sa_node_plugin_wasi_config_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    const version = wasiVersion();
    const binding_name = wasiBindingName(version) orelse return fail();
    const args_json = wasiReadJsonConfig(allocator, "SA_NODE_WASI_ARGS", "[]", .array) catch return fail();
    defer allocator.free(args_json);
    const env_json = wasiReadJsonConfig(allocator, "SA_NODE_WASI_ENV", "{}", .object) catch return fail();
    defer allocator.free(env_json);
    const preopens_json = wasiReadJsonConfig(allocator, "SA_NODE_WASI_PREOPENS", "{}", .object) catch return fail();
    defer allocator.free(preopens_json);

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"version\":") catch return fail();
    appendJsonString(&out, version) catch return fail();
    out.appendSlice(",\"bindingName\":") catch return fail();
    appendJsonString(&out, binding_name) catch return fail();
    out.appendSlice(",\"args\":") catch return fail();
    out.appendSlice(args_json) catch return fail();
    out.appendSlice(",\"env\":") catch return fail();
    out.appendSlice(env_json) catch return fail();
    out.appendSlice(",\"preopens\":") catch return fail();
    out.appendSlice(preopens_json) catch return fail();
    out.appendSlice(",\"returnOnExit\":") catch return fail();
    out.appendSlice(if (wasiReturnOnExit()) "true" else "false") catch return fail();
    out.writer().print(",\"stdio\":{{\"stdin\":{d},\"stdout\":{d},\"stderr\":{d}}}", .{
        wasiStdioFd("SA_NODE_WASI_STDIN", 0),
        wasiStdioFd("SA_NODE_WASI_STDOUT", 1),
        wasiStdioFd("SA_NODE_WASI_STDERR", 2),
    }) catch return fail();
    out.appendSlice(",\"permissionRequired\":true,\"permissionSatisfied\":") catch return fail();
    out.appendSlice(if (wasiAllowedInternal()) "true" else "false") catch return fail();
    out.appendSlice(",\"experimentalFlag\":") catch return fail();
    out.appendSlice(if (wasiExperimentalFlag()) "true" else "false") catch return fail();
    out.append('}') catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_wasi_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var versions_ptr: ?[*]const u8 = null;
    var versions_len: u64 = 0;
    if (sa_node_plugin_wasi_supported_versions_json(&versions_ptr, &versions_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(versions_ptr, versions_len);

    var imports_ptr: ?[*]const u8 = null;
    var imports_len: u64 = 0;
    if (sa_node_plugin_wasi_import_modules_json(&imports_ptr, &imports_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(imports_ptr, imports_len);

    var config_ptr: ?[*]const u8 = null;
    var config_len: u64 = 0;
    if (sa_node_plugin_wasi_config_json(&config_ptr, &config_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(config_ptr, config_len);

    const versions = if (versions_ptr) |ptr| ptr[0..@intCast(versions_len)] else "[]";
    const imports = if (imports_ptr) |ptr| ptr[0..@intCast(imports_len)] else "[]";
    const config = if (config_ptr) |ptr| ptr[0..@intCast(config_len)] else "{}";

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"wasi\",\"supported\":true,\"mode\":\"top-level-native-wasi-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &wasi_export_names) catch return fail();
    out.appendSlice(",\"versions\":") catch return fail();
    out.appendSlice(versions) catch return fail();
    out.appendSlice(",\"importModules\":") catch return fail();
    out.appendSlice(imports) catch return fail();
    out.appendSlice(",\"allowed\":") catch return fail();
    out.appendSlice(if (wasiAllowedInternal()) "true" else "false") catch return fail();
    out.appendSlice(",\"experimentalFlag\":") catch return fail();
    out.appendSlice(if (wasiExperimentalFlag()) "true" else "false") catch return fail();
    out.appendSlice(",\"config\":") catch return fail();
    out.appendSlice(config) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"WASI\":false,\"supportedVersions\":true,\"importModules\":true,\"config\":true,\"permissionIntrospection\":true,\"experimentalFlag\":true,\"wasiImportObject\":false,\"start\":false,\"initialize\":false,\"finalizeBindings\":false,\"getImportObject\":false},\"capabilities\":[\"supported version metadata\",\"import module name metadata\",\"host-config args/env/preopens/stdio snapshot\",\"permission and experimental flag introspection\"],\"limitations\":[\"no WebAssembly instantiation or execution\",\"no uvwasi syscall bridge or wasiImport object model\",\"preopens are reported as configuration only, not enforced sandbox mounts\",\"top-level WASI export is metadata only rather than a constructible JavaScript class\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_wasi_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &wasi_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_wasi_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"WASI\":{\"supported\":false,\"reason\":\"constructible JavaScript WASI class instances are not modeled without a WebAssembly runtime\"},\"supportedVersions\":{\"supported\":true,\"mode\":\"native version metadata JSON\"},\"importModules\":{\"supported\":true,\"mode\":\"native module-name metadata JSON\"},\"config\":{\"supported\":true,\"mode\":\"environment-backed args/env/preopens/stdio snapshot JSON\"},\"permissionIntrospection\":{\"supported\":true,\"mode\":\"host NODE_OPTIONS permission flag introspection\"},\"experimentalFlag\":{\"supported\":true,\"mode\":\"host NODE_OPTIONS experimental flag introspection\"},\"wasiImportObject\":{\"supported\":false,\"reason\":\"live wasiImport objects require a WebAssembly runtime binding surface\"},\"start\":{\"supported\":false,\"reason\":\"WebAssembly instance start execution is not modeled\"},\"initialize\":{\"supported\":false,\"reason\":\"WebAssembly instance initialize execution is not modeled\"},\"finalizeBindings\":{\"supported\":false,\"reason\":\"memory binding to a live WebAssembly instance is not modeled\"},\"getImportObject\":{\"supported\":false,\"reason\":\"constructing binding-name keyed import objects is not modeled without a WASM runtime\"}}");
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
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"tty\",\"supported\":true,\"mode\":\"top-level-native-tty-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &tty_export_names) catch return fail();
    out.appendSlice(",\"runtime\":") catch return fail();
    ttyAppendRuntimeJson(&out) catch return fail();
    out.appendSlice(",\"featureSupport\":{\"isatty\":true,\"ReadStream\":true,\"WriteStream\":true,\"setRawMode\":true,\"getWindowSize\":true,\"getColorDepth\":true,\"hasColors\":true,\"resizeEvent\":false,\"netSocketPrototype\":false,\"readlineCursorMethods\":false},\"limitations\":[\"ReadStream and WriteStream are native TTY handle facades rather than JavaScript net.Socket subclasses\",\"no resize event emitter integration or inherited cursorTo/moveCursor/clearLine/clearScreenDown methods on stream objects\",\"raw mode and color/window helpers operate on explicit native handles instead of JavaScript stream instances\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

const tty_export_names = [_][]const u8{
    "isatty",
    "ReadStream",
    "WriteStream",
};

fn ttyAppendRuntimeJson(out: *std.ArrayList(u8)) !void {
    var stdin_is_tty: u64 = 0;
    if (sa_node_plugin_tty_isatty(0, &stdin_is_tty) != 0) return error.Unexpected;
    var stdout_is_tty: u64 = 0;
    if (sa_node_plugin_tty_isatty(1, &stdout_is_tty) != 0) return error.Unexpected;
    var stderr_is_tty: u64 = 0;
    if (sa_node_plugin_tty_isatty(2, &stderr_is_tty) != 0) return error.Unexpected;

    var stdout_handle: ?*anyopaque = null;
    if (sa_node_plugin_tty_write_stream_new(1, &stdout_handle) != 0) return error.Unexpected;
    defer _ = sa_node_plugin_tty_stream_free(stdout_handle);

    var cols: u64 = 0;
    var rows: u64 = 0;
    if (sa_node_plugin_tty_stream_get_window_size(stdout_handle, &cols, &rows) != 0) return error.Unexpected;
    var color_depth: u64 = 0;
    if (sa_node_plugin_tty_stream_get_color_depth(stdout_handle, &color_depth) != 0) return error.Unexpected;
    var has_colors: u64 = 0;
    if (sa_node_plugin_tty_stream_has_colors(stdout_handle, &has_colors) != 0) return error.Unexpected;

    try out.appendSlice("{\"stdin\":{\"isTTY\":");
    try out.appendSlice(if (stdin_is_tty != 0) "true" else "false");
    try out.appendSlice("},\"stdout\":{\"isTTY\":");
    try out.appendSlice(if (stdout_is_tty != 0) "true" else "false");
    try out.appendSlice(",\"columns\":");
    try out.writer().print("{d}", .{cols});
    try out.appendSlice(",\"rows\":");
    try out.writer().print("{d}", .{rows});
    try out.appendSlice(",\"colorDepth\":");
    try out.writer().print("{d}", .{color_depth});
    try out.appendSlice(",\"hasColors\":");
    try out.appendSlice(if (has_colors != 0) "true" else "false");
    try out.appendSlice("},\"stderr\":{\"isTTY\":");
    try out.appendSlice(if (stderr_is_tty != 0) "true" else "false");
    try out.appendSlice("}}");
}

pub export fn sa_node_plugin_tty_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &tty_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_tty_stdio_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    ttyAppendRuntimeJson(&out) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_tty_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"isatty\":{\"supported\":true,\"mode\":\"POSIX isatty on host fd\"},\"ReadStream\":{\"supported\":true,\"mode\":\"native read-handle allocation\",\"limitations\":[\"not a JavaScript net.Socket subclass\",\"no EventEmitter object model\"]},\"WriteStream\":{\"supported\":true,\"mode\":\"native write-handle allocation\",\"limitations\":[\"not a JavaScript net.Socket subclass\",\"no resize event emitter\"]},\"setRawMode\":{\"supported\":true,\"mode\":\"termios raw-mode toggle on explicit native handle\"},\"getWindowSize\":{\"supported\":true,\"mode\":\"ioctl or environment fallback\"},\"getColorDepth\":{\"supported\":true,\"mode\":\"environment-aware native helper\"},\"hasColors\":{\"supported\":true,\"mode\":\"derived from native color depth\"},\"cursorTo\":{\"supported\":false,\"reason\":\"readline cursor helpers are not attached to TTY stream handles\"},\"moveCursor\":{\"supported\":false,\"reason\":\"readline cursor helpers are not attached to TTY stream handles\"},\"clearLine\":{\"supported\":false,\"reason\":\"readline cursor helpers are not attached to TTY stream handles\"},\"clearScreenDown\":{\"supported\":false,\"reason\":\"readline cursor helpers are not attached to TTY stream handles\"},\"resizeEvent\":{\"supported\":false,\"reason\":\"window resize event dispatch is not modeled\"}}");
}

const diagnostics_channel_export_names = [_][]const u8{
    "channel",
    "hasSubscribers",
    "subscribe",
    "tracingChannel",
    "unsubscribe",
    "boundedChannel",
    "Channel",
    "BoundedChannel",
};

pub export fn sa_node_plugin_diagnostics_channel_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"module\":\"diagnostics_channel\",\"supported\":true,\"mode\":\"top-level-native-channel-facade\",\"exports\":") catch return fail();
    appendStringArray(&out, &diagnostics_channel_export_names) catch return fail();
    out.appendSlice(",\"factories\":{\"channel\":{\"supported\":true,\"mode\":\"native channel handle\"},\"tracingChannel\":{\"supported\":true,\"mode\":\"opaque tracing handle placeholder\"},\"boundedChannel\":{\"supported\":false,\"reason\":\"bounded channel window composition is not modeled as a first-class native handle\"}},\"channelOps\":{\"subscribe\":true,\"unsubscribe\":true,\"hasSubscribers\":true,\"publish\":true,\"snapshot\":true},\"featureSupport\":{\"ChannelClass\":false,\"BoundedChannelClass\":false,\"WeakRefMapLifecycle\":false,\"storeBinding\":false,\"runStores\":false,\"traceSync\":false,\"tracePromise\":false,\"traceCallback\":false,\"channel\":true,\"subscribe\":true,\"unsubscribe\":true,\"hasSubscribers\":true,\"tracingChannel\":true},\"limitations\":[\"channel handles are explicit native allocations rather than JavaScript Channel or ActiveChannel instances\",\"boundedChannel windows, store binding, and tracing callback wrappers are not modeled\",\"tracingChannel currently exposes opaque handle allocation metadata only and does not implement sync/promise/callback tracing flows\"]}") catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_diagnostics_channel_exports_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendStringArray(&out, &diagnostics_channel_export_names) catch return fail();
    return writeOwnedBytes(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_diagnostics_channel_factories_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"channel\":{\"supported\":true,\"returns\":\"native DiagnosticsChannel handle\",\"operations\":[\"subscribe\",\"unsubscribe\",\"hasSubscribers\",\"publish\",\"snapshot\",\"free\"]},\"tracingChannel\":{\"supported\":true,\"returns\":\"opaque tracing handle placeholder\",\"operations\":[\"allocate\",\"free via generic buffer free compatibility path\"],\"limitations\":[\"no sync/callback/promise trace wrappers\",\"no error/start/end/asyncStart/asyncEnd channel fanout\"]},\"boundedChannel\":{\"supported\":false,\"reason\":\"bounded multi-channel window handles are not modeled\"}}");
}

pub export fn sa_node_plugin_diagnostics_channel_feature_support_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"channel\":{\"supported\":true,\"mode\":\"native channel handle\"},\"hasSubscribers\":{\"supported\":true,\"mode\":\"subscriber count boolean\"},\"subscribe\":{\"supported\":true,\"mode\":\"opaque callback token registry\"},\"unsubscribe\":{\"supported\":true,\"mode\":\"opaque callback token registry\"},\"publish\":{\"supported\":true,\"mode\":\"payload passthrough with subscriber count result\"},\"snapshot\":{\"supported\":true,\"mode\":\"channel metadata JSON\"},\"tracingChannel\":{\"supported\":true,\"mode\":\"opaque tracing handle placeholder\",\"limitations\":[\"no traceSync\",\"no tracePromise\",\"no traceCallback\"]},\"boundedChannel\":{\"supported\":false,\"reason\":\"bounded channel composition is not modeled\"},\"Channel\":{\"supported\":false,\"reason\":\"JavaScript Channel class instances and prototype switching are not modeled\"},\"BoundedChannel\":{\"supported\":false,\"reason\":\"JavaScript BoundedChannel class instances are not modeled\"},\"storeBinding\":{\"supported\":false,\"reason\":\"AsyncLocalStorage-style store scopes are not modeled\"}}");
}
