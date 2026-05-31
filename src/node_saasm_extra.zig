const std = @import("std");
const builtin = @import("builtin");
const plugin_api = @import("plugin_api");
const base = @import("node_saasm_api.zig");

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
    return writeStatusJson(out_ptr, out_len, "command_line_options", false, "command-line option parsing is not modeled");
}

pub export fn sa_node_plugin_debugger_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "debugger", false, "debugger protocol is not modeled");
}

pub export fn sa_node_plugin_deprecated_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "deprecated", false, "deprecated Node APIs are not modeled");
}

pub export fn sa_node_plugin_environment_variables_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "environment_variables", true, "backed by process env shims");
}

pub export fn sa_node_plugin_errors_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "errors", false, "Node error helpers are not modeled");
}

pub export fn sa_node_plugin_internationalization_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "internationalization", false, "ICU and i18n APIs are not modeled");
}

pub export fn sa_node_plugin_iterable_streams_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "iterable_streams", false, "iterable stream adapters are not modeled");
}

pub export fn sa_node_plugin_permissions_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "permissions", false, "Node permissions model is not enforced here");
}

pub export fn sa_node_plugin_repl_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "repl", false, "interactive REPL is not modeled");
}

pub export fn sa_node_plugin_test_runner_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "test_runner", false, "Node test runner APIs are not modeled");
}

pub export fn sa_node_plugin_web_crypto_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "web_crypto", false, "Web Crypto API is not modeled separately");
}

pub export fn sa_node_plugin_web_streams_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "web_streams", false, "Web Streams API is not modeled separately");
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
    return writeOwnedBool(out_bool, false);
}

pub export fn sa_node_plugin_sea_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "sea", true, "single executable application shims are exposed");
}

pub export fn sa_node_plugin_sea_asset_keys_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "[]");
}

pub export fn sa_node_plugin_sea_get_asset(key_ptr: ?[*]const u8, key_len: u64, encoding_ptr: ?[*]const u8, encoding_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = key_ptr;
    _ = key_len;
    _ = encoding_ptr;
    _ = encoding_len;
    out_ptr.?.* = null;
    out_len.?.* = 0;
    return fail();
}

pub export fn sa_node_plugin_sea_get_raw_asset(key_ptr: ?[*]const u8, key_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = key_ptr;
    _ = key_len;
    out_ptr.?.* = null;
    out_len.?.* = 0;
    return fail();
}

pub export fn sa_node_plugin_sea_get_asset_as_blob(key_ptr: ?[*]const u8, key_len: u64, out_ptr: ?*?*anyopaque) u32 {
    _ = key_ptr;
    _ = key_len;
    out_ptr.?.* = null;
    return fail();
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
    fd: std.posix.fd_t,
    is_write: bool,
    raw_mode: bool = false,

    fn deinit(self: *TtyHandle) void {
        self.allocator.destroy(self);
    }
};

fn makeTtyHandle(fd: std.posix.fd_t, is_write: bool, out_handle: ?*?*anyopaque) u32 {
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

pub export fn sa_node_plugin_tty_isatty(fd: u32, out_bool: ?*u32) u32 {
    return writeOwnedBool(out_bool, std.posix.isatty(@as(std.posix.fd_t, @intCast(fd))));
}

pub export fn sa_node_plugin_tty_read_stream_new(fd: u32, out_handle: ?*?*anyopaque) u32 {
    return makeTtyHandle(@as(std.posix.fd_t, @intCast(fd)), false, out_handle);
}

pub export fn sa_node_plugin_tty_write_stream_new(fd: u32, out_handle: ?*?*anyopaque) u32 {
    return makeTtyHandle(@as(std.posix.fd_t, @intCast(fd)), true, out_handle);
}

pub export fn sa_node_plugin_tty_stream_set_raw_mode(handle_ptr: ?*anyopaque, flag: u8) u32 {
    const handle: *TtyHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    handle.raw_mode = flag != 0;
    return 0;
}

pub export fn sa_node_plugin_tty_stream_get_window_size(handle_ptr: ?*anyopaque, out_cols: ?*u64, out_rows: ?*u64) u32 {
    const handle: *TtyHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    _ = handle;
    var cols: u64 = 0;
    var rows: u64 = 0;
    if (std.posix.getenv("COLUMNS")) |value| cols = std.fmt.parseInt(u64, value, 10) catch 0;
    if (std.posix.getenv("LINES")) |value| rows = std.fmt.parseInt(u64, value, 10) catch 0;
    out_cols.?.* = cols;
    out_rows.?.* = rows;
    return 0;
}

pub export fn sa_node_plugin_tty_stream_get_color_depth(handle_ptr: ?*anyopaque, out_depth: ?*u32) u32 {
    const handle: *TtyHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    var depth: u32 = 1;
    if (std.posix.isatty(handle.fd)) depth = 24;
    out_depth.?.* = depth;
    return 0;
}

pub export fn sa_node_plugin_tty_stream_has_colors(handle_ptr: ?*anyopaque, out_bool: ?*u32) u32 {
    const handle: *TtyHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    const no_color = std.posix.getenv("NO_COLOR") != null;
    return writeOwnedBool(out_bool, std.posix.isatty(handle.fd) and !no_color);
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

pub export fn sa_node_plugin_worker_threads_is_main_thread(out_bool: ?*u32) u32 {
    return writeOwnedBool(out_bool, true);
}

pub export fn sa_node_plugin_worker_threads_is_internal_thread(out_bool: ?*u32) u32 {
    return writeOwnedBool(out_bool, false);
}

pub export fn sa_node_plugin_worker_threads_thread_id(out_id: ?*u64) u32 {
    out_id.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_worker_threads_thread_name(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "main");
}

pub export fn sa_node_plugin_worker_threads_resource_limits_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"maxOldGenerationSizeMb\":0,\"maxYoungGenerationSizeMb\":0,\"codeRangeSizeMb\":0,\"stackSizeMb\":0}");
}

pub export fn sa_node_plugin_worker_threads_set_environment_data(key_ptr: ?[*]const u8, key_len: u64, value_ptr: ?[*]const u8, value_len: u64) u32 {
    const key = key_ptr.?[0..key_len];
    const value = value_ptr.?[0..value_len];
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
    const key = key_ptr.?[0..key_len];
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

// --- Status-only compatibility shims ---
pub export fn sa_node_plugin_cluster_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "cluster", false, "not modeled; use worker_threads or child_process");
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
        false,
        "Node HTTP object model is not modeled; use dedicated HTTP plugins",
    );
}

pub export fn sa_node_plugin_https_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(
        out_ptr,
        out_len,
        "https",
        false,
        "Node HTTPS object model is not modeled; use dedicated HTTP/TLS plugins",
    );
}

pub export fn sa_node_plugin_http2_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "http2", false, "HTTP/2 session semantics are not modeled");
}

pub export fn sa_node_plugin_tls_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "tls", false, "TLS socket semantics are not modeled");
}

pub export fn sa_node_plugin_dgram_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "dgram", true, "UDP socket create/bind/send/recv/close are exposed");
}

pub export fn sa_node_plugin_wasi_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "wasi", false, "WASI runtime is not modeled");
}

pub export fn sa_node_plugin_sqlite_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeStatusJson(out_ptr, out_len, "sqlite", false, "SQLite binding is not modeled");
}

pub export fn sa_node_plugin_tty_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"tty\":{\"isatty\":true}}");
}
pub export fn sa_node_plugin_diagnostics_channel_status_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwnedString(out_ptr, out_len, "{\"diagnostics_channel\":{\"supported\":true}}");
}
