const std = @import("std");
const plugin_api = @import("plugin_api");
const plugin = @import("node");

extern fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern fn unsetenv(name: [*:0]const u8) c_int;

fn jsonPort(bytes: []const u8) !u16 {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    const port_value = parsed.value.object.get("port") orelse return error.MissingPort;
    return @intCast(port_value.integer);
}

fn writeH2Frame(stream: std.net.Stream, frame_type: u8, flags: u8, stream_id: u32, payload: []const u8) !void {
    var header: [9]u8 = undefined;
    header[0] = @intCast((payload.len >> 16) & 0xff);
    header[1] = @intCast((payload.len >> 8) & 0xff);
    header[2] = @intCast(payload.len & 0xff);
    header[3] = frame_type;
    header[4] = flags;
    header[5] = @intCast((stream_id >> 24) & 0x7f);
    header[6] = @intCast((stream_id >> 16) & 0xff);
    header[7] = @intCast((stream_id >> 8) & 0xff);
    header[8] = @intCast(stream_id & 0xff);
    try stream.writeAll(&header);
    try stream.writeAll(payload);
}

fn writeDnsNameForTest(out: *std.ArrayList(u8), name: []const u8) !void {
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0) continue;
        try out.append(@intCast(label.len));
        try out.appendSlice(label);
    }
    try out.append(0);
}

fn makeSaArgv(args: []const []const u8) [512]u8 {
    var buf: [512]u8 = undefined;
    @memset(&buf, 0);
    for (args, 0..) |arg, i| {
        std.mem.writeInt(usize, buf[i * 16 ..][0..@sizeOf(usize)], @intFromPtr(arg.ptr), .little);
        std.mem.writeInt(u64, buf[i * 16 + 8 ..][0..8], arg.len, .little);
    }
    return buf;
}

test "node plugin events create and free" {
    const ee = plugin.sa_node_plugin_events_create();
    try std.testing.expect(ee != null);
    _ = plugin.sa_node_plugin_events_free(ee);
}

test "node plugin async context tracking native stack helpers" {
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_reset());

    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullAsyncContextTrackingStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"async_context_tracking\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "explicit enter and exit") != null);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_snapshot_json(&snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const empty_snapshot = (snapshot_ptr orelse return error.NullAsyncContextTrackingSnapshot0)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, empty_snapshot, "\"depth\":0") != null);

    var handle: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_hooks_async_resource_create("TestResource".ptr, 12, 41, &handle));
    defer _ = plugin.sa_node_plugin_async_hooks_async_resource_free(handle);

    var enter_depth: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_enter(handle, &enter_depth));
    try std.testing.expectEqual(@as(u64, 1), enter_depth);

    var depth: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_depth(&depth));
    try std.testing.expectEqual(@as(u64, 1), depth);

    var execution_async_id: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_execution_async_id(&execution_async_id));
    try std.testing.expect(execution_async_id != 0);

    var trigger_async_id: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_trigger_async_id(&trigger_async_id));
    try std.testing.expectEqual(@as(u64, 41), trigger_async_id);

    var hooks_execution_async_id: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_hooks_execution_async_id(&hooks_execution_async_id));
    try std.testing.expectEqual(execution_async_id, hooks_execution_async_id);

    var active_snapshot_ptr: ?[*]const u8 = null;
    var active_snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_snapshot_json(&active_snapshot_ptr, &active_snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(active_snapshot_ptr, active_snapshot_len);
    const active_snapshot = (active_snapshot_ptr orelse return error.NullAsyncContextTrackingSnapshot1)[0..@intCast(active_snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, active_snapshot, "\"depth\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_snapshot, "TestResource") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_snapshot, "\"triggerAsyncId\":41") != null);

    var popped_async_id: u64 = 0;
    var popped: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_exit(&popped_async_id, &popped));
    try std.testing.expectEqual(@as(u64, 1), popped);
    try std.testing.expectEqual(execution_async_id, popped_async_id);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_depth(&depth));
    try std.testing.expectEqual(@as(u64, 0), depth);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_async_context_tracking_exit(&popped_async_id, &popped));
    try std.testing.expectEqual(@as(u64, 0), popped);
}

test "node plugin events stateful extra APIs" {
    const ee = plugin.sa_node_plugin_events_create();
    try std.testing.expect(ee != null);
    defer _ = plugin.sa_node_plugin_events_free(ee);

    const evt = "tick";
    const cb1: ?*anyopaque = @ptrFromInt(@as(usize, 0x1001));
    const cb2: ?*anyopaque = @ptrFromInt(@as(usize, 0x1002));

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_on(ee, evt.ptr, evt.len, cb1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_once(ee, evt.ptr, evt.len, cb2));

    var count: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_listener_count(ee, evt.ptr, evt.len, &count));
    try std.testing.expectEqual(@as(u64, 2), count);

    var max: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_set_max_listeners(ee, 42));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_get_max_listeners(ee, &max));
    try std.testing.expectEqual(@as(u32, 42), max);

    var listeners_ptr: ?[*]const u8 = null;
    var listeners_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_get_event_listeners(ee, evt.ptr, evt.len, &listeners_ptr, &listeners_len));
    defer _ = plugin.sa_node_plugin_free_buffer(listeners_ptr, listeners_len);
    const listeners_json = (listeners_ptr orelse return error.NullListeners)[0..@intCast(listeners_len)];
    try std.testing.expect(std.mem.indexOf(u8, listeners_json, "listener") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_emit(ee, evt.ptr, evt.len, "", 0));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_listener_count_by_event(ee, evt.ptr, evt.len, &count));
    try std.testing.expectEqual(@as(u64, 1), count);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_off(ee, evt.ptr, evt.len, cb1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_listener_count(ee, evt.ptr, evt.len, &count));
    try std.testing.expectEqual(@as(u64, 0), count);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_prepend_listener(ee, evt.ptr, evt.len, cb1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_remove_all_listeners(ee, evt.ptr, evt.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_events_listener_count(ee, evt.ptr, evt.len, &count));
    try std.testing.expectEqual(@as(u64, 0), count);
}

test "node plugin dns lookup" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    const status = plugin.sa_node_plugin_dns_lookup("localhost", 9, &ptr, &len);
    try std.testing.expectEqual(@as(u32, 0), status);
    try std.testing.expect(ptr != null);
    try std.testing.expect(len > 0);
    const result = ptr.?[0..len];
    try std.testing.expect(std.mem.indexOf(u8, result, "127.0.0.1") != null);
    _ = plugin.sa_node_plugin_free_buffer(ptr, len);
}

test "node plugin dns lookup options" {
    var single_ptr: ?[*]const u8 = null;
    var single_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_lookup_options("localhost", 9, 4, 0, "ipv4first", 9, &single_ptr, &single_len));
    defer _ = plugin.sa_node_plugin_free_buffer(single_ptr, single_len);
    const single = (single_ptr orelse return error.NullDnsLookupOptionsSingle)[0..@intCast(single_len)];
    try std.testing.expect(std.mem.indexOf(u8, single, "\"address\":\"127.0.0.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, single, "\"family\":4") != null);

    var all_ptr: ?[*]const u8 = null;
    var all_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_lookup_options("localhost", 9, 4, 1, "verbatim", 8, &all_ptr, &all_len));
    defer _ = plugin.sa_node_plugin_free_buffer(all_ptr, all_len);
    const all = (all_ptr orelse return error.NullDnsLookupOptionsAll)[0..@intCast(all_len)];
    try std.testing.expect(std.mem.startsWith(u8, all, "["));
    try std.testing.expect(std.mem.indexOf(u8, all, "\"family\":4") != null);

    var promises_ptr: ?[*]const u8 = null;
    var promises_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_lookup_options("localhost", 9, 4, 0, null, 0, &promises_ptr, &promises_len));
    defer _ = plugin.sa_node_plugin_free_buffer(promises_ptr, promises_len);
    try std.testing.expect(std.mem.indexOf(u8, (promises_ptr orelse return error.NullDnsPromisesLookupOptions)[0..@intCast(promises_len)], "\"family\":4") != null);

    var hints_ptr: ?[*]const u8 = null;
    var hints_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_lookup_options_hints("localhost", 9, 4, 1, 0, "verbatim", 8, &hints_ptr, &hints_len));
    defer _ = plugin.sa_node_plugin_free_buffer(hints_ptr, hints_len);
    try std.testing.expect(std.mem.indexOf(u8, (hints_ptr orelse return error.NullDnsLookupOptionsHints)[0..@intCast(hints_len)], "\"family\":4") != null);

    var promises_hints_ptr: ?[*]const u8 = null;
    var promises_hints_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_lookup_options_hints("localhost", 9, 4, 0, 0, null, 0, &promises_hints_ptr, &promises_hints_len));
    defer _ = plugin.sa_node_plugin_free_buffer(promises_hints_ptr, promises_hints_len);
    try std.testing.expect(std.mem.indexOf(u8, (promises_hints_ptr orelse return error.NullDnsPromisesLookupOptionsHints)[0..@intCast(promises_hints_len)], "\"family\":4") != null);

    try std.testing.expect(plugin.sa_node_plugin_dns_lookup_options("localhost", 9, 5, 0, null, 0, &single_ptr, &single_len) != 0);
    try std.testing.expect(plugin.sa_node_plugin_dns_lookup_options("localhost", 9, 4, 0, "bad", 3, &single_ptr, &single_len) != 0);
    try std.testing.expect(plugin.sa_node_plugin_dns_lookup_options_hints("localhost", 9, 4, 0, 0x80000000, null, 0, &single_ptr, &single_len) != 0);
}

test "node plugin dns constants" {
    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_constants_json(&constants_ptr, &constants_len));
    defer _ = plugin.sa_node_plugin_free_buffer(constants_ptr, constants_len);
    const constants_json = (constants_ptr orelse return error.NullDnsConstants)[0..@intCast(constants_len)];
    var constants = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, constants_json, .{});
    defer constants.deinit();
    try std.testing.expectEqual(@as(i64, 32), constants.value.object.get("ADDRCONFIG").?.integer);
    try std.testing.expectEqual(@as(i64, 8), constants.value.object.get("V4MAPPED").?.integer);
    try std.testing.expectEqual(@as(i64, 16), constants.value.object.get("ALL").?.integer);
    try std.testing.expectEqualStrings("ENOTFOUND", constants.value.object.get("NOTFOUND").?.string);
    try std.testing.expectEqualStrings("ECANCELLED", constants.value.object.get("CANCELLED").?.string);

    var promises_ptr: ?[*]const u8 = null;
    var promises_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_constants_json(&promises_ptr, &promises_len));
    defer _ = plugin.sa_node_plugin_free_buffer(promises_ptr, promises_len);
    try std.testing.expectEqualStrings(constants_json, (promises_ptr orelse return error.NullDnsPromisesConstants)[0..@intCast(promises_len)]);
}

test "node plugin dns resolve4 returns plain addresses" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    const status = plugin.sa_node_plugin_dns_resolve4("localhost", 9, &ptr, &len);
    try std.testing.expectEqual(@as(u32, 0), status);
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);
    const result = (ptr orelse return error.NullDnsResult)[0..@intCast(len)];
    try std.testing.expect(std.mem.indexOf(u8, result, "127.0.0.1") != null or std.mem.indexOf(u8, result, "::1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, ":0") == null);
}

test "node plugin dns resolver settings use system data" {
    var servers_ptr: ?[*]const u8 = null;
    var servers_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_get_servers(&servers_ptr, &servers_len));
    defer _ = plugin.sa_node_plugin_free_buffer(servers_ptr, servers_len);
    const servers = (servers_ptr orelse return error.NullDnsServers)[0..@intCast(servers_len)];
    try std.testing.expect(std.mem.startsWith(u8, servers, "["));
    try std.testing.expect(std.mem.endsWith(u8, servers, "]"));

    var order_ptr: ?[*]const u8 = null;
    var order_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_get_default_result_order(&order_ptr, &order_len));
    defer _ = plugin.sa_node_plugin_free_buffer(order_ptr, order_len);
    try std.testing.expectEqualStrings("\"verbatim\"", (order_ptr orelse return error.NullDnsOrder)[0..@intCast(order_len)]);
}

test "node plugin dns resolver settings are stateful" {
    const servers_json = "[\"127.0.0.1\",\"[::1]:5353\",\"8.8.8.8:53\"]";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_set_servers(servers_json.ptr, servers_json.len));

    var servers_ptr: ?[*]const u8 = null;
    var servers_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_get_servers(&servers_ptr, &servers_len));
    defer _ = plugin.sa_node_plugin_free_buffer(servers_ptr, servers_len);
    try std.testing.expectEqualStrings(servers_json, (servers_ptr orelse return error.NullDnsServers)[0..@intCast(servers_len)]);

    const invalid_servers = "[\"example.com\"]";
    try std.testing.expect(plugin.sa_node_plugin_dns_set_servers(invalid_servers.ptr, invalid_servers.len) != 0);
    try std.testing.expect(plugin.sa_node_plugin_dns_set_servers(null, 0) != 0);

    const order = "ipv6first";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_set_default_result_order(order.ptr, order.len));

    var order_ptr: ?[*]const u8 = null;
    var order_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_get_default_result_order(&order_ptr, &order_len));
    defer _ = plugin.sa_node_plugin_free_buffer(order_ptr, order_len);
    try std.testing.expectEqualStrings("\"ipv6first\"", (order_ptr orelse return error.NullDnsOrder)[0..@intCast(order_len)]);

    const bad_order = "random";
    try std.testing.expect(plugin.sa_node_plugin_dns_set_default_result_order(bad_order.ptr, bad_order.len) != 0);
    try std.testing.expect(plugin.sa_node_plugin_dns_set_default_result_order(null, 0) != 0);
}

test "node plugin dns resolver instances keep independent settings" {
    const dns_sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(dns_sock);
    const bind_addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try std.posix.bind(dns_sock, &bind_addr.any, bind_addr.getOsSockLen());
    var sock_addr: std.net.Address = undefined;
    var sock_len: std.posix.socklen_t = @sizeOf(std.net.Address);
    try std.posix.getsockname(dns_sock, &sock_addr.any, &sock_len);

    const dns_thread = try std.Thread.spawn(.{}, struct {
        fn run(fd: std.posix.socket_t) void {
            var query_buf: [512]u8 = undefined;
            var peer: std.net.Address = undefined;
            var peer_len: std.posix.socklen_t = @sizeOf(std.net.Address);
            const n = std.posix.recvfrom(fd, &query_buf, 0, &peer.any, &peer_len) catch return;
            if (n < 12) return;
            var q_end: usize = 12;
            while (q_end < n and query_buf[q_end] != 0) : (q_end += 1) {}
            if (q_end + 5 > n) return;
            const question = query_buf[12 .. q_end + 5];

            var response = std.ArrayList(u8).init(std.heap.page_allocator);
            defer response.deinit();
            response.appendSlice(query_buf[0..2]) catch return;
            response.writer().writeInt(u16, 0x8180, .big) catch return;
            response.writer().writeInt(u16, 1, .big) catch return;
            response.writer().writeInt(u16, 1, .big) catch return;
            response.writer().writeInt(u16, 0, .big) catch return;
            response.writer().writeInt(u16, 0, .big) catch return;
            response.appendSlice(question) catch return;
            writeDnsNameForTest(&response, "custom.local") catch return;
            response.writer().writeInt(u16, 1, .big) catch return;
            response.writer().writeInt(u16, 1, .big) catch return;
            response.writer().writeInt(u32, 30, .big) catch return;
            response.writer().writeInt(u16, 4, .big) catch return;
            response.appendSlice(&.{ 203, 0, 113, 7 }) catch return;
            _ = std.posix.sendto(fd, response.items, 0, &peer.any, peer_len) catch return;
        }
    }.run, .{dns_sock});

    var resolver: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolver_new(2500, 3, &resolver));
    defer _ = plugin.sa_node_plugin_dns_resolver_free(resolver);

    const servers_json = try std.fmt.allocPrint(std.testing.allocator, "[\"127.0.0.1:{d}\"]", .{sock_addr.getPort()});
    defer std.testing.allocator.free(servers_json);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolver_set_servers(resolver, servers_json.ptr, servers_json.len));

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolver_set_local_address(resolver, "127.0.0.1", 9, "::1", 3));
    try std.testing.expect(plugin.sa_node_plugin_dns_resolver_set_local_address(resolver, "999.0.0.1", 9, "::1", 3) != 0);
    try std.testing.expect(plugin.sa_node_plugin_dns_resolver_set_local_address(resolver, "127.0.0.1", 9, "bad::ip::", 9) != 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolver_cancel(resolver));

    var servers_ptr: ?[*]const u8 = null;
    var servers_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolver_get_servers(resolver, &servers_ptr, &servers_len));
    defer _ = plugin.sa_node_plugin_free_buffer(servers_ptr, servers_len);
    try std.testing.expectEqualStrings(servers_json, (servers_ptr orelse return error.NullResolverServers)[0..@intCast(servers_len)]);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolver_snapshot_json(resolver, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullResolverSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"timeoutMs\":2500") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"tries\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"usesSystemServers\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"localAddress\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "127.0.0.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "::1") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"cancelCount\":1") != null);

    var addresses_ptr: ?[*]const u8 = null;
    var addresses_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolver_resolve4(resolver, "custom.local", 12, &addresses_ptr, &addresses_len));
    defer _ = plugin.sa_node_plugin_free_buffer(addresses_ptr, addresses_len);
    const addresses = (addresses_ptr orelse return error.NullResolverResolve4)[0..@intCast(addresses_len)];
    try std.testing.expect(std.mem.indexOf(u8, addresses, "203.0.113.7") != null);
    dns_thread.join();

    var system_resolver: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolver_new(0, 0, &system_resolver));
    defer _ = plugin.sa_node_plugin_dns_resolver_free(system_resolver);

    var generic_ptr: ?[*]const u8 = null;
    var generic_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolver_resolve(system_resolver, "localhost", 9, "A", 1, &generic_ptr, &generic_len));
    defer _ = plugin.sa_node_plugin_free_buffer(generic_ptr, generic_len);
    try std.testing.expect(generic_len >= 2);

    try std.testing.expect(plugin.sa_node_plugin_dns_resolver_resolve(system_resolver, "localhost", 9, "BADTYPE", 7, &generic_ptr, &generic_len) != 0);

    var promise_resolver: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolver_new(0, 0, &promise_resolver));
    defer _ = plugin.sa_node_plugin_dns_promises_resolver_free(promise_resolver);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolver_set_local_address(promise_resolver, "127.0.0.1", 9, "", 0));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolver_cancel(promise_resolver));

    var promise_snapshot_ptr: ?[*]const u8 = null;
    var promise_snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolver_snapshot_json(promise_resolver, &promise_snapshot_ptr, &promise_snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(promise_snapshot_ptr, promise_snapshot_len);
    const promise_snapshot = (promise_snapshot_ptr orelse return error.NullDnsPromisesResolverSnapshot)[0..@intCast(promise_snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, promise_snapshot, "127.0.0.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, promise_snapshot, "\"cancelCount\":1") != null);
}

test "node plugin dns promises helpers" {
    var servers_ptr: ?[*]const u8 = null;
    var servers_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_get_servers(&servers_ptr, &servers_len));
    defer _ = plugin.sa_node_plugin_free_buffer(servers_ptr, servers_len);
    try std.testing.expect((servers_ptr orelse return error.NullDnsPromisesGetServers)[0] == '[');
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_set_servers(servers_ptr, servers_len));

    var order_ptr: ?[*]const u8 = null;
    var order_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_get_default_result_order(&order_ptr, &order_len));
    defer _ = plugin.sa_node_plugin_free_buffer(order_ptr, order_len);
    const order = (order_ptr orelse return error.NullDnsPromisesDefaultOrder)[0..@intCast(order_len)];
    try std.testing.expect(std.mem.indexOf(u8, order, "verbatim") != null or std.mem.indexOf(u8, order, "ipv4first") != null or std.mem.indexOf(u8, order, "ipv6first") != null);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_set_default_result_order("verbatim", 8));
    try std.testing.expect(plugin.sa_node_plugin_dns_promises_set_default_result_order("bad", 3) != 0);

    var lookup_ptr: ?[*]const u8 = null;
    var lookup_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_lookup("localhost", 9, &lookup_ptr, &lookup_len));
    defer _ = plugin.sa_node_plugin_free_buffer(lookup_ptr, lookup_len);
    const lookup = (lookup_ptr orelse return error.NullDnsPromisesLookup)[0..@intCast(lookup_len)];
    try std.testing.expect(std.mem.indexOf(u8, lookup, "127.0.0.1") != null or std.mem.indexOf(u8, lookup, "::1") != null);

    var resolve4_ptr: ?[*]const u8 = null;
    var resolve4_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve4("localhost", 9, &resolve4_ptr, &resolve4_len));
    defer _ = plugin.sa_node_plugin_free_buffer(resolve4_ptr, resolve4_len);
    const resolve4 = (resolve4_ptr orelse return error.NullDnsPromisesResolve4)[0..@intCast(resolve4_len)];
    try std.testing.expect(std.mem.indexOf(u8, resolve4, "127.0.0.1") != null);

    var generic_ptr: ?[*]const u8 = null;
    var generic_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve("localhost", 9, "A", 1, &generic_ptr, &generic_len));
    defer _ = plugin.sa_node_plugin_free_buffer(generic_ptr, generic_len);
    const generic = (generic_ptr orelse return error.NullDnsPromisesResolve)[0..@intCast(generic_len)];
    try std.testing.expect(std.mem.indexOf(u8, generic, "127.0.0.1") != null);

    var any_ptr: ?[*]const u8 = null;
    var any_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve_any("localhost", 9, &any_ptr, &any_len));
    defer _ = plugin.sa_node_plugin_free_buffer(any_ptr, any_len);
    try std.testing.expect(std.mem.startsWith(u8, (any_ptr orelse return error.NullDnsPromisesResolveAny)[0..@intCast(any_len)], "["));

    var cname_ptr: ?[*]const u8 = null;
    var cname_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve_cname("www.github.com", 14, &cname_ptr, &cname_len));
    defer _ = plugin.sa_node_plugin_free_buffer(cname_ptr, cname_len);
    try std.testing.expect(std.mem.startsWith(u8, (cname_ptr orelse return error.NullDnsPromisesResolveCname)[0..@intCast(cname_len)], "["));

    var mx_ptr: ?[*]const u8 = null;
    var mx_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve_mx("gmail.com", 9, &mx_ptr, &mx_len));
    defer _ = plugin.sa_node_plugin_free_buffer(mx_ptr, mx_len);
    try std.testing.expect(std.mem.indexOf(u8, (mx_ptr orelse return error.NullDnsPromisesResolveMx)[0..@intCast(mx_len)], "\"exchange\":") != null);

    var ns_ptr: ?[*]const u8 = null;
    var ns_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve_ns("nodejs.org", 10, &ns_ptr, &ns_len));
    defer _ = plugin.sa_node_plugin_free_buffer(ns_ptr, ns_len);
    try std.testing.expect(std.mem.startsWith(u8, (ns_ptr orelse return error.NullDnsPromisesResolveNs)[0..@intCast(ns_len)], "["));

    var txt_ptr: ?[*]const u8 = null;
    var txt_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve_txt("gmail.com", 9, &txt_ptr, &txt_len));
    defer _ = plugin.sa_node_plugin_free_buffer(txt_ptr, txt_len);
    try std.testing.expect(std.mem.startsWith(u8, (txt_ptr orelse return error.NullDnsPromisesResolveTxt)[0..@intCast(txt_len)], "["));

    const srv_name = "_xmpp-server._tcp.gmail.com";
    var srv_ptr: ?[*]const u8 = null;
    var srv_len: u64 = 0;
    _ = plugin.sa_node_plugin_dns_promises_resolve_srv(srv_name, srv_name.len, &srv_ptr, &srv_len);
    if (srv_ptr != null) {
        defer _ = plugin.sa_node_plugin_free_buffer(srv_ptr, srv_len);
    }

    var ptr_ptr: ?[*]const u8 = null;
    var ptr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve_ptr("8.8.8.8", 7, &ptr_ptr, &ptr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr_ptr, ptr_len);
    try std.testing.expect(std.mem.startsWith(u8, (ptr_ptr orelse return error.NullDnsPromisesResolvePtr)[0..@intCast(ptr_len)], "["));

    var soa_ptr: ?[*]const u8 = null;
    var soa_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve_soa("nodejs.org", 10, &soa_ptr, &soa_len));
    defer _ = plugin.sa_node_plugin_free_buffer(soa_ptr, soa_len);
    try std.testing.expect(std.mem.indexOf(u8, (soa_ptr orelse return error.NullDnsPromisesResolveSoa)[0..@intCast(soa_len)], "\"serial\":") != null);

    var caa_ptr: ?[*]const u8 = null;
    var caa_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolve_caa("cloudflare.com", 14, &caa_ptr, &caa_len));
    defer _ = plugin.sa_node_plugin_free_buffer(caa_ptr, caa_len);
    try std.testing.expect(std.mem.startsWith(u8, (caa_ptr orelse return error.NullDnsPromisesResolveCaa)[0..@intCast(caa_len)], "["));

    var service_ptr: ?[*]const u8 = null;
    var service_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_lookup_service("127.0.0.1", 9, 80, &service_ptr, &service_len));
    defer _ = plugin.sa_node_plugin_free_buffer(service_ptr, service_len);
    const service = (service_ptr orelse return error.NullDnsPromisesLookupService)[0..@intCast(service_len)];
    try std.testing.expect(std.mem.indexOf(u8, service, "localhost") != null or std.mem.indexOf(u8, service, "http") != null);

    var resolver: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolver_new(1000, 2, &resolver));
    defer _ = plugin.sa_node_plugin_dns_promises_resolver_free(resolver);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolver_snapshot_json(resolver, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullDnsPromisesSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"timeoutMs\":1000") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"tries\":2") != null);

    var resolver_ptr: ?[*]const u8 = null;
    var resolver_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_promises_resolver_resolve4(resolver, "localhost", 9, &resolver_ptr, &resolver_len));
    defer _ = plugin.sa_node_plugin_free_buffer(resolver_ptr, resolver_len);
    const resolver_result = (resolver_ptr orelse return error.NullDnsPromisesResolverResolve4)[0..@intCast(resolver_len)];
    try std.testing.expect(std.mem.indexOf(u8, resolver_result, "127.0.0.1") != null);
}

test "node plugin dns lookup service" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_lookup_service("127.0.0.1", 9, 80, &ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);

    const result = (ptr orelse return error.NullDnsLookupService)[0..@intCast(len)];
    try std.testing.expect(std.mem.indexOf(u8, result, "\"hostname\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"service\":") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, result, "80") != null or
            std.mem.indexOf(u8, result, "http") != null or
            std.mem.indexOf(u8, result, "domain") != null,
    );
}

test "node plugin dns resolve any" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolve_any("localhost", 9, &ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);

    const result = (ptr orelse return error.NullDnsResolveAny)[0..@intCast(len)];
    try std.testing.expect(std.mem.startsWith(u8, result, "["));
    try std.testing.expect(std.mem.endsWith(u8, result, "]"));
    try std.testing.expect(std.mem.indexOfAny(u8, result, "0123456789") != null);
}

test "node plugin dns resolve soa" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolve_soa("nodejs.org", 10, &ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);

    const result = (ptr orelse return error.NullDnsResolveSoa)[0..@intCast(len)];
    try std.testing.expect(std.mem.startsWith(u8, result, "["));
    try std.testing.expect(std.mem.indexOf(u8, result, "\"nsname\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"hostmaster\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"serial\":") != null);
}

test "node plugin dns resolve caa" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolve_caa("cloudflare.com", 14, &ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);

    const result = (ptr orelse return error.NullDnsResolveCaa)[0..@intCast(len)];
    try std.testing.expect(std.mem.startsWith(u8, result, "["));
    try std.testing.expect(std.mem.endsWith(u8, result, "]"));
    try std.testing.expect(std.mem.indexOf(u8, result, "\"critical\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"type\":\"CAA\"") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, result, "\"issue\":") != null or
            std.mem.indexOf(u8, result, "\"issuewild\":") != null or
            std.mem.indexOf(u8, result, "\"iodef\":") != null,
    );
}

test "node plugin dns resolve naptr" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolve_naptr("sip2sip.info", 12, &ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);

    const result = (ptr orelse return error.NullDnsResolveNaptr)[0..@intCast(len)];
    try std.testing.expect(std.mem.startsWith(u8, result, "["));
    try std.testing.expect(std.mem.endsWith(u8, result, "]"));
    try std.testing.expect(std.mem.indexOf(u8, result, "\"flags\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"service\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"regexp\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"replacement\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"order\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"preference\":") != null);
}

test "node plugin dns resolve tlsa" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dns_resolve_tlsa("_443._tcp.www.nic.cz", 20, &ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);

    const result = (ptr orelse return error.NullDnsResolveTlsa)[0..@intCast(len)];
    try std.testing.expect(std.mem.startsWith(u8, result, "["));
    try std.testing.expect(std.mem.endsWith(u8, result, "]"));
    try std.testing.expect(std.mem.indexOf(u8, result, "\"certUsage\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"selector\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"match\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"data\":") != null);
}

test "node plugin punycode to ascii" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    const input = "mañana.com";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_punycode_to_ascii(input.ptr, input.len, &ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);
    try std.testing.expectEqualStrings("xn--maana-pta.com", (ptr orelse return error.NullPunycodeAscii)[0..@intCast(len)]);
}

test "node plugin punycode to unicode" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    const input = "xn--maana-pta.com";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_punycode_to_unicode(input.ptr, input.len, &ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);
    try std.testing.expectEqualStrings("mañana.com", (ptr orelse return error.NullPunycodeUnicode)[0..@intCast(len)]);
}

test "node plugin dns reverse ipv6 helper" {
    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();

    try plugin.dnsReverseName("2001:db8::1", &out);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ip6.arpa") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "1.0.0.0") != null);
}

test "node plugin buffer resolve object url" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    const input = "blob:https://example.com/uuid";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_buffer_resolve_object_url(input.ptr, input.len, &ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);
    try std.testing.expectEqualStrings("https://example.com/uuid", (ptr orelse return error.NullResolvedObjectUrl)[0..@intCast(len)]);
}

test "node plugin buffer base64 and byte checks" {
    {
        var out_ptr: ?[*]const u8 = null;
        var out_len: u64 = 0;
        try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_buffer_atob("aGVsbG8=", 8, &out_ptr, &out_len));
        defer _ = plugin.sa_node_plugin_free_buffer(out_ptr, out_len);
        try std.testing.expectEqualStrings("hello", (out_ptr orelse return error.NullAtob)[0..@intCast(out_len)]);
    }

    {
        var out_ptr: ?[*]const u8 = null;
        var out_len: u64 = 0;
        try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_buffer_btoa("hello", 5, &out_ptr, &out_len));
        defer _ = plugin.sa_node_plugin_free_buffer(out_ptr, out_len);
        try std.testing.expectEqualStrings("aGVsbG8=", (out_ptr orelse return error.NullBtoa)[0..@intCast(out_len)]);
    }

    var is_utf8: u32 = 0;
    var is_ascii: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_buffer_is_utf8("hello", 5, &is_utf8));
    try std.testing.expectEqual(@as(u32, 1), is_utf8);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_buffer_is_ascii("hello", 5, &is_ascii));
    try std.testing.expectEqual(@as(u32, 1), is_ascii);

    {
        var out_ptr: ?[*]const u8 = null;
        var out_len: u64 = 0;
        try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_buffer_transcode("hello", 5, "utf8", 4, "utf16le", 7, &out_ptr, &out_len));
        defer _ = plugin.sa_node_plugin_free_buffer(out_ptr, out_len);
        const out = (out_ptr orelse return error.NullUtf16Transcode)[0..@intCast(out_len)];
        try std.testing.expectEqualSlices(u8, &.{ 'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0 }, out);
    }

    {
        const utf16 = [_]u8{ 'h', 0, 'i', 0 };
        var out_ptr: ?[*]const u8 = null;
        var out_len: u64 = 0;
        try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_buffer_transcode(&utf16, utf16.len, "utf16le", 7, "utf8", 4, &out_ptr, &out_len));
        defer _ = plugin.sa_node_plugin_free_buffer(out_ptr, out_len);
        try std.testing.expectEqualStrings("hi", (out_ptr orelse return error.NullUtf8Transcode)[0..@intCast(out_len)]);
    }

    {
        var out_ptr: ?[*]const u8 = null;
        var out_len: u64 = 0;
        try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_buffer_transcode("hello", 5, "utf8", 4, "base64", 6, &out_ptr, &out_len));
        defer _ = plugin.sa_node_plugin_free_buffer(out_ptr, out_len);
        try std.testing.expectEqualStrings("aGVsbG8=", (out_ptr orelse return error.NullBase64Transcode)[0..@intCast(out_len)]);
    }

    {
        var out_ptr: ?[*]const u8 = null;
        var out_len: u64 = 0;
        try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_buffer_transcode("6869", 4, "hex", 3, "utf8", 4, &out_ptr, &out_len));
        defer _ = plugin.sa_node_plugin_free_buffer(out_ptr, out_len);
        try std.testing.expectEqualStrings("hi", (out_ptr orelse return error.NullHexTranscode)[0..@intCast(out_len)]);
    }
}

test "node plugin web crypto sync helpers" {
    var random_buf: [32]u8 = .{0} ** 32;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_get_random_values(&random_buf, random_buf.len));
    try std.testing.expect(!std.mem.allEqual(u8, random_buf[0..], 0));

    var uuid_ptr: ?[*]const u8 = null;
    var uuid_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_random_uuid(&uuid_ptr, &uuid_len));
    defer _ = plugin.sa_node_plugin_free_buffer(uuid_ptr, uuid_len);
    const uuid = (uuid_ptr orelse return error.NullWebCryptoUuid)[0..@intCast(uuid_len)];
    try std.testing.expectEqual(@as(usize, 36), uuid.len);
    try std.testing.expect(uuid[8] == '-' and uuid[13] == '-' and uuid[18] == '-' and uuid[23] == '-');

    var digest_ptr: ?[*]const u8 = null;
    var digest_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_digest("sha-256", 7, "abc", 3, &digest_ptr, &digest_len));
    defer _ = plugin.sa_node_plugin_free_buffer(digest_ptr, digest_len);
    const digest = (digest_ptr orelse return error.NullWebCryptoDigest)[0..@intCast(digest_len)];
    var hex_buf: [64]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(digest)}) catch return error.WebCryptoHex;
    try std.testing.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex);
}

test "node plugin crypto scrypt derives RFC 7914 vector" {
    var out_ptr: ?[*]const u8 = null;
    try std.testing.expectEqual(
        @as(u32, 0),
        plugin.sa_node_plugin_crypto_scrypt("password".ptr, 8, "NaCl".ptr, 4, 1024, 8, 16, 64, &out_ptr),
    );
    defer _ = plugin.sa_node_plugin_free_buffer(out_ptr, 64);

    const out = (out_ptr orelse return error.NullScryptOut)[0..64];
    var hex_buf: [128]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(out)}) catch return error.ScryptHex;
    try std.testing.expectEqualStrings(
        "fdbabe1c9d3472007856e7190d01e9fe" ++
            "7c6ad7cbc8237830e77376634b373162" ++
            "2eaf30d92e22a3886ff109279d9830da" ++
            "c727afb94a83ee6d8360cbdfa2cc0640",
        hex,
    );
}

test "node plugin web crypto key encrypt sign helpers" {
    var hmac_key: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_import_key_raw("HMAC".ptr, 4, "sign".ptr, 4, "secret".ptr, 6, &hmac_key));
    defer _ = plugin.sa_node_plugin_web_crypto_key_free(hmac_key);

    var mac_ptr: ?[*]const u8 = null;
    var mac_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_sign(hmac_key, "payload".ptr, 7, &mac_ptr, &mac_len));
    defer _ = plugin.sa_node_plugin_free_buffer(mac_ptr, mac_len);
    try std.testing.expectEqual(@as(u64, 32), mac_len);

    var mac_ok: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_verify(hmac_key, "payload".ptr, 7, mac_ptr, mac_len, &mac_ok));
    try std.testing.expectEqual(@as(u32, 1), mac_ok);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_verify(hmac_key, "tamper".ptr, 6, mac_ptr, mac_len, &mac_ok));
    try std.testing.expectEqual(@as(u32, 0), mac_ok);

    var seed: [32]u8 = [_]u8{0x42} ** 32;
    var ed_private: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_import_key_raw("Ed25519".ptr, 7, "sign".ptr, 4, &seed, seed.len, &ed_private));
    defer _ = plugin.sa_node_plugin_web_crypto_key_free(ed_private);

    var public_ptr: ?[*]const u8 = null;
    var public_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_export_public_key_raw(ed_private, &public_ptr, &public_len));
    defer _ = plugin.sa_node_plugin_free_buffer(public_ptr, public_len);
    try std.testing.expectEqual(@as(u64, 32), public_len);

    var ed_public: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_import_key_raw("Ed25519".ptr, 7, "verify".ptr, 6, public_ptr, public_len, &ed_public));
    defer _ = plugin.sa_node_plugin_web_crypto_key_free(ed_public);

    var sig_ptr: ?[*]const u8 = null;
    var sig_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_sign(ed_private, "message".ptr, 7, &sig_ptr, &sig_len));
    defer _ = plugin.sa_node_plugin_free_buffer(sig_ptr, sig_len);
    try std.testing.expectEqual(@as(u64, 64), sig_len);

    var verified: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_verify(ed_public, "message".ptr, 7, sig_ptr, sig_len, &verified));
    try std.testing.expectEqual(@as(u32, 1), verified);

    var aes_key: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_generate_key("AES-GCM".ptr, 7, "encrypt".ptr, 7, 256, &aes_key));
    defer _ = plugin.sa_node_plugin_web_crypto_key_free(aes_key);

    const iv = [_]u8{0x11} ** 12;
    const aad = "aad";
    var encrypted_ptr: ?[*]const u8 = null;
    var encrypted_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_encrypt(aes_key, &iv, iv.len, aad.ptr, aad.len, "plain".ptr, 5, &encrypted_ptr, &encrypted_len));
    defer _ = plugin.sa_node_plugin_free_buffer(encrypted_ptr, encrypted_len);
    try std.testing.expectEqual(@as(u64, 21), encrypted_len);

    var decrypted_ptr: ?[*]const u8 = null;
    var decrypted_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_crypto_decrypt(aes_key, &iv, iv.len, aad.ptr, aad.len, encrypted_ptr, encrypted_len, &decrypted_ptr, &decrypted_len));
    defer _ = plugin.sa_node_plugin_free_buffer(decrypted_ptr, decrypted_len);
    try std.testing.expectEqualStrings("plain", (decrypted_ptr orelse return error.NullWebCryptoDecrypt)[0..@intCast(decrypted_len)]);
}

test "node plugin worker resource limits report process limits" {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_resource_limits_json(&ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);

    const json = (ptr orelse return error.NullWorkerResourceLimits)[0..@intCast(len)];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"maxOldGenerationSizeMb\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"maxYoungGenerationSizeMb\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"codeRangeSizeMb\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"stackSizeMb\":") != null);
}

test "node plugin sea assets from environment provider" {
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_SEA_ASSETS", "{\"test-key\":\"hello\",\"num\":7}", 1));
    defer _ = unsetenv("SA_NODE_SEA_ASSETS");
    defer _ = unsetenv("SA_NODE_SEA_ASSET_DIR");

    var is_sea: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sea_is_sea(&is_sea));
    try std.testing.expectEqual(@as(u32, 1), is_sea);

    var keys_ptr: ?[*]const u8 = null;
    var keys_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sea_asset_keys_json(&keys_ptr, &keys_len));
    defer _ = plugin.sa_node_plugin_free_buffer(keys_ptr, keys_len);
    const keys = (keys_ptr orelse return error.NullSeaKeys)[0..@intCast(keys_len)];
    try std.testing.expect(std.mem.indexOf(u8, keys, "test-key") != null);

    var raw_ptr: ?[*]const u8 = null;
    var raw_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sea_get_raw_asset("test-key".ptr, 8, &raw_ptr, &raw_len));
    defer _ = plugin.sa_node_plugin_free_buffer(raw_ptr, raw_len);
    try std.testing.expectEqualStrings("hello", (raw_ptr orelse return error.NullSeaRaw)[0..@intCast(raw_len)]);

    var asset_ptr: ?[*]const u8 = null;
    var asset_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sea_get_asset("test-key".ptr, 8, "base64".ptr, 6, &asset_ptr, &asset_len));
    defer _ = plugin.sa_node_plugin_free_buffer(asset_ptr, asset_len);
    try std.testing.expectEqualStrings("aGVsbG8=", (asset_ptr orelse return error.NullSeaAsset)[0..@intCast(asset_len)]);

    var blob: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sea_get_asset_as_blob("test-key".ptr, 8, &blob));
    defer _ = plugin.sa_node_plugin_web_streams_free(blob);
    try std.testing.expect(blob != null);

    var missing_ptr: ?[*]const u8 = null;
    var missing_len: u64 = 0;
    try std.testing.expect(plugin.sa_node_plugin_sea_get_raw_asset("missing".ptr, 7, &missing_ptr, &missing_len) != 0);
}

test "node plugin sqlite native helpers" {
    var version_ptr: ?[*]const u8 = null;
    var version_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_version_json(&version_ptr, &version_len));
    defer _ = plugin.sa_node_plugin_free_buffer(version_ptr, version_len);
    const version = (version_ptr orelse return error.NullSqliteVersion)[0..@intCast(version_len)];
    try std.testing.expect(std.mem.indexOf(u8, version, "sqlite") != null);

    const uri = "file:node-plugin-test?mode=memory&cache=shared";
    var db: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_open(uri.ptr, uri.len, &db));
    defer _ = plugin.sa_node_plugin_sqlite_close(db);

    const ddl = "CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, n INTEGER);";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_exec(db, ddl.ptr, ddl.len));
    const insert = "INSERT INTO t(name,n) VALUES ('alpha', 7), ('beta', 9);";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_exec(db, insert.ptr, insert.len));

    var changes: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_changes(db, &changes));
    try std.testing.expectEqual(@as(u64, 2), changes);
    var rowid: i64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_last_insert_rowid(db, &rowid));
    try std.testing.expect(rowid >= 2);

    var rows_ptr: ?[*]const u8 = null;
    var rows_len: u64 = 0;
    const query = "SELECT name,n FROM t ORDER BY id";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_query_json(db, query.ptr, query.len, &rows_ptr, &rows_len));
    defer _ = plugin.sa_node_plugin_free_buffer(rows_ptr, rows_len);
    const rows = (rows_ptr orelse return error.NullSqliteRows)[0..@intCast(rows_len)];
    try std.testing.expect(std.mem.indexOf(u8, rows, "\"name\":\"alpha\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rows, "\"n\":9") != null);

    var stmt: ?*anyopaque = null;
    const stmt_sql = "SELECT id,name FROM t ORDER BY id";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_prepare(db, stmt_sql.ptr, stmt_sql.len, &stmt));
    defer _ = plugin.sa_node_plugin_sqlite_finalize(stmt);

    var ready: u32 = 0;
    var row_ptr: ?[*]const u8 = null;
    var row_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_step_json(stmt, &ready, &row_ptr, &row_len));
    defer _ = plugin.sa_node_plugin_free_buffer(row_ptr, row_len);
    try std.testing.expectEqual(@as(u32, 1), ready);
    const first = (row_ptr orelse return error.NullSqliteStepRow)[0..@intCast(row_len)];
    try std.testing.expect(std.mem.indexOf(u8, first, "\"alpha\"") != null);

    const bind_ddl = "CREATE TABLE bound(name TEXT, n INTEGER, r REAL, data BLOB, maybe TEXT);";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_exec(db, bind_ddl.ptr, bind_ddl.len));

    var insert_stmt: ?*anyopaque = null;
    const bind_sql = "INSERT INTO bound(name,n,r,data,maybe) VALUES (?1,?2,?3,?4,?5);";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_prepare(db, bind_sql.ptr, bind_sql.len, &insert_stmt));
    defer _ = plugin.sa_node_plugin_sqlite_finalize(insert_stmt);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_text(insert_stmt, 1, "gamma".ptr, 5));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_int(insert_stmt, 2, 11));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_double(insert_stmt, 3, 2.5));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_blob(insert_stmt, 4, "bin".ptr, 3));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_null(insert_stmt, 5));
    var done_ptr: ?[*]const u8 = null;
    var done_len: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_step_json(insert_stmt, &ready, &done_ptr, &done_len));
    try std.testing.expectEqual(@as(u32, 0), ready);
    try std.testing.expect(done_ptr == null);
    try std.testing.expectEqual(@as(u64, 0), done_len);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_reset(insert_stmt));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_clear_bindings(insert_stmt));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_text(insert_stmt, 1, "delta".ptr, 5));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_int(insert_stmt, 2, 12));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_double(insert_stmt, 3, 3.25));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_blob(insert_stmt, 4, "raw".ptr, 3));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_bind_text(insert_stmt, 5, "set".ptr, 3));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_step_json(insert_stmt, &ready, &done_ptr, &done_len));
    try std.testing.expectEqual(@as(u32, 0), ready);

    var bound_ptr: ?[*]const u8 = null;
    var bound_len: u64 = 0;
    const bound_query = "SELECT name,n,r,data,maybe FROM bound ORDER BY name";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_query_json(db, bound_query.ptr, bound_query.len, &bound_ptr, &bound_len));
    defer _ = plugin.sa_node_plugin_free_buffer(bound_ptr, bound_len);
    const bound = (bound_ptr orelse return error.NullSqliteBoundRows)[0..@intCast(bound_len)];
    try std.testing.expect(std.mem.indexOf(u8, bound, "\"name\":\"delta\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bound, "\"n\":12") != null);
    try std.testing.expect(std.mem.indexOf(u8, bound, "\"r\":3.25") != null);
    try std.testing.expect(std.mem.indexOf(u8, bound, "\"data\":\"Ymlu\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bound, "\"maybe\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, bound, "\"maybe\":\"set\"") != null);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const backup_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "backup.sqlite" });
    defer std.testing.allocator.free(backup_path);
    var copied_pages: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_backup_to_file(db, backup_path.ptr, backup_path.len, 1, &copied_pages));
    try std.testing.expect(copied_pages > 0);

    var backup_db: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_open(backup_path.ptr, backup_path.len, &backup_db));
    defer _ = plugin.sa_node_plugin_sqlite_close(backup_db);
    var backup_rows_ptr: ?[*]const u8 = null;
    var backup_rows_len: u64 = 0;
    const backup_query = "SELECT count(*) AS count FROM bound";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_query_json(backup_db, backup_query.ptr, backup_query.len, &backup_rows_ptr, &backup_rows_len));
    defer _ = plugin.sa_node_plugin_free_buffer(backup_rows_ptr, backup_rows_len);
    const backup_rows = (backup_rows_ptr orelse return error.NullSqliteBackupRows)[0..@intCast(backup_rows_len)];
    try std.testing.expect(std.mem.indexOf(u8, backup_rows, "\"count\":2") != null);

    const step_backup_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "step-backup.sqlite" });
    defer std.testing.allocator.free(step_backup_path);
    var backup_handle: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_backup_init(db, step_backup_path.ptr, step_backup_path.len, &backup_handle));
    defer _ = plugin.sa_node_plugin_sqlite_backup_finish(backup_handle);
    var remaining: u64 = 0;
    var pagecount: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_backup_remaining(backup_handle, &remaining, &pagecount));
    var backup_done: u32 = 0;
    while (backup_done == 0) {
        try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_backup_step(backup_handle, 1, &backup_done, &remaining, &pagecount));
    }
    try std.testing.expect(pagecount > 0);

    const session_table_sql = "CREATE TABLE sync_items(id INTEGER PRIMARY KEY, name TEXT);";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_exec(db, session_table_sql.ptr, session_table_sql.len));

    const target_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "changeset-target.sqlite" });
    defer std.testing.allocator.free(target_path);
    var target_db: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_open(target_path.ptr, target_path.len, &target_db));
    defer _ = plugin.sa_node_plugin_sqlite_close(target_db);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_exec(target_db, session_table_sql.ptr, session_table_sql.len));

    const patch_target_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "patchset-target.sqlite" });
    defer std.testing.allocator.free(patch_target_path);
    var patch_target_db: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_open(patch_target_path.ptr, patch_target_path.len, &patch_target_db));
    defer _ = plugin.sa_node_plugin_sqlite_close(patch_target_db);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_exec(patch_target_db, session_table_sql.ptr, session_table_sql.len));

    var session: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_session_create(db, "main".ptr, 4, "sync_items".ptr, 10, &session));
    defer _ = plugin.sa_node_plugin_sqlite_session_close(session);

    var session_empty: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_session_isempty(session, &session_empty));
    try std.testing.expectEqual(@as(u64, 1), session_empty);

    const session_insert_sql = "INSERT INTO sync_items(id,name) VALUES (1,'one'),(2,'two');";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_exec(db, session_insert_sql.ptr, session_insert_sql.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_session_isempty(session, &session_empty));
    try std.testing.expectEqual(@as(u64, 0), session_empty);

    var session_memory: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_session_memory_used(session, &session_memory));
    try std.testing.expect(session_memory > 0);

    var changeset_ptr: ?[*]const u8 = null;
    var changeset_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_session_changeset(session, &changeset_ptr, &changeset_len));
    defer _ = plugin.sa_node_plugin_free_buffer(changeset_ptr, changeset_len);
    try std.testing.expect(changeset_len > 0);

    var applied: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_apply_changeset(target_db, changeset_ptr, changeset_len, &applied));
    try std.testing.expectEqual(@as(u64, 1), applied);

    var target_rows_ptr: ?[*]const u8 = null;
    var target_rows_len: u64 = 0;
    const target_query = "SELECT id,name FROM sync_items ORDER BY id";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_query_json(target_db, target_query.ptr, target_query.len, &target_rows_ptr, &target_rows_len));
    defer _ = plugin.sa_node_plugin_free_buffer(target_rows_ptr, target_rows_len);
    const target_rows = (target_rows_ptr orelse return error.NullSqliteChangesetRows)[0..@intCast(target_rows_len)];
    try std.testing.expect(std.mem.indexOf(u8, target_rows, "\"name\":\"one\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, target_rows, "\"name\":\"two\"") != null);

    var patchset_ptr: ?[*]const u8 = null;
    var patchset_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_session_patchset(session, &patchset_ptr, &patchset_len));
    defer _ = plugin.sa_node_plugin_free_buffer(patchset_ptr, patchset_len);
    try std.testing.expect(patchset_len > 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_apply_changeset(patch_target_db, patchset_ptr, patchset_len, &applied));
    try std.testing.expectEqual(@as(u64, 1), applied);

    var tagstore: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_tagstore_new(db, 2, &tagstore));
    defer _ = plugin.sa_node_plugin_sqlite_tagstore_free(tagstore);

    const tag_insert = "INSERT INTO bound(name,n,r,data,maybe) VALUES (?1,?2,?3,?4,?5)";
    const tag_params = "[\"epsilon\",13,4.5,\"tag\",null]";
    var run_ptr: ?[*]const u8 = null;
    var run_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_tagstore_run(tagstore, tag_insert.ptr, tag_insert.len, tag_params.ptr, tag_params.len, &run_ptr, &run_len));
    defer _ = plugin.sa_node_plugin_free_buffer(run_ptr, run_len);
    const run_json = (run_ptr orelse return error.NullSqliteTagRun)[0..@intCast(run_len)];
    try std.testing.expect(std.mem.indexOf(u8, run_json, "\"changes\":1") != null);

    const tag_get = "SELECT name,n,maybe FROM bound WHERE name=?1";
    const get_params = "[\"epsilon\"]";
    var get_ptr: ?[*]const u8 = null;
    var get_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_tagstore_get(tagstore, tag_get.ptr, tag_get.len, get_params.ptr, get_params.len, &get_ptr, &get_len));
    defer _ = plugin.sa_node_plugin_free_buffer(get_ptr, get_len);
    const get_json = (get_ptr orelse return error.NullSqliteTagGet)[0..@intCast(get_len)];
    try std.testing.expect(std.mem.indexOf(u8, get_json, "\"name\":\"epsilon\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_json, "\"maybe\":null") != null);

    const tag_all = "SELECT name FROM bound WHERE n>=?1 ORDER BY n";
    const all_params = "[12]";
    var all_ptr: ?[*]const u8 = null;
    var all_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_tagstore_all(tagstore, tag_all.ptr, tag_all.len, all_params.ptr, all_params.len, &all_ptr, &all_len));
    defer _ = plugin.sa_node_plugin_free_buffer(all_ptr, all_len);
    const all_json = (all_ptr orelse return error.NullSqliteTagAll)[0..@intCast(all_len)];
    try std.testing.expect(std.mem.indexOf(u8, all_json, "\"name\":\"delta\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, all_json, "\"name\":\"epsilon\"") != null);

    var tag_snap_ptr: ?[*]const u8 = null;
    var tag_snap_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_tagstore_snapshot_json(tagstore, &tag_snap_ptr, &tag_snap_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tag_snap_ptr, tag_snap_len);
    const tag_snap = (tag_snap_ptr orelse return error.NullSqliteTagSnapshot)[0..@intCast(tag_snap_len)];
    try std.testing.expect(std.mem.indexOf(u8, tag_snap, "\"capacity\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, tag_snap, "\"size\":2") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_tagstore_clear(tagstore));
    var tag_empty_ptr: ?[*]const u8 = null;
    var tag_empty_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sqlite_tagstore_snapshot_json(tagstore, &tag_empty_ptr, &tag_empty_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tag_empty_ptr, tag_empty_len);
    const tag_empty = (tag_empty_ptr orelse return error.NullSqliteTagEmpty)[0..@intCast(tag_empty_len)];
    try std.testing.expect(std.mem.indexOf(u8, tag_empty, "\"size\":0") != null);
}

test "node plugin ffi native helpers" {
    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_ffi_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullFfiStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"supported\":true") != null);

    const libc = "libc.so.6";
    var lib: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_ffi_open(libc.ptr, libc.len, &lib));
    defer _ = plugin.sa_node_plugin_ffi_close(lib);

    var has_strlen: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_ffi_has_symbol(lib, "strlen".ptr, 6, &has_strlen));
    try std.testing.expectEqual(@as(u32, 1), has_strlen);

    var pid_value: i64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_ffi_call_i64_0(lib, "getpid".ptr, 6, &pid_value));
    try std.testing.expect(pid_value > 0);

    var strlen_value: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_ffi_call_strlen(lib, "strlen".ptr, 6, "hello".ptr, 5, &strlen_value));
    try std.testing.expectEqual(@as(u64, 5), strlen_value);

    var abs_value: i64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_ffi_call_i64_1(lib, "abs".ptr, 3, -42, &abs_value));
    try std.testing.expectEqual(@as(i64, 42), abs_value);

    var kill_value: i64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_ffi_call_i64_2(lib, "kill".ptr, 4, pid_value, 0, &kill_value));
    try std.testing.expectEqual(@as(i64, 0), kill_value);

    var getenv_ptr: ?[*]const u8 = null;
    var getenv_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_ffi_call_ptr_string(lib, "getenv".ptr, 6, "PATH".ptr, 4, &getenv_ptr, &getenv_len));
    defer _ = plugin.sa_node_plugin_free_buffer(getenv_ptr, getenv_len);
    try std.testing.expect(getenv_len > 0);
}

test "node plugin zlib zstd roundtrip" {
    const input = "hello zstd native compression";
    var compressed_ptr: ?[*]const u8 = null;
    var compressed_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_zlib_zstd_compress(input.ptr, input.len, &compressed_ptr, &compressed_len));
    defer _ = plugin.sa_node_plugin_free_buffer(compressed_ptr, compressed_len);
    try std.testing.expect(compressed_len > 0);

    var plain_ptr: ?[*]const u8 = null;
    var plain_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_zlib_zstd_decompress(compressed_ptr, compressed_len, &plain_ptr, &plain_len));
    defer _ = plugin.sa_node_plugin_free_buffer(plain_ptr, plain_len);
    const plain = (plain_ptr orelse return error.NullZstdPlain)[0..@intCast(plain_len)];
    try std.testing.expectEqualStrings(input, plain);
}

test "node plugin process resource usage and kill" {
    var usage_ptr: ?[*]const u8 = null;
    var usage_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_resource_usage_json(&usage_ptr, &usage_len));
    defer _ = plugin.sa_node_plugin_free_buffer(usage_ptr, usage_len);
    const usage = (usage_ptr orelse return error.NullProcessResourceUsage)[0..@intCast(usage_len)];
    try std.testing.expect(std.mem.indexOf(u8, usage, "\"userCPUTime\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "\"systemCPUTime\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "\"voluntaryContextSwitches\":") != null);

    var self_pid: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_pid(&self_pid));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_kill(self_pid, 0));
    try std.testing.expect(plugin.sa_node_plugin_process_kill(999999, 0) != 0);
    try std.testing.expect(plugin.sa_node_plugin_process_kill_signal(999999, "SIGTERM".ptr, 7) != 0);

    var available: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_available_memory(&available));
    try std.testing.expect(available > 0);

    var constrained: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_constrained_memory(&constrained));

    var features_ptr: ?[*]const u8 = null;
    var features_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_features_json(&features_ptr, &features_len));
    defer _ = plugin.sa_node_plugin_free_buffer(features_ptr, features_len);
    const features = (features_ptr orelse return error.NullProcessFeatures)[0..@intCast(features_len)];
    try std.testing.expect(std.mem.indexOf(u8, features, "\"ipv6\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, features, "\"tls\":true") != null);
}

test "node plugin vfs memory helpers" {
    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullVfsStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"supported\":true") != null);

    var vfs: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_new(&vfs));
    defer _ = plugin.sa_node_plugin_vfs_free(vfs);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/tmp".ptr, 4));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/tmp/app".ptr, 8));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_write_file(vfs, "/tmp/app/hello.txt".ptr, 18, "hello vfs".ptr, 9));

    var exists: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_exists(vfs, "/tmp/app/hello.txt".ptr, 18, &exists));
    try std.testing.expectEqual(@as(u32, 1), exists);

    var read_ptr: ?[*]const u8 = null;
    var read_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_read_file(vfs, "/tmp/app/hello.txt".ptr, 18, &read_ptr, &read_len));
    defer _ = plugin.sa_node_plugin_free_buffer(read_ptr, read_len);
    try std.testing.expectEqualStrings("hello vfs", (read_ptr orelse return error.NullVfsRead)[0..@intCast(read_len)]);

    var list_ptr: ?[*]const u8 = null;
    var list_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_readdir(vfs, "/tmp/app".ptr, 8, &list_ptr, &list_len));
    defer _ = plugin.sa_node_plugin_free_buffer(list_ptr, list_len);
    const list = (list_ptr orelse return error.NullVfsList)[0..@intCast(list_len)];
    try std.testing.expectEqualStrings("[\"hello.txt\"]", list);

    var stat_ptr: ?[*]const u8 = null;
    var stat_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_stat_json(vfs, "/tmp/app/hello.txt".ptr, 18, &stat_ptr, &stat_len));
    defer _ = plugin.sa_node_plugin_free_buffer(stat_ptr, stat_len);
    const stat = (stat_ptr orelse return error.NullVfsStat)[0..@intCast(stat_len)];
    try std.testing.expect(std.mem.indexOf(u8, stat, "\"type\":\"file\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stat, "\"size\":9") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_unlink(vfs, "/tmp/app/hello.txt".ptr, 18));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_exists(vfs, "/tmp/app/hello.txt".ptr, 18, &exists));
    try std.testing.expectEqual(@as(u32, 0), exists);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_write_file(vfs, "/tmp/app/nested.txt".ptr, 19, "x".ptr, 1));
    try std.testing.expect(plugin.sa_node_plugin_vfs_rm(vfs, "/tmp".ptr, 4, 0) != 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_rm(vfs, "/tmp".ptr, 4, 1));

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_snapshot_json(vfs, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullVfsSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"path\":\"/\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "nested.txt") == null);
}

test "node plugin vfs provider path mutation helpers" {
    var vfs: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_new(&vfs));
    defer _ = plugin.sa_node_plugin_vfs_free(vfs);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/workspace".ptr, 10));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/workspace/src".ptr, 14));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_chdir(vfs, "/workspace".ptr, 10));

    var cwd_ptr: ?[*]const u8 = null;
    var cwd_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_cwd(vfs, &cwd_ptr, &cwd_len));
    defer _ = plugin.sa_node_plugin_free_buffer(cwd_ptr, cwd_len);
    try std.testing.expectEqualStrings("/workspace", (cwd_ptr orelse return error.NullVfsCwd)[0..@intCast(cwd_len)]);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_write_file(vfs, "src/main.sa".ptr, 11, "one".ptr, 3));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_append_file(vfs, "src/main.sa".ptr, 11, " two".ptr, 4));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_copy_file(vfs, "src/main.sa".ptr, 11, "src/copy.sa".ptr, 11));

    var copy_ptr: ?[*]const u8 = null;
    var copy_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_read_file(vfs, "/workspace/src/copy.sa".ptr, 22, &copy_ptr, &copy_len));
    defer _ = plugin.sa_node_plugin_free_buffer(copy_ptr, copy_len);
    try std.testing.expectEqualStrings("one two", (copy_ptr orelse return error.NullVfsCopy)[0..@intCast(copy_len)]);

    var real_ptr: ?[*]const u8 = null;
    var real_len: u64 = 0;
    const relative_main = "./src/../src/main.sa";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_realpath(vfs, relative_main.ptr, relative_main.len, &real_ptr, &real_len));
    defer _ = plugin.sa_node_plugin_free_buffer(real_ptr, real_len);
    try std.testing.expectEqualStrings("/workspace/src/main.sa", (real_ptr orelse return error.NullVfsRealpath)[0..@intCast(real_len)]);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_rename(vfs, "src".ptr, 3, "lib".ptr, 3));
    var exists: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_exists(vfs, "/workspace/src/main.sa".ptr, 22, &exists));
    try std.testing.expectEqual(@as(u32, 0), exists);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_exists(vfs, "/workspace/lib/main.sa".ptr, 22, &exists));
    try std.testing.expectEqual(@as(u32, 1), exists);

    var list_ptr: ?[*]const u8 = null;
    var list_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_readdir(vfs, ".".ptr, 1, &list_ptr, &list_len));
    defer _ = plugin.sa_node_plugin_free_buffer(list_ptr, list_len);
    try std.testing.expectEqualStrings("[\"lib\"]", (list_ptr orelse return error.NullVfsRelativeList)[0..@intCast(list_len)]);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_snapshot_json(vfs, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullVfsProviderSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"provider\":\"memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"cwd\":\"/workspace\"") != null);
}

test "node plugin vfs symlink lstat readlink helpers" {
    var vfs: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_new(&vfs));
    defer _ = plugin.sa_node_plugin_vfs_free(vfs);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/project".ptr, 8));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_write_file(vfs, "/project/data.txt".ptr, 17, "target".ptr, 6));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_symlink(vfs, "data.txt".ptr, 8, "/project/link.txt".ptr, 17));

    var readlink_ptr: ?[*]const u8 = null;
    var readlink_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_readlink(vfs, "/project/link.txt".ptr, 17, &readlink_ptr, &readlink_len));
    defer _ = plugin.sa_node_plugin_free_buffer(readlink_ptr, readlink_len);
    try std.testing.expectEqualStrings("data.txt", (readlink_ptr orelse return error.NullVfsReadlink)[0..@intCast(readlink_len)]);

    var data_ptr: ?[*]const u8 = null;
    var data_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_read_file(vfs, "/project/link.txt".ptr, 17, &data_ptr, &data_len));
    defer _ = plugin.sa_node_plugin_free_buffer(data_ptr, data_len);
    try std.testing.expectEqualStrings("target", (data_ptr orelse return error.NullVfsSymlinkRead)[0..@intCast(data_len)]);

    var stat_ptr: ?[*]const u8 = null;
    var stat_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_stat_json(vfs, "/project/link.txt".ptr, 17, &stat_ptr, &stat_len));
    defer _ = plugin.sa_node_plugin_free_buffer(stat_ptr, stat_len);
    const stat = (stat_ptr orelse return error.NullVfsSymlinkStat)[0..@intCast(stat_len)];
    try std.testing.expect(std.mem.indexOf(u8, stat, "\"type\":\"file\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stat, "\"isSymbolicLink\":false") != null);

    var lstat_ptr: ?[*]const u8 = null;
    var lstat_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_lstat_json(vfs, "/project/link.txt".ptr, 17, &lstat_ptr, &lstat_len));
    defer _ = plugin.sa_node_plugin_free_buffer(lstat_ptr, lstat_len);
    const lstat = (lstat_ptr orelse return error.NullVfsSymlinkLstat)[0..@intCast(lstat_len)];
    try std.testing.expect(std.mem.indexOf(u8, lstat, "\"type\":\"symlink\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, lstat, "\"isSymbolicLink\":true") != null);

    var real_ptr: ?[*]const u8 = null;
    var real_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_realpath(vfs, "/project/link.txt".ptr, 17, &real_ptr, &real_len));
    defer _ = plugin.sa_node_plugin_free_buffer(real_ptr, real_len);
    try std.testing.expectEqualStrings("/project/data.txt", (real_ptr orelse return error.NullVfsSymlinkRealpath)[0..@intCast(real_len)]);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_unlink(vfs, "/project/link.txt".ptr, 17));
    var exists: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_exists(vfs, "/project/data.txt".ptr, 17, &exists));
    try std.testing.expectEqual(@as(u32, 1), exists);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_symlink(vfs, "loop".ptr, 4, "/project/loop".ptr, 13));
    try std.testing.expect(plugin.sa_node_plugin_vfs_realpath(vfs, "/project/loop".ptr, 13, &real_ptr, &real_len) != 0);
}

test "node plugin vfs file handle helpers" {
    var vfs: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_new(&vfs));
    defer _ = plugin.sa_node_plugin_vfs_free(vfs);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/fh".ptr, 3));

    var fh: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_open(vfs, "/fh/data.bin".ptr, 12, 3, &fh));

    var written: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_file_write(fh, "abcdef".ptr, 6, 0, 0, &written));
    try std.testing.expectEqual(@as(u64, 6), written);

    var patch_written: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_file_write(fh, "XY".ptr, 2, 2, 1, &patch_written));
    try std.testing.expectEqual(@as(u64, 2), patch_written);

    var buf: [8]u8 = undefined;
    var nread: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_file_read(fh, &buf, 6, 0, 1, &nread));
    try std.testing.expectEqual(@as(u64, 6), nread);
    try std.testing.expectEqualStrings("abXYef", buf[0..@intCast(nread)]);

    var stat_ptr: ?[*]const u8 = null;
    var stat_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_file_fstat_json(fh, &stat_ptr, &stat_len));
    defer _ = plugin.sa_node_plugin_free_buffer(stat_ptr, stat_len);
    const stat = (stat_ptr orelse return error.NullVfsFileStat)[0..@intCast(stat_len)];
    try std.testing.expect(std.mem.indexOf(u8, stat, "\"size\":6") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_file_truncate(fh, 4));
    var read_ptr: ?[*]const u8 = null;
    var read_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_read_file(vfs, "/fh/data.bin".ptr, 12, &read_ptr, &read_len));
    defer _ = plugin.sa_node_plugin_free_buffer(read_ptr, read_len);
    try std.testing.expectEqualStrings("abXY", (read_ptr orelse return error.NullVfsFileReadAfterTruncate)[0..@intCast(read_len)]);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_file_close(fh));

    var append_fh: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_open(vfs, "/fh/data.bin".ptr, 12, 5, &append_fh));
    defer _ = plugin.sa_node_plugin_vfs_file_close(append_fh);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_file_write(append_fh, "zz".ptr, 2, 0, 1, &written));

    var appended_ptr: ?[*]const u8 = null;
    var appended_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_read_file(vfs, "/fh/data.bin".ptr, 12, &appended_ptr, &appended_len));
    defer _ = plugin.sa_node_plugin_free_buffer(appended_ptr, appended_len);
    try std.testing.expectEqualStrings("abXYzz", (appended_ptr orelse return error.NullVfsAppendHandleRead)[0..@intCast(appended_len)]);
}

test "node plugin vfs directory handle helpers" {
    var vfs: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_new(&vfs));
    defer _ = plugin.sa_node_plugin_vfs_free(vfs);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/dir".ptr, 4));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/dir/b".ptr, 6));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_write_file(vfs, "/dir/a.txt".ptr, 10, "a".ptr, 1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_symlink(vfs, "a.txt".ptr, 5, "/dir/c.link".ptr, 11));

    var dir: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_opendir(vfs, "/dir".ptr, 4, &dir));
    defer _ = plugin.sa_node_plugin_vfs_dir_close(dir);

    var snap_ptr: ?[*]const u8 = null;
    var snap_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_dir_snapshot_json(dir, &snap_ptr, &snap_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snap_ptr, snap_len);
    const snap = (snap_ptr orelse return error.NullVfsDirSnapshot)[0..@intCast(snap_len)];
    try std.testing.expect(std.mem.indexOf(u8, snap, "\"path\":\"/dir\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snap, "\"name\":\"a.txt\"") != null);

    var name_ptr: ?[*]const u8 = null;
    var name_len: u64 = 0;
    var entry_type: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_dir_next(dir, &name_ptr, &name_len, &entry_type));
    defer _ = plugin.sa_node_plugin_free_buffer(name_ptr, name_len);
    try std.testing.expectEqualStrings("a.txt", (name_ptr orelse return error.NullVfsDirFirst)[0..@intCast(name_len)]);
    try std.testing.expectEqual(@as(u32, 1), entry_type);

    var name2_ptr: ?[*]const u8 = null;
    var name2_len: u64 = 0;
    var entry2_type: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_dir_next(dir, &name2_ptr, &name2_len, &entry2_type));
    defer _ = plugin.sa_node_plugin_free_buffer(name2_ptr, name2_len);
    try std.testing.expectEqualStrings("b", (name2_ptr orelse return error.NullVfsDirSecond)[0..@intCast(name2_len)]);
    try std.testing.expectEqual(@as(u32, 2), entry2_type);

    var name3_ptr: ?[*]const u8 = null;
    var name3_len: u64 = 0;
    var entry3_type: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_dir_next(dir, &name3_ptr, &name3_len, &entry3_type));
    defer _ = plugin.sa_node_plugin_free_buffer(name3_ptr, name3_len);
    try std.testing.expectEqualStrings("c.link", (name3_ptr orelse return error.NullVfsDirThird)[0..@intCast(name3_len)]);
    try std.testing.expectEqual(@as(u32, 3), entry3_type);

    var eof_ptr: ?[*]const u8 = undefined;
    var eof_len: u64 = 99;
    var eof_type: u32 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_dir_next(dir, &eof_ptr, &eof_len, &eof_type));
    try std.testing.expect(eof_ptr == null);
    try std.testing.expectEqual(@as(u64, 0), eof_len);
    try std.testing.expectEqual(@as(u32, 0), eof_type);
}

test "node plugin vfs watcher helpers" {
    var vfs: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_new(&vfs));
    defer _ = plugin.sa_node_plugin_vfs_free(vfs);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/watched".ptr, 8));

    var watcher: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_watch(vfs, "/watched".ptr, 8, 0, &watcher));
    defer _ = plugin.sa_node_plugin_vfs_watcher_close(watcher);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_write_file(vfs, "/watched/a.txt".ptr, 14, "one".ptr, 3));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_append_file(vfs, "/watched/a.txt".ptr, 14, " two".ptr, 4));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_mkdir(vfs, "/watched/sub".ptr, 12));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_write_file(vfs, "/watched/sub/nested.txt".ptr, 23, "x".ptr, 1));

    var snap_ptr: ?[*]const u8 = null;
    var snap_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_watcher_snapshot_json(watcher, &snap_ptr, &snap_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snap_ptr, snap_len);
    const snap = (snap_ptr orelse return error.NullVfsWatcherSnapshot)[0..@intCast(snap_len)];
    try std.testing.expect(std.mem.indexOf(u8, snap, "\"path\":\"/watched\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snap, "\"recursive\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, snap, "\"queued\":3") != null);

    var event_ptr: ?[*]const u8 = null;
    var event_len: u64 = 0;
    var filename_ptr: ?[*]const u8 = null;
    var filename_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_watcher_next(watcher, &event_ptr, &event_len, &filename_ptr, &filename_len));
    defer _ = plugin.sa_node_plugin_free_buffer(event_ptr, event_len);
    defer _ = plugin.sa_node_plugin_free_buffer(filename_ptr, filename_len);
    try std.testing.expectEqualStrings("rename", (event_ptr orelse return error.NullVfsWatchEvent1)[0..@intCast(event_len)]);
    try std.testing.expectEqualStrings("a.txt", (filename_ptr orelse return error.NullVfsWatchFilename1)[0..@intCast(filename_len)]);

    var event2_ptr: ?[*]const u8 = null;
    var event2_len: u64 = 0;
    var filename2_ptr: ?[*]const u8 = null;
    var filename2_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_watcher_next(watcher, &event2_ptr, &event2_len, &filename2_ptr, &filename2_len));
    defer _ = plugin.sa_node_plugin_free_buffer(event2_ptr, event2_len);
    defer _ = plugin.sa_node_plugin_free_buffer(filename2_ptr, filename2_len);
    try std.testing.expectEqualStrings("change", (event2_ptr orelse return error.NullVfsWatchEvent2)[0..@intCast(event2_len)]);
    try std.testing.expectEqualStrings("a.txt", (filename2_ptr orelse return error.NullVfsWatchFilename2)[0..@intCast(filename2_len)]);

    var event3_ptr: ?[*]const u8 = null;
    var event3_len: u64 = 0;
    var filename3_ptr: ?[*]const u8 = null;
    var filename3_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_watcher_next(watcher, &event3_ptr, &event3_len, &filename3_ptr, &filename3_len));
    defer _ = plugin.sa_node_plugin_free_buffer(event3_ptr, event3_len);
    defer _ = plugin.sa_node_plugin_free_buffer(filename3_ptr, filename3_len);
    try std.testing.expectEqualStrings("rename", (event3_ptr orelse return error.NullVfsWatchEvent3)[0..@intCast(event3_len)]);
    try std.testing.expectEqualStrings("sub", (filename3_ptr orelse return error.NullVfsWatchFilename3)[0..@intCast(filename3_len)]);

    var eof_event_ptr: ?[*]const u8 = undefined;
    var eof_event_len: u64 = 99;
    var eof_filename_ptr: ?[*]const u8 = undefined;
    var eof_filename_len: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_watcher_next(watcher, &eof_event_ptr, &eof_event_len, &eof_filename_ptr, &eof_filename_len));
    try std.testing.expect(eof_event_ptr == null);
    try std.testing.expectEqual(@as(u64, 0), eof_event_len);
    try std.testing.expect(eof_filename_ptr == null);
    try std.testing.expectEqual(@as(u64, 0), eof_filename_len);

    var recursive: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_watch(vfs, "/watched".ptr, 8, 1, &recursive));
    defer _ = plugin.sa_node_plugin_vfs_watcher_close(recursive);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_write_file(vfs, "/watched/sub/next.txt".ptr, 21, "y".ptr, 1));
    var rec_event_ptr: ?[*]const u8 = null;
    var rec_event_len: u64 = 0;
    var rec_filename_ptr: ?[*]const u8 = null;
    var rec_filename_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_vfs_watcher_next(recursive, &rec_event_ptr, &rec_event_len, &rec_filename_ptr, &rec_filename_len));
    defer _ = plugin.sa_node_plugin_free_buffer(rec_event_ptr, rec_event_len);
    defer _ = plugin.sa_node_plugin_free_buffer(rec_filename_ptr, rec_filename_len);
    try std.testing.expectEqualStrings("rename", (rec_event_ptr orelse return error.NullVfsRecursiveEvent)[0..@intCast(rec_event_len)]);
    try std.testing.expectEqualStrings("sub/next.txt", (rec_filename_ptr orelse return error.NullVfsRecursiveFilename)[0..@intCast(rec_filename_len)]);
}

test "node plugin web streams byte helpers" {
    var readable: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_readable_new(&readable));
    defer _ = plugin.sa_node_plugin_web_streams_free(readable);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_enqueue(readable, "hello".ptr, 5));

    var read_ptr: ?[*]const u8 = null;
    var read_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_read(readable, 2, &read_ptr, &read_len));
    defer _ = plugin.sa_node_plugin_free_buffer(read_ptr, read_len);
    try std.testing.expectEqualStrings("he", (read_ptr orelse return error.NullWebStreamRead)[0..@intCast(read_len)]);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_snapshot_json(readable, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullWebStreamSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"kind\":\"readable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"queuedBytes\":3") != null);

    var writable: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_writable_new(&writable));
    defer _ = plugin.sa_node_plugin_web_streams_free(writable);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_write(writable, "sink".ptr, 4));

    var writable_snapshot_ptr: ?[*]const u8 = null;
    var writable_snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_snapshot_json(writable, &writable_snapshot_ptr, &writable_snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(writable_snapshot_ptr, writable_snapshot_len);
    const writable_snapshot = (writable_snapshot_ptr orelse return error.NullWritableWebStreamSnapshot)[0..@intCast(writable_snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, writable_snapshot, "\"kind\":\"writable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, writable_snapshot, "\"queuedBytes\":4") != null);

    var transform_readable: ?*anyopaque = null;
    var transform_writable: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_transform_new(&transform_readable, &transform_writable));
    defer _ = plugin.sa_node_plugin_web_streams_free(transform_readable);
    defer _ = plugin.sa_node_plugin_web_streams_free(transform_writable);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_write(transform_writable, "pipe".ptr, 4));

    var transformed_ptr: ?[*]const u8 = null;
    var transformed_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_read(transform_readable, 16, &transformed_ptr, &transformed_len));
    defer _ = plugin.sa_node_plugin_free_buffer(transformed_ptr, transformed_len);
    try std.testing.expectEqualStrings("pipe", (transformed_ptr orelse return error.NullTransformWebStreamRead)[0..@intCast(transformed_len)]);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_web_streams_close(readable));
    try std.testing.expectEqual(@as(u32, 2), plugin.sa_node_plugin_web_streams_enqueue(readable, "x".ptr, 1));
}

test "node plugin stream pipeline finished and compose track state" {
    var first: ?*anyopaque = null;
    var second: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_stream_duplex_pair(&first, &second));
    defer _ = plugin.sa_node_plugin_stream_destroy(first);
    defer _ = plugin.sa_node_plugin_stream_destroy(second);

    var pipe_ptr: ?[*]const u8 = null;
    var pipe_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_stream_pipeline(first, @intFromPtr(second), &pipe_ptr, &pipe_len));
    defer _ = plugin.sa_node_plugin_free_buffer(pipe_ptr, pipe_len);
    const pipe = (pipe_ptr orelse return error.NullStreamPipeline)[0..@intCast(pipe_len)];
    try std.testing.expect(std.mem.indexOf(u8, pipe, "\"status\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pipe, "\"count\":2") != null);

    var finished_ptr: ?[*]const u8 = null;
    var finished_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_stream_finished(first, &finished_ptr, &finished_len));
    defer _ = plugin.sa_node_plugin_free_buffer(finished_ptr, finished_len);
    const finished = (finished_ptr orelse return error.NullStreamFinished)[0..@intCast(finished_len)];
    try std.testing.expect(std.mem.indexOf(u8, finished, "\"finished\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, finished, "\"ended\":true") != null);

    var vec: [16]u8 = undefined;
    std.mem.writeInt(usize, vec[0..@sizeOf(usize)], @intFromPtr(first), .little);
    std.mem.writeInt(u64, vec[8..16], 1, .little);
    var composed: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_stream_compose(&vec, 1, &composed));
    defer _ = plugin.sa_node_plugin_stream_destroy(composed);

    var composed_ptr: ?[*]const u8 = null;
    var composed_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_stream_finished(composed, &composed_ptr, &composed_len));
    defer _ = plugin.sa_node_plugin_free_buffer(composed_ptr, composed_len);
    const composed_json = (composed_ptr orelse return error.NullStreamComposed)[0..@intCast(composed_len)];
    try std.testing.expect(std.mem.indexOf(u8, composed_json, "\"finished\":false") != null);
}

test "node plugin os network interfaces returns json" {
    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_os_constants(&constants_ptr, &constants_len));
    defer _ = plugin.sa_node_plugin_free_buffer(constants_ptr, constants_len);
    const constants = (constants_ptr orelse return error.NullOsConstants)[0..@intCast(constants_len)];
    try std.testing.expect(std.mem.indexOf(u8, constants, "\"signals\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, constants, "\"SIGTERM\":15") != null);
    try std.testing.expect(std.mem.indexOf(u8, constants, "\"errno\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, constants, "\"ENOENT\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, constants, "\"priority\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, constants, "\"PRIORITY_NORMAL\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, constants, "\"dlopen\":") != null);

    var priority: i32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_os_get_priority(0, &priority));
    try std.testing.expect(priority >= -20 and priority <= 19);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_os_set_priority(0, priority));
    try std.testing.expect(plugin.sa_node_plugin_os_set_priority(0, 99) != 0);

    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_os_network_interfaces(&ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);
    const result = (ptr orelse return error.NullNetworkInterfaces)[0..@intCast(len)];
    try std.testing.expect(std.mem.startsWith(u8, result, "{"));
    try std.testing.expect(std.mem.indexOf(u8, result, "127.0.0.1") != null or std.mem.indexOf(u8, result, "::1") != null or len > 2);
}

test "node plugin perf hooks and diagnostics channel" {
    var now_ms: f64 = 0;
    var origin_ms: f64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_now_ms(&now_ms));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_time_origin_ms(&origin_ms));
    try std.testing.expect(now_ms >= 0);
    try std.testing.expect(origin_ms > 0);

    var event_loop_ptr: ?[*]const u8 = null;
    var event_loop_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_event_loop_utilization(&event_loop_ptr, &event_loop_len));
    defer _ = plugin.sa_node_plugin_free_buffer(event_loop_ptr, event_loop_len);
    const event_loop = (event_loop_ptr orelse return error.NullEventLoopUtil)[0..@intCast(event_loop_len)];
    try std.testing.expect(std.mem.indexOf(u8, event_loop, "\"idle\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, event_loop, "\"active\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, event_loop, "\"utilization\"") != null);

    var timer_id: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_timerify("mark".ptr, 4, &timer_id));
    try std.testing.expect(timer_id > 0);

    var channel: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_create("node:test".ptr, 9, &channel));
    defer _ = plugin.sa_node_plugin_diagnostics_channel_free(channel);

    var has_subs: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_has_subscribers(channel, &has_subs));
    try std.testing.expectEqual(@as(u32, 0), has_subs);

    const cb: ?*anyopaque = @ptrFromInt(@as(usize, 0x2001));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_subscribe(channel, cb));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_has_subscribers(channel, &has_subs));
    try std.testing.expectEqual(@as(u32, 1), has_subs);

    var count: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_publish(channel, "payload", 7, &count));
    try std.testing.expectEqual(@as(u64, 1), count);

    var snap_ptr: ?[*]const u8 = null;
    var snap_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_snapshot_json(channel, &snap_ptr, &snap_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snap_ptr, snap_len);
    const snap = (snap_ptr orelse return error.NullDiagSnapshot)[0..@intCast(snap_len)];
    try std.testing.expect(std.mem.indexOf(u8, snap, "node:test") != null);
    try std.testing.expect(std.mem.indexOf(u8, snap, "\"enabled\":true") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_unsubscribe(channel, cb));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_has_subscribers(channel, &has_subs));
    try std.testing.expectEqual(@as(u32, 0), has_subs);

    var tracing: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_tracing_channel("trace".ptr, 5, &tracing));
    defer _ = plugin.sa_node_plugin_free_buffer(@ptrCast(tracing), 1);
}

test "node plugin diagnostics_channel top-level facade helpers" {
    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullDiagnosticsChannelStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"diagnostics_channel\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mode\":\"top-level-native-channel-facade\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"boundedChannel\":{\"supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"tracingChannel\":true") != null);

    var exports_ptr: ?[*]const u8 = null;
    var exports_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_exports_json(&exports_ptr, &exports_len));
    defer _ = plugin.sa_node_plugin_free_buffer(exports_ptr, exports_len);
    const exports_json = (exports_ptr orelse return error.NullDiagnosticsChannelExports)[0..@intCast(exports_len)];
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"channel\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"tracingChannel\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"Channel\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"BoundedChannel\"") != null);

    var factories_ptr: ?[*]const u8 = null;
    var factories_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_factories_json(&factories_ptr, &factories_len));
    defer _ = plugin.sa_node_plugin_free_buffer(factories_ptr, factories_len);
    const factories_json = (factories_ptr orelse return error.NullDiagnosticsChannelFactories)[0..@intCast(factories_len)];
    try std.testing.expect(std.mem.indexOf(u8, factories_json, "\"channel\":{\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, factories_json, "\"tracingChannel\":{\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, factories_json, "\"boundedChannel\":{\"supported\":false") != null);

    var feature_ptr: ?[*]const u8 = null;
    var feature_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_diagnostics_channel_feature_support_json(&feature_ptr, &feature_len));
    defer _ = plugin.sa_node_plugin_free_buffer(feature_ptr, feature_len);
    const feature_json = (feature_ptr orelse return error.NullDiagnosticsChannelFeatureSupport)[0..@intCast(feature_len)];
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"channel\":{\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"Channel\":{\"supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"tracingChannel\":{\"supported\":true") != null);
}

test "node plugin perf hooks histogram extended statistics" {
    var hist: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_create_histogram(&hist));
    defer _ = plugin.sa_node_plugin_perf_hooks_histogram_free(hist);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_histogram_record(hist, 10));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_histogram_record(hist, 20));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_histogram_record(hist, 30));

    var stats_ptr: ?[*]const u8 = null;
    var stats_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_histogram_get_statistics(hist, &stats_ptr, &stats_len));
    defer _ = plugin.sa_node_plugin_free_buffer(stats_ptr, stats_len);
    const stats = (stats_ptr orelse return error.NullHistogramStats)[0..@intCast(stats_len)];
    try std.testing.expect(std.mem.indexOf(u8, stats, "\"count\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, stats, "\"min\":10") != null);
    try std.testing.expect(std.mem.indexOf(u8, stats, "\"max\":30") != null);
    try std.testing.expect(std.mem.indexOf(u8, stats, "\"percentiles\"") != null);
}

test "node plugin perf_hooks top-level facade helpers" {
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_clear_marks());
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_clear_measures());
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_mark("start".ptr, 5));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_mark("end".ptr, 3));

    var duration_ms: f64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_measure("span".ptr, 4, "start".ptr, 5, "end".ptr, 3, &duration_ms));
    try std.testing.expect(duration_ms >= 0);

    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullPerfHooksStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"perf_hooks\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mode\":\"top-level-native-perf-facade\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"createHistogram\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"monitorEventLoopDelay\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"PerformanceObserver\":false") != null);

    var exports_ptr: ?[*]const u8 = null;
    var exports_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_exports_json(&exports_ptr, &exports_len));
    defer _ = plugin.sa_node_plugin_free_buffer(exports_ptr, exports_len);
    const exports_json = (exports_ptr orelse return error.NullPerfHooksExports)[0..@intCast(exports_len)];
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"Performance\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"eventLoopUtilization\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"constants\"") != null);

    var entry_types_ptr: ?[*]const u8 = null;
    var entry_types_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_supported_entry_types_json(&entry_types_ptr, &entry_types_len));
    defer _ = plugin.sa_node_plugin_free_buffer(entry_types_ptr, entry_types_len);
    const entry_types = (entry_types_ptr orelse return error.NullPerfHooksEntryTypes)[0..@intCast(entry_types_len)];
    try std.testing.expectEqualStrings("[\"mark\",\"measure\",\"function\"]", entry_types);

    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_constants_json(&constants_ptr, &constants_len));
    defer _ = plugin.sa_node_plugin_free_buffer(constants_ptr, constants_len);
    const constants = (constants_ptr orelse return error.NullPerfHooksConstants)[0..@intCast(constants_len)];
    try std.testing.expect(std.mem.indexOf(u8, constants, "NODE_PERFORMANCE_GC_MAJOR") != null);
    try std.testing.expect(std.mem.indexOf(u8, constants, "NODE_PERFORMANCE_GC_FLAGS_SCHEDULE_IDLE") != null);

    var perf_ptr: ?[*]const u8 = null;
    var perf_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_performance_json(&perf_ptr, &perf_len));
    defer _ = plugin.sa_node_plugin_free_buffer(perf_ptr, perf_len);
    const perf_json = (perf_ptr orelse return error.NullPerfHooksPerformance)[0..@intCast(perf_len)];
    try std.testing.expect(std.mem.indexOf(u8, perf_json, "\"nowMs\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, perf_json, "\"timeOriginMs\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, perf_json, "\"supportedEntryTypes\":[\"mark\",\"measure\",\"function\"]") != null);

    var feature_ptr: ?[*]const u8 = null;
    var feature_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_perf_hooks_feature_support_json(&feature_ptr, &feature_len));
    defer _ = plugin.sa_node_plugin_free_buffer(feature_ptr, feature_len);
    const feature_json = (feature_ptr orelse return error.NullPerfHooksFeatureSupport)[0..@intCast(feature_len)];
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"PerformanceObserver\":{\"supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"performance.now\":{\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"monitorEventLoopDelay\":{\"supported\":true") != null);
}

test "node plugin tty u64 ABI and stdio fallback" {
    var is_tty: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tty_isatty(0, &is_tty));
    try std.testing.expect(is_tty == 0 or is_tty == 1);

    var read_handle: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tty_read_stream_new(0, &read_handle));
    defer _ = plugin.sa_node_plugin_tty_stream_free(read_handle);

    var write_handle: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tty_write_stream_new(1, &write_handle));
    defer _ = plugin.sa_node_plugin_tty_stream_free(write_handle);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tty_stream_set_raw_mode(read_handle, 0));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tty_stream_set_raw_mode(null, 0));

    var cols: u64 = 0;
    var rows: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tty_stream_get_window_size(write_handle, &cols, &rows));

    var depth: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tty_stream_get_color_depth(null, &depth));
    try std.testing.expect(depth == 1 or depth == 4 or depth == 8 or depth == 24);

    var has_colors: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tty_stream_has_colors(write_handle, &has_colors));
    try std.testing.expect(has_colors == 0 or has_colors == 1);
}

test "node plugin worker_threads message ports and u64 bools" {
    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullWorkerThreadsStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"worker_threads\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mode\":\"top-level-main-thread-facade\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"Worker\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"MessageChannel\":true") != null);

    var exports_ptr: ?[*]const u8 = null;
    var exports_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_exports_json(&exports_ptr, &exports_len));
    defer _ = plugin.sa_node_plugin_free_buffer(exports_ptr, exports_len);
    const exports_json = (exports_ptr orelse return error.NullWorkerThreadsExports)[0..@intCast(exports_len)];
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"Worker\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"MessageChannel\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"locks\"") != null);

    var share_env_ptr: ?[*]const u8 = null;
    var share_env_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_share_env_json(&share_env_ptr, &share_env_len));
    defer _ = plugin.sa_node_plugin_free_buffer(share_env_ptr, share_env_len);
    const share_env = (share_env_ptr orelse return error.NullWorkerThreadsShareEnv)[0..@intCast(share_env_len)];
    try std.testing.expect(std.mem.indexOf(u8, share_env, "\"SHARE_ENV\":true") != null);

    var parent_port_ptr: ?[*]const u8 = null;
    var parent_port_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_parent_port_json(&parent_port_ptr, &parent_port_len));
    defer _ = plugin.sa_node_plugin_free_buffer(parent_port_ptr, parent_port_len);
    try std.testing.expectEqualStrings("null", (parent_port_ptr orelse return error.NullWorkerThreadsParentPort)[0..@intCast(parent_port_len)]);

    var feature_ptr: ?[*]const u8 = null;
    var feature_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_feature_support_json(&feature_ptr, &feature_len));
    defer _ = plugin.sa_node_plugin_free_buffer(feature_ptr, feature_len);
    const feature_json = (feature_ptr orelse return error.NullWorkerThreadsFeatureSupport)[0..@intCast(feature_len)];
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"Worker\":{\"supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"MessagePort\":{\"supported\":true") != null);

    var is_main: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_is_main_thread(&is_main));
    try std.testing.expectEqual(@as(u64, 1), is_main);

    var is_internal: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_is_internal_thread(&is_internal));
    try std.testing.expectEqual(@as(u64, 0), is_internal);

    var worker_data_ptr: ?[*]const u8 = null;
    var worker_data_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_worker_data(&worker_data_ptr, &worker_data_len));
    defer _ = plugin.sa_node_plugin_free_buffer(worker_data_ptr, worker_data_len);
    try std.testing.expectEqualStrings("null", (worker_data_ptr orelse return error.NullWorkerData)[0..@intCast(worker_data_len)]);

    var port1: ?*anyopaque = null;
    var port2: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_message_channel_new(&port1, &port2));
    defer _ = plugin.sa_node_plugin_worker_threads_message_port_free(port1);
    defer _ = plugin.sa_node_plugin_worker_threads_message_port_free(port2);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_message_port_post_message(port1, "hello", 5));
    var msg_ptr: ?[*]const u8 = null;
    var msg_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_receive_message_on_port(port2, &msg_ptr, &msg_len));
    defer _ = plugin.sa_node_plugin_free_buffer(msg_ptr, msg_len);
    try std.testing.expectEqualStrings("hello", (msg_ptr orelse return error.NullWorkerMessage)[0..@intCast(msg_len)]);

    var posted: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_post_message_to_thread(0, "main", 4, &posted));
    try std.testing.expectEqual(@as(u64, 1), posted);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_worker_threads_post_message_to_thread(9999, "nope", 4, &posted));
    try std.testing.expectEqual(@as(u64, 0), posted);
}

test "node plugin cluster subprocess worker helpers" {
    var is_primary: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_is_primary(&is_primary));
    try std.testing.expectEqual(@as(u64, 1), is_primary);

    var is_worker: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_is_worker(&is_worker));
    try std.testing.expectEqual(@as(u64, 0), is_worker);

    var policy: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_get_scheduling_policy(&policy));
    try std.testing.expect(policy == 1 or policy == 2);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_set_scheduling_policy(1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_get_scheduling_policy(&policy));
    try std.testing.expectEqual(@as(u64, 1), policy);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_set_scheduling_policy(2));

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_setup_primary("/bin/cat".ptr, 8, null, 0));

    var primary_snapshot_ptr: ?[*]const u8 = null;
    var primary_snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_primary_snapshot_json(&primary_snapshot_ptr, &primary_snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(primary_snapshot_ptr, primary_snapshot_len);
    const primary_snapshot = (primary_snapshot_ptr orelse return error.NullClusterPrimarySnapshot)[0..@intCast(primary_snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, primary_snapshot, "\"exec\":\"/bin/cat\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, primary_snapshot, "\"useCustomEnv\":false") != null);

    var worker: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_fork(null, 0, null, 0, &worker));
    defer _ = plugin.sa_node_plugin_cluster_worker_free(worker);

    var pid: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_pid(worker, &pid));
    try std.testing.expect(pid > 1);

    var connected: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_is_connected(worker, &connected));
    try std.testing.expectEqual(@as(u64, 1), connected);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_send_message(worker, "cluster-echo\n", 13));

    var recv_ptr: ?[*]const u8 = null;
    var recv_len: u64 = 0;
    var got_message = false;
    var attempts: usize = 0;
    while (attempts < 50) : (attempts += 1) {
        try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_receive_message(worker, &recv_ptr, &recv_len));
        if (recv_ptr != null and recv_len > 0) {
            got_message = true;
            break;
        }
        std.time.sleep(10 * std.time.ns_per_ms);
    }
    try std.testing.expect(got_message);
    defer {
        if (got_message) _ = plugin.sa_node_plugin_free_buffer(recv_ptr, recv_len);
    }
    try std.testing.expect(std.mem.indexOf(u8, (recv_ptr orelse return error.NullClusterWorkerMessage)[0..@intCast(recv_len)], "cluster-echo") != null);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_snapshot_json(worker, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullClusterWorkerSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"pid\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"command\":\"/bin/cat\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"envCount\":0") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_disconnect(worker));

    var waited_ptr: ?[*]const u8 = null;
    var waited_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_wait_json(worker, &waited_ptr, &waited_len));
    defer _ = plugin.sa_node_plugin_free_buffer(waited_ptr, waited_len);
    const waited = (waited_ptr orelse return error.NullClusterWorkerWait)[0..@intCast(waited_len)];
    try std.testing.expect(std.mem.indexOf(u8, waited, "\"disconnectRequested\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, waited, "\"exited\":true") != null);

    var disconnected_exit: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_exited_after_disconnect(worker, &disconnected_exit));
    try std.testing.expectEqual(@as(u64, 1), disconnected_exit);

    var alive: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_is_alive(worker, &alive));
    try std.testing.expectEqual(@as(u64, 0), alive);
}

test "node plugin cluster setup_primary_json and signal wait helpers" {
    const config = "{\"exec\":\"/bin/cat\",\"cwd\":\".\",\"env\":{\"CLUSTER_TEST\":\"1\"}}";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_setup_primary_json(config.ptr, config.len));

    var primary_ptr: ?[*]const u8 = null;
    var primary_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_primary_snapshot_json(&primary_ptr, &primary_len));
    defer _ = plugin.sa_node_plugin_free_buffer(primary_ptr, primary_len);
    const primary = (primary_ptr orelse return error.NullClusterPrimaryJsonSnapshot)[0..@intCast(primary_len)];
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, primary, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("/bin/cat", parsed.value.object.get("exec").?.string);
    try std.testing.expectEqualStrings(".", parsed.value.object.get("cwd").?.string);
    try std.testing.expectEqual(true, parsed.value.object.get("useCustomEnv").?.bool);
    try std.testing.expectEqualStrings("1", parsed.value.object.get("env").?.object.get("CLUSTER_TEST").?.string);

    var worker: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_fork(null, 0, null, 0, &worker));
    defer _ = plugin.sa_node_plugin_cluster_worker_free(worker);

    var worker_snapshot_ptr: ?[*]const u8 = null;
    var worker_snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_snapshot_json(worker, &worker_snapshot_ptr, &worker_snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(worker_snapshot_ptr, worker_snapshot_len);
    const worker_snapshot = (worker_snapshot_ptr orelse return error.NullClusterWorkerJsonSnapshot)[0..@intCast(worker_snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, worker_snapshot, "\"cwd\":\".\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, worker_snapshot, "\"envCount\":1") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_kill_signal(worker, "SIGTERM".ptr, 7));

    var waited_ptr: ?[*]const u8 = null;
    var waited_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_wait_json(worker, &waited_ptr, &waited_len));
    defer _ = plugin.sa_node_plugin_free_buffer(waited_ptr, waited_len);
    const waited = (waited_ptr orelse return error.NullClusterKilledWait)[0..@intCast(waited_len)];
    try std.testing.expect(std.mem.indexOf(u8, waited, "\"signalCode\":15") != null);

    var exited_after_disconnect: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_cluster_worker_exited_after_disconnect(worker, &exited_after_disconnect));
    try std.testing.expectEqual(@as(u64, 0), exited_after_disconnect);
}

test "node plugin domain handle helpers" {
    var domain: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_create(&domain));
    defer _ = plugin.sa_node_plugin_domain_free(domain);

    var active: ?*anyopaque = @ptrFromInt(1);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_get_active(&active));
    try std.testing.expectEqual(@as(?*anyopaque, null), active);

    const member1: ?*anyopaque = @ptrFromInt(@as(usize, 0x1001));
    const member2: ?*anyopaque = @ptrFromInt(@as(usize, 0x1002));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_add(domain, member1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_add(domain, member1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_add(domain, member2));

    var member_count: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_member_count(domain, &member_count));
    try std.testing.expectEqual(@as(u64, 2), member_count);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_enter(domain));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_get_active(&active));
    try std.testing.expectEqual(domain, active);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_snapshot_json(domain, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullDomainSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"active\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"memberCount\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"stackDepth\":1") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_remove(domain, member1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_member_count(domain, &member_count));
    try std.testing.expectEqual(@as(u64, 1), member_count);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_exit(domain));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_get_active(&active));
    try std.testing.expectEqual(@as(?*anyopaque, null), active);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_dispose(domain));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_member_count(domain, &member_count));
    try std.testing.expectEqual(@as(u64, 0), member_count);

    var disposed_ptr: ?[*]const u8 = null;
    var disposed_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_domain_snapshot_json(domain, &disposed_ptr, &disposed_len));
    defer _ = plugin.sa_node_plugin_free_buffer(disposed_ptr, disposed_len);
    const disposed_snapshot = (disposed_ptr orelse return error.NullDisposedDomainSnapshot)[0..@intCast(disposed_len)];
    try std.testing.expect(std.mem.indexOf(u8, disposed_snapshot, "\"disposed\":true") != null);
}

test "node plugin timers promises helpers" {
    var timeout_ptr: ?[*]const u8 = null;
    var timeout_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_promises_set_timeout(5, "done".ptr, 4, &timeout_ptr, &timeout_len));
    defer _ = plugin.sa_node_plugin_free_buffer(timeout_ptr, timeout_len);
    try std.testing.expectEqualStrings("done", (timeout_ptr orelse return error.NullTimersPromisesTimeout)[0..@intCast(timeout_len)]);

    var immediate_ptr: ?[*]const u8 = null;
    var immediate_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_promises_set_immediate("soon".ptr, 4, &immediate_ptr, &immediate_len));
    defer _ = plugin.sa_node_plugin_free_buffer(immediate_ptr, immediate_len);
    try std.testing.expectEqualStrings("soon", (immediate_ptr orelse return error.NullTimersPromisesImmediate)[0..@intCast(immediate_len)]);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_promises_scheduler_yield());
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_promises_scheduler_wait(1));

    var interval: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_promises_set_interval(1, "tick".ptr, 4, &interval));
    defer _ = plugin.sa_node_plugin_timers_promises_interval_free(interval);

    var tick_ptr: ?[*]const u8 = null;
    var tick_len: u64 = 0;
    var done: u32 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_promises_interval_next(interval, &tick_ptr, &tick_len, &done));
    defer _ = plugin.sa_node_plugin_free_buffer(tick_ptr, tick_len);
    try std.testing.expectEqual(@as(u32, 0), done);
    try std.testing.expectEqualStrings("tick", (tick_ptr orelse return error.NullTimersPromisesTick)[0..@intCast(tick_len)]);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_promises_interval_snapshot_json(interval, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullTimersPromisesSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"tickCount\":1") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_promises_interval_return(interval));
    var after_return_ptr: ?[*]const u8 = null;
    var after_return_len: u64 = 0;
    var after_return_done: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_promises_interval_next(interval, &after_return_ptr, &after_return_len, &after_return_done));
    try std.testing.expectEqual(@as(u32, 1), after_return_done);
    try std.testing.expect(after_return_ptr == null and after_return_len == 0);
}

test "node plugin timers create and clear registry entries" {
    var timeout_id: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_set_timeout(10, null, &timeout_id));
    try std.testing.expect(timeout_id > 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_clear_timeout(timeout_id));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_clear_timeout(timeout_id));

    var interval_id: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_set_interval(20, @ptrFromInt(@as(usize, 0x1234)), &interval_id));
    try std.testing.expect(interval_id > timeout_id);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_clear_interval(interval_id));

    var immediate_id: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_set_immediate(null, &immediate_id));
    try std.testing.expect(immediate_id > interval_id);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_timers_clear_immediate(immediate_id));
}

test "node plugin test runner reports native harness support" {
    try std.testing.expectEqual(@as(c_int, 0), setenv("NODE_OPTIONS", "--experimental-test-coverage --test-only --test-concurrency=4 --test-timeout=250 --test-isolation=none --test-reporter=tap --test-reporter-destination=stdout", 1));
    defer _ = unsetenv("NODE_OPTIONS");

    var test_status_ptr: ?[*]const u8 = null;
    var test_status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_status_json(&test_status_ptr, &test_status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(test_status_ptr, test_status_len);
    const test_status = (test_status_ptr orelse return error.NullTestStatus)[0..@intCast(test_status_len)];
    try std.testing.expect(std.mem.indexOf(u8, test_status, "\"module\":\"test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, test_status, "\"mode\":\"top-level-native-test-module\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, test_status, "\"describe\":\"suite\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, test_status, "\"it\":\"test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, test_status, "\"mock\":{\"supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, test_status, "\"snapshot\":{\"supported\":false") != null);

    var exports_ptr: ?[*]const u8 = null;
    var exports_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_exports_json(&exports_ptr, &exports_len));
    defer _ = plugin.sa_node_plugin_free_buffer(exports_ptr, exports_len);
    const exports_json = (exports_ptr orelse return error.NullTestExports)[0..@intCast(exports_len)];
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"suite\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"assert\"") != null);

    var top_reporters_ptr: ?[*]const u8 = null;
    var top_reporters_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_reporters_json(&top_reporters_ptr, &top_reporters_len));
    defer _ = plugin.sa_node_plugin_free_buffer(top_reporters_ptr, top_reporters_len);
    try std.testing.expectEqualStrings("[\"spec\",\"tap\",\"dot\",\"junit\",\"lcov\"]", (top_reporters_ptr orelse return error.NullTestReporters)[0..@intCast(top_reporters_len)]);

    var test_assert_ptr: ?[*]const u8 = null;
    var test_assert_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_assert_support_json(&test_assert_ptr, &test_assert_len));
    defer _ = plugin.sa_node_plugin_free_buffer(test_assert_ptr, test_assert_len);
    const test_assert = (test_assert_ptr orelse return error.NullTestAssertSupport)[0..@intCast(test_assert_len)];
    try std.testing.expect(std.mem.indexOf(u8, test_assert, "\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, test_assert, "\"register\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, test_assert, "deepStrictEqual") != null);

    var property_ptr: ?[*]const u8 = null;
    var property_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_property_support_json(&property_ptr, &property_len));
    defer _ = plugin.sa_node_plugin_free_buffer(property_ptr, property_len);
    const property_json = (property_ptr orelse return error.NullTestPropertySupport)[0..@intCast(property_len)];
    try std.testing.expect(std.mem.indexOf(u8, property_json, "\"getTestContext\":{\"supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, property_json, "\"run\":{\"supported\":false") != null);

    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_runner_status_json(&ptr, &len));
    defer _ = plugin.sa_node_plugin_free_buffer(ptr, len);
    const json = (ptr orelse return error.NullTestRunnerStatus)[0..@intCast(len)];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"module\":\"test_runner\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"backend\":\"sa test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"mode\":\"sync-native-config-introspection\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"builtinReporters\":[\"spec\",\"tap\",\"dot\",\"junit\",\"lcov\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"coverage\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"only\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"concurrency\":4") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"timeout\":250") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"isolation\":\"none\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"tap\"") != null);

    var reporters_ptr: ?[*]const u8 = null;
    var reporters_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_runner_builtin_reporters_json(&reporters_ptr, &reporters_len));
    defer _ = plugin.sa_node_plugin_free_buffer(reporters_ptr, reporters_len);
    const reporters = (reporters_ptr orelse return error.NullTestRunnerReporters)[0..@intCast(reporters_len)];
    try std.testing.expectEqualStrings("[\"spec\",\"tap\",\"dot\",\"junit\",\"lcov\"]", reporters);

    var has_spec: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_runner_has_builtin_reporter("spec".ptr, 4, &has_spec));
    try std.testing.expectEqual(@as(u64, 1), has_spec);

    var has_fake: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_runner_has_builtin_reporter("fake".ptr, 4, &has_fake));
    try std.testing.expectEqual(@as(u64, 0), has_fake);

    var config_ptr: ?[*]const u8 = null;
    var config_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_test_runner_config_json(&config_ptr, &config_len));
    defer _ = plugin.sa_node_plugin_free_buffer(config_ptr, config_len);
    const config = (config_ptr orelse return error.NullTestRunnerConfig)[0..@intCast(config_len)];
    try std.testing.expect(std.mem.indexOf(u8, config, "\"coverage\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"reporters\":[\"tap\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"reporterDestinations\":[\"stdout\"]") != null);
}

test "node plugin module top level native facade" {
    try std.testing.expectEqual(@as(c_int, 0), setenv("NODE_PATH", "/opt/node_modules:/srv/node_modules", 1));
    defer _ = unsetenv("NODE_PATH");

    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullModuleStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"module\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"builtinModules\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"compileCacheStatus\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"createRequire\":false") != null);

    var exports_ptr: ?[*]const u8 = null;
    var exports_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_exports_json(&exports_ptr, &exports_len));
    defer _ = plugin.sa_node_plugin_free_buffer(exports_ptr, exports_len);
    const exports_json = (exports_ptr orelse return error.NullModuleExports)[0..@intCast(exports_len)];
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"builtinModules\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"findPackageJSON\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"stripTypeScriptTypes\"") != null);

    var builtin_ptr: ?[*]const u8 = null;
    var builtin_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_builtin_modules_json(&builtin_ptr, &builtin_len));
    defer _ = plugin.sa_node_plugin_free_buffer(builtin_ptr, builtin_len);
    const builtins = (builtin_ptr orelse return error.NullModuleBuiltins)[0..@intCast(builtin_len)];
    try std.testing.expect(std.mem.indexOf(u8, builtins, "\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, builtins, "\"module\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, builtins, "\"test\"") != null);

    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_constants_json(&constants_ptr, &constants_len));
    defer _ = plugin.sa_node_plugin_free_buffer(constants_ptr, constants_len);
    const module_constants = (constants_ptr orelse return error.NullModuleConstants)[0..@intCast(constants_len)];
    try std.testing.expect(std.mem.indexOf(u8, module_constants, "\"FAILED\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, module_constants, "\"ENABLED\":1") != null);

    var global_paths_ptr: ?[*]const u8 = null;
    var global_paths_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_global_paths_json(&global_paths_ptr, &global_paths_len));
    defer _ = plugin.sa_node_plugin_free_buffer(global_paths_ptr, global_paths_len);
    const global_paths = (global_paths_ptr orelse return error.NullModuleGlobalPaths)[0..@intCast(global_paths_len)];
    try std.testing.expect(std.mem.indexOf(u8, global_paths, "/opt/node_modules") != null);
    try std.testing.expect(std.mem.indexOf(u8, global_paths, "/srv/node_modules") != null);

    var is_fs: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_is_builtin("fs".ptr, 2, &is_fs));
    try std.testing.expectEqual(@as(u64, 1), is_fs);

    var is_node_test: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_is_builtin("node:test".ptr, 9, &is_node_test));
    try std.testing.expectEqual(@as(u64, 1), is_node_test);

    var is_fake: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_is_builtin("fake".ptr, 4, &is_fake));
    try std.testing.expectEqual(@as(u64, 0), is_fake);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("pkg/src");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/package.json", .data = "{\"name\":\"demo\"}" });
    try tmp.dir.writeFile(.{ .sub_path = "pkg/src/index.js", .data = "module.exports = 1;" });
    const entry_path = try tmp.dir.realpathAlloc(std.testing.allocator, "pkg/src/index.js");
    defer std.testing.allocator.free(entry_path);

    var package_ptr: ?[*]const u8 = null;
    var package_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_find_package_json(entry_path.ptr, entry_path.len, &package_ptr, &package_len));
    defer _ = plugin.sa_node_plugin_free_buffer(package_ptr, package_len);
    const package_json_path = (package_ptr orelse return error.NullModulePackageJson)[0..@intCast(package_len)];
    try std.testing.expect(std.mem.indexOf(u8, package_json_path, "package.json") != null);

    var enable_ptr: ?[*]const u8 = null;
    var enable_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_enable_compile_cache_json(&enable_ptr, &enable_len));
    defer _ = plugin.sa_node_plugin_free_buffer(enable_ptr, enable_len);
    const enable_json = (enable_ptr orelse return error.NullModuleEnableCompileCache)[0..@intCast(enable_len)];
    try std.testing.expect(std.mem.indexOf(u8, enable_json, "\"status\":1") != null or std.mem.indexOf(u8, enable_json, "\"status\":2") != null);

    var cache_dir_ptr: ?[*]const u8 = null;
    var cache_dir_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_get_compile_cache_dir_json(&cache_dir_ptr, &cache_dir_len));
    defer _ = plugin.sa_node_plugin_free_buffer(cache_dir_ptr, cache_dir_len);
    const cache_dir_json = (cache_dir_ptr orelse return error.NullModuleCompileCacheDir)[0..@intCast(cache_dir_len)];
    try std.testing.expect(cache_dir_json.len > 2);

    var flush_ptr: ?[*]const u8 = null;
    var flush_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_flush_compile_cache_json(&flush_ptr, &flush_len));
    defer _ = plugin.sa_node_plugin_free_buffer(flush_ptr, flush_len);
    const flush_json = (flush_ptr orelse return error.NullModuleFlushCompileCache)[0..@intCast(flush_len)];
    try std.testing.expect(std.mem.indexOf(u8, flush_json, "metadata-only") != null);

    var source_maps_ptr: ?[*]const u8 = null;
    var source_maps_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_get_source_maps_support_json(&source_maps_ptr, &source_maps_len));
    defer _ = plugin.sa_node_plugin_free_buffer(source_maps_ptr, source_maps_len);
    const source_maps = (source_maps_ptr orelse return error.NullModuleSourceMapsSupport)[0..@intCast(source_maps_len)];
    try std.testing.expect(std.mem.indexOf(u8, source_maps, "\"enabled\":") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_set_source_maps_support(1, 1, 0));
    var source_maps2_ptr: ?[*]const u8 = null;
    var source_maps2_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_get_source_maps_support_json(&source_maps2_ptr, &source_maps2_len));
    defer _ = plugin.sa_node_plugin_free_buffer(source_maps2_ptr, source_maps2_len);
    const source_maps2 = (source_maps2_ptr orelse return error.NullModuleSourceMapsSupport2)[0..@intCast(source_maps2_len)];
    try std.testing.expect(std.mem.indexOf(u8, source_maps2, "\"enabled\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, source_maps2, "\"nodeModules\":true") != null);

    var feature_ptr: ?[*]const u8 = null;
    var feature_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_module_feature_support_json(&feature_ptr, &feature_len));
    defer _ = plugin.sa_node_plugin_free_buffer(feature_ptr, feature_len);
    const feature_json = (feature_ptr orelse return error.NullModuleFeatureSupport)[0..@intCast(feature_len)];
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"createRequire\":{\"supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"stripTypeScriptTypes\":{\"supported\":false") != null);
}

test "node plugin inspector top-level facade helpers" {
    try std.testing.expectEqual(@as(c_int, 0), setenv("NODE_OPTIONS", "--permission --allow-inspector --inspect-wait=127.0.0.1:9333", 1));
    defer _ = unsetenv("NODE_OPTIONS");

    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_inspector_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullInspectorStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"inspector\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mode\":\"top-level-config-facade\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"allowed\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"configuredPort\":9333") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"waitForDebugger\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"Session\":false") != null);

    var exports_ptr: ?[*]const u8 = null;
    var exports_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_inspector_exports_json(&exports_ptr, &exports_len));
    defer _ = plugin.sa_node_plugin_free_buffer(exports_ptr, exports_len);
    const exports_json = (exports_ptr orelse return error.NullInspectorExports)[0..@intCast(exports_len)];
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"open\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"url\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"Session\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exports_json, "\"DOMStorage\"") != null);

    var enabled: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_inspector_is_enabled(&enabled));
    try std.testing.expectEqual(@as(u64, 1), enabled);

    var allowed: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_inspector_is_allowed(&allowed));
    try std.testing.expectEqual(@as(u64, 1), allowed);

    var config_ptr: ?[*]const u8 = null;
    var config_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_inspector_config_json(&config_ptr, &config_len));
    defer _ = plugin.sa_node_plugin_free_buffer(config_ptr, config_len);
    const config = (config_ptr orelse return error.NullInspectorConfig)[0..@intCast(config_len)];
    try std.testing.expect(std.mem.indexOf(u8, config, "\"selectedFlag\":\"--inspect-wait=127.0.0.1:9333\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"kind\":\"inspect-wait\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"host\":\"127.0.0.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"port\":9333") != null);

    var url_ptr: ?[*]const u8 = null;
    var url_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_inspector_url_json(&url_ptr, &url_len));
    defer _ = plugin.sa_node_plugin_free_buffer(url_ptr, url_len);
    const url_json = (url_ptr orelse return error.NullInspectorUrl)[0..@intCast(url_len)];
    try std.testing.expect(std.mem.indexOf(u8, url_json, "\"active\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, url_json, "\"configured\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, url_json, "\"host\":\"127.0.0.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, url_json, "\"port\":9333") != null);

    var feature_ptr: ?[*]const u8 = null;
    var feature_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_inspector_feature_support_json(&feature_ptr, &feature_len));
    defer _ = plugin.sa_node_plugin_free_buffer(feature_ptr, feature_len);
    const feature_json = (feature_ptr orelse return error.NullInspectorFeatureSupport)[0..@intCast(feature_len)];
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"url\":{\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"open\":{\"supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, feature_json, "\"Session\":{\"supported\":false") != null);
}

test "node plugin wasi reports native config introspection" {
    try std.testing.expectEqual(@as(c_int, 0), setenv("NODE_OPTIONS", "--permission --allow-wasi --experimental-wasi-unstable-preview1", 1));
    defer _ = unsetenv("NODE_OPTIONS");
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_WASI_VERSION", "preview1", 1));
    defer _ = unsetenv("SA_NODE_WASI_VERSION");
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_WASI_ARGS", "[\"/virtual/app.wasm\",\"--demo\"]", 1));
    defer _ = unsetenv("SA_NODE_WASI_ARGS");
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_WASI_ENV", "{\"FOO\":\"bar\"}", 1));
    defer _ = unsetenv("SA_NODE_WASI_ENV");
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_WASI_PREOPENS", "{\"/sandbox\":\"/tmp\"}", 1));
    defer _ = unsetenv("SA_NODE_WASI_PREOPENS");
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_WASI_RETURN_ON_EXIT", "1", 1));
    defer _ = unsetenv("SA_NODE_WASI_RETURN_ON_EXIT");
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_WASI_STDIN", "3", 1));
    defer _ = unsetenv("SA_NODE_WASI_STDIN");
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_WASI_STDOUT", "4", 1));
    defer _ = unsetenv("SA_NODE_WASI_STDOUT");
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_WASI_STDERR", "5", 1));
    defer _ = unsetenv("SA_NODE_WASI_STDERR");

    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_wasi_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullWasiStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"wasi\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mode\":\"native-config-introspection\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "wasi_snapshot_preview1") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"allowed\":true") != null);

    var versions_ptr: ?[*]const u8 = null;
    var versions_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_wasi_supported_versions_json(&versions_ptr, &versions_len));
    defer _ = plugin.sa_node_plugin_free_buffer(versions_ptr, versions_len);
    try std.testing.expectEqualStrings("[\"unstable\",\"preview1\"]", (versions_ptr orelse return error.NullWasiVersions)[0..@intCast(versions_len)]);

    var imports_ptr: ?[*]const u8 = null;
    var imports_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_wasi_import_modules_json(&imports_ptr, &imports_len));
    defer _ = plugin.sa_node_plugin_free_buffer(imports_ptr, imports_len);
    const imports = (imports_ptr orelse return error.NullWasiImports)[0..@intCast(imports_len)];
    try std.testing.expect(std.mem.indexOf(u8, imports, "wasi_unstable") != null);
    try std.testing.expect(std.mem.indexOf(u8, imports, "wasi_snapshot_preview1") != null);

    var allowed: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_wasi_is_allowed(&allowed));
    try std.testing.expectEqual(@as(u64, 1), allowed);

    var config_ptr: ?[*]const u8 = null;
    var config_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_wasi_config_json(&config_ptr, &config_len));
    defer _ = plugin.sa_node_plugin_free_buffer(config_ptr, config_len);
    const config = (config_ptr orelse return error.NullWasiConfig)[0..@intCast(config_len)];
    try std.testing.expect(std.mem.indexOf(u8, config, "\"version\":\"preview1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"bindingName\":\"wasi_snapshot_preview1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"args\":[\"/virtual/app.wasm\",\"--demo\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"env\":{\"FOO\":\"bar\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"preopens\":{\"/sandbox\":\"/tmp\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"returnOnExit\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"stdin\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"stdout\":4") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"stderr\":5") != null);
}

test "node plugin errors and permissions report native compatibility status" {
    try std.testing.expectEqual(@as(c_int, 0), setenv("SA_NODE_ENV_TEST", "demo-value", 1));
    defer _ = unsetenv("SA_NODE_ENV_TEST");

    var env_status_ptr: ?[*]const u8 = null;
    var env_status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_environment_variables_status_json(&env_status_ptr, &env_status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(env_status_ptr, env_status_len);
    const env_status = (env_status_ptr orelse return error.NullEnvironmentVariablesStatus)[0..@intCast(env_status_len)];
    try std.testing.expect(std.mem.indexOf(u8, env_status, "\"module\":\"environment_variables\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, env_status, "\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, env_status, "dotenv parse and load helpers") != null);

    var env_snapshot_ptr: ?[*]const u8 = null;
    var env_snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_environment_variables_snapshot_json(&env_snapshot_ptr, &env_snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(env_snapshot_ptr, env_snapshot_len);
    const env_snapshot = (env_snapshot_ptr orelse return error.NullEnvironmentVariablesSnapshot)[0..@intCast(env_snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, env_snapshot, "\"SA_NODE_ENV_TEST\":\"demo-value\"") != null);

    var env_has: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_environment_variables_has("SA_NODE_ENV_TEST".ptr, 16, &env_has));
    try std.testing.expectEqual(@as(u64, 1), env_has);

    var env_value_ptr: ?[*]const u8 = null;
    var env_value_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_environment_variables_get_json("SA_NODE_ENV_TEST".ptr, 16, &env_value_ptr, &env_value_len));
    defer _ = plugin.sa_node_plugin_free_buffer(env_value_ptr, env_value_len);
    try std.testing.expectEqualStrings("\"demo-value\"", (env_value_ptr orelse return error.NullEnvironmentVariablesGet)[0..@intCast(env_value_len)]);

    const env_content =
        "FOO=bar\n" ++
        "export BAR = \"baz\"\n" ++
        "HASH=value # comment\n" ++
        "MULTILINE=\"line1\\nline2\"\n" ++
        "NODE_OPTIONS=--inspect\n" ++
        "BAD-NAME=skip\n";
    var parsed_env_ptr: ?[*]const u8 = null;
    var parsed_env_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_environment_variables_parse_env_json(env_content.ptr, env_content.len, &parsed_env_ptr, &parsed_env_len));
    defer _ = plugin.sa_node_plugin_free_buffer(parsed_env_ptr, parsed_env_len);
    const parsed_env = (parsed_env_ptr orelse return error.NullEnvironmentVariablesParse)[0..@intCast(parsed_env_len)];
    try std.testing.expect(std.mem.indexOf(u8, parsed_env, "\"FOO\":\"bar\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed_env, "\"BAR\":\"baz\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed_env, "\"HASH\":\"value\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed_env, "\"MULTILINE\":\"line1\\nline2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed_env, "BAD-NAME") == null);

    try std.testing.expectEqual(@as(c_int, 0), setenv("EXISTING_ENV", "keep", 1));
    defer _ = unsetenv("EXISTING_ENV");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "fixture.env", .data = "FOO=loaded\nEXISTING_ENV=override\nNODE_OPTIONS=--trace-warnings\n" });
    const fixture_path = try tmp.dir.realpathAlloc(std.testing.allocator, "fixture.env");
    defer std.testing.allocator.free(fixture_path);

    var loaded_env_ptr: ?[*]const u8 = null;
    var loaded_env_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_environment_variables_load_env_file_json(fixture_path.ptr, fixture_path.len, &loaded_env_ptr, &loaded_env_len));
    defer _ = plugin.sa_node_plugin_free_buffer(loaded_env_ptr, loaded_env_len);
    const loaded_env = (loaded_env_ptr orelse return error.NullEnvironmentVariablesLoad)[0..@intCast(loaded_env_len)];
    try std.testing.expect(std.mem.indexOf(u8, loaded_env, "\"loaded\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, loaded_env, "\"skipped\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, loaded_env, "\"FOO\":\"loaded\"") != null);

    var err_ptr: ?[*]const u8 = null;
    var err_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_errors_status_json(&err_ptr, &err_len));
    defer _ = plugin.sa_node_plugin_free_buffer(err_ptr, err_len);
    const errors = (err_ptr orelse return error.NullErrorsStatus)[0..@intCast(err_len)];
    try std.testing.expect(std.mem.indexOf(u8, errors, "\"module\":\"errors\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, errors, "\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, errors, "ERR_INVALID_ARG_TYPE") != null);
    try std.testing.expect(std.mem.indexOf(u8, errors, "ECONNRESET") != null);

    var codes_ptr: ?[*]const u8 = null;
    var codes_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_errors_codes_json(&codes_ptr, &codes_len));
    defer _ = plugin.sa_node_plugin_free_buffer(codes_ptr, codes_len);
    const codes = (codes_ptr orelse return error.NullErrorsCodes)[0..@intCast(codes_len)];
    try std.testing.expect(std.mem.indexOf(u8, codes, "\"node\":[\"ERR_INVALID_ARG_TYPE\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, codes, "\"ENOENT\":2") != null);

    var enoent_name_ptr: ?[*]const u8 = null;
    var enoent_name_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_errors_get_system_error_name(2, &enoent_name_ptr, &enoent_name_len));
    defer _ = plugin.sa_node_plugin_free_buffer(enoent_name_ptr, enoent_name_len);
    try std.testing.expectEqualStrings("ENOENT", (enoent_name_ptr orelse return error.NullErrorsSystemName)[0..@intCast(enoent_name_len)]);

    var enoent_msg_ptr: ?[*]const u8 = null;
    var enoent_msg_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_errors_get_system_error_message(2, &enoent_msg_ptr, &enoent_msg_len));
    defer _ = plugin.sa_node_plugin_free_buffer(enoent_msg_ptr, enoent_msg_len);
    const enoent_msg = (enoent_msg_ptr orelse return error.NullErrorsSystemMessage)[0..@intCast(enoent_msg_len)];
    try std.testing.expect(enoent_msg.len > 0);

    var sys_ptr: ?[*]const u8 = null;
    var sys_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_errors_system_error_json(2, "open".ptr, 4, "/tmp/missing".ptr, 12, null, 0, &sys_ptr, &sys_len));
    defer _ = plugin.sa_node_plugin_free_buffer(sys_ptr, sys_len);
    const sys = (sys_ptr orelse return error.NullErrorsSystemJson)[0..@intCast(sys_len)];
    try std.testing.expect(std.mem.indexOf(u8, sys, "\"code\":\"ENOENT\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sys, "\"syscall\":\"open\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sys, "\"path\":\"/tmp/missing\"") != null);

    var type_ptr: ?[*]const u8 = null;
    var type_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_errors_invalid_arg_type_json("path".ptr, 4, "string".ptr, 6, "number".ptr, 6, &type_ptr, &type_len));
    defer _ = plugin.sa_node_plugin_free_buffer(type_ptr, type_len);
    const type_json = (type_ptr orelse return error.NullErrorsInvalidArgType)[0..@intCast(type_len)];
    try std.testing.expect(std.mem.indexOf(u8, type_json, "ERR_INVALID_ARG_TYPE") != null);
    try std.testing.expect(std.mem.indexOf(u8, type_json, "Received type number") != null);

    var value_ptr: ?[*]const u8 = null;
    var value_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_errors_invalid_arg_value_json("mode".ptr, 4, "weird".ptr, 5, "is invalid".ptr, 10, &value_ptr, &value_len));
    defer _ = plugin.sa_node_plugin_free_buffer(value_ptr, value_len);
    const value_json = (value_ptr orelse return error.NullErrorsInvalidArgValue)[0..@intCast(value_len)];
    try std.testing.expect(std.mem.indexOf(u8, value_json, "ERR_INVALID_ARG_VALUE") != null);
    try std.testing.expect(std.mem.indexOf(u8, value_json, "\"value\":\"weird\"") != null);

    var range_ptr: ?[*]const u8 = null;
    var range_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_errors_out_of_range_json("port".ptr, 4, ">= 0 and <= 65535".ptr, 19, "99999".ptr, 5, &range_ptr, &range_len));
    defer _ = plugin.sa_node_plugin_free_buffer(range_ptr, range_len);
    const range_json = (range_ptr orelse return error.NullErrorsOutOfRange)[0..@intCast(range_len)];
    try std.testing.expect(std.mem.indexOf(u8, range_json, "ERR_OUT_OF_RANGE") != null);
    try std.testing.expect(std.mem.indexOf(u8, range_json, "\"received\":\"99999\"") != null);

    var assert_status_ptr: ?[*]const u8 = null;
    var assert_status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_assert_status_json(&assert_status_ptr, &assert_status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(assert_status_ptr, assert_status_len);
    const assert_status = (assert_status_ptr orelse return error.NullAssertStatus)[0..@intCast(assert_status_len)];
    try std.testing.expect(std.mem.indexOf(u8, assert_status, "\"module\":\"assert\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, assert_status, "deepStrictEqual") != null);

    var assert_ok_ptr: ?[*]const u8 = null;
    var assert_ok_len: u64 = 0;
    var assert_ok: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_assert_ok(1, null, 0, &assert_ok_ptr, &assert_ok_len, &assert_ok));
    defer _ = plugin.sa_node_plugin_free_buffer(assert_ok_ptr, assert_ok_len);
    try std.testing.expectEqual(@as(u64, 1), assert_ok);
    try std.testing.expectEqualStrings("null", (assert_ok_ptr orelse return error.NullAssertOkSuccess)[0..@intCast(assert_ok_len)]);

    var assert_fail_ptr: ?[*]const u8 = null;
    var assert_fail_len: u64 = 0;
    var assert_fail_ok: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_assert_ok(0, "boom".ptr, 4, &assert_fail_ptr, &assert_fail_len, &assert_fail_ok));
    defer _ = plugin.sa_node_plugin_free_buffer(assert_fail_ptr, assert_fail_len);
    try std.testing.expectEqual(@as(u64, 0), assert_fail_ok);
    const assert_fail_json = (assert_fail_ptr orelse return error.NullAssertOkFailure)[0..@intCast(assert_fail_len)];
    try std.testing.expect(std.mem.indexOf(u8, assert_fail_json, "ERR_ASSERTION") != null);
    try std.testing.expect(std.mem.indexOf(u8, assert_fail_json, "\"message\":\"boom\"") != null);

    var equal_ptr: ?[*]const u8 = null;
    var equal_len: u64 = 0;
    var equal_ok: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_assert_equal("1".ptr, 1, "1".ptr, 1, 1, null, 0, &equal_ptr, &equal_len, &equal_ok));
    defer _ = plugin.sa_node_plugin_free_buffer(equal_ptr, equal_len);
    try std.testing.expectEqual(@as(u64, 1), equal_ok);

    var deep_ptr: ?[*]const u8 = null;
    var deep_len: u64 = 0;
    var deep_ok: u64 = 0;
    const same_json = "{\"a\":1,\"b\":[2,3]}";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_assert_deep_strict_equal(same_json.ptr, same_json.len, same_json.ptr, same_json.len, null, 0, &deep_ptr, &deep_len, &deep_ok));
    defer _ = plugin.sa_node_plugin_free_buffer(deep_ptr, deep_len);
    try std.testing.expectEqual(@as(u64, 1), deep_ok);

    var fail_json_ptr: ?[*]const u8 = null;
    var fail_json_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_assert_fail_json("forced".ptr, 6, "1".ptr, 1, "2".ptr, 1, "fail".ptr, 4, &fail_json_ptr, &fail_json_len));
    defer _ = plugin.sa_node_plugin_free_buffer(fail_json_ptr, fail_json_len);
    const forced_fail_json = (fail_json_ptr orelse return error.NullAssertFailJson)[0..@intCast(fail_json_len)];
    try std.testing.expect(std.mem.indexOf(u8, forced_fail_json, "\"operator\":\"fail\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, forced_fail_json, "\"message\":\"forced\"") != null);

    var strict_cfg_ptr: ?[*]const u8 = null;
    var strict_cfg_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_assert_strict_config_json(&strict_cfg_ptr, &strict_cfg_len));
    defer _ = plugin.sa_node_plugin_free_buffer(strict_cfg_ptr, strict_cfg_len);
    const strict_cfg = (strict_cfg_ptr orelse return error.NullAssertStrictConfig)[0..@intCast(strict_cfg_len)];
    try std.testing.expect(std.mem.indexOf(u8, strict_cfg, "\"strict\":true") != null);

    var constants_status_ptr: ?[*]const u8 = null;
    var constants_status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_constants_status_json(&constants_status_ptr, &constants_status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(constants_status_ptr, constants_status_len);
    const constants_status = (constants_status_ptr orelse return error.NullConstantsStatus)[0..@intCast(constants_status_len)];
    try std.testing.expect(std.mem.indexOf(u8, constants_status, "\"module\":\"constants\"") != null);

    var constants_ptr2: ?[*]const u8 = null;
    var constants_len2: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_constants_json(&constants_ptr2, &constants_len2));
    defer _ = plugin.sa_node_plugin_free_buffer(constants_ptr2, constants_len2);
    const constants_json2 = (constants_ptr2 orelse return error.NullConstantsJson)[0..@intCast(constants_len2)];
    var constants2 = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, constants_json2, .{});
    defer constants2.deinit();
    try std.testing.expectEqual(@as(i64, 0), constants2.value.object.get("F_OK").?.integer);
    try std.testing.expectEqual(@as(i64, 4), constants2.value.object.get("COPYFILE_FICLONE_FORCE").?.integer);
    try std.testing.expect(constants2.value.object.get("CRYPTO_HASHES").?.array.items.len > 0);
    try std.testing.expect(constants2.value.object.get("SIGTERM") != null);

    var sys_status_ptr2: ?[*]const u8 = null;
    var sys_status_len2: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sys_status_json(&sys_status_ptr2, &sys_status_len2));
    defer _ = plugin.sa_node_plugin_free_buffer(sys_status_ptr2, sys_status_len2);
    const sys_status2 = (sys_status_ptr2 orelse return error.NullSysStatus)[0..@intCast(sys_status_len2)];
    try std.testing.expect(std.mem.indexOf(u8, sys_status2, "DEP0025") != null);

    var sys_deprecation_ptr: ?[*]const u8 = null;
    var sys_deprecation_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sys_deprecation_json(&sys_deprecation_ptr, &sys_deprecation_len));
    defer _ = plugin.sa_node_plugin_free_buffer(sys_deprecation_ptr, sys_deprecation_len);
    const sys_deprecation = (sys_deprecation_ptr orelse return error.NullSysDeprecation)[0..@intCast(sys_deprecation_len)];
    try std.testing.expect(std.mem.indexOf(u8, sys_deprecation, "node:util") != null);

    var sys_format_ptr: ?[*]const u8 = null;
    var sys_format_len: u64 = 0;
    const sys_args = "[\"world\",7]";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sys_format("hello %s %d".ptr, 11, sys_args.ptr, sys_args.len, &sys_format_ptr, &sys_format_len));
    defer _ = plugin.sa_node_plugin_free_buffer(sys_format_ptr, sys_format_len);
    try std.testing.expectEqualStrings("hello world 7", (sys_format_ptr orelse return error.NullSysFormat)[0..@intCast(sys_format_len)]);

    var sys_inspect_ptr: ?[*]const u8 = null;
    var sys_inspect_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sys_inspect(same_json.ptr, same_json.len, &sys_inspect_ptr, &sys_inspect_len));
    defer _ = plugin.sa_node_plugin_free_buffer(sys_inspect_ptr, sys_inspect_len);
    const sys_inspect = (sys_inspect_ptr orelse return error.NullSysInspect)[0..@intCast(sys_inspect_len)];
    try std.testing.expect(std.mem.indexOf(u8, sys_inspect, "a") != null);

    var sys_debug_ptr: ?[*]const u8 = null;
    var sys_debug_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_sys_debuglog("http".ptr, 4, &sys_debug_ptr, &sys_debug_len));
    defer _ = plugin.sa_node_plugin_free_buffer(sys_debug_ptr, sys_debug_len);
    const sys_debug = (sys_debug_ptr orelse return error.NullSysDebuglog)[0..@intCast(sys_debug_len)];
    try std.testing.expect(std.mem.indexOf(u8, sys_debug, "\"section\":\"http\"") != null);

    var perm_ptr: ?[*]const u8 = null;
    var perm_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_status_json(&perm_ptr, &perm_len));
    defer _ = plugin.sa_node_plugin_free_buffer(perm_ptr, perm_len);
    const permissions = (perm_ptr orelse return error.NullPermissionsStatus)[0..@intCast(perm_len)];
    try std.testing.expect(std.mem.indexOf(u8, permissions, "\"module\":\"permissions\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, permissions, "\"model\":\"sa-plugin-manifest\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, permissions, "\"declared\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, permissions, "\"availableFlags\":") != null);
}

test "node plugin permissions native manifest helpers" {
    var enabled: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_is_enabled(&enabled));
    try std.testing.expect(enabled == 0 or enabled == 1);

    var audit_mode: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_is_audit_mode(&audit_mode));
    try std.testing.expect(audit_mode == 0 or audit_mode == 1);

    var flags_ptr: ?[*]const u8 = null;
    var flags_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_available_flags_json(&flags_ptr, &flags_len));
    defer _ = plugin.sa_node_plugin_free_buffer(flags_ptr, flags_len);
    const flags = (flags_ptr orelse return error.NullPermissionsFlags)[0..@intCast(flags_len)];
    try std.testing.expect(std.mem.indexOf(u8, flags, "--allow-fs-read") != null);
    try std.testing.expect(std.mem.indexOf(u8, flags, "--allow-net") != null);

    var declared_ptr: ?[*]const u8 = null;
    var declared_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_declared_json(&declared_ptr, &declared_len));
    defer _ = plugin.sa_node_plugin_free_buffer(declared_ptr, declared_len);
    const declared = (declared_ptr orelse return error.NullPermissionsDeclared)[0..@intCast(declared_len)];
    try std.testing.expect(std.mem.indexOf(u8, declared, "\"process\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, declared, "\"net\"") != null);

    var has_fs_read: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_has("fs.read".ptr, 7, "sap.json".ptr, 8, &has_fs_read));
    try std.testing.expectEqual(@as(u64, 1), has_fs_read);

    var has_env: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_has("env".ptr, 3, "SA_PLUGIN_DEV".ptr, 13, &has_env));
    try std.testing.expectEqual(@as(u64, 1), has_env);

    var has_spawn: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_has("process.spawn".ptr, 13, null, 0, &has_spawn));
    try std.testing.expectEqual(@as(u64, 1), has_spawn);

    var has_exec_echo: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_has("process.exec".ptr, 12, "/bin/echo".ptr, 9, &has_exec_echo));
    try std.testing.expectEqual(@as(u64, 1), has_exec_echo);

    var has_denied_net: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_permissions_has("net".ptr, 3, "http://example.com".ptr, 18, &has_denied_net));
    try std.testing.expectEqual(@as(u64, 0), has_denied_net);
}

test "node plugin status reports native command line i18n deprecation and iterable stream support" {
    try std.testing.expectEqual(@as(c_int, 0), setenv("NODE_OPTIONS", "--env-file=.env --env-file-if-exists .env.local --require ./preload.js -C development --inspect=127.0.0.1:9229", 1));
    defer _ = unsetenv("NODE_OPTIONS");

    var cmd_ptr: ?[*]const u8 = null;
    var cmd_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_command_line_options_status_json(&cmd_ptr, &cmd_len));
    defer _ = plugin.sa_node_plugin_free_buffer(cmd_ptr, cmd_len);
    const cmd = (cmd_ptr orelse return error.NullCommandLineOptionsStatus)[0..@intCast(cmd_len)];
    try std.testing.expect(std.mem.indexOf(u8, cmd, "\"module\":\"command_line_options\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "\"supported\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "NODE_OPTIONS") != null or std.mem.indexOf(u8, cmd, "nodeOptions") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "\"nodeOptionsPresent\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "\"preloadModules\":[\"./preload.js\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "\"conditions\":[\"development\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "\"inspectFlags\":[\"--inspect=127.0.0.1:9229\"]") != null);

    var argv_ptr: ?[*]const u8 = null;
    var argv_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_command_line_options_argv_json(&argv_ptr, &argv_len));
    defer _ = plugin.sa_node_plugin_free_buffer(argv_ptr, argv_len);
    const argv_json = (argv_ptr orelse return error.NullCommandLineOptionsArgv)[0..@intCast(argv_len)];
    try std.testing.expect(std.mem.startsWith(u8, argv_json, "["));

    var tokens_ptr: ?[*]const u8 = null;
    var tokens_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_command_line_options_node_options_tokens_json(&tokens_ptr, &tokens_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tokens_ptr, tokens_len);
    const tokens = (tokens_ptr orelse return error.NullCommandLineOptionsTokens)[0..@intCast(tokens_len)];
    try std.testing.expectEqualStrings("[\"--env-file=.env\",\"--env-file-if-exists\",\".env.local\",\"--require\",\"./preload.js\",\"-C\",\"development\",\"--inspect=127.0.0.1:9229\"]", tokens);

    var env_files_ptr: ?[*]const u8 = null;
    var env_files_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_command_line_options_env_files_json(&env_files_ptr, &env_files_len));
    defer _ = plugin.sa_node_plugin_free_buffer(env_files_ptr, env_files_len);
    const env_files = (env_files_ptr orelse return error.NullCommandLineOptionsEnvFiles)[0..@intCast(env_files_len)];
    try std.testing.expectEqualStrings("{\"required\":[\".env\"],\"optional\":[\".env.local\"]}", env_files);

    var has_require: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_command_line_options_has_flag("--require".ptr, 9, &has_require));
    try std.testing.expectEqual(@as(u64, 1), has_require);

    var has_fake: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_command_line_options_has_flag("--does-not-exist".ptr, 16, &has_fake));
    try std.testing.expectEqual(@as(u64, 0), has_fake);

    var dep_ptr: ?[*]const u8 = null;
    var dep_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_status_json(&dep_ptr, &dep_len));
    defer _ = plugin.sa_node_plugin_free_buffer(dep_ptr, dep_len);
    const dep = (dep_ptr orelse return error.NullDeprecatedStatus)[0..@intCast(dep_len)];
    try std.testing.expect(std.mem.indexOf(u8, dep, "\"module\":\"deprecated\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, dep, "util.deprecate-style registry") != null);

    var intl_ptr: ?[*]const u8 = null;
    var intl_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_internationalization_status_json(&intl_ptr, &intl_len));
    defer _ = plugin.sa_node_plugin_free_buffer(intl_ptr, intl_len);
    const intl = (intl_ptr orelse return error.NullInternationalizationStatus)[0..@intCast(intl_len)];
    try std.testing.expect(std.mem.indexOf(u8, intl, "\"module\":\"internationalization\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, intl, "\"icu\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, intl, "\"encoding\":\"utf-8\"") != null);

    var iter_ptr: ?[*]const u8 = null;
    var iter_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_iterable_streams_status_json(&iter_ptr, &iter_len));
    defer _ = plugin.sa_node_plugin_free_buffer(iter_ptr, iter_len);
    const iter = (iter_ptr orelse return error.NullIterableStreamsStatus)[0..@intCast(iter_len)];
    try std.testing.expect(std.mem.indexOf(u8, iter, "\"module\":\"iterable_streams\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, iter, "WebReadableStream") != null);
    try std.testing.expect(std.mem.indexOf(u8, iter, "pipeline state tracking") != null);
}

test "node plugin internationalization reports native config introspection" {
    try std.testing.expectEqual(@as(c_int, 0), setenv("NODE_OPTIONS", "--icu-data-dir=/opt/demo-icu", 1));
    defer _ = unsetenv("NODE_OPTIONS");
    try std.testing.expectEqual(@as(c_int, 0), setenv("NODE_ICU_DATA", "/env/icu", 1));
    defer _ = unsetenv("NODE_ICU_DATA");
    try std.testing.expectEqual(@as(c_int, 0), setenv("LC_ALL", "zh_CN.UTF-8", 1));
    defer _ = unsetenv("LC_ALL");
    try std.testing.expectEqual(@as(c_int, 0), setenv("TZ", "Asia/Shanghai", 1));
    defer _ = unsetenv("TZ");

    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_internationalization_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullInternationalizationStatus2)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"internationalization\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"nodeIcuData\":\"/env/icu\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"icuDataDirFlag\":\"/opt/demo-icu\"") != null);

    var config_ptr: ?[*]const u8 = null;
    var config_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_internationalization_config_json(&config_ptr, &config_len));
    defer _ = plugin.sa_node_plugin_free_buffer(config_ptr, config_len);
    const config = (config_ptr orelse return error.NullInternationalizationConfig)[0..@intCast(config_len)];
    try std.testing.expect(std.mem.indexOf(u8, config, "\"effectiveLocale\":\"zh_CN.UTF-8\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"icuConfigured\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "\"supportedEncodings\":") != null);

    var locale_ptr: ?[*]const u8 = null;
    var locale_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_internationalization_effective_locale_json(&locale_ptr, &locale_len));
    defer _ = plugin.sa_node_plugin_free_buffer(locale_ptr, locale_len);
    try std.testing.expectEqualStrings("\"zh_CN.UTF-8\"", (locale_ptr orelse return error.NullInternationalizationLocale)[0..@intCast(locale_len)]);

    var encodings_ptr: ?[*]const u8 = null;
    var encodings_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_internationalization_supported_encodings_json(&encodings_ptr, &encodings_len));
    defer _ = plugin.sa_node_plugin_free_buffer(encodings_ptr, encodings_len);
    const encodings = (encodings_ptr orelse return error.NullInternationalizationEncodings)[0..@intCast(encodings_len)];
    try std.testing.expect(std.mem.indexOf(u8, encodings, "utf-8") != null);
    try std.testing.expect(std.mem.indexOf(u8, encodings, "utf16le") != null);

    var has_utf8: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_internationalization_has_encoding("utf-8".ptr, 5, &has_utf8));
    try std.testing.expectEqual(@as(u64, 1), has_utf8);

    var has_fake: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_internationalization_has_encoding("shift-jis".ptr, 9, &has_fake));
    try std.testing.expectEqual(@as(u64, 0), has_fake);

    var has_icu: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_internationalization_has_icu_config(&has_icu));
    try std.testing.expectEqual(@as(u64, 1), has_icu);
}

test "node plugin iterable streams reports native bridge metadata" {
    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_iterable_streams_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullIterableStreamsStatus2)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"iterable_streams\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"bridge\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "classic and web stream bridge metadata") != null);

    var types_ptr: ?[*]const u8 = null;
    var types_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_iterable_streams_stream_types_json(&types_ptr, &types_len));
    defer _ = plugin.sa_node_plugin_free_buffer(types_ptr, types_len);
    const types = (types_ptr orelse return error.NullIterableStreamsTypes)[0..@intCast(types_len)];
    try std.testing.expect(std.mem.indexOf(u8, types, "WebReadableStream") != null);
    try std.testing.expect(std.mem.indexOf(u8, types, "PassThrough") != null);

    var caps_ptr: ?[*]const u8 = null;
    var caps_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_iterable_streams_capabilities_json(&caps_ptr, &caps_len));
    defer _ = plugin.sa_node_plugin_free_buffer(caps_ptr, caps_len);
    const caps = (caps_ptr orelse return error.NullIterableStreamsCapabilities)[0..@intCast(caps_len)];
    try std.testing.expect(std.mem.indexOf(u8, caps, "pipeline state tracking") != null);
    try std.testing.expect(std.mem.indexOf(u8, caps, "web stream read/write/enqueue helpers") != null);

    var bridge_ptr: ?[*]const u8 = null;
    var bridge_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_iterable_streams_bridge_json(&bridge_ptr, &bridge_len));
    defer _ = plugin.sa_node_plugin_free_buffer(bridge_ptr, bridge_len);
    const bridge = (bridge_ptr orelse return error.NullIterableStreamsBridge)[0..@intCast(bridge_len)];
    try std.testing.expect(std.mem.indexOf(u8, bridge, "\"asyncIterator\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, bridge, "stream.pipeline") != null);
    try std.testing.expect(std.mem.indexOf(u8, bridge, "web_streams.read") != null);

    var has_type: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_iterable_streams_has_stream_type("Readable".ptr, 8, &has_type));
    try std.testing.expectEqual(@as(u64, 1), has_type);

    var has_missing_type: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_iterable_streams_has_stream_type("Generator".ptr, 9, &has_missing_type));
    try std.testing.expectEqual(@as(u64, 0), has_missing_type);

    var has_cap: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_iterable_streams_has_capability("stream.pipeline".ptr, 15, &has_cap));
    try std.testing.expectEqual(@as(u64, 1), has_cap);

    var has_missing_cap: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_iterable_streams_has_capability("Readable.from".ptr, 13, &has_missing_cap));
    try std.testing.expectEqual(@as(u64, 0), has_missing_cap);
}

test "node plugin deprecated registry helpers" {
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_clear());

    var has_before: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_has("DEP9000".ptr, 7, &has_before));
    try std.testing.expectEqual(@as(u64, 0), has_before);

    var first_ptr: ?[*]const u8 = null;
    var first_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_record_json("DEP9000".ptr, 7, "native test warning".ptr, 19, &first_ptr, &first_len));
    defer _ = plugin.sa_node_plugin_free_buffer(first_ptr, first_len);
    const first = (first_ptr orelse return error.NullDeprecatedRecordFirst)[0..@intCast(first_len)];
    try std.testing.expect(std.mem.indexOf(u8, first, "\"count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, first, "\"firstOccurrence\":true") != null);

    var has_after: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_has("DEP9000".ptr, 7, &has_after));
    try std.testing.expectEqual(@as(u64, 1), has_after);

    var second_ptr: ?[*]const u8 = null;
    var second_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_record_json("DEP9000".ptr, 7, "ignored replacement".ptr, 19, &second_ptr, &second_len));
    defer _ = plugin.sa_node_plugin_free_buffer(second_ptr, second_len);
    const second = (second_ptr orelse return error.NullDeprecatedRecordSecond)[0..@intCast(second_len)];
    try std.testing.expect(std.mem.indexOf(u8, second, "\"count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, second, "\"firstOccurrence\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, second, "native test warning") != null);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_snapshot_json(&snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullDeprecatedSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"registeredCount\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "DEP9000") != null);

    try std.testing.expectEqual(@as(c_int, 0), setenv("NODE_OPTIONS", "--pending-deprecation --trace-deprecation", 1));
    defer _ = unsetenv("NODE_OPTIONS");
    try std.testing.expectEqual(@as(c_int, 0), setenv("NODE_PENDING_DEPRECATION", "1", 1));
    defer _ = unsetenv("NODE_PENDING_DEPRECATION");

    var flags_ptr: ?[*]const u8 = null;
    var flags_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_flags_json(&flags_ptr, &flags_len));
    defer _ = plugin.sa_node_plugin_free_buffer(flags_ptr, flags_len);
    const flags = (flags_ptr orelse return error.NullDeprecatedFlags)[0..@intCast(flags_len)];
    try std.testing.expect(std.mem.indexOf(u8, flags, "\"pendingDeprecation\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, flags, "\"traceDeprecation\":true") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_clear());
    var cleared_has: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_deprecated_has("DEP9000".ptr, 7, &cleared_has));
    try std.testing.expectEqual(@as(u64, 0), cleared_has);
}

test "node plugin readline promises interface" {
    const input = "first\nsecond\r\n";
    var iface: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_readline_promises_create_interface(input.ptr, input.len, &iface));
    defer _ = plugin.sa_node_plugin_readline_promises_free(iface);

    var first_ptr: ?[*]const u8 = null;
    var first_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_readline_promises_question(iface, "q1> ".ptr, 4, &first_ptr, &first_len));
    defer _ = plugin.sa_node_plugin_free_buffer(first_ptr, first_len);
    try std.testing.expectEqualStrings("first", (first_ptr orelse return error.NullReadlinePromisesFirst)[0..@intCast(first_len)]);

    var second_ptr: ?[*]const u8 = null;
    var second_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_readline_promises_question(iface, "q2> ".ptr, 4, &second_ptr, &second_len));
    defer _ = plugin.sa_node_plugin_free_buffer(second_ptr, second_len);
    try std.testing.expectEqualStrings("second", (second_ptr orelse return error.NullReadlinePromisesSecond)[0..@intCast(second_len)]);

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_readline_promises_snapshot_json(iface, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullReadlinePromisesSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"closed\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"inputLen\":14") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_readline_promises_close(iface));
    var after_close_ptr: ?[*]const u8 = null;
    var after_close_len: u64 = 0;
    try std.testing.expect(plugin.sa_node_plugin_readline_promises_question(iface, "q3> ".ptr, 4, &after_close_ptr, &after_close_len) != 0);
}

test "node plugin repl native session subset" {
    var status_ptr: ?[*]const u8 = null;
    var status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_status_json(&status_ptr, &status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_ptr, status_len);
    const status = (status_ptr orelse return error.NullReplStatus)[0..@intCast(status_len)];
    try std.testing.expect(std.mem.indexOf(u8, status, "\"module\":\"repl\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "native-session-subset") != null);

    var session: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_create_session("node> ".ptr, 6, &session));
    defer _ = plugin.sa_node_plugin_repl_free(session);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_define_command(session, "hello".ptr, 5, "custom help".ptr, 11));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_set_prompt(session, "sa> ".ptr, 4));

    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_snapshot_json(session, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot = (snapshot_ptr orelse return error.NullReplSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"prompt\":\"sa> \"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, ".hello") != null);

    var help_ptr: ?[*]const u8 = null;
    var help_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_eval_line(session, ".help".ptr, 5, &help_ptr, &help_len));
    defer _ = plugin.sa_node_plugin_free_buffer(help_ptr, help_len);
    const help = (help_ptr orelse return error.NullReplHelp)[0..@intCast(help_len)];
    try std.testing.expect(std.mem.indexOf(u8, help, ".history") != null);
    try std.testing.expect(std.mem.indexOf(u8, help, ".hello") != null);

    var buffer_ptr: ?[*]const u8 = null;
    var buffer_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_eval_line(session, "const x = \\".ptr, 11, &buffer_ptr, &buffer_len));
    defer _ = plugin.sa_node_plugin_free_buffer(buffer_ptr, buffer_len);
    const buffer_json = (buffer_ptr orelse return error.NullReplBuffer)[0..@intCast(buffer_len)];
    try std.testing.expect(std.mem.indexOf(u8, buffer_json, "\"continued\":true") != null);

    var input_ptr: ?[*]const u8 = null;
    var input_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_eval_line(session, "1 + 2".ptr, 5, &input_ptr, &input_len));
    defer _ = plugin.sa_node_plugin_free_buffer(input_ptr, input_len);
    const input_json = (input_ptr orelse return error.NullReplInput)[0..@intCast(input_len)];
    try std.testing.expect(std.mem.indexOf(u8, input_json, "\"submitted\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, input_json, "const x = ") != null);

    var history_ptr: ?[*]const u8 = null;
    var history_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_history_json(session, &history_ptr, &history_len));
    defer _ = plugin.sa_node_plugin_free_buffer(history_ptr, history_len);
    const history = (history_ptr orelse return error.NullReplHistory)[0..@intCast(history_len)];
    try std.testing.expect(std.mem.indexOf(u8, history, ".help") != null);
    try std.testing.expect(std.mem.indexOf(u8, history, "1 + 2") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_repl_close(session));
    var after_close_ptr: ?[*]const u8 = null;
    var after_close_len: u64 = 0;
    try std.testing.expect(plugin.sa_node_plugin_repl_eval_line(session, "x".ptr, 1, &after_close_ptr, &after_close_len) != 0);
}

test "node plugin readline terminal control writes ansi sequences" {
    const pipe_fds = try std.posix.pipe();
    defer std.posix.close(pipe_fds[0]);

    const write_fd: u64 = @intCast(pipe_fds[1]);
    try std.testing.expectEqual(@as(u64, 0), plugin.sa_node_plugin_readline_clear_line(write_fd, 0));
    try std.testing.expectEqual(@as(u64, 0), plugin.sa_node_plugin_readline_clear_line(write_fd, @bitCast(@as(i64, -1))));
    try std.testing.expectEqual(@as(u64, 0), plugin.sa_node_plugin_readline_clear_line(write_fd, 1));
    try std.testing.expectEqual(@as(u64, 0), plugin.sa_node_plugin_readline_clear_screen_down(write_fd));
    try std.testing.expectEqual(@as(u64, 0), plugin.sa_node_plugin_readline_cursor_to(write_fd, 4, 2));
    try std.testing.expectEqual(@as(u64, 0), plugin.sa_node_plugin_readline_move_cursor(write_fd, 3, @bitCast(@as(i64, -2))));

    std.posix.close(pipe_fds[1]);
    var buf: [128]u8 = undefined;
    const n = try std.posix.read(pipe_fds[0], &buf);
    try std.testing.expectEqualStrings("\x1b[2K\x1b[1K\x1b[0K\x1b[0J\x1b[3;5H\x1b[3C\x1b[2A", buf[0..n]);
}

test "node plugin util mime type and parse args" {
    var mime_ptr: ?[*]const u8 = null;
    var mime_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_util_mime_type("test.js", 7, &mime_ptr, &mime_len));
    defer _ = plugin.sa_node_plugin_free_buffer(mime_ptr, mime_len);
    try std.testing.expectEqualStrings("\"application/javascript\"", (mime_ptr orelse return error.NullMimeType)[0..@intCast(mime_len)]);

    var args_ptr: ?[*]const u8 = null;
    var args_len: u64 = 0;
    const config = "{}";
    const argv = "[\"--foo=bar\",\"pos1\",\"--baz=qux\"]";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_util_parse_args(config.ptr, config.len, argv.ptr, argv.len, &args_ptr, &args_len));
    defer _ = plugin.sa_node_plugin_free_buffer(args_ptr, args_len);
    const args = (args_ptr orelse return error.NullParsedArgs)[0..@intCast(args_len)];
    try std.testing.expect(std.mem.indexOf(u8, args, "\"foo\":\"bar\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, args, "\"baz\":\"qux\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, args, "\"pos1\"") != null);

    var debug_ptr: ?[*]const u8 = null;
    var debug_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_util_debuglog("stream".ptr, 6, &debug_ptr, &debug_len));
    defer _ = plugin.sa_node_plugin_free_buffer(debug_ptr, debug_len);
    const debug = (debug_ptr orelse return error.NullUtilDebuglog)[0..@intCast(debug_len)];
    try std.testing.expect(std.mem.indexOf(u8, debug, "\"section\":\"stream\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug, "\"enabled\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug, "\"prefix\":") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_util_deprecate("DEP9001".ptr, 7, "old api".ptr, 7));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_util_deprecate("DEP9001".ptr, 7, "old api".ptr, 7));
}

test "node plugin fs opendir next yields entry" {
    var handle: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_opendir("/tmp", 4, &handle));
    defer _ = plugin.sa_node_plugin_fs_opendir_free(handle);

    var name_ptr: ?[*]const u8 = null;
    var name_len: u64 = 0;
    var entry_type: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_opendir_next(handle, &name_ptr, &name_len, &entry_type));
    defer _ = plugin.sa_node_plugin_free_buffer(name_ptr, name_len);
    try std.testing.expect(name_len > 0);
}

test "node plugin fs exists" {
    var exists: u32 = 0;
    const status = plugin.sa_node_plugin_fs_exists("sap.json", 8, &exists);
    try std.testing.expectEqual(@as(u32, 0), status);
    try std.testing.expectEqual(@as(u32, 1), exists);
}

test "node plugin fs metadata and sync use system calls" {
    const path = try std.fmt.allocPrintZ(std.testing.allocator, "/tmp/sa-node-fs-meta-{d}.txt", .{std.crypto.random.int(u64)});
    defer std.testing.allocator.free(path);
    const file = try std.fs.createFileAbsolute(path, .{ .read = true, .truncate = true });
    defer file.close();
    defer std.fs.deleteFileAbsolute(path) catch {};

    try file.writeAll("metadata");
    const fd: u32 = @intCast(file.handle);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_fsync(fd));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_fdatasync(fd));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_futimes(fd, 1000, 2000));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_utimes(path.ptr, path.len, 3000, 4000));

    var uid: u32 = 0;
    var gid: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_getuid(&uid));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_getgid(&gid));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_chown(path.ptr, path.len, uid, gid));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_fchown(fd, uid, gid));

    var statfs_ptr: ?[*]const u8 = null;
    var statfs_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_statfs(path.ptr, &statfs_ptr, &statfs_len));
    defer _ = plugin.sa_node_plugin_free_buffer(statfs_ptr, statfs_len);
    const statfs_json = (statfs_ptr orelse return error.NullStatfs)[0..@intCast(statfs_len)];
    try std.testing.expect(std.mem.indexOf(u8, statfs_json, "\"bsize\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, statfs_json, "\"blocks\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, statfs_json, "\"bfree\":0") == null);
}

test "node plugin fs promises helpers" {
    const dir_path = "zig-cache-fs-promises-test";
    const file_path = "zig-cache-fs-promises-test/a.txt";
    const copy_path = "zig-cache-fs-promises-test/b.txt";
    const renamed_path = "zig-cache-fs-promises-test/c.txt";
    const hardlink_path = "zig-cache-fs-promises-test/d.txt";
    const symlink_path = "zig-cache-fs-promises-test/e.txt";
    const mkdtemp_template = "zig-cache-fs-promises-temp-XXXXXX";
    _ = plugin.sa_node_plugin_fs_rm(dir_path.ptr, dir_path.len, 1);
    defer _ = plugin.sa_node_plugin_fs_rm(dir_path.ptr, dir_path.len, 1);
    var temp_dir_ptr: ?[*]const u8 = null;
    var temp_dir_len: u64 = 0;
    defer if (temp_dir_ptr != null) {
        _ = plugin.sa_node_plugin_fs_promises_rmdir(temp_dir_ptr, temp_dir_len);
        _ = plugin.sa_node_plugin_free_buffer(temp_dir_ptr, temp_dir_len);
    };

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_mkdir(dir_path.ptr, dir_path.len, 1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_write_file(file_path.ptr, file_path.len, "hello".ptr, 5));

    var read_ptr: ?[*]const u8 = null;
    var read_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_read_file(file_path.ptr, file_path.len, &read_ptr, &read_len));
    defer _ = plugin.sa_node_plugin_free_buffer(read_ptr, read_len);
    try std.testing.expectEqualStrings("hello", (read_ptr orelse return error.NullFsPromisesReadFile)[0..@intCast(read_len)]);

    var stat_ptr: ?[*]const u8 = null;
    var stat_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_stat(file_path.ptr, file_path.len, &stat_ptr, &stat_len));
    defer _ = plugin.sa_node_plugin_free_buffer(stat_ptr, stat_len);
    const stat = (stat_ptr orelse return error.NullFsPromisesStat)[0..@intCast(stat_len)];
    try std.testing.expect(std.mem.indexOf(u8, stat, "\"size\":5") != null);

    var lstat_ptr: ?[*]const u8 = null;
    var lstat_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_lstat(file_path.ptr, file_path.len, &lstat_ptr, &lstat_len));
    defer _ = plugin.sa_node_plugin_free_buffer(lstat_ptr, lstat_len);
    try std.testing.expect(std.mem.indexOf(u8, (lstat_ptr orelse return error.NullFsPromisesLstat)[0..@intCast(lstat_len)], "\"mode\":") != null);

    var entries_ptr: ?[*]const u8 = null;
    var entries_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_readdir(dir_path.ptr, dir_path.len, &entries_ptr, &entries_len));
    defer _ = plugin.sa_node_plugin_free_buffer(entries_ptr, entries_len);
    const entries = (entries_ptr orelse return error.NullFsPromisesReaddir)[0..@intCast(entries_len)];
    try std.testing.expect(std.mem.indexOf(u8, entries, "a.txt") != null);

    var typed_entries_ptr: ?[*]const u8 = null;
    var typed_entries_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_readdir_with_types(dir_path.ptr, dir_path.len, &typed_entries_ptr, &typed_entries_len));
    defer _ = plugin.sa_node_plugin_free_buffer(typed_entries_ptr, typed_entries_len);
    const typed_entries = (typed_entries_ptr orelse return error.NullFsPromisesReaddirWithTypes)[0..@intCast(typed_entries_len)];
    try std.testing.expect(std.mem.indexOf(u8, typed_entries, "a.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, typed_entries, "\"type\":") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_copy_file(file_path.ptr, file_path.len, copy_path.ptr, copy_path.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_rename(copy_path.ptr, copy_path.len, renamed_path.ptr, renamed_path.len));

    var exists: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_exists(renamed_path.ptr, renamed_path.len, &exists));
    try std.testing.expectEqual(@as(u32, 1), exists);

    var access: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_access(renamed_path.ptr, renamed_path.len, 0, &access));
    try std.testing.expectEqual(@as(u32, 1), access);

    var realpath_ptr: ?[*]const u8 = null;
    var realpath_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_realpath(renamed_path.ptr, renamed_path.len, &realpath_ptr, &realpath_len));
    defer _ = plugin.sa_node_plugin_free_buffer(realpath_ptr, realpath_len);
    const realpath = (realpath_ptr orelse return error.NullFsPromisesRealpath)[0..@intCast(realpath_len)];
    try std.testing.expect(realpath.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, realpath, "c.txt") != null);

    var uid: u32 = 0;
    var gid: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_getuid(&uid));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_getgid(&gid));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_chmod(renamed_path.ptr, renamed_path.len, 0o644));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_chown(renamed_path.ptr, renamed_path.len, uid, gid));

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_link(renamed_path.ptr, renamed_path.len, hardlink_path.ptr, hardlink_path.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_symlink(renamed_path.ptr, renamed_path.len, symlink_path.ptr, symlink_path.len));

    var readlink_ptr: ?[*]const u8 = null;
    var readlink_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_readlink(symlink_path.ptr, symlink_path.len, &readlink_ptr, &readlink_len));
    defer _ = plugin.sa_node_plugin_free_buffer(readlink_ptr, readlink_len);
    try std.testing.expect(std.mem.indexOf(u8, (readlink_ptr orelse return error.NullFsPromisesReadlink)[0..@intCast(readlink_len)], "c.txt") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_mkdtemp(mkdtemp_template.ptr, mkdtemp_template.len, &temp_dir_ptr, &temp_dir_len));
    try std.testing.expect(temp_dir_len >= mkdtemp_template.len - 6);

    var statfs_ptr: ?[*]const u8 = null;
    var statfs_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_statfs(dir_path.ptr, &statfs_ptr, &statfs_len));
    defer _ = plugin.sa_node_plugin_free_buffer(statfs_ptr, statfs_len);
    try std.testing.expect(std.mem.indexOf(u8, (statfs_ptr orelse return error.NullFsPromisesStatfs)[0..@intCast(statfs_len)], "\"bsize\":") != null);

    var fd: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_open(renamed_path.ptr, renamed_path.len, 2, 0o644, &fd));
    defer _ = plugin.sa_node_plugin_fs_promises_close_file(fd);

    var written: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_write(fd, "!".ptr, 1, 5, &written));
    try std.testing.expectEqual(@as(u64, 1), written);

    var buf: [6]u8 = undefined;
    var nread: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_read(fd, &buf, buf.len, 0, &nread));
    try std.testing.expectEqual(@as(u64, 6), nread);
    try std.testing.expectEqualStrings("hello!", buf[0..@intCast(nread)]);

    var fstat_ptr: ?[*]const u8 = null;
    var fstat_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_fstat(fd, &fstat_ptr, &fstat_len));
    defer _ = plugin.sa_node_plugin_free_buffer(fstat_ptr, fstat_len);
    try std.testing.expect(std.mem.indexOf(u8, (fstat_ptr orelse return error.NullFsPromisesFstat)[0..@intCast(fstat_len)], "\"size\":6") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_fsync(fd));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_fdatasync(fd));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_fchmod(fd, 0o644));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_fchown(fd, uid, gid));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_futimes(fd, 1000, 2000));

    var readv_n: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_readv(fd, null, 0, &readv_n));
    try std.testing.expectEqual(@as(u64, 0), readv_n);

    var writev_n: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_writev(fd, null, 0, &writev_n));
    try std.testing.expectEqual(@as(u64, 0), writev_n);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_ftruncate(fd, 0));

    var dir_handle: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_opendir(dir_path.ptr, dir_path.len, &dir_handle));
    defer _ = plugin.sa_node_plugin_fs_promises_opendir_free(dir_handle);
    var name_ptr: ?[*]const u8 = null;
    var name_len: u64 = 0;
    var entry_type: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_opendir_next(dir_handle, &name_ptr, &name_len, &entry_type));
    defer _ = plugin.sa_node_plugin_free_buffer(name_ptr, name_len);
    try std.testing.expect(name_len > 0);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_unlink(file_path.ptr, file_path.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_unlink(renamed_path.ptr, renamed_path.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_unlink(hardlink_path.ptr, hardlink_path.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_unlink(symlink_path.ptr, symlink_path.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_fs_promises_rmdir(dir_path.ptr, dir_path.len));
}

test "node plugin tcp socket address metadata" {
    var server: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_listen("127.0.0.1", 9, 0, &server));
    defer _ = plugin.sa_node_plugin_net_end(server);

    var listening: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_listening(server, &listening));
    try std.testing.expectEqual(@as(u64, 1), listening);
    var server_has_ref: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_has_ref(server, &server_has_ref));
    try std.testing.expectEqual(@as(u64, 1), server_has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_unref(server));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_has_ref(server, &server_has_ref));
    try std.testing.expectEqual(@as(u64, 0), server_has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_ref(server));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_has_ref(server, &server_has_ref));
    try std.testing.expectEqual(@as(u64, 1), server_has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_set_max_connections(server, 64));
    var max_connections: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_get_max_connections(server, &max_connections));
    try std.testing.expectEqual(@as(u64, 64), max_connections);

    var server_addr_ptr: ?[*]const u8 = null;
    var server_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_address(server, &server_addr_ptr, &server_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(server_addr_ptr, server_addr_len);
    const server_addr = (server_addr_ptr orelse return error.NullServerAddress)[0..@intCast(server_addr_len)];
    try std.testing.expect(std.mem.indexOf(u8, server_addr, "\"family\":\"IPv4\"") != null);
    const port = try jsonPort(server_addr);
    try std.testing.expect(port > 0);

    var explicit_server_addr_ptr: ?[*]const u8 = null;
    var explicit_server_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_address(server, &explicit_server_addr_ptr, &explicit_server_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(explicit_server_addr_ptr, explicit_server_addr_len);
    const explicit_server_addr = (explicit_server_addr_ptr orelse return error.NullExplicitServerAddress)[0..@intCast(explicit_server_addr_len)];
    try std.testing.expect(std.mem.indexOf(u8, explicit_server_addr, "\"family\":\"IPv4\"") != null);
    try std.testing.expectEqual(port, try jsonPort(explicit_server_addr));

    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(listen_server: ?*anyopaque) void {
            var accepted: ?*anyopaque = null;
            if (plugin.sa_node_plugin_net_accept(listen_server, &accepted) != 0) return;
            var active_count: u64 = 0;
            if (plugin.sa_node_plugin_net_server_get_connections(listen_server, &active_count) == 0) {
                std.testing.expectEqual(@as(u64, 1), active_count) catch return;
            }
            defer _ = plugin.sa_node_plugin_net_end(accepted);

            var remote_ptr: ?[*]const u8 = null;
            var remote_len: u64 = 0;
            if (plugin.sa_node_plugin_net_remote_address(accepted, &remote_ptr, &remote_len) == 0) {
                _ = plugin.sa_node_plugin_free_buffer(remote_ptr, remote_len);
            }

            var buf_ptr: ?[*]const u8 = null;
            var buf_len: u64 = 0;
            if (plugin.sa_node_plugin_net_read(accepted, 16, &buf_ptr, &buf_len) == 0) {
                _ = plugin.sa_node_plugin_free_buffer(buf_ptr, buf_len);
            }
            var bytes_read: u64 = 0;
            if (plugin.sa_node_plugin_net_bytes_read(accepted, &bytes_read) == 0) {
                std.testing.expectEqual(@as(u64, 2), bytes_read) catch return;
            }
            var bytes_written: u64 = 0;
            if (plugin.sa_node_plugin_net_bytes_written(accepted, &bytes_written) == 0) {
                std.testing.expectEqual(@as(u64, 0), bytes_written) catch return;
            }
        }
    }.run, .{server});

    var initial_connections: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_get_connections(server, &initial_connections));
    try std.testing.expectEqual(@as(u64, 0), initial_connections);

    var client: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_connect("127.0.0.1", 9, port, &client));
    defer _ = plugin.sa_node_plugin_net_end(client);
    try std.testing.expect(plugin.sa_node_plugin_net_server_address(client, &explicit_server_addr_ptr, &explicit_server_addr_len) != 0);

    var pending: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_pending(client, &pending));
    try std.testing.expectEqual(@as(u64, 0), pending);
    var connecting: u64 = 1;
    var buffer_size: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_connecting(client, &connecting));
    try std.testing.expectEqual(@as(u64, 0), connecting);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_buffer_size(client, &buffer_size));
    try std.testing.expectEqual(@as(u64, 0), buffer_size);
    var attempts_ptr: ?[*]const u8 = null;
    var attempts_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_auto_select_family_attempted_addresses(client, &attempts_ptr, &attempts_len));
    defer _ = plugin.sa_node_plugin_free_buffer(attempts_ptr, attempts_len);
    const attempts = (attempts_ptr orelse return error.NullNetAutoSelectAttempts)[0..@intCast(attempts_len)];
    try std.testing.expect(std.mem.indexOf(u8, attempts, "127.0.0.1:") != null);
    const port_attempt = try std.fmt.allocPrint(std.testing.allocator, ":{d}", .{port});
    defer std.testing.allocator.free(port_attempt);
    try std.testing.expect(std.mem.indexOf(u8, attempts, port_attempt) != null);
    try std.testing.expect(plugin.sa_node_plugin_net_auto_select_family_attempted_addresses(client, null, &attempts_len) != 0);
    var client_has_ref: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_has_ref(client, &client_has_ref));
    try std.testing.expectEqual(@as(u64, 1), client_has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_unref(client));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_has_ref(client, &client_has_ref));
    try std.testing.expectEqual(@as(u64, 0), client_has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_ref(client));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_has_ref(client, &client_has_ref));
    try std.testing.expectEqual(@as(u64, 1), client_has_ref);
    try std.testing.expect(plugin.sa_node_plugin_net_has_ref(client, null) != 0);
    var readable: u64 = 0;
    var writable: u64 = 0;
    var closed: u64 = 1;
    var destroyed: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_readable(client, &readable));
    try std.testing.expectEqual(@as(u64, 1), readable);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_writable(client, &writable));
    try std.testing.expectEqual(@as(u64, 1), writable);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_closed(client, &closed));
    try std.testing.expectEqual(@as(u64, 0), closed);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_destroyed(client, &destroyed));
    try std.testing.expectEqual(@as(u64, 0), destroyed);
    var ready_ptr: ?[*]const u8 = null;
    var ready_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_ready_state(client, &ready_ptr, &ready_len));
    defer _ = plugin.sa_node_plugin_free_buffer(ready_ptr, ready_len);
    try std.testing.expectEqualStrings("open", (ready_ptr orelse return error.NullNetReadyState)[0..@intCast(ready_len)]);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_no_delay(client, 1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_keep_alive(client, 1, 1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_timeout(client, 250));
    var timeout_ms: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_timeout(client, &timeout_ms));
    try std.testing.expectEqual(@as(u64, 250), timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_timeout(client, 0));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_timeout(client, &timeout_ms));
    try std.testing.expectEqual(@as(u64, 0), timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_recv_buffer_size(client, 4096));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_send_buffer_size(client, 4096));
    var net_recv_buf_size: u64 = 0;
    var net_send_buf_size: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_recv_buffer_size(client, &net_recv_buf_size));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_send_buffer_size(client, &net_send_buf_size));
    try std.testing.expect(net_recv_buf_size >= 4096);
    try std.testing.expect(net_send_buf_size >= 4096);
    try std.testing.expect(plugin.sa_node_plugin_net_set_type_of_service(client, 256) != 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_type_of_service(client, 0));
    var tos: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_type_of_service(client, &tos));
    try std.testing.expect(tos <= 255);
    try std.testing.expect(plugin.sa_node_plugin_net_get_type_of_service(client, null) != 0);

    var local_ptr: ?[*]const u8 = null;
    var local_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_address(client, &local_ptr, &local_len));
    defer _ = plugin.sa_node_plugin_free_buffer(local_ptr, local_len);
    try std.testing.expect(std.mem.indexOf(u8, (local_ptr orelse return error.NullLocalAddress)[0..@intCast(local_len)], "\"port\":") != null);

    var local_address_ptr: ?[*]const u8 = null;
    var local_address_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_local_address(client, &local_address_ptr, &local_address_len));
    defer _ = plugin.sa_node_plugin_free_buffer(local_address_ptr, local_address_len);
    try std.testing.expectEqualStrings("127.0.0.1", (local_address_ptr orelse return error.NullLocalAddressValue)[0..@intCast(local_address_len)]);
    var local_family_ptr: ?[*]const u8 = null;
    var local_family_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_local_family(client, &local_family_ptr, &local_family_len));
    defer _ = plugin.sa_node_plugin_free_buffer(local_family_ptr, local_family_len);
    try std.testing.expectEqualStrings("IPv4", (local_family_ptr orelse return error.NullLocalFamily)[0..@intCast(local_family_len)]);
    var local_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_local_port(client, &local_port));
    try std.testing.expect(local_port > 0);

    var remote_ptr: ?[*]const u8 = null;
    var remote_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_remote_address(client, &remote_ptr, &remote_len));
    defer _ = plugin.sa_node_plugin_free_buffer(remote_ptr, remote_len);
    const remote = (remote_ptr orelse return error.NullRemoteAddress)[0..@intCast(remote_len)];
    try std.testing.expect(std.mem.indexOf(u8, remote, "\"port\":") != null);

    var remote_address_ptr: ?[*]const u8 = null;
    var remote_address_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_remote_address_value(client, &remote_address_ptr, &remote_address_len));
    defer _ = plugin.sa_node_plugin_free_buffer(remote_address_ptr, remote_address_len);
    try std.testing.expectEqualStrings("127.0.0.1", (remote_address_ptr orelse return error.NullRemoteAddressValue)[0..@intCast(remote_address_len)]);
    var remote_family_ptr: ?[*]const u8 = null;
    var remote_family_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_remote_family(client, &remote_family_ptr, &remote_family_len));
    defer _ = plugin.sa_node_plugin_free_buffer(remote_family_ptr, remote_family_len);
    try std.testing.expectEqualStrings("IPv4", (remote_family_ptr orelse return error.NullRemoteFamily)[0..@intCast(remote_family_len)]);
    var remote_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_remote_port(client, &remote_port));
    try std.testing.expectEqual(port, remote_port);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_write(client, "hi", 2));
    var client_bytes_written: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_bytes_written(client, &client_bytes_written));
    try std.testing.expectEqual(@as(u64, 2), client_bytes_written);
    var client_bytes_read: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_bytes_read(client, &client_bytes_read));
    try std.testing.expectEqual(@as(u64, 0), client_bytes_read);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_shutdown_write(client));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_writable(client, &writable));
    try std.testing.expectEqual(@as(u64, 0), writable);
    var read_only_ptr: ?[*]const u8 = null;
    var read_only_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_ready_state(client, &read_only_ptr, &read_only_len));
    defer _ = plugin.sa_node_plugin_free_buffer(read_only_ptr, read_only_len);
    try std.testing.expectEqualStrings("readOnly", (read_only_ptr orelse return error.NullNetReadyStateAfterShutdown)[0..@intCast(read_only_len)]);
    accept_thread.join();
    var final_connections: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_get_connections(server, &final_connections));
    try std.testing.expectEqual(@as(u64, 0), final_connections);
}

test "node plugin net blocklist matches address range and subnet rules" {
    var blocklist: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_new(&blocklist));
    defer _ = plugin.sa_node_plugin_net_blocklist_free(blocklist);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_address(blocklist, "127.0.0.1", 9));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_range(blocklist, "10.0.0.10", 9, "10.0.0.20", 9));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_subnet(blocklist, "192.168.1.0", 11, 24));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_subnet(blocklist, "2001:db8::", 10, 32));

    var blocked: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_check(blocklist, "127.0.0.1", 9, &blocked));
    try std.testing.expectEqual(@as(u64, 1), blocked);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_check(blocklist, "10.0.0.15", 9, &blocked));
    try std.testing.expectEqual(@as(u64, 1), blocked);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_check(blocklist, "192.168.1.44", 12, &blocked));
    try std.testing.expectEqual(@as(u64, 1), blocked);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_check(blocklist, "2001:db8::1", 11, &blocked));
    try std.testing.expectEqual(@as(u64, 1), blocked);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_check(blocklist, "8.8.8.8", 7, &blocked));
    try std.testing.expectEqual(@as(u64, 0), blocked);

    try std.testing.expect(plugin.sa_node_plugin_net_blocklist_add_range(blocklist, "10.0.0.20", 9, "10.0.0.10", 9) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_blocklist_add_subnet(blocklist, "192.168.1.0", 11, 33) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_blocklist_check(blocklist, "bad-ip", 6, &blocked) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_blocklist_check(blocklist, "127.0.0.1", 9, null) != 0);

    var rules_ptr: ?[*]const u8 = null;
    var rules_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_rules(blocklist, &rules_ptr, &rules_len));
    defer _ = plugin.sa_node_plugin_free_buffer(rules_ptr, rules_len);
    const rules = (rules_ptr orelse return error.NullBlockListRules)[0..@intCast(rules_len)];
    try std.testing.expect(std.mem.indexOf(u8, rules, "Address: IPv4 127.0.0.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "Range: IPv4 10.0.0.10-10.0.0.20") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "Subnet: IPv4 192.168.1.0/24") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "Subnet: IPv6 2001:db8::/32") != null);
}

test "node plugin net blocklists filter tcp connect and accept" {
    var server: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_listen("127.0.0.1", 9, 0, &server));
    defer _ = plugin.sa_node_plugin_net_end(server);

    var addr_ptr: ?[*]const u8 = null;
    var addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_address(server, &addr_ptr, &addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(addr_ptr, addr_len);
    const port = try jsonPort((addr_ptr orelse return error.NullTcpBlockListServerAddress)[0..@intCast(addr_len)]);

    var blocklist: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_new(&blocklist));
    defer _ = plugin.sa_node_plugin_net_blocklist_free(blocklist);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_address(blocklist, "127.0.0.1", 9));

    var blocked_client: ?*anyopaque = @ptrFromInt(@as(usize, 0x1));
    try std.testing.expectEqual(@as(u32, 3), plugin.sa_node_plugin_net_connect_blocklist("127.0.0.1", 9, port, blocklist, &blocked_client));
    try std.testing.expect(blocked_client == null);

    var allowed_client: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_connect_blocklist("127.0.0.1", 9, port, null, &allowed_client));
    defer _ = plugin.sa_node_plugin_net_end(allowed_client);
    var accepted: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_accept(server, &accepted));
    try std.testing.expect(accepted != null);
    _ = plugin.sa_node_plugin_net_end(accepted);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_set_blocklist(server, blocklist));
    var inbound_status: u32 = 99;
    const client_thread = try std.Thread.spawn(.{}, struct {
        fn run(target_port: u16, status: *u32) void {
            var client: ?*anyopaque = null;
            status.* = plugin.sa_node_plugin_net_connect("127.0.0.1", 9, target_port, &client);
            if (client) |ptr| _ = plugin.sa_node_plugin_net_end(ptr);
        }
    }.run, .{ port, &inbound_status });
    var blocked_accept: ?*anyopaque = @ptrFromInt(@as(usize, 0x1));
    try std.testing.expectEqual(@as(u32, 3), plugin.sa_node_plugin_net_accept(server, &blocked_accept));
    client_thread.join();
    try std.testing.expectEqual(@as(u32, 0), inbound_status);
    try std.testing.expect(blocked_accept == null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_set_blocklist(server, null));
    var inbound_allowed_status: u32 = 99;
    const allowed_thread = try std.Thread.spawn(.{}, struct {
        fn run(target_port: u16, status: *u32) void {
            var client: ?*anyopaque = null;
            status.* = plugin.sa_node_plugin_net_connect("127.0.0.1", 9, target_port, &client);
            if (client) |ptr| _ = plugin.sa_node_plugin_net_end(ptr);
        }
    }.run, .{ port, &inbound_allowed_status });
    var allowed_accept: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_accept(server, &allowed_accept));
    allowed_thread.join();
    try std.testing.expectEqual(@as(u32, 0), inbound_allowed_status);
    try std.testing.expect(allowed_accept != null);
    _ = plugin.sa_node_plugin_net_end(allowed_accept);
}

test "node plugin net connect options applies local bind socket options and blocklist" {
    var server: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_listen("127.0.0.1", 9, 0, &server));
    defer _ = plugin.sa_node_plugin_net_end(server);

    var addr_ptr: ?[*]const u8 = null;
    var addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_address(server, &addr_ptr, &addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(addr_ptr, addr_len);
    const port = try jsonPort((addr_ptr orelse return error.NullTcpOptionsServerAddress)[0..@intCast(addr_len)]);

    var blocklist: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_new(&blocklist));
    defer _ = plugin.sa_node_plugin_net_blocklist_free(blocklist);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_address(blocklist, "127.0.0.1", 9));

    var blocked_client: ?*anyopaque = @ptrFromInt(@as(usize, 0x1));
    try std.testing.expectEqual(@as(u32, 3), plugin.sa_node_plugin_net_connect_options(
        "127.0.0.1",
        9,
        port,
        4,
        null,
        0,
        0,
        1,
        1,
        1,
        250,
        blocklist,
        &blocked_client,
    ));
    try std.testing.expect(blocked_client == null);

    var client: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_connect_options(
        "localhost",
        9,
        port,
        4,
        "127.0.0.1",
        9,
        0,
        1,
        1,
        1,
        250,
        null,
        &client,
    ));
    defer _ = plugin.sa_node_plugin_net_end(client);

    var accepted: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_accept(server, &accepted));
    defer _ = plugin.sa_node_plugin_net_end(accepted);

    var timeout_ms: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_timeout(client, &timeout_ms));
    try std.testing.expectEqual(@as(u64, 250), timeout_ms);

    var family_ptr: ?[*]const u8 = null;
    var family_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_local_family(client, &family_ptr, &family_len));
    defer _ = plugin.sa_node_plugin_free_buffer(family_ptr, family_len);
    try std.testing.expectEqualStrings("IPv4", (family_ptr orelse return error.NullTcpOptionsFamily)[0..@intCast(family_len)]);

    var local_address_ptr: ?[*]const u8 = null;
    var local_address_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_local_address(client, &local_address_ptr, &local_address_len));
    defer _ = plugin.sa_node_plugin_free_buffer(local_address_ptr, local_address_len);
    try std.testing.expectEqualStrings("127.0.0.1", (local_address_ptr orelse return error.NullTcpOptionsLocalAddress)[0..@intCast(local_address_len)]);
}

test "node plugin net socket address exposes properties and JSON" {
    var addr: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_new("127.0.0.1", 9, 8080, "ipv4", 4, 0, &addr));
    defer _ = plugin.sa_node_plugin_net_socket_address_free(addr);

    var address_ptr: ?[*]const u8 = null;
    var address_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_address(addr, &address_ptr, &address_len));
    defer _ = plugin.sa_node_plugin_free_buffer(address_ptr, address_len);
    try std.testing.expectEqualStrings("127.0.0.1", (address_ptr orelse return error.NullSocketAddressAddress)[0..@intCast(address_len)]);

    var family_ptr: ?[*]const u8 = null;
    var family_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_family(addr, &family_ptr, &family_len));
    defer _ = plugin.sa_node_plugin_free_buffer(family_ptr, family_len);
    try std.testing.expectEqualStrings("ipv4", (family_ptr orelse return error.NullSocketAddressFamily)[0..@intCast(family_len)]);

    var port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_port(addr, &port));
    try std.testing.expectEqual(@as(u64, 8080), port);

    var flowlabel: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_flowlabel(addr, &flowlabel));
    try std.testing.expectEqual(@as(u64, 0), flowlabel);

    var json_ptr: ?[*]const u8 = null;
    var json_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_json(addr, &json_ptr, &json_len));
    defer _ = plugin.sa_node_plugin_free_buffer(json_ptr, json_len);
    try std.testing.expectEqualStrings(
        "{\"address\":\"127.0.0.1\",\"port\":8080,\"family\":\"ipv4\",\"flowlabel\":0}",
        (json_ptr orelse return error.NullSocketAddressJson)[0..@intCast(json_len)],
    );

    var default_addr: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_new(null, 0, 0, "ipv6", 4, 12, &default_addr));
    defer _ = plugin.sa_node_plugin_net_socket_address_free(default_addr);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_flowlabel(default_addr, &flowlabel));
    try std.testing.expectEqual(@as(u64, 12), flowlabel);

    var default_address_ptr: ?[*]const u8 = null;
    var default_address_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_address(default_addr, &default_address_ptr, &default_address_len));
    defer _ = plugin.sa_node_plugin_free_buffer(default_address_ptr, default_address_len);
    try std.testing.expectEqualStrings("::", (default_address_ptr orelse return error.NullDefaultSocketAddress)[0..@intCast(default_address_len)]);
}

test "node plugin net socket address parse and blocklist handle rules" {
    var parsed_v4: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_parse("127.0.0.1:8080", 14, &parsed_v4));
    defer _ = plugin.sa_node_plugin_net_socket_address_free(parsed_v4);

    var port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_port(parsed_v4, &port));
    try std.testing.expectEqual(@as(u64, 8080), port);

    var parsed_v6: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_parse("[2001:db8::1]:443", 17, &parsed_v6));
    defer _ = plugin.sa_node_plugin_net_socket_address_free(parsed_v6);

    var family_ptr: ?[*]const u8 = null;
    var family_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_family(parsed_v6, &family_ptr, &family_len));
    defer _ = plugin.sa_node_plugin_free_buffer(family_ptr, family_len);
    try std.testing.expectEqualStrings("ipv6", (family_ptr orelse return error.NullParsedSocketFamily)[0..@intCast(family_len)]);

    var range_start: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_parse("10.0.0.10:0", 11, &range_start));
    defer _ = plugin.sa_node_plugin_net_socket_address_free(range_start);
    var range_end: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_parse("10.0.0.20:0", 11, &range_end));
    defer _ = plugin.sa_node_plugin_net_socket_address_free(range_end);
    var range_hit: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_parse("10.0.0.15:0", 11, &range_hit));
    defer _ = plugin.sa_node_plugin_net_socket_address_free(range_hit);
    var subnet: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_parse("192.168.1.0:0", 13, &subnet));
    defer _ = plugin.sa_node_plugin_net_socket_address_free(subnet);
    var subnet_hit: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_socket_address_parse("192.168.1.44:0", 14, &subnet_hit));
    defer _ = plugin.sa_node_plugin_net_socket_address_free(subnet_hit);

    var blocklist: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_new(&blocklist));
    defer _ = plugin.sa_node_plugin_net_blocklist_free(blocklist);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_address_handle(blocklist, parsed_v4));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_range_handle(blocklist, range_start, range_end));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_subnet_handle(blocklist, subnet, 24));

    var blocked: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_check_handle(blocklist, parsed_v4, &blocked));
    try std.testing.expectEqual(@as(u64, 1), blocked);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_check_handle(blocklist, range_hit, &blocked));
    try std.testing.expectEqual(@as(u64, 1), blocked);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_check_handle(blocklist, subnet_hit, &blocked));
    try std.testing.expectEqual(@as(u64, 1), blocked);

    var rules_ptr: ?[*]const u8 = null;
    var rules_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_rules(blocklist, &rules_ptr, &rules_len));
    defer _ = plugin.sa_node_plugin_free_buffer(rules_ptr, rules_len);
    const rules = (rules_ptr orelse return error.NullBlockListHandleRules)[0..@intCast(rules_len)];
    try std.testing.expect(std.mem.indexOf(u8, rules, "Address: IPv4 127.0.0.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "Range: IPv4 10.0.0.10-10.0.0.20") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "Subnet: IPv4 192.168.1.0/24") != null);

    try std.testing.expect(plugin.sa_node_plugin_net_socket_address_parse("127.0.0.1:bad", 13, &parsed_v4) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_socket_address_parse("2001:db8::1:443", 15, &parsed_v6) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_socket_address_new("127.0.0.1", 9, 65536, "ipv4", 4, 0, &parsed_v4) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_socket_address_new("127.0.0.1", 9, 0, "ip4", 3, 0, &parsed_v4) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_blocklist_check_handle(blocklist, null, &blocked) != 0);
}

test "node plugin net default auto select family state" {
    var enabled: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_default_auto_select_family(&enabled));
    try std.testing.expectEqual(@as(u64, 1), enabled);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_default_auto_select_family(0));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_default_auto_select_family(&enabled));
    try std.testing.expectEqual(@as(u64, 0), enabled);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_default_auto_select_family(1));
    try std.testing.expect(plugin.sa_node_plugin_net_set_default_auto_select_family(2) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_get_default_auto_select_family(null) != 0);

    var timeout: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_default_auto_select_family_attempt_timeout(&timeout));
    try std.testing.expectEqual(@as(u64, 500), timeout);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_default_auto_select_family_attempt_timeout(7));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_default_auto_select_family_attempt_timeout(&timeout));
    try std.testing.expectEqual(@as(u64, 10), timeout);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_default_auto_select_family_attempt_timeout(250));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_get_default_auto_select_family_attempt_timeout(&timeout));
    try std.testing.expectEqual(@as(u64, 250), timeout);
    try std.testing.expect(plugin.sa_node_plugin_net_set_default_auto_select_family_attempt_timeout(0) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_set_default_auto_select_family_attempt_timeout(@as(u64, std.math.maxInt(i32)) + 1) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_get_default_auto_select_family_attempt_timeout(null) != 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_set_default_auto_select_family_attempt_timeout(500));

    var ip_version: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_is_ip("::1", 3, &ip_version));
    try std.testing.expectEqual(@as(u64, 6), ip_version);
    try std.testing.expect(plugin.sa_node_plugin_net_is_ip(null, 0, &ip_version) != 0);
    try std.testing.expect(plugin.sa_node_plugin_net_is_ipv4("127.0.0.1", 9, null) != 0);
}

test "node plugin tcp server close updates listening state" {
    var server: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_listen("127.0.0.1", 9, 0, &server));
    defer _ = plugin.sa_node_plugin_net_end(server);

    var listening: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_listening(server, &listening));
    try std.testing.expectEqual(@as(u64, 1), listening);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_close(server));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_listening(server, &listening));
    try std.testing.expectEqual(@as(u64, 0), listening);

    var max_connections: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_get_max_connections(server, &max_connections));
    try std.testing.expectEqual(@as(u64, 0), max_connections);
}

test "node plugin tcp maxConnections zero drops incoming connections" {
    var server: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_listen("127.0.0.1", 9, 0, &server));
    defer _ = plugin.sa_node_plugin_net_end(server);

    var addr_ptr: ?[*]const u8 = null;
    var addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_address(server, &addr_ptr, &addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(addr_ptr, addr_len);
    const port = try jsonPort((addr_ptr orelse return error.NullMaxConnectionsZeroServerAddress)[0..@intCast(addr_len)]);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_set_max_connections(server, 0));
    var max_connections: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_get_max_connections(server, &max_connections));
    try std.testing.expectEqual(@as(u64, 0), max_connections);

    var connect_status: u32 = 99;
    const client_thread = try std.Thread.spawn(.{}, struct {
        fn run(target_port: u16, status: *u32) void {
            var client: ?*anyopaque = null;
            status.* = plugin.sa_node_plugin_net_connect("127.0.0.1", 9, target_port, &client);
            if (client) |ptr| _ = plugin.sa_node_plugin_net_end(ptr);
        }
    }.run, .{ port, &connect_status });

    var accepted: ?*anyopaque = @ptrFromInt(@as(usize, 0x1));
    try std.testing.expectEqual(@as(u32, 3), plugin.sa_node_plugin_net_accept(server, &accepted));
    client_thread.join();
    try std.testing.expectEqual(@as(u32, 0), connect_status);
    try std.testing.expect(accepted == null);

    var active_connections: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_get_connections(server, &active_connections));
    try std.testing.expectEqual(@as(u64, 0), active_connections);
}

test "node plugin tcp socket destroy state helpers" {
    var server: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_listen("127.0.0.1", 9, 0, &server));
    defer _ = plugin.sa_node_plugin_net_end(server);

    var server_addr_ptr: ?[*]const u8 = null;
    var server_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_address(server, &server_addr_ptr, &server_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(server_addr_ptr, server_addr_len);
    const port = try jsonPort((server_addr_ptr orelse return error.NullServerAddress)[0..@intCast(server_addr_len)]);

    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(listen_server: ?*anyopaque) void {
            var accepted: ?*anyopaque = null;
            if (plugin.sa_node_plugin_net_accept(listen_server, &accepted) != 0) return;
            _ = plugin.sa_node_plugin_net_end(accepted);
        }
    }.run, .{server});

    var client: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_connect("127.0.0.1", 9, port, &client));
    defer _ = plugin.sa_node_plugin_net_end(client);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_destroy(client));
    var readable: u64 = 1;
    var writable: u64 = 1;
    var closed: u64 = 0;
    var destroyed: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_readable(client, &readable));
    try std.testing.expectEqual(@as(u64, 0), readable);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_writable(client, &writable));
    try std.testing.expectEqual(@as(u64, 0), writable);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_closed(client, &closed));
    try std.testing.expectEqual(@as(u64, 1), closed);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_destroyed(client, &destroyed));
    try std.testing.expectEqual(@as(u64, 1), destroyed);

    accept_thread.join();
}

test "node plugin unix domain socket round trip" {
    const tmp_dir = std.testing.tmpDir(.{});
    var dir = tmp_dir;
    defer dir.cleanup();

    const tmp_path = try dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);
    const socket_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "node-plugin.sock" });
    defer std.testing.allocator.free(socket_path);
    _ = std.fs.deleteFileAbsolute(socket_path) catch {};
    defer _ = std.fs.deleteFileAbsolute(socket_path) catch {};

    var server: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_listen_unix(socket_path.ptr, socket_path.len, &server));
    defer _ = plugin.sa_node_plugin_net_end(server);

    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(listen_server: ?*anyopaque) void {
            var accepted: ?*anyopaque = null;
            if (plugin.sa_node_plugin_net_accept(listen_server, &accepted) != 0) return;
            defer _ = plugin.sa_node_plugin_net_end(accepted);

            var buf_ptr: ?[*]const u8 = null;
            var buf_len: u64 = 0;
            if (plugin.sa_node_plugin_net_read(accepted, 32, &buf_ptr, &buf_len) == 0) {
                defer _ = plugin.sa_node_plugin_free_buffer(buf_ptr, buf_len);
                if (buf_ptr != null and std.mem.eql(u8, buf_ptr.?[0..@intCast(buf_len)], "unix ping")) {
                    _ = plugin.sa_node_plugin_net_write(accepted, "unix pong", 9);
                }
            }
        }
    }.run, .{server});

    var client: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_connect_unix(socket_path.ptr, socket_path.len, &client));
    defer _ = plugin.sa_node_plugin_net_end(client);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_write(client, "unix ping", 9));
    var reply_ptr: ?[*]const u8 = null;
    var reply_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_read(client, 32, &reply_ptr, &reply_len));
    defer _ = plugin.sa_node_plugin_free_buffer(reply_ptr, reply_len);
    try std.testing.expectEqualStrings("unix pong", (reply_ptr orelse return error.NullUnixReply)[0..@intCast(reply_len)]);

    accept_thread.join();
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_server_close(server));
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(socket_path, .{}));
}

test "node plugin tcp reset and destroy closes socket with linger reset" {
    var server: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_listen("127.0.0.1", 9, 0, &server));
    defer _ = plugin.sa_node_plugin_net_end(server);

    var server_addr_ptr: ?[*]const u8 = null;
    var server_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_address(server, &server_addr_ptr, &server_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(server_addr_ptr, server_addr_len);
    const port = try jsonPort((server_addr_ptr orelse return error.NullResetServerAddress)[0..@intCast(server_addr_len)]);

    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(listen_server: ?*anyopaque) void {
            var accepted: ?*anyopaque = null;
            if (plugin.sa_node_plugin_net_accept(listen_server, &accepted) != 0) return;
            defer _ = plugin.sa_node_plugin_net_end(accepted);
            var buf_ptr: ?[*]const u8 = null;
            var buf_len: u64 = 0;
            _ = plugin.sa_node_plugin_net_read(accepted, 16, &buf_ptr, &buf_len);
            _ = plugin.sa_node_plugin_free_buffer(buf_ptr, buf_len);
        }
    }.run, .{server});

    var client: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_connect("127.0.0.1", 9, port, &client));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_reset_and_destroy(client));
    accept_thread.join();
}

test "node plugin udp connected send and address metadata" {
    const host = "127.0.0.1";
    const receiver = plugin.sa_node_plugin_dgram_create();
    try std.testing.expect(receiver != null);
    defer _ = plugin.sa_node_plugin_dgram_close(receiver);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_bind(receiver, host.ptr, host.len, 0));
    var receiver_addr_ptr: ?[*]const u8 = null;
    var receiver_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_address(receiver, &receiver_addr_ptr, &receiver_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(receiver_addr_ptr, receiver_addr_len);
    const receiver_addr = (receiver_addr_ptr orelse return error.NullUdpAddress)[0..@intCast(receiver_addr_len)];
    const port = try jsonPort(receiver_addr);
    try std.testing.expect(port > 0);

    const sender = plugin.sa_node_plugin_dgram_create();
    try std.testing.expect(sender != null);
    defer _ = plugin.sa_node_plugin_dgram_close(sender);

    var has_ref: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_has_ref(sender, &has_ref));
    try std.testing.expectEqual(@as(u64, 1), has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_unref(sender));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_has_ref(sender, &has_ref));
    try std.testing.expectEqual(@as(u64, 0), has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_ref(sender));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_has_ref(sender, &has_ref));
    try std.testing.expectEqual(@as(u64, 1), has_ref);
    try std.testing.expect(plugin.sa_node_plugin_dgram_has_ref(sender, null) != 0);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_broadcast(sender, 1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_ttl(sender, 64));
    try std.testing.expect(plugin.sa_node_plugin_dgram_set_ttl(sender, 0) != 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_multicast_ttl(sender, 16));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_multicast_loopback(sender, 1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_multicast_interface(sender, host.ptr, host.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_recv_buffer_size(sender, 4096));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_send_buffer_size(sender, 4096));
    var recv_buf_size: u64 = 0;
    var send_buf_size: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_get_recv_buffer_size(sender, &recv_buf_size));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_get_send_buffer_size(sender, &send_buf_size));
    try std.testing.expect(recv_buf_size >= 4096);
    try std.testing.expect(send_buf_size >= 4096);

    var send_queue_size: u64 = 1;
    var send_queue_count: u64 = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_get_send_queue_size(sender, &send_queue_size));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_get_send_queue_count(sender, &send_queue_count));
    try std.testing.expectEqual(@as(u64, 0), send_queue_size);
    try std.testing.expectEqual(@as(u64, 0), send_queue_count);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_connect(sender, host.ptr, host.len, port));

    var remote_ptr: ?[*]const u8 = null;
    var remote_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_remote_address(sender, &remote_ptr, &remote_len));
    defer _ = plugin.sa_node_plugin_free_buffer(remote_ptr, remote_len);
    try std.testing.expect(std.mem.indexOf(u8, (remote_ptr orelse return error.NullUdpRemote)[0..@intCast(remote_len)], "\"port\":") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_send_connected(sender, "pong", 4));
    send_queue_size = 1;
    send_queue_count = 1;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_get_send_queue_size(sender, &send_queue_size));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_get_send_queue_count(sender, &send_queue_count));
    try std.testing.expectEqual(@as(u64, 0), send_queue_size);
    try std.testing.expectEqual(@as(u64, 0), send_queue_count);

    var msg_ptr: ?[*]const u8 = null;
    var msg_len: u64 = 0;
    var peer_ptr: ?[*]const u8 = null;
    var peer_len: u64 = 0;
    var peer_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_recv(receiver, 32, &msg_ptr, &msg_len, &peer_ptr, &peer_len, &peer_port));
    defer _ = plugin.sa_node_plugin_free_buffer(msg_ptr, msg_len);
    defer _ = plugin.sa_node_plugin_free_buffer(peer_ptr, peer_len);
    try std.testing.expectEqualStrings("pong", (msg_ptr orelse return error.NullUdpMessage)[0..@intCast(msg_len)]);
    try std.testing.expect(peer_port > 0);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_disconnect(sender));
    try std.testing.expect(plugin.sa_node_plugin_dgram_send_connected(sender, "fail", 4) != 0);
}

test "node plugin dgram create options map to socket options" {
    var sock: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_create_options(4, 1, 0, 0, 8192, 16384, &sock));
    defer _ = plugin.sa_node_plugin_dgram_close(sock);

    var recv_buf_size: u64 = 0;
    var send_buf_size: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_get_recv_buffer_size(sock, &recv_buf_size));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_get_send_buffer_size(sock, &send_buf_size));
    try std.testing.expect(recv_buf_size >= 8192);
    try std.testing.expect(send_buf_size >= 16384);

    var udp6: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_create_options(6, 0, 0, 1, 0, 0, &udp6));
    defer _ = plugin.sa_node_plugin_dgram_close(udp6);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_bind(udp6, "::1", 3, 0));

    try std.testing.expect(plugin.sa_node_plugin_dgram_create_options(5, 0, 0, 0, 0, 0, &sock) != 0);
    try std.testing.expect(plugin.sa_node_plugin_dgram_create_options(4, 0, 0, 1, 0, 0, &sock) != 0);
    try std.testing.expect(plugin.sa_node_plugin_dgram_create_options(4, 0, 0, 0, 0, 0, null) != 0);
}

test "node plugin dgram reusePort option allows shared UDP port" {
    const host = "127.0.0.1";
    var first: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_create_options(4, 1, 1, 0, 0, 0, &first));
    defer _ = plugin.sa_node_plugin_dgram_close(first);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_bind(first, host.ptr, host.len, 0));

    var first_addr_ptr: ?[*]const u8 = null;
    var first_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_address(first, &first_addr_ptr, &first_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(first_addr_ptr, first_addr_len);
    const port = try jsonPort((first_addr_ptr orelse return error.NullReusePortAddress)[0..@intCast(first_addr_len)]);

    var second: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_create_options(4, 1, 1, 0, 0, 0, &second));
    defer _ = plugin.sa_node_plugin_dgram_close(second);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_bind(second, host.ptr, host.len, port));
}

test "node plugin dgram send and receive blocklists filter datagrams" {
    const host = "127.0.0.1";
    const receiver = plugin.sa_node_plugin_dgram_create();
    try std.testing.expect(receiver != null);
    defer _ = plugin.sa_node_plugin_dgram_close(receiver);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_bind(receiver, host.ptr, host.len, 0));

    var receiver_addr_ptr: ?[*]const u8 = null;
    var receiver_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_address(receiver, &receiver_addr_ptr, &receiver_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(receiver_addr_ptr, receiver_addr_len);
    const receiver_port = try jsonPort((receiver_addr_ptr orelse return error.NullDgramBlockReceiver)[0..@intCast(receiver_addr_len)]);

    var send_blocklist: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_new(&send_blocklist));
    defer _ = plugin.sa_node_plugin_net_blocklist_free(send_blocklist);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_address(send_blocklist, host.ptr, host.len));

    const blocked_sender = plugin.sa_node_plugin_dgram_create();
    try std.testing.expect(blocked_sender != null);
    defer _ = plugin.sa_node_plugin_dgram_close(blocked_sender);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_send_blocklist(blocked_sender, send_blocklist));
    try std.testing.expect(plugin.sa_node_plugin_dgram_send(blocked_sender, "blocked", 7, host.ptr, host.len, receiver_port) != 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_send_blocklist(blocked_sender, null));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_send(blocked_sender, "allowed", 7, host.ptr, host.len, receiver_port));

    var allowed_msg_ptr: ?[*]const u8 = null;
    var allowed_msg_len: u64 = 0;
    var allowed_peer_ptr: ?[*]const u8 = null;
    var allowed_peer_len: u64 = 0;
    var allowed_peer_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_recv(receiver, 32, &allowed_msg_ptr, &allowed_msg_len, &allowed_peer_ptr, &allowed_peer_len, &allowed_peer_port));
    defer _ = plugin.sa_node_plugin_free_buffer(allowed_msg_ptr, allowed_msg_len);
    defer _ = plugin.sa_node_plugin_free_buffer(allowed_peer_ptr, allowed_peer_len);
    try std.testing.expectEqualStrings("allowed", (allowed_msg_ptr orelse return error.NullDgramBlockAllowed)[0..@intCast(allowed_msg_len)]);

    const filtered_receiver = plugin.sa_node_plugin_dgram_create();
    try std.testing.expect(filtered_receiver != null);
    defer _ = plugin.sa_node_plugin_dgram_close(filtered_receiver);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_bind(filtered_receiver, host.ptr, host.len, 0));

    var filtered_addr_ptr: ?[*]const u8 = null;
    var filtered_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_address(filtered_receiver, &filtered_addr_ptr, &filtered_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(filtered_addr_ptr, filtered_addr_len);
    const filtered_port = try jsonPort((filtered_addr_ptr orelse return error.NullDgramFilteredReceiver)[0..@intCast(filtered_addr_len)]);

    var receive_blocklist: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_new(&receive_blocklist));
    defer _ = plugin.sa_node_plugin_net_blocklist_free(receive_blocklist);

    const blocked_source = plugin.sa_node_plugin_dgram_create();
    try std.testing.expect(blocked_source != null);
    defer _ = plugin.sa_node_plugin_dgram_close(blocked_source);
    const blocked_host = "127.0.0.2";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_bind(blocked_source, blocked_host.ptr, blocked_host.len, 0));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_address(receive_blocklist, blocked_host.ptr, blocked_host.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_receive_blocklist(filtered_receiver, receive_blocklist));

    const allowed_source = plugin.sa_node_plugin_dgram_create();
    try std.testing.expect(allowed_source != null);
    defer _ = plugin.sa_node_plugin_dgram_close(allowed_source);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_send(blocked_source, "drop", 4, host.ptr, host.len, filtered_port));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_send(allowed_source, "keep", 4, host.ptr, host.len, filtered_port));

    var msg_ptr: ?[*]const u8 = null;
    var msg_len: u64 = 0;
    var peer_ptr: ?[*]const u8 = null;
    var peer_len: u64 = 0;
    var peer_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_recv(filtered_receiver, 32, &msg_ptr, &msg_len, &peer_ptr, &peer_len, &peer_port));
    defer _ = plugin.sa_node_plugin_free_buffer(msg_ptr, msg_len);
    defer _ = plugin.sa_node_plugin_free_buffer(peer_ptr, peer_len);
    try std.testing.expectEqualStrings("keep", (msg_ptr orelse return error.NullDgramReceiveBlocklist)[0..@intCast(msg_len)]);
    try std.testing.expectEqualStrings("127.0.0.1", (peer_ptr orelse return error.NullDgramReceiveBlocklistPeer)[0..@intCast(peer_len)]);
}

test "node plugin udp multicast membership options" {
    const host = "127.0.0.1";
    const group = "224.0.0.251";
    const sock = plugin.sa_node_plugin_dgram_create();
    try std.testing.expect(sock != null);
    defer _ = plugin.sa_node_plugin_dgram_close(sock);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_bind(sock, "0.0.0.0", 7, 0));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_multicast_ttl(sock, 1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_multicast_loopback(sock, 1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_add_membership(sock, group.ptr, group.len, host.ptr, host.len));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_drop_membership(sock, group.ptr, group.len, host.ptr, host.len));
    try std.testing.expect(plugin.sa_node_plugin_dgram_add_membership(sock, "127.0.0.1", 9, host.ptr, host.len) != 0);

    try std.testing.expect(plugin.sa_node_plugin_dgram_add_source_specific_membership(sock, "bad", 3, group.ptr, group.len, host.ptr, host.len) != 0);
    try std.testing.expect(plugin.sa_node_plugin_dgram_add_source_specific_membership(sock, host.ptr, host.len, "127.0.0.1", 9, host.ptr, host.len) != 0);

    const udp6 = plugin.sa_node_plugin_dgram_create_udp6();
    try std.testing.expect(udp6 != null);
    defer _ = plugin.sa_node_plugin_dgram_close(udp6);
    try std.testing.expect(plugin.sa_node_plugin_dgram_add_source_specific_membership(udp6, host.ptr, host.len, group.ptr, group.len, host.ptr, host.len) != 0);
}

test "node plugin udp6 connected send and address metadata" {
    const host = "::1";
    const receiver = plugin.sa_node_plugin_dgram_create_udp6();
    try std.testing.expect(receiver != null);
    defer _ = plugin.sa_node_plugin_dgram_close(receiver);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_bind(receiver, host.ptr, host.len, 0));
    var receiver_addr_ptr: ?[*]const u8 = null;
    var receiver_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_address(receiver, &receiver_addr_ptr, &receiver_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(receiver_addr_ptr, receiver_addr_len);
    const receiver_addr = (receiver_addr_ptr orelse return error.NullUdp6Address)[0..@intCast(receiver_addr_len)];
    const port = try jsonPort(receiver_addr);
    try std.testing.expect(port > 0);
    try std.testing.expect(std.mem.indexOf(u8, receiver_addr, "::1") != null);

    const sender = plugin.sa_node_plugin_dgram_create_udp6();
    try std.testing.expect(sender != null);
    defer _ = plugin.sa_node_plugin_dgram_close(sender);

    var has_ref: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_unref(sender));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_has_ref(sender, &has_ref));
    try std.testing.expectEqual(@as(u64, 0), has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_ref(sender));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_has_ref(sender, &has_ref));
    try std.testing.expectEqual(@as(u64, 1), has_ref);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_multicast_hops6(sender, 16));
    try std.testing.expect(plugin.sa_node_plugin_dgram_set_multicast_hops6(sender, 256) != 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_multicast_loopback6(sender, 1));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_set_multicast_interface6(sender, 0));
    try std.testing.expect(plugin.sa_node_plugin_dgram_add_membership6(sender, "not-ipv6".ptr, 8, "".ptr, 0) != 0);
    try std.testing.expect(plugin.sa_node_plugin_dgram_drop_membership6(sender, "not-ipv6".ptr, 8, "".ptr, 0) != 0);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_connect(sender, host.ptr, host.len, port));
    var remote_ptr: ?[*]const u8 = null;
    var remote_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_remote_address(sender, &remote_ptr, &remote_len));
    defer _ = plugin.sa_node_plugin_free_buffer(remote_ptr, remote_len);
    const remote = (remote_ptr orelse return error.NullUdp6Remote)[0..@intCast(remote_len)];
    try std.testing.expect(std.mem.indexOf(u8, remote, "::1") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_send_connected(sender, "pong6", 5));

    var msg_ptr: ?[*]const u8 = null;
    var msg_len: u64 = 0;
    var peer_ptr: ?[*]const u8 = null;
    var peer_len: u64 = 0;
    var peer_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dgram_recv(receiver, 32, &msg_ptr, &msg_len, &peer_ptr, &peer_len, &peer_port));
    defer _ = plugin.sa_node_plugin_free_buffer(msg_ptr, msg_len);
    defer _ = plugin.sa_node_plugin_free_buffer(peer_ptr, peer_len);
    try std.testing.expectEqualStrings("pong6", (msg_ptr orelse return error.NullUdp6Message)[0..@intCast(msg_len)]);
    try std.testing.expect(peer_port > 0);
}

test "node plugin http client bridge loopback GET" {
    const address = try std.net.Address.parseIp4("127.0.0.1", 0);
    const server = try std.testing.allocator.create(std.net.Server);
    server.* = try address.listen(.{ .reuse_address = true });
    defer std.testing.allocator.destroy(server);

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(listen_server: *std.net.Server) void {
            defer listen_server.deinit();
            var conn = listen_server.accept() catch return;
            defer conn.stream.close();

            var request_buffer: [4096]u8 = undefined;
            var http_server = std.http.Server.init(conn, &request_buffer);
            const request = http_server.receiveHead() catch return;
            _ = request;

            conn.stream.writeAll(
                "HTTP/1.1 201 Created\r\ncontent-type: text/plain\r\nconnection: close\r\ncontent-length: 11\r\n\r\nnode bridge",
            ) catch return;
        }
    }.run, .{server});

    var client: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_client_new(0, &client));
    defer _ = plugin.sa_node_plugin_http_client_free(client);

    const url = try std.fmt.allocPrint(std.testing.allocator, "http://127.0.0.1:{d}/bridge", .{server.listen_address.getPort()});
    defer std.testing.allocator.free(url);

    var req: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_client_req_new(client, 1, url.ptr, url.len, &req));
    defer _ = plugin.sa_node_plugin_http_client_req_free(req);

    var resp: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_client_req_send(req, &resp));
    defer _ = plugin.sa_node_plugin_http_client_resp_free(resp);

    try std.testing.expectEqual(@as(u16, 201), plugin.sa_node_plugin_http_client_resp_status(resp));

    var body_ptr: ?[*]const u8 = null;
    var body_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_client_resp_body_slice(resp, &body_ptr, &body_len));
    try std.testing.expectEqualStrings("node bridge", (body_ptr orelse return error.NullBody)[0..@intCast(body_len)]);

    thread.join();
}

test "node plugin http one-shot request helpers" {
    const address = try std.net.Address.parseIp4("127.0.0.1", 0);
    const server = try std.testing.allocator.create(std.net.Server);
    server.* = try address.listen(.{ .reuse_address = true });
    defer std.testing.allocator.destroy(server);

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(listen_server: *std.net.Server) void {
            defer listen_server.deinit();
            var conn = listen_server.accept() catch return;
            defer conn.stream.close();

            var request_buffer: [4096]u8 = undefined;
            var http_server = std.http.Server.init(conn, &request_buffer);
            const request = http_server.receiveHead() catch return;
            _ = request;

            conn.stream.writeAll(
                "HTTP/1.1 202 Accepted\r\ncontent-type: text/plain\r\nconnection: close\r\ncontent-length: 12\r\n\r\none-shot ok!",
            ) catch return;
        }
    }.run, .{server});

    const url = try std.fmt.allocPrint(std.testing.allocator, "http://127.0.0.1:{d}/one-shot", .{server.listen_address.getPort()});
    defer std.testing.allocator.free(url);

    var out_ptr: ?[*]const u8 = null;
    var out_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_get_json(url.ptr, url.len, &out_ptr, &out_len));
    defer _ = plugin.sa_node_plugin_free_buffer(out_ptr, out_len);
    const json = (out_ptr orelse return error.NullHttpOneShot)[0..@intCast(out_len)];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"statusCode\":202") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "one-shot ok!") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "text/plain") != null);

    var invalid_ptr: ?[*]const u8 = null;
    var invalid_len: u64 = 0;
    try std.testing.expect(plugin.sa_node_plugin_http_request_json("PATCH", 5, url.ptr, url.len, null, 0, &invalid_ptr, &invalid_len) != 0);
    try std.testing.expect(invalid_ptr == null);
    try std.testing.expectEqual(@as(u64, 0), invalid_len);

    thread.join();
}

test "node plugin https one-shot request helpers" {
    const https_url = "https://127.0.0.1:1/";
    const http_url = "http://127.0.0.1:1/";

    var out_ptr: ?[*]const u8 = null;
    var out_len: u64 = 99;
    try std.testing.expect(plugin.sa_node_plugin_https_get_json(http_url.ptr, http_url.len, &out_ptr, &out_len) != 0);
    try std.testing.expect(out_ptr == null);
    try std.testing.expectEqual(@as(u64, 0), out_len);

    try std.testing.expect(plugin.sa_node_plugin_https_request_json("PATCH", 5, https_url.ptr, https_url.len, null, 0, &out_ptr, &out_len) != 0);
    try std.testing.expect(out_ptr == null);
    try std.testing.expectEqual(@as(u64, 0), out_len);

    try std.testing.expect(plugin.sa_node_plugin_https_get_json(https_url.ptr, https_url.len, &out_ptr, &out_len) != 0);
    try std.testing.expect(out_ptr == null);
    try std.testing.expectEqual(@as(u64, 0), out_len);
}

test "node plugin http static metadata and header validators" {
    var max_header_size: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_max_header_size(&max_header_size));
    try std.testing.expectEqual(@as(u64, 16 * 1024), max_header_size);
    try std.testing.expect(plugin.sa_node_plugin_http_max_header_size(null) != 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_set_max_idle_http_parsers(1));
    try std.testing.expect(plugin.sa_node_plugin_http_set_max_idle_http_parsers(0) != 0);

    var methods_ptr: ?[*]const u8 = null;
    var methods_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_methods_json(&methods_ptr, &methods_len));
    defer _ = plugin.sa_node_plugin_free_buffer(methods_ptr, methods_len);
    const methods_json = (methods_ptr orelse return error.NullHttpMethods)[0..@intCast(methods_len)];
    try std.testing.expect(std.mem.indexOf(u8, methods_json, "\"GET\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, methods_json, "\"M-SEARCH\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, methods_json, "\"UNSUBSCRIBE\"") != null);

    var status_codes_ptr: ?[*]const u8 = null;
    var status_codes_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_status_codes_json(&status_codes_ptr, &status_codes_len));
    defer _ = plugin.sa_node_plugin_free_buffer(status_codes_ptr, status_codes_len);
    const status_codes_json = (status_codes_ptr orelse return error.NullHttpStatusCodes)[0..@intCast(status_codes_len)];
    var status_codes = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, status_codes_json, .{});
    defer status_codes.deinit();
    try std.testing.expectEqualStrings("OK", status_codes.value.object.get("200").?.string);
    try std.testing.expectEqualStrings("Not Found", status_codes.value.object.get("404").?.string);
    try std.testing.expectEqualStrings("I'm a Teapot", status_codes.value.object.get("418").?.string);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_validate_header_name("content-type", 12));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_validate_header_name("x_custom.header", 15));
    try std.testing.expect(plugin.sa_node_plugin_http_validate_header_name("bad header", 10) != 0);
    try std.testing.expect(plugin.sa_node_plugin_http_validate_header_name("", 0) != 0);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_validate_header_value("x-test", 6, "plain\tvalue", 11));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http_validate_header_value("x-test", 6, "", 0));
    try std.testing.expect(plugin.sa_node_plugin_http_validate_header_value("x-test", 6, "bad\nvalue", 9) != 0);
    try std.testing.expect(plugin.sa_node_plugin_http_validate_header_value("x-test", 6, null, 0) != 0);
}

test "node plugin http2 settings pack and unpack helpers" {
    var defaults_ptr: ?[*]const u8 = null;
    var defaults_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http2_get_default_settings_json(&defaults_ptr, &defaults_len));
    defer _ = plugin.sa_node_plugin_free_buffer(defaults_ptr, defaults_len);
    const defaults_json = (defaults_ptr orelse return error.NullHttp2Defaults)[0..@intCast(defaults_len)];
    try std.testing.expect(std.mem.indexOf(u8, defaults_json, "\"headerTableSize\":4096") != null);
    try std.testing.expect(std.mem.indexOf(u8, defaults_json, "\"maxConcurrentStreams\":4294967295") != null);

    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http2_constants_json(&constants_ptr, &constants_len));
    defer _ = plugin.sa_node_plugin_free_buffer(constants_ptr, constants_len);
    const constants_json = (constants_ptr orelse return error.NullHttp2Constants)[0..@intCast(constants_len)];
    var constants = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, constants_json, .{});
    defer constants.deinit();
    try std.testing.expectEqual(@as(i64, 2), constants.value.object.get("NGHTTP2_SETTINGS_ENABLE_PUSH").?.integer);
    try std.testing.expectEqual(@as(i64, 200), constants.value.object.get("HTTP_STATUS_OK").?.integer);
    try std.testing.expectEqualStrings(":path", constants.value.object.get("HTTP2_HEADER_PATH").?.string);
    try std.testing.expectEqualStrings("GET", constants.value.object.get("HTTP2_METHOD_GET").?.string);

    var sensitive_ptr: ?[*]const u8 = null;
    var sensitive_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http2_sensitive_headers(&sensitive_ptr, &sensitive_len));
    defer _ = plugin.sa_node_plugin_free_buffer(sensitive_ptr, sensitive_len);
    try std.testing.expectEqualStrings("Symbol(sensitiveHeaders)", (sensitive_ptr orelse return error.NullHttp2SensitiveHeaders)[0..@intCast(sensitive_len)]);

    const enable_push_false = "{\"enablePush\":false}";
    var packed_ptr: ?[*]const u8 = null;
    var packed_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http2_get_packed_settings(enable_push_false.ptr, enable_push_false.len, &packed_ptr, &packed_len));
    defer _ = plugin.sa_node_plugin_free_buffer(packed_ptr, packed_len);
    const packed_bytes = (packed_ptr orelse return error.NullHttp2Packed)[0..@intCast(packed_len)];
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 }, packed_bytes);

    var unpacked_ptr: ?[*]const u8 = null;
    var unpacked_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http2_get_unpacked_settings_json(packed_bytes.ptr, packed_bytes.len, &unpacked_ptr, &unpacked_len));
    defer _ = plugin.sa_node_plugin_free_buffer(unpacked_ptr, unpacked_len);
    const unpacked_json = (unpacked_ptr orelse return error.NullHttp2Unpacked)[0..@intCast(unpacked_len)];
    try std.testing.expect(std.mem.indexOf(u8, unpacked_json, "\"enablePush\":false") != null);

    const settings_json = "{\"initialWindowSize\":65535,\"maxFrameSize\":16384,\"maxHeaderSize\":123,\"customSettings\":{\"99\":123}}";
    var packed2_ptr: ?[*]const u8 = null;
    var packed2_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http2_get_packed_settings(settings_json.ptr, settings_json.len, &packed2_ptr, &packed2_len));
    defer _ = plugin.sa_node_plugin_free_buffer(packed2_ptr, packed2_len);
    const packed2 = (packed2_ptr orelse return error.NullHttp2Packed2)[0..@intCast(packed2_len)];
    try std.testing.expectEqual(@as(usize, 24), packed2.len);

    var unpacked2_ptr: ?[*]const u8 = null;
    var unpacked2_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http2_get_unpacked_settings_json(packed2.ptr, packed2.len, &unpacked2_ptr, &unpacked2_len));
    defer _ = plugin.sa_node_plugin_free_buffer(unpacked2_ptr, unpacked2_len);
    const unpacked2_json = (unpacked2_ptr orelse return error.NullHttp2Unpacked2)[0..@intCast(unpacked2_len)];
    try std.testing.expect(std.mem.indexOf(u8, unpacked2_json, "\"initialWindowSize\":65535") != null);
    try std.testing.expect(std.mem.indexOf(u8, unpacked2_json, "\"maxFrameSize\":16384") != null);
    try std.testing.expect(std.mem.indexOf(u8, unpacked2_json, "\"maxHeaderListSize\":123") != null);
    try std.testing.expect(std.mem.indexOf(u8, unpacked2_json, "\"customSettings\":{\"99\":123}") != null);

    const invalid_settings = "{\"maxFrameSize\":100}";
    var invalid_ptr: ?[*]const u8 = null;
    var invalid_len: u64 = 0;
    try std.testing.expect(plugin.sa_node_plugin_http2_get_packed_settings(invalid_settings.ptr, invalid_settings.len, &invalid_ptr, &invalid_len) != 0);
}

test "node plugin quic and http3 metadata helpers" {
    var quic_constants_ptr: ?[*]const u8 = null;
    var quic_constants_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_constants_json(&quic_constants_ptr, &quic_constants_len));
    defer _ = plugin.sa_node_plugin_free_buffer(quic_constants_ptr, quic_constants_len);
    const quic_constants_json = (quic_constants_ptr orelse return error.NullQuicConstants)[0..@intCast(quic_constants_len)];
    var quic_constants = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, quic_constants_json, .{});
    defer quic_constants.deinit();
    try std.testing.expectEqualStrings("cubic", quic_constants.value.object.get("cc").?.object.get("CUBIC").?.string);
    try std.testing.expectEqualStrings("h3", quic_constants.value.object.get("ALPN_H3").?.string);
    try std.testing.expect(std.mem.indexOf(u8, quic_constants.value.object.get("DEFAULT_CIPHERS").?.string, "TLS_AES_128_GCM_SHA256") != null);

    var caps_ptr: ?[*]const u8 = null;
    var caps_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_capabilities_json(&caps_ptr, &caps_len));
    defer _ = plugin.sa_node_plugin_free_buffer(caps_ptr, caps_len);
    const caps_json = (caps_ptr orelse return error.NullQuicCapabilities)[0..@intCast(caps_len)];
    var caps = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, caps_json, .{});
    defer caps.deinit();
    try std.testing.expect(caps.value.object.get("supported") != null);
    try std.testing.expect(caps.value.object.get("ngtcp2") != null);
    try std.testing.expect(caps.value.object.get("nghttp3") != null);
    try std.testing.expect(caps.value.object.get("openssl") != null);

    var http3_constants_ptr: ?[*]const u8 = null;
    var http3_constants_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http3_constants_json(&http3_constants_ptr, &http3_constants_len));
    defer _ = plugin.sa_node_plugin_free_buffer(http3_constants_ptr, http3_constants_len);
    const http3_constants_json = (http3_constants_ptr orelse return error.NullHttp3Constants)[0..@intCast(http3_constants_len)];
    var http3_constants = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, http3_constants_json, .{});
    defer http3_constants.deinit();
    try std.testing.expectEqualStrings("h3", http3_constants.value.object.get("ALPN_H3").?.string);
    try std.testing.expectEqual(@as(i64, 9114), http3_constants.value.object.get("RFC_HTTP3").?.integer);
}

test "node plugin quic http3 and dtls native endpoint subsets" {
    var quic_endpoint: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_listen(4, "127.0.0.1", 9, 0, "h3", 2, "cubic", 5, 1500, &quic_endpoint));
    defer _ = plugin.sa_node_plugin_quic_endpoint_free(quic_endpoint);

    var qsnap_ptr: ?[*]const u8 = null;
    var qsnap_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_endpoint_snapshot_json(quic_endpoint, &qsnap_ptr, &qsnap_len));
    defer _ = plugin.sa_node_plugin_free_buffer(qsnap_ptr, qsnap_len);
    const qsnap = (qsnap_ptr orelse return error.NullQuicSnapshot)[0..@intCast(qsnap_len)];
    try std.testing.expect(std.mem.indexOf(u8, qsnap, "\"server\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, qsnap, "\"alpn\":\"h3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, qsnap, "\"cc\":\"cubic\"") != null);

    var qaddr_ptr: ?[*]const u8 = null;
    var qaddr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_endpoint_address_json(quic_endpoint, &qaddr_ptr, &qaddr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(qaddr_ptr, qaddr_len);
    const port = try jsonPort((qaddr_ptr orelse return error.NullQuicAddress)[0..@intCast(qaddr_len)]);
    try std.testing.expect(port != 0);

    var has_ref: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_endpoint_has_ref(quic_endpoint, &has_ref));
    try std.testing.expectEqual(@as(u64, 1), has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_endpoint_unref(quic_endpoint));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_endpoint_has_ref(quic_endpoint, &has_ref));
    try std.testing.expectEqual(@as(u64, 0), has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_endpoint_ref(quic_endpoint));

    var client_endpoint: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_connect(4, "127.0.0.1", 9, port, null, 0, 0, "h3", 2, "reno", 4, 500, &client_endpoint));
    defer _ = plugin.sa_node_plugin_quic_endpoint_free(client_endpoint);

    var client_raddr_ptr: ?[*]const u8 = null;
    var client_raddr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_endpoint_remote_address_json(client_endpoint, &client_raddr_ptr, &client_raddr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(client_raddr_ptr, client_raddr_len);
    try std.testing.expectEqual(port, try jsonPort((client_raddr_ptr orelse return error.NullQuicRemote)[0..@intCast(client_raddr_len)]));

    var http3_session: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http3_create_session(client_endpoint, "example.test", 12, "/echo", 5, "POST", 4, &http3_session));
    defer _ = plugin.sa_node_plugin_http3_session_free(http3_session);

    var h3snap_ptr: ?[*]const u8 = null;
    var h3snap_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http3_session_snapshot_json(http3_session, &h3snap_ptr, &h3snap_len));
    defer _ = plugin.sa_node_plugin_free_buffer(h3snap_ptr, h3snap_len);
    const h3snap = (h3snap_ptr orelse return error.NullHttp3Snapshot)[0..@intCast(h3snap_len)];
    try std.testing.expect(std.mem.indexOf(u8, h3snap, "example.test") != null);
    try std.testing.expect(std.mem.indexOf(u8, h3snap, "\"method\":\"POST\"") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http3_session_send_datagram(http3_session, "ping", 4));
    var recv_ptr: ?[*]const u8 = null;
    var recv_len: u64 = 0;
    var recv_host_ptr: ?[*]const u8 = null;
    var recv_host_len: u64 = 0;
    var recv_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http3_session_recv_datagram(http3_session, 64, &recv_ptr, &recv_len, &recv_host_ptr, &recv_host_len, &recv_port));
    defer _ = plugin.sa_node_plugin_free_buffer(recv_ptr, recv_len);
    defer _ = plugin.sa_node_plugin_free_buffer(recv_host_ptr, recv_host_len);
    try std.testing.expectEqualStrings("ping", (recv_ptr orelse return error.NullHttp3Recv)[0..@intCast(recv_len)]);
    try std.testing.expectEqual(port, @as(u16, @intCast(recv_port)));

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http3_session_close(http3_session));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_endpoint_close(client_endpoint));

    var dtls_status_ptr: ?[*]const u8 = null;
    var dtls_status_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dtls_status_json(&dtls_status_ptr, &dtls_status_len));
    defer _ = plugin.sa_node_plugin_free_buffer(dtls_status_ptr, dtls_status_len);
    try std.testing.expect(std.mem.indexOf(u8, (dtls_status_ptr orelse return error.NullDtlsStatus)[0..@intCast(dtls_status_len)], "\"module\":\"dtls\"") != null);

    var dtls_server: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dtls_listen(4, "127.0.0.1", 9, 0, &dtls_server));
    defer _ = plugin.sa_node_plugin_dtls_free(dtls_server);
    var dtls_addr_ptr: ?[*]const u8 = null;
    var dtls_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_quic_endpoint_address_json(dtls_server, &dtls_addr_ptr, &dtls_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(dtls_addr_ptr, dtls_addr_len);
    const dtls_port = try jsonPort((dtls_addr_ptr orelse return error.NullDtlsAddress)[0..@intCast(dtls_addr_len)]);

    var dtls_client: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dtls_connect(4, "127.0.0.1", 9, dtls_port, null, 0, 0, &dtls_client));
    defer _ = plugin.sa_node_plugin_dtls_free(dtls_client);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dtls_send(dtls_client, "hi", 2));

    var dtls_recv_ptr: ?[*]const u8 = null;
    var dtls_recv_len: u64 = 0;
    var dtls_recv_host_ptr: ?[*]const u8 = null;
    var dtls_recv_host_len: u64 = 0;
    var dtls_recv_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dtls_recv(dtls_server, 64, &dtls_recv_ptr, &dtls_recv_len, &dtls_recv_host_ptr, &dtls_recv_host_len, &dtls_recv_port));
    defer _ = plugin.sa_node_plugin_free_buffer(dtls_recv_ptr, dtls_recv_len);
    defer _ = plugin.sa_node_plugin_free_buffer(dtls_recv_host_ptr, dtls_recv_host_len);
    try std.testing.expectEqualStrings("hi", (dtls_recv_ptr orelse return error.NullDtlsRecv)[0..@intCast(dtls_recv_len)]);

    var dtls_snap_ptr: ?[*]const u8 = null;
    var dtls_snap_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dtls_endpoint_snapshot_json(dtls_client, &dtls_snap_ptr, &dtls_snap_len));
    defer _ = plugin.sa_node_plugin_free_buffer(dtls_snap_ptr, dtls_snap_len);
    try std.testing.expect(std.mem.indexOf(u8, (dtls_snap_ptr orelse return error.NullDtlsSnapshot)[0..@intCast(dtls_snap_len)], "\"alpn\":\"dtls\"") != null);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dtls_close(dtls_client));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_dtls_close(dtls_server));
}

test "node plugin tls top level constants and cipher helpers" {
    var ciphers_ptr: ?[*]const u8 = null;
    var ciphers_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_get_ciphers_json(&ciphers_ptr, &ciphers_len));
    defer _ = plugin.sa_node_plugin_free_buffer(ciphers_ptr, ciphers_len);
    const ciphers_json = (ciphers_ptr orelse return error.NullTlsCiphers)[0..@intCast(ciphers_len)];
    var ciphers = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, ciphers_json, .{});
    defer ciphers.deinit();
    try std.testing.expect(ciphers.value.array.items.len >= 4);
    var saw_tls13 = false;
    for (ciphers.value.array.items) |item| {
        if (std.mem.eql(u8, item.string, "tls_aes_128_gcm_sha256")) saw_tls13 = true;
    }
    try std.testing.expect(saw_tls13);

    var detailed_ptr: ?[*]const u8 = null;
    var detailed_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_get_ciphers_detailed_json(&detailed_ptr, &detailed_len));
    defer _ = plugin.sa_node_plugin_free_buffer(detailed_ptr, detailed_len);
    const detailed_json = (detailed_ptr orelse return error.NullTlsCiphersDetailed)[0..@intCast(detailed_len)];
    var detailed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, detailed_json, .{});
    defer detailed.deinit();
    try std.testing.expect(detailed.value.array.items.len == ciphers.value.array.items.len);
    try std.testing.expectEqualStrings("TLS_AES_128_GCM_SHA256", detailed.value.array.items[0].object.get("standardName").?.string);
    try std.testing.expectEqualStrings("TLSv1.3", detailed.value.array.items[0].object.get("version").?.string);

    var constants_ptr: ?[*]const u8 = null;
    var constants_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_default_constants_json(&constants_ptr, &constants_len));
    defer _ = plugin.sa_node_plugin_free_buffer(constants_ptr, constants_len);
    const constants_json = (constants_ptr orelse return error.NullTlsDefaultConstants)[0..@intCast(constants_len)];
    var constants = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, constants_json, .{});
    defer constants.deinit();
    try std.testing.expectEqual(@as(i64, 3), constants.value.object.get("CLIENT_RENEG_LIMIT").?.integer);
    try std.testing.expectEqual(@as(i64, 600), constants.value.object.get("CLIENT_RENEG_WINDOW").?.integer);
    try std.testing.expectEqualStrings("TLSv1.2", constants.value.object.get("DEFAULT_MIN_VERSION").?.string);
    try std.testing.expectEqualStrings("TLSv1.3", constants.value.object.get("DEFAULT_MAX_VERSION").?.string);
    try std.testing.expect(std.mem.indexOf(u8, constants.value.object.get("DEFAULT_CIPHERS").?.string, "TLS_AES_128_GCM_SHA256") != null);

    var min_ptr: ?[*]const u8 = null;
    var min_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_default_min_version(&min_ptr, &min_len));
    defer _ = plugin.sa_node_plugin_free_buffer(min_ptr, min_len);
    try std.testing.expectEqualStrings("TLSv1.2", (min_ptr orelse return error.NullTlsMinVersion)[0..@intCast(min_len)]);

    var max_ptr: ?[*]const u8 = null;
    var max_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_default_max_version(&max_ptr, &max_len));
    defer _ = plugin.sa_node_plugin_free_buffer(max_ptr, max_len);
    try std.testing.expectEqualStrings("TLSv1.3", (max_ptr orelse return error.NullTlsMaxVersion)[0..@intCast(max_len)]);

    var alpn_ptr: ?[*]const u8 = null;
    var alpn_len: u64 = 0;
    const alpn_json = "[\"h2\",\"http/1.1\"]";
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_convert_alpn_protocols(alpn_json.ptr, alpn_json.len, &alpn_ptr, &alpn_len));
    defer _ = plugin.sa_node_plugin_free_buffer(alpn_ptr, alpn_len);
    const alpn = (alpn_ptr orelse return error.NullTlsAlpnWire)[0..@intCast(alpn_len)];
    try std.testing.expectEqualSlices(u8, &[_]u8{ 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' }, alpn);

    var empty_alpn_ptr: ?[*]const u8 = null;
    var empty_alpn_len: u64 = 99;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_convert_alpn_protocols("[]", 2, &empty_alpn_ptr, &empty_alpn_len));
    defer _ = plugin.sa_node_plugin_free_buffer(empty_alpn_ptr, empty_alpn_len);
    try std.testing.expectEqual(@as(u64, 0), empty_alpn_len);
    try std.testing.expect(plugin.sa_node_plugin_tls_convert_alpn_protocols("[1]", 3, &empty_alpn_ptr, &empty_alpn_len) != 0);

    var root_ptr: ?[*]const u8 = null;
    var root_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_root_certificates_json(&root_ptr, &root_len));
    defer _ = plugin.sa_node_plugin_free_buffer(root_ptr, root_len);
    const root_json = (root_ptr orelse return error.NullTlsRootCertificates)[0..@intCast(root_len)];
    var root = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, root_json, .{});
    defer root.deinit();
    try std.testing.expect(root.value.array.items.len > 0);
    const first_root = root.value.array.items[0].string;
    try std.testing.expect(std.mem.indexOf(u8, first_root, "-----BEGIN CERTIFICATE-----") != null);

    var system_ptr: ?[*]const u8 = null;
    var system_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_get_ca_certificates_json("system".ptr, 6, &system_ptr, &system_len));
    defer _ = plugin.sa_node_plugin_free_buffer(system_ptr, system_len);
    const system_json = (system_ptr orelse return error.NullTlsSystemCertificates)[0..@intCast(system_len)];
    var system_certs = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, system_json, .{});
    defer system_certs.deinit();
    try std.testing.expect(system_certs.value.array.items.len > 0);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_set_default_ca_certificates(first_root.ptr, first_root.len));
    defer _ = plugin.sa_node_plugin_tls_reset_default_ca_certificates();
    var default_ptr: ?[*]const u8 = null;
    var default_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_get_ca_certificates_json("default".ptr, 7, &default_ptr, &default_len));
    defer _ = plugin.sa_node_plugin_free_buffer(default_ptr, default_len);
    const default_json = (default_ptr orelse return error.NullTlsDefaultCertificates)[0..@intCast(default_len)];
    var default_certs = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, default_json, .{});
    defer default_certs.deinit();
    try std.testing.expectEqual(@as(usize, 1), default_certs.value.array.items.len);

    var context: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_create_secure_context(first_root.ptr, first_root.len, null, 0, null, 0, null, 0, "TLSv1.2".ptr, 7, "TLSv1.3".ptr, 7, &context));
    defer _ = plugin.sa_node_plugin_tls_secure_context_free(context);
    var snapshot_ptr: ?[*]const u8 = null;
    var snapshot_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_secure_context_snapshot_json(context, &snapshot_ptr, &snapshot_len));
    defer _ = plugin.sa_node_plugin_free_buffer(snapshot_ptr, snapshot_len);
    const snapshot_json = (snapshot_ptr orelse return error.NullTlsSecureContextSnapshot)[0..@intCast(snapshot_len)];
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"caCount\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"minVersion\":\"TLSv1.2\"") != null);
}

test "node plugin http2 h2c client request helper" {
    var version_ptr: ?[*]const u8 = null;
    var version_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_http2_nghttp2_version_json(&version_ptr, &version_len));
    defer _ = plugin.sa_node_plugin_free_buffer(version_ptr, version_len);
    const version_json = (version_ptr orelse return error.NullNghttp2Version)[0..@intCast(version_len)];
    try std.testing.expect(std.mem.indexOf(u8, version_json, "nghttp2") != null or std.mem.indexOf(u8, version_json, "h2") != null);

    const address = try std.net.Address.parseIp4("127.0.0.1", 0);
    const server = try std.testing.allocator.create(std.net.Server);
    server.* = try address.listen(.{ .reuse_address = true });
    defer std.testing.allocator.destroy(server);

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(listen_server: *std.net.Server) void {
            defer listen_server.deinit();
            var conn = listen_server.accept() catch return;
            defer conn.stream.close();

            var preface: [24]u8 = undefined;
            conn.stream.reader().readNoEof(&preface) catch return;
            if (!std.mem.eql(u8, &preface, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) return;

            var header: [9]u8 = undefined;
            conn.stream.reader().readNoEof(&header) catch return;
            const settings_len = (@as(usize, header[0]) << 16) | (@as(usize, header[1]) << 8) | @as(usize, header[2]);
            var discard: [4096]u8 = undefined;
            if (settings_len > discard.len) return;
            conn.stream.reader().readNoEof(discard[0..settings_len]) catch return;

            writeH2Frame(conn.stream, 0x4, 0x0, 0, "") catch return;
            writeH2Frame(conn.stream, 0x4, 0x1, 0, "") catch return;

            var saw_headers = false;
            while (!saw_headers) {
                conn.stream.reader().readNoEof(&header) catch return;
                const len = (@as(usize, header[0]) << 16) | (@as(usize, header[1]) << 8) | @as(usize, header[2]);
                if (len > discard.len) return;
                conn.stream.reader().readNoEof(discard[0..len]) catch return;
                if (header[3] == 0x1) saw_headers = true;
            }

            const response_headers = [_]u8{0x88};
            writeH2Frame(conn.stream, 0x1, 0x4, 1, &response_headers) catch return;
            writeH2Frame(conn.stream, 0x0, 0x1, 1, "h2 ok") catch return;
            std.time.sleep(100 * std.time.ns_per_ms);
        }
    }.run, .{server});

    const url = try std.fmt.allocPrint(std.testing.allocator, "http://127.0.0.1:{d}/h2", .{server.listen_address.getPort()});
    defer std.testing.allocator.free(url);

    var resp_ptr: ?[*]const u8 = null;
    var resp_len: u64 = 0;
    const h2_status = plugin.sa_node_plugin_http2_client_request(url.ptr, url.len, "GET".ptr, 3, "".ptr, 0, &resp_ptr, &resp_len);
    try std.testing.expectEqual(@as(u32, 0), h2_status);
    defer _ = plugin.sa_node_plugin_free_buffer(resp_ptr, resp_len);
    const response = (resp_ptr orelse return error.NullHttp2Response)[0..@intCast(resp_len)];
    try std.testing.expect(std.mem.indexOf(u8, response, "\"status\":200") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"body\":\"h2 ok\"") != null);

    thread.join();
}

test "node plugin tls client round trip against local self-signed server" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var original_cwd = try std.fs.cwd().openDir(".", .{});
    defer original_cwd.close();
    try tmp.dir.setAsCwd();
    defer original_cwd.setAsCwd() catch {};

    const cert_conf =
        \\[req]
        \\distinguished_name = req_distinguished_name
        \\x509_extensions = v3_req
        \\prompt = no
        \\
        \\[req_distinguished_name]
        \\CN = localhost
        \\
        \\[v3_req]
        \\subjectAltName = @alt_names
        \\
        \\[alt_names]
        \\DNS.1 = localhost
        \\IP.1 = 127.0.0.1
    ;
    try std.fs.cwd().writeFile(.{ .sub_path = "cert.cnf", .data = cert_conf });

    const gen = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.crt",
            "-config",
            "cert.cnf",
            "-extensions",
            "v3_req",
        },
        .cwd = ".",
    });
    defer std.testing.allocator.free(gen.stdout);
    defer std.testing.allocator.free(gen.stderr);
    switch (gen.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }

    var server_child = std.process.Child.init(&.{
        "openssl",
        "s_server",
        "-accept",
        "18444",
        "-cert",
        "server.crt",
        "-key",
        "server.key",
        "-www",
        "-quiet",
        "-naccept",
        "2",
    }, std.testing.allocator);
    server_child.cwd = ".";
    server_child.stdin_behavior = .Ignore;
    server_child.stdout_behavior = .Ignore;
    server_child.stderr_behavior = .Ignore;
    try server_child.spawn();

    const server_cert = try std.fs.cwd().readFileAlloc(std.testing.allocator, "server.crt", 1024 * 1024);
    defer std.testing.allocator.free(server_cert);
    var trusted_context: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_create_secure_context(server_cert.ptr, server_cert.len, null, 0, null, 0, null, 0, null, 0, null, 0, &trusted_context));
    defer _ = plugin.sa_node_plugin_tls_secure_context_free(trusted_context);

    var trusted_client: ?*anyopaque = null;
    var trusted_connected = false;
    for (0..80) |_| {
        if (plugin.sa_node_plugin_tls_connect_secure_context(trusted_context, "localhost", 9, 18444, "localhost", 9, 1, &trusted_client) == 0) {
            trusted_connected = true;
            break;
        }
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    try std.testing.expect(trusted_connected);
    var trusted_auth_ptr: ?[*]const u8 = null;
    var trusted_auth_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_authorized_json(trusted_client, &trusted_auth_ptr, &trusted_auth_len));
    defer _ = plugin.sa_node_plugin_free_buffer(trusted_auth_ptr, trusted_auth_len);
    try std.testing.expect(std.mem.indexOf(u8, (trusted_auth_ptr orelse return error.NullTrustedTlsAuth)[0..@intCast(trusted_auth_len)], "\"authorized\":true") != null);
    _ = plugin.sa_node_plugin_tls_close(trusted_client);

    var blocklist: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_new(&blocklist));
    defer _ = plugin.sa_node_plugin_net_blocklist_free(blocklist);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_net_blocklist_add_address(blocklist, "127.0.0.1", 9));

    var blocked_tls: ?*anyopaque = @ptrFromInt(@as(usize, 0x1));
    try std.testing.expectEqual(@as(u32, 3), plugin.sa_node_plugin_tls_connect_options(
        "127.0.0.1",
        9,
        18444,
        "localhost",
        9,
        0,
        4,
        null,
        0,
        0,
        1,
        1,
        1,
        500,
        blocklist,
        &blocked_tls,
    ));
    try std.testing.expect(blocked_tls == null);

    var client: ?*anyopaque = null;
    var connected = false;
    for (0..80) |_| {
        if (plugin.sa_node_plugin_tls_connect_options(
            "localhost",
            9,
            18444,
            "localhost",
            9,
            0,
            4,
            "127.0.0.1",
            9,
            0,
            1,
            1,
            1,
            500,
            null,
            &client,
        ) == 0) {
            connected = true;
            break;
        }
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    try std.testing.expect(connected);
    defer _ = plugin.sa_node_plugin_tls_close(client);

    var auth_ptr: ?[*]const u8 = null;
    var auth_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_authorized_json(client, &auth_ptr, &auth_len));
    defer _ = plugin.sa_node_plugin_free_buffer(auth_ptr, auth_len);
    try std.testing.expect(std.mem.indexOf(u8, (auth_ptr orelse return error.NullTlsAuth)[0..@intCast(auth_len)], "\"authorized\":false") != null);

    var servername_ptr: ?[*]const u8 = null;
    var servername_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_servername(client, &servername_ptr, &servername_len));
    defer _ = plugin.sa_node_plugin_free_buffer(servername_ptr, servername_len);
    try std.testing.expectEqualStrings("localhost", (servername_ptr orelse return error.NullTlsServername)[0..@intCast(servername_len)]);

    var alpn_ptr: ?[*]const u8 = null;
    var alpn_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_alpn_protocol(client, &alpn_ptr, &alpn_len));
    defer _ = plugin.sa_node_plugin_free_buffer(alpn_ptr, alpn_len);
    try std.testing.expectEqualStrings("false", (alpn_ptr orelse return error.NullTlsAlpn)[0..@intCast(alpn_len)]);

    var protocol_ptr: ?[*]const u8 = null;
    var protocol_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_get_protocol(client, &protocol_ptr, &protocol_len));
    defer _ = plugin.sa_node_plugin_free_buffer(protocol_ptr, protocol_len);
    const protocol = (protocol_ptr orelse return error.NullTlsProtocol)[0..@intCast(protocol_len)];
    try std.testing.expect(std.mem.eql(u8, protocol, "TLSv1.2") or std.mem.eql(u8, protocol, "TLSv1.3"));

    var cipher_ptr: ?[*]const u8 = null;
    var cipher_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_get_cipher_json(client, &cipher_ptr, &cipher_len));
    defer _ = plugin.sa_node_plugin_free_buffer(cipher_ptr, cipher_len);
    const cipher_json = (cipher_ptr orelse return error.NullTlsCipher)[0..@intCast(cipher_len)];
    try std.testing.expect(std.mem.indexOf(u8, cipher_json, "\"name\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, cipher_json, "\"standardName\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, cipher_json, "\"version\":") != null);

    var tls_addr_ptr: ?[*]const u8 = null;
    var tls_addr_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_address(client, &tls_addr_ptr, &tls_addr_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tls_addr_ptr, tls_addr_len);
    try std.testing.expect(std.mem.indexOf(u8, (tls_addr_ptr orelse return error.NullTlsAddress)[0..@intCast(tls_addr_len)], "\"port\":") != null);

    var tls_remote_ptr: ?[*]const u8 = null;
    var tls_remote_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_remote_address(client, &tls_remote_ptr, &tls_remote_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tls_remote_ptr, tls_remote_len);
    try std.testing.expect(std.mem.indexOf(u8, (tls_remote_ptr orelse return error.NullTlsRemoteAddress)[0..@intCast(tls_remote_len)], "127.0.0.1") != null);

    var tls_local_address_ptr: ?[*]const u8 = null;
    var tls_local_address_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_local_address(client, &tls_local_address_ptr, &tls_local_address_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tls_local_address_ptr, tls_local_address_len);
    try std.testing.expectEqualStrings("127.0.0.1", (tls_local_address_ptr orelse return error.NullTlsLocalAddress)[0..@intCast(tls_local_address_len)]);

    var tls_local_family_ptr: ?[*]const u8 = null;
    var tls_local_family_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_local_family(client, &tls_local_family_ptr, &tls_local_family_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tls_local_family_ptr, tls_local_family_len);
    try std.testing.expectEqualStrings("IPv4", (tls_local_family_ptr orelse return error.NullTlsLocalFamily)[0..@intCast(tls_local_family_len)]);

    var tls_local_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_local_port(client, &tls_local_port));
    try std.testing.expect(tls_local_port > 0);

    var tls_remote_address_ptr: ?[*]const u8 = null;
    var tls_remote_address_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_remote_address_value(client, &tls_remote_address_ptr, &tls_remote_address_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tls_remote_address_ptr, tls_remote_address_len);
    try std.testing.expectEqualStrings("127.0.0.1", (tls_remote_address_ptr orelse return error.NullTlsRemoteAddressValue)[0..@intCast(tls_remote_address_len)]);

    var tls_remote_family_ptr: ?[*]const u8 = null;
    var tls_remote_family_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_remote_family(client, &tls_remote_family_ptr, &tls_remote_family_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tls_remote_family_ptr, tls_remote_family_len);
    try std.testing.expectEqualStrings("IPv4", (tls_remote_family_ptr orelse return error.NullTlsRemoteFamily)[0..@intCast(tls_remote_family_len)]);

    var tls_remote_port: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_remote_port(client, &tls_remote_port));
    try std.testing.expectEqual(@as(u64, 18444), tls_remote_port);

    var tls_timeout: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_get_timeout(client, &tls_timeout));
    try std.testing.expectEqual(@as(u64, 500), tls_timeout);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_set_timeout(client, 750));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_get_timeout(client, &tls_timeout));
    try std.testing.expectEqual(@as(u64, 750), tls_timeout);

    var tls_readable: u64 = 0;
    var tls_writable: u64 = 0;
    var tls_closed: u64 = 1;
    var tls_destroyed: u64 = 1;
    var tls_bytes_read: u64 = 99;
    var tls_bytes_written: u64 = 99;
    var tls_buffer_size: u64 = 99;
    var tls_connecting: u64 = 99;
    var tls_pending: u64 = 99;
    var tls_has_ref: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_readable(client, &tls_readable));
    try std.testing.expectEqual(@as(u64, 1), tls_readable);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_writable(client, &tls_writable));
    try std.testing.expectEqual(@as(u64, 1), tls_writable);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_closed(client, &tls_closed));
    try std.testing.expectEqual(@as(u64, 0), tls_closed);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_destroyed(client, &tls_destroyed));
    try std.testing.expectEqual(@as(u64, 0), tls_destroyed);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_bytes_read(client, &tls_bytes_read));
    try std.testing.expectEqual(@as(u64, 0), tls_bytes_read);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_bytes_written(client, &tls_bytes_written));
    try std.testing.expectEqual(@as(u64, 0), tls_bytes_written);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_buffer_size(client, &tls_buffer_size));
    try std.testing.expectEqual(@as(u64, 0), tls_buffer_size);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_connecting(client, &tls_connecting));
    try std.testing.expectEqual(@as(u64, 0), tls_connecting);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_pending(client, &tls_pending));
    try std.testing.expectEqual(@as(u64, 0), tls_pending);
    var tls_ready_ptr: ?[*]const u8 = null;
    var tls_ready_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_ready_state(client, &tls_ready_ptr, &tls_ready_len));
    defer _ = plugin.sa_node_plugin_free_buffer(tls_ready_ptr, tls_ready_len);
    try std.testing.expectEqualStrings("open", (tls_ready_ptr orelse return error.NullTlsReadyState)[0..@intCast(tls_ready_len)]);
    try std.testing.expect(plugin.sa_node_plugin_tls_buffer_size(client, null) != 0);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_has_ref(client, &tls_has_ref));
    try std.testing.expectEqual(@as(u64, 1), tls_has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_unref(client));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_has_ref(client, &tls_has_ref));
    try std.testing.expectEqual(@as(u64, 0), tls_has_ref);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_ref(client));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_has_ref(client, &tls_has_ref));
    try std.testing.expectEqual(@as(u64, 1), tls_has_ref);
    try std.testing.expect(plugin.sa_node_plugin_tls_has_ref(client, null) != 0);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_write(client, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", 37));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_bytes_written(client, &tls_bytes_written));
    try std.testing.expectEqual(@as(u64, 37), tls_bytes_written);

    var resp_ptr: ?[*]const u8 = null;
    var resp_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_read(client, 8192, &resp_ptr, &resp_len));
    defer _ = plugin.sa_node_plugin_free_buffer(resp_ptr, resp_len);
    const resp = (resp_ptr orelse return error.NullTlsResponse)[0..@intCast(resp_len)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "s_server") != null or std.mem.indexOf(u8, resp, "HTTP/") != null);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_bytes_read(client, &tls_bytes_read));
    try std.testing.expectEqual(resp_len, tls_bytes_read);

    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_destroy(client));
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_closed(client, &tls_closed));
    try std.testing.expectEqual(@as(u64, 1), tls_closed);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_destroyed(client, &tls_destroyed));
    try std.testing.expectEqual(@as(u64, 1), tls_destroyed);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_readable(client, &tls_readable));
    try std.testing.expectEqual(@as(u64, 0), tls_readable);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_tls_writable(client, &tls_writable));
    try std.testing.expectEqual(@as(u64, 0), tls_writable);

    _ = plugin.sa_node_plugin_tls_close(client);
    client = null;
    const wait_result = try server_child.wait();
    _ = wait_result;
}

test "node plugin child_process argv vector execution" {
    var args = makeSaArgv(&.{ "/bin/echo", "node-child" });
    var out_ptr: ?[*]const u8 = null;
    var out_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_child_process_spawn_sync(&args, 2, null, 0, &out_ptr, &out_len));
    defer _ = plugin.sa_node_plugin_free_buffer(out_ptr, out_len);
    try std.testing.expectEqualStrings("node-child\n", (out_ptr orelse return error.NullChildStdout)[0..@intCast(out_len)]);

    var file_args = makeSaArgv(&.{ "/bin/echo", "exec-file" });
    var file_out_ptr: ?[*]const u8 = null;
    var file_out_len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_child_process_exec_file(&file_args, 2, null, 0, &file_out_ptr, &file_out_len));
    defer _ = plugin.sa_node_plugin_free_buffer(file_out_ptr, file_out_len);
    try std.testing.expectEqualStrings("exec-file\n", (file_out_ptr orelse return error.NullExecFileStdout)[0..@intCast(file_out_len)]);
}

test "node plugin child_process spawn and fork return real child pids" {
    var spawn_args = makeSaArgv(&.{"/bin/true"});
    var pid: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_child_process_spawn(&spawn_args, 1, null, 0, &pid));
    try std.testing.expect(pid > 1);
    try std.testing.expect(pid != @as(u64, @intCast(std.os.linux.getpid())));

    const node_check = std.process.Child.run(.{ .allocator = std.testing.allocator, .argv = &.{ "node", "--version" }, .max_output_bytes = 4096 }) catch return error.SkipZigTest;
    defer std.testing.allocator.free(node_check.stdout);
    defer std.testing.allocator.free(node_check.stderr);
    switch (node_check.term) {
        .Exited => |code| if (code != 0) return error.SkipZigTest,
        else => return error.SkipZigTest,
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "child.js", .data = "setTimeout(() => {}, 50);" });
    const script_path = try tmp.dir.realpathAlloc(std.testing.allocator, "child.js");
    defer std.testing.allocator.free(script_path);

    var fork_pid: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_child_process_fork(script_path.ptr, script_path.len, null, 0, &fork_pid));
    try std.testing.expect(fork_pid > 1);
    try std.testing.expect(fork_pid != @as(u64, @intCast(std.os.linux.getpid())));
}
