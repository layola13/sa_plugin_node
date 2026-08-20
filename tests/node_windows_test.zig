const std = @import("std");
const plugin = @import("node");
const plugin_api = @import("plugin_api");

fn readOwned(comptime function: anytype) ![]const u8 {
    var ptr: ?[*]const u8 = null;
    var len: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), function(&ptr, &len));
    const bytes = (ptr orelse return error.NullBuffer)[0..@intCast(len)];
    const copy = try std.testing.allocator.dupe(u8, bytes);
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_free_buffer(ptr, len));
    return copy;
}

test "node Windows descriptor and platform values" {
    try std.testing.expectEqualStrings("node", std.mem.span(plugin.saasm_plugin_descriptor_v1.name));
    try std.testing.expectEqual(plugin_api.abi_version, plugin.saasm_plugin_descriptor_v1.abi_version);
    const platform = try readOwned(plugin.sa_node_plugin_os_platform);
    defer std.testing.allocator.free(platform);
    try std.testing.expectEqualStrings("win32", platform);
    const arch = try readOwned(plugin.sa_node_plugin_os_arch);
    defer std.testing.allocator.free(arch);
    try std.testing.expectEqualStrings("x64", arch);
}

test "node Windows process and environment APIs return owned data" {
    var pid: u64 = 0;
    try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_process_pid(&pid));
    try std.testing.expect(pid > 0);
    const cwd = try readOwned(plugin.sa_node_plugin_process_cwd);
    defer std.testing.allocator.free(cwd);
    try std.testing.expect(cwd.len > 0);
    const key = "TEMP";
    var value_ptr: ?[*]const u8 = null;
    var value_len: u64 = 0;
    const status = plugin.sa_node_plugin_process_env_get(key.ptr, key.len, &value_ptr, &value_len);
    if (status == 0) {
        try std.testing.expect(value_ptr != null);
        try std.testing.expect(value_len > 0);
        try std.testing.expectEqual(@as(u32, 0), plugin.sa_node_plugin_free_buffer(value_ptr, value_len));
    } else {
        try std.testing.expectEqual(@as(u32, 1), status);
    }
}