const std = @import("std");
const plugin_api = @import("plugin_api");
const plugin = @import("node");

test "node plugin events create and free" {
    const ee = plugin.sa_node_plugin_events_create();
    try std.testing.expect(ee != null);
    _ = plugin.sa_node_plugin_events_free(ee);
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

test "node plugin fs exists" {
    var exists: u32 = 0;
    const status = plugin.sa_node_plugin_fs_exists("sap.json", 8, &exists);
    try std.testing.expectEqual(@as(u32, 0), status);
    try std.testing.expectEqual(@as(u32, 1), exists);
}
