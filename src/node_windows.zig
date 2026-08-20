const std = @import("std");
const builtin = @import("builtin");

fn writeOwned(out_ptr: ?*?[*]const u8, out_len: ?*u64, bytes: []const u8) u32 {
    const ptr = out_ptr orelse return 2;
    const len_ptr = out_len orelse return 2;
    const owned = std.heap.page_allocator.dupe(u8, bytes) catch return 2;
    ptr.* = owned.ptr;
    len_ptr.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_free_buffer(ptr: ?[*]const u8, len: u64) u32 {
    if (ptr) |p| std.heap.page_allocator.free(p[0..len]);
    return 0;
}

pub export fn sa_node_plugin_os_platform(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "win32"); }
pub export fn sa_node_plugin_os_arch(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "x64"); }
pub export fn sa_node_plugin_os_release(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "Windows"); }
pub export fn sa_node_plugin_os_type(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "Windows_NT"); }
pub export fn sa_node_plugin_os_endianness(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "LE"); }
pub export fn sa_node_plugin_os_cpus(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_os_network_interfaces(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "{}"); }
pub export fn sa_node_plugin_os_totalmem(out_mem: ?*u64) u32 { if (out_mem) |p| p.* = 0; return 0; }
pub export fn sa_node_plugin_os_freemem(out_mem: ?*u64) u32 { if (out_mem) |p| p.* = 0; return 0; }

fn envOwned(name: []const u8) ?[]u8 {
    return std.process.getEnvVarOwned(std.heap.page_allocator, name) catch null;
}

pub export fn sa_node_plugin_os_homedir(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (envOwned("USERPROFILE")) |value| return writeOwned(out_ptr, out_len, value);
    return writeOwned(out_ptr, out_len, "C:\\");
}
pub export fn sa_node_plugin_os_tmpdir(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (envOwned("TEMP")) |value| return writeOwned(out_ptr, out_len, value);
    if (envOwned("TMP")) |value| return writeOwned(out_ptr, out_len, value);
    return writeOwned(out_ptr, out_len, "C:\\Windows\\Temp");
}
pub export fn sa_node_plugin_os_hostname(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (envOwned("COMPUTERNAME")) |value| return writeOwned(out_ptr, out_len, value);
    return writeOwned(out_ptr, out_len, "windows");
}
pub export fn sa_node_plugin_os_user_info(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, "{\"uid\":0,\"gid\":0,\"username\":\"\",\"homedir\":\"\",\"shell\":\"\"}");
}
pub export fn sa_node_plugin_os_system_uptime(out_uptime: ?*u64) u32 { if (out_uptime) |p| p.* = 0; return 0; }
pub export fn sa_node_plugin_os_loadavg(out_load: ?*f64) u32 { if (out_load) |p| { const values: [*]f64 = @ptrCast(p); values[0] = 0; values[1] = 0; values[2] = 0; } return 0; }

pub export fn sa_node_plugin_process_hrtime_bigint(out_ns: ?*u64) u32 { if (out_ns) |p| p.* = @intCast(std.time.nanoTimestamp()); return 0; }
pub export fn sa_node_plugin_process_pid(out_pid: ?*u64) u32 { if (out_pid) |p| p.* = std.os.windows.GetCurrentProcessId(); return 0; }
pub export fn sa_node_plugin_process_ppid(out_pid: ?*u64) u32 { if (out_pid) |p| p.* = 0; return 0; }
pub export fn sa_node_plugin_process_getuid(out_uid: ?*u64) u32 { if (out_uid) |p| p.* = 0; return 0; }
pub export fn sa_node_plugin_process_getgid(out_gid: ?*u64) u32 { if (out_gid) |p| p.* = 0; return 0; }
pub export fn sa_node_plugin_process_geteuid(out_uid: ?*u64) u32 { if (out_uid) |p| p.* = 0; return 0; }
pub export fn sa_node_plugin_process_getegid(out_gid: ?*u64) u32 { if (out_gid) |p| p.* = 0; return 0; }
pub export fn sa_node_plugin_process_groups(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_process_cwd(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = std.process.getCwd(&buf) catch return 2;
    return writeOwned(out_ptr, out_len, cwd);
}
pub export fn sa_node_plugin_process_uptime(out_uptime: ?*u64) u32 { if (out_uptime) |p| p.* = 0; return 0; }
pub export fn sa_node_plugin_process_cpu_usage(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "{\"user\":0,\"system\":0}"); }
pub export fn sa_node_plugin_process_memory_usage(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "{\"rss\":0,\"heapTotal\":0,\"heapUsed\":0,\"external\":0,\"arrayBuffers\":0}"); }
pub export fn sa_node_plugin_process_argv_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_process_version(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "v22.0.0"); }
pub export fn sa_node_plugin_process_versions_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "{\"node\":\"22.0.0\"}"); }

pub export fn sa_node_plugin_process_env_get(key_ptr: ?[*]const u8, key_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const key = (key_ptr orelse return 2)[0..key_len];
    if (envOwned(key)) |value| return writeOwned(out_ptr, out_len, value);
    return 1;
}
pub export fn sa_node_plugin_process_env_set(_: ?[*]const u8, _: u64, _: ?[*]const u8, _: u64) u32 { return 2; }
pub export fn sa_node_plugin_process_env_delete(_: ?[*]const u8, _: u64) u32 { return 2; }

comptime {
    _ = builtin;
}

