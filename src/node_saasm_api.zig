const std = @import("std");
const builtin = @import("builtin");

// --- POSIX/C Signatures ---
extern fn getpid() c_int;
extern fn getppid() c_int;
extern fn getuid() c_uint;
extern fn getgid() c_uint;
extern fn geteuid() c_uint;
extern fn getegid() c_uint;
extern fn getgroups(size: c_int, list: [*]c_uint) c_int;
extern fn sysconf(name: c_int) c_long;
extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern fn unsetenv(name: [*:0]const u8) c_int;
extern fn getsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: ?*anyopaque, optlen: *std.posix.socklen_t) c_int;
extern fn setsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: ?*const anyopaque, optlen: std.posix.socklen_t) c_int;

const struct_sockaddr = extern struct {
    sa_family: u16,
    sa_data: [14]u8,
};
const struct_ifaddrs = extern struct {
    ifa_next: ?*struct_ifaddrs,
    ifa_name: [*:0]const u8,
    ifa_flags: c_uint,
    ifa_addr: ?*struct_sockaddr,
    ifa_netmask: ?*struct_sockaddr,
    ifa_ifu: extern union {
        ifu_broadaddr: ?*struct_sockaddr,
        ifu_dstaddr: ?*struct_sockaddr,
    },
    ifa_data: ?*anyopaque,
};
const InAddr = extern struct {
    s_addr: [4]u8,
};
const IpMreq = extern struct {
    imr_multiaddr: InAddr,
    imr_interface: InAddr,
};
const IpMreqSource = extern struct {
    imr_multiaddr: InAddr,
    imr_interface: InAddr,
    imr_sourceaddr: InAddr,
};
const Ipv6Mreq = extern struct {
    ipv6mr_multiaddr: [16]u8,
    ipv6mr_interface: c_uint,
};
extern fn getifaddrs(ifap: *?*struct_ifaddrs) c_int;
extern fn freeifaddrs(ifa: ?*struct_ifaddrs) void;
extern fn inet_ntop(af: c_int, src: ?*const anyopaque, dst: [*]u8, size: c_uint) ?[*:0]const u8;

// Global process start time for process.uptime()
var process_start_ms: i64 = 0;

fn getProcessStartMs() i64 {
    if (process_start_ms == 0) {
        process_start_ms = std.time.milliTimestamp();
    }
    return process_start_ms;
}

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

// --- Helper: Free Buffer ---
pub export fn sa_node_plugin_free_buffer(ptr: ?[*]const u8, len: u64) u32 {
    if (ptr) |p| {
        const slice = p[0..len];
        std.heap.page_allocator.free(slice);
    }
    return 0;
}

// --- os module ---

pub export fn sa_node_plugin_os_cpus(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = getProcessStartMs(); // ensure initialized
    var model_name: []const u8 = "Intel(R) Xeon(R) CPU @ 2.50GHz";
    const speed: u64 = 2500;

    if (std.fs.openFileAbsolute("/proc/cpuinfo", .{})) |file| {
        defer file.close();
        var buf: [4096]u8 = undefined;
        if (file.readAll(&buf)) |n| {
            const content = buf[0..n];
            var it = std.mem.tokenizeScalar(u8, content, '\n');
            while (it.next()) |line| {
                if (std.mem.startsWith(u8, line, "model name")) {
                    if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
                        model_name = std.mem.trim(u8, line[colon + 1 ..], " \t\r\n");
                        break;
                    }
                }
            }
        } else |_| {}
    } else |_| {}

    var cpus_list = std.ArrayList(struct {
        user: u64,
        nice: u64,
        sys: u64,
        idle: u64,
        irq: u64,
    }).init(std.heap.page_allocator);
    defer cpus_list.deinit();

    if (std.fs.openFileAbsolute("/proc/stat", .{})) |file| {
        defer file.close();
        var buf: [8192]u8 = undefined;
        if (file.readAll(&buf)) |n| {
            const content = buf[0..n];
            var it = std.mem.tokenizeScalar(u8, content, '\n');
            while (it.next()) |line| {
                if (std.mem.startsWith(u8, line, "cpu") and line.len > 3 and std.ascii.isDigit(line[3])) {
                    var token_it = std.mem.tokenizeScalar(u8, line, ' ');
                    _ = token_it.next(); // skip "cpuN"
                    const user_ticks = std.fmt.parseInt(u64, token_it.next() orelse "0", 10) catch 0;
                    const nice_ticks = std.fmt.parseInt(u64, token_it.next() orelse "0", 10) catch 0;
                    const sys_ticks = std.fmt.parseInt(u64, token_it.next() orelse "0", 10) catch 0;
                    const idle_ticks = std.fmt.parseInt(u64, token_it.next() orelse "0", 10) catch 0;
                    const irq_ticks = std.fmt.parseInt(u64, token_it.next() orelse "0", 10) catch 0;

                    cpus_list.append(.{
                        .user = user_ticks * 10,
                        .nice = nice_ticks * 10,
                        .sys = sys_ticks * 10,
                        .idle = idle_ticks * 10,
                        .irq = irq_ticks * 10,
                    }) catch {};
                }
            }
        } else |_| {}
    } else |_| {}

    if (cpus_list.items.len == 0) {
        cpus_list.append(.{ .user = 100, .nice = 0, .sys = 50, .idle = 1000, .irq = 0 }) catch {};
    }

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    defer json.deinit();

    json.appendSlice("[") catch return 2;
    for (cpus_list.items, 0..) |cpu, idx| {
        if (idx > 0) json.appendSlice(",") catch return 2;
        var item_buf: [512]u8 = undefined;
        const item = std.fmt.bufPrint(&item_buf, "{{\"model\":\"{s}\",\"speed\":{d},\"times\":{{\"user\":{d},\"nice\":{d},\"sys\":{d},\"idle\":{d},\"irq\":{d}}}}}", .{ model_name, speed, cpu.user, cpu.nice, cpu.sys, cpu.idle, cpu.irq }) catch return 2;
        json.appendSlice(item) catch return 2;
    }
    json.appendSlice("]") catch return 2;

    const owned = std.heap.page_allocator.dupe(u8, json.items) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

fn parseMemInfo(key: []const u8) u64 {
    var file = std.fs.openFileAbsolute("/proc/meminfo", .{}) catch return 0;
    defer file.close();
    var buf: [2048]u8 = undefined;
    const n = file.readAll(&buf) catch return 0;
    const content = buf[0..n];

    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, key)) {
            var line_it = std.mem.tokenizeAny(u8, line, " \t:");
            _ = line_it.next(); // skip key
            const val_str = line_it.next() orelse continue;
            const val = std.fmt.parseInt(u64, val_str, 10) catch continue;
            return val * 1024; // KB to Bytes
        }
    }
    return 0;
}

pub export fn sa_node_plugin_os_totalmem(out_mem: ?*u64) u32 {
    out_mem.?.* = parseMemInfo("MemTotal");
    return 0;
}

pub export fn sa_node_plugin_os_freemem(out_mem: ?*u64) u32 {
    out_mem.?.* = parseMemInfo("MemFree");
    return 0;
}

pub export fn sa_node_plugin_os_homedir(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const home = std.posix.getenv("HOME") orelse "/home/vscode";
    const owned = std.heap.page_allocator.dupe(u8, home) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_os_tmpdir(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const tmp = std.posix.getenv("TMPDIR") orelse (std.posix.getenv("TMP") orelse (std.posix.getenv("TEMP") orelse "/tmp"));
    const owned = std.heap.page_allocator.dupe(u8, tmp) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_os_platform(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const plat = "linux";
    const owned = std.heap.page_allocator.dupe(u8, plat) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_os_arch(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const arch = "x64";
    const owned = std.heap.page_allocator.dupe(u8, arch) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_os_release(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const uname = std.posix.uname();
    const release = std.mem.sliceTo(&uname.release, 0);
    const owned = std.heap.page_allocator.dupe(u8, release) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_os_type(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const ostype = "Linux";
    const owned = std.heap.page_allocator.dupe(u8, ostype) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_os_system_uptime(out_uptime: ?*u64) u32 {
    var file = std.fs.openFileAbsolute("/proc/uptime", .{}) catch return 2;
    defer file.close();
    var buf: [64]u8 = undefined;
    const n = file.readAll(&buf) catch return 2;
    const content = buf[0..n];
    const space_idx = std.mem.indexOfScalar(u8, content, ' ') orelse content.len;
    const uptime_str = std.mem.trim(u8, content[0..space_idx], " \t\r\n");
    const uptime_f = std.fmt.parseFloat(f64, uptime_str) catch return 2;
    out_uptime.?.* = @as(u64, @intFromFloat(uptime_f));
    return 0;
}

pub export fn sa_node_plugin_os_loadavg(out_load: ?*f64) u32 {
    var file = std.fs.openFileAbsolute("/proc/loadavg", .{}) catch return 2;
    defer file.close();
    var buf: [64]u8 = undefined;
    const n = file.readAll(&buf) catch return 2;
    const content = buf[0..n];
    var it = std.mem.tokenizeScalar(u8, content, ' ');
    const l1_str = it.next() orelse return 2;
    const l2_str = it.next() orelse return 2;
    const l3_str = it.next() orelse return 2;
    const l1 = std.fmt.parseFloat(f64, l1_str) catch return 2;
    const l2 = std.fmt.parseFloat(f64, l2_str) catch return 2;
    const l3 = std.fmt.parseFloat(f64, l3_str) catch return 2;

    const dest: [*]f64 = @ptrCast(out_load.?);
    dest[0] = l1;
    dest[1] = l2;
    dest[2] = l3;
    return 0;
}

pub export fn sa_node_plugin_os_network_interfaces(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var ifap: ?*struct_ifaddrs = null;
    if (getifaddrs(&ifap) != 0) return 2;
    defer freeifaddrs(ifap);

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    defer json.deinit();

    json.appendSlice("{") catch return 2;
    var curr = ifap;
    var first_if = true;
    while (curr) |ifa| : (curr = ifa.ifa_next) {
        if (ifa.ifa_addr == null) continue;
        const family = ifa.ifa_addr.?.sa_family;
        if (family != 2 and family != 10) continue; // AF_INET (2) or AF_INET6 (10)

        const ifname = std.mem.span(ifa.ifa_name);

        var ip_buf: [46]u8 = undefined;
        var ip_str: []const u8 = "";

        if (family == 2) { // AF_INET
            const addr: *const std.posix.sockaddr.in = @ptrCast(@alignCast(ifa.ifa_addr.?));
            const ret = inet_ntop(2, &addr.addr, &ip_buf, ip_buf.len) orelse continue;
            ip_str = std.mem.span(ret);
        } else { // AF_INET6
            const addr: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(ifa.ifa_addr.?));
            const ret = inet_ntop(10, &addr.addr, &ip_buf, ip_buf.len) orelse continue;
            ip_str = std.mem.span(ret);
        }

        var net_buf: [46]u8 = undefined;
        var net_str: []const u8 = "255.255.255.0";
        if (ifa.ifa_netmask) |mask| {
            if (family == 2) {
                const addr: *const std.posix.sockaddr.in = @ptrCast(@alignCast(mask));
                if (inet_ntop(2, &addr.addr, &net_buf, net_buf.len)) |ret| net_str = std.mem.span(ret);
            } else {
                const addr: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(mask));
                if (inet_ntop(10, &addr.addr, &net_buf, net_buf.len)) |ret| net_str = std.mem.span(ret);
            }
        }

        const is_internal = std.mem.eql(u8, ifname, "lo");

        if (!first_if) json.appendSlice(",") catch return 2;
        first_if = false;

        var details_buf: [512]u8 = undefined;
        const details = std.fmt.bufPrint(&details_buf, "\"{s}\":[{{\"address\":\"{s}\",\"netmask\":\"{s}\",\"family\":\"{s}\",\"internal\":{s}}}]", .{ ifname, ip_str, net_str, if (family == 2) "IPv4" else "IPv6", if (is_internal) "true" else "false" }) catch return 2;
        json.appendSlice(details) catch return 2;
    }
    json.appendSlice("}") catch return 2;

    const owned = std.heap.page_allocator.dupe(u8, json.items) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_os_hostname(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const uname = std.posix.uname();
    const nodename = std.mem.sliceTo(&uname.nodename, 0);
    const owned = std.heap.page_allocator.dupe(u8, nodename) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_os_user_info(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const uid = getuid();
    const gid = getgid();
    const user = std.posix.getenv("USER") orelse "vscode";
    const home = std.posix.getenv("HOME") orelse "/home/vscode";
    const shell = std.posix.getenv("SHELL") orelse "/bin/bash";

    var out_buf: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&out_buf, "{{\"uid\":{d},\"gid\":{d},\"username\":\"{s}\",\"homedir\":\"{s}\",\"shell\":\"{s}\"}}", .{ uid, gid, user, home, shell }) catch return 2;

    const owned = std.heap.page_allocator.dupe(u8, json) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

// --- process module ---

pub export fn sa_node_plugin_process_hrtime_bigint(out_ns: ?*u64) u32 {
    const ts = std.posix.clock_gettime(.MONOTONIC) catch {
        out_ns.?.* = @as(u64, @intCast(std.time.nanoTimestamp()));
        return 0;
    };
    out_ns.?.* = @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
    return 0;
}

pub export fn sa_node_plugin_process_cpu_usage(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var user_us: u64 = 0;
    var system_us: u64 = 0;

    if (std.fs.openFileAbsolute("/proc/self/stat", .{})) |file| {
        defer file.close();
        var buf: [1024]u8 = undefined;
        if (file.readAll(&buf)) |n| {
            const content = buf[0..n];
            var it = std.mem.tokenizeScalar(u8, content, ' ');
            var field_idx: usize = 1;
            while (it.next()) |field| : (field_idx += 1) {
                if (field_idx == 14) { // utime
                    const utime_ticks = std.fmt.parseInt(u64, field, 10) catch 0;
                    user_us = utime_ticks * 10000;
                } else if (field_idx == 15) { // stime
                    const stime_ticks = std.fmt.parseInt(u64, field, 10) catch 0;
                    system_us = stime_ticks * 10000;
                    break;
                }
            }
        } else |_| {}
    } else |_| {}

    var out_buf: [128]u8 = undefined;
    const json = std.fmt.bufPrint(&out_buf, "{{\"user\":{d},\"system\":{d}}}", .{ user_us, system_us }) catch return 2;
    const owned = std.heap.page_allocator.dupe(u8, json) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_process_memory_usage(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var rss: u64 = 0;

    if (std.fs.openFileAbsolute("/proc/self/statm", .{})) |file| {
        defer file.close();
        var buf: [128]u8 = undefined;
        if (file.readAll(&buf)) |n| {
            const content = buf[0..n];
            var it = std.mem.tokenizeScalar(u8, content, ' ');
            _ = it.next();
            const resident_pages = std.fmt.parseInt(u64, it.next() orelse "0", 10) catch 0;
            rss = resident_pages * 4096;
        } else |_| {}
    } else |_| {}

    if (rss == 0) {
        rss = 32 * 1024 * 1024;
    }

    var out_buf: [256]u8 = undefined;
    const json = std.fmt.bufPrint(&out_buf, "{{\"rss\":{d},\"heapTotal\":{d},\"heapUsed\":{d},\"external\":0}}", .{ rss, rss, rss }) catch return 2;
    const owned = std.heap.page_allocator.dupe(u8, json) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_process_cwd(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var buf: [1024]u8 = undefined;
    const cwd = std.posix.getcwd(&buf) catch "/home/vscode";
    const owned = std.heap.page_allocator.dupe(u8, cwd) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_process_uptime(out_uptime: ?*f64) u32 {
    const start = getProcessStartMs();
    const current = std.time.milliTimestamp();
    const diff_ms = @as(f64, @floatFromInt(current - start));
    out_uptime.?.* = diff_ms / 1000.0;
    return 0;
}

pub export fn sa_node_plugin_process_argv_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var file = std.fs.openFileAbsolute("/proc/self/cmdline", .{}) catch return 2;
    defer file.close();
    var buf: [4096]u8 = undefined;
    const n = file.readAll(&buf) catch return 2;
    const content = buf[0..n];

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    defer json.deinit();

    json.appendSlice("[") catch return 2;
    var it = std.mem.splitScalar(u8, content, '\x00');
    var first = true;
    while (it.next()) |arg| {
        if (arg.len == 0) continue;
        if (!first) json.appendSlice(",") catch return 2;
        first = false;

        json.appendSlice("\"") catch return 2;
        // Escape quotes
        for (arg) |c| {
            if (c == '"' or c == '\\') {
                json.appendSlice("\\") catch return 2;
            }
            json.append(c) catch return 2;
        }
        json.appendSlice("\"") catch return 2;
    }
    json.appendSlice("]") catch return 2;

    const owned = std.heap.page_allocator.dupe(u8, json.items) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_process_geteuid(out_uid: ?*u32) u32 {
    out_uid.?.* = geteuid();
    return 0;
}

pub export fn sa_node_plugin_process_getegid(out_gid: ?*u32) u32 {
    out_gid.?.* = getegid();
    return 0;
}

pub export fn sa_node_plugin_process_groups(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var list: [128]c_uint = undefined;
    const n = getgroups(list.len, &list);
    if (n < 0) return 2;

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    defer json.deinit();

    json.appendSlice("[") catch return 2;
    var i: usize = 0;
    while (i < @as(usize, @intCast(n))) : (i += 1) {
        if (i > 0) json.appendSlice(",") catch return 2;
        var num_buf: [32]u8 = undefined;
        const num = std.fmt.bufPrint(&num_buf, "{d}", .{list[i]}) catch return 2;
        json.appendSlice(num) catch return 2;
    }
    json.appendSlice("]") catch return 2;

    const owned = std.heap.page_allocator.dupe(u8, json.items) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

// --- path module ---

const SaSlice = extern struct {
    ptr: [*]const u8,
    len: u64,
};

pub export fn sa_node_plugin_path_join(paths_argv: ?*const anyopaque, paths_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (paths_len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, ".") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }

    const slices: [*]const SaSlice = @ptrCast(@alignCast(paths_argv.?));
    var list = std.ArrayList([]const u8).init(std.heap.page_allocator);
    defer list.deinit();

    var i: usize = 0;
    while (i < paths_len) : (i += 1) {
        const slice = slices[i].ptr[0..slices[i].len];
        list.append(slice) catch return 2;
    }

    const joined = std.fs.path.join(std.heap.page_allocator, list.items) catch return 2;
    out_ptr.?.* = joined.ptr;
    out_len.?.* = joined.len;
    return 0;
}

pub export fn sa_node_plugin_path_resolve(paths_argv: ?*const anyopaque, paths_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (paths_len == 0) {
        var buf: [1024]u8 = undefined;
        const cwd = std.posix.getcwd(&buf) catch ".";
        const owned = std.heap.page_allocator.dupe(u8, cwd) catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }

    const slices: [*]const SaSlice = @ptrCast(@alignCast(paths_argv.?));
    var list = std.ArrayList([]const u8).init(std.heap.page_allocator);
    defer list.deinit();

    var i: usize = 0;
    while (i < paths_len) : (i += 1) {
        const slice = slices[i].ptr[0..slices[i].len];
        list.append(slice) catch return 2;
    }

    const resolved = std.fs.path.resolve(std.heap.page_allocator, list.items) catch return 2;
    out_ptr.?.* = resolved.ptr;
    out_len.?.* = resolved.len;
    return 0;
}

pub export fn sa_node_plugin_path_normalize(path: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const slice = path.?[0..len];
    // std.fs.path.resolve is used to normalize/clean paths as standard path.clean is not exposed directly
    const resolved = std.fs.path.resolve(std.heap.page_allocator, &.{slice}) catch return 2;
    out_ptr.?.* = resolved.ptr;
    out_len.?.* = resolved.len;
    return 0;
}

pub export fn sa_node_plugin_path_basename(path: ?[*]const u8, len: u64, ext: ?[*]const u8, ext_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const slice = path.?[0..len];
    var base = std.fs.path.basename(slice);
    if (ext_len > 0 and std.mem.endsWith(u8, base, ext.?[0..ext_len])) {
        base = base[0 .. base.len - ext_len];
    }
    const owned = std.heap.page_allocator.dupe(u8, base) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_path_dirname(path: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const slice = path.?[0..len];
    const dir = std.fs.path.dirname(slice) orelse ".";
    const owned = std.heap.page_allocator.dupe(u8, dir) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_path_extname(path: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const slice = path.?[0..len];
    const ext = std.fs.path.extension(slice);
    const owned = std.heap.page_allocator.dupe(u8, ext) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_path_is_absolute(path: ?[*]const u8, len: u64, out_bool: ?*u64) u32 {
    const slice = path.?[0..len];
    const is_abs = std.fs.path.isAbsolute(slice);
    out_bool.?.* = if (is_abs) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_path_to_namespaced_path(path: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const slice = if (len == 0) "" else (path orelse return 2)[0..len];
    const owned = std.heap.page_allocator.dupe(u8, slice) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

// --- crypto module ---

pub export fn sa_node_plugin_crypto_random_bytes(size: u64, out_ptr: ?*?[*]const u8) u32 {
    const buf = std.heap.page_allocator.alloc(u8, size) catch return 2;
    std.crypto.random.bytes(buf);
    out_ptr.?.* = buf.ptr;
    return 0;
}

pub export fn sa_node_plugin_crypto_hash(algo: ?[*]const u8, algo_len: u64, data: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const a = algo.?[0..algo_len];
    const d = data.?[0..data_len];

    var hash_buf: [64]u8 = undefined;
    var hash_len: usize = 0;

    if (std.mem.eql(u8, a, "sha256") or std.mem.eql(u8, a, "SHA256")) {
        hash_len = 32;
        std.crypto.hash.sha2.Sha256.hash(d, hash_buf[0..32], .{});
    } else if (std.mem.eql(u8, a, "sha512") or std.mem.eql(u8, a, "SHA512")) {
        hash_len = 64;
        std.crypto.hash.sha2.Sha512.hash(d, hash_buf[0..64], .{});
    } else if (std.mem.eql(u8, a, "sha1") or std.mem.eql(u8, a, "SHA1")) {
        hash_len = 20;
        std.crypto.hash.Sha1.hash(d, hash_buf[0..20], .{});
    } else if (std.mem.eql(u8, a, "md5") or std.mem.eql(u8, a, "MD5")) {
        hash_len = 16;
        std.crypto.hash.Md5.hash(d, hash_buf[0..16], .{});
    } else {
        return 2; // unsupported algorithm
    }

    var hex_buf: [128]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(hash_buf[0..hash_len])}) catch return 2;
    const owned = std.heap.page_allocator.dupe(u8, hex) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_crypto_pbkdf2(pass: ?[*]const u8, pass_len: u64, salt: ?[*]const u8, salt_len: u64, iter: u64, keylen: u64, digest: ?[*]const u8, digest_len: u64, out_ptr: ?*?[*]const u8) u32 {
    const p = pass.?[0..pass_len];
    const s = salt.?[0..salt_len];
    _ = digest;
    _ = digest_len; // we always use HMAC-SHA256 for compatibility

    const key = std.heap.page_allocator.alloc(u8, keylen) catch return 2;
    errdefer std.heap.page_allocator.free(key);

    std.crypto.pwhash.pbkdf2(key, p, s, @as(u32, @intCast(iter)), std.crypto.auth.hmac.sha2.HmacSha256) catch return 2;
    out_ptr.?.* = key.ptr;
    return 0;
}

// --- zlib module ---

pub export fn sa_node_plugin_zlib_gzip(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const d = data.?[0..len];
    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();

    var compressor = std.compress.gzip.compressor(out_list.writer(), .{}) catch return 2;
    compressor.writer().writeAll(d) catch return 2;
    compressor.finish() catch return 2;

    const slice = out_list.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_zlib_gunzip(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const d = data.?[0..len];
    var in_stream = std.io.fixedBufferStream(d);
    var decompressor = std.compress.gzip.decompressor(in_stream.reader());

    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();

    var temp_buf: [1024]u8 = undefined;
    while (true) {
        const bytes_read = decompressor.read(&temp_buf) catch return 2;
        if (bytes_read == 0) break;
        out_list.appendSlice(temp_buf[0..bytes_read]) catch return 2;
    }

    const slice = out_list.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

// --- New core FFI extensions ---

pub export fn sa_node_plugin_os_endianness(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const end = if (builtin.target.cpu.arch.endian() == .little) "LE" else "BE";
    const owned = std.heap.page_allocator.dupe(u8, end) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_process_pid(out_pid: ?*u32) u32 {
    out_pid.?.* = @as(u32, @intCast(getpid()));
    return 0;
}

pub export fn sa_node_plugin_process_ppid(out_ppid: ?*u32) u32 {
    out_ppid.?.* = @as(u32, @intCast(getppid()));
    return 0;
}

pub export fn sa_node_plugin_process_getuid(out_uid: ?*u32) u32 {
    out_uid.?.* = getuid();
    return 0;
}

pub export fn sa_node_plugin_process_getgid(out_gid: ?*u32) u32 {
    out_gid.?.* = getgid();
    return 0;
}

pub export fn sa_node_plugin_process_env_get(key_ptr: ?[*]const u8, key_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (key_ptr == null or key_len == 0) return 2;
    const key = key_ptr.?[0..key_len];
    const key_z = std.heap.page_allocator.dupeZ(u8, key) catch return 2;
    defer std.heap.page_allocator.free(key_z);

    const value = getenv(key_z.ptr) orelse return 1; // 1 means null/not found
    const val_slice = std.mem.span(value);
    const owned = std.heap.page_allocator.dupe(u8, val_slice) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_process_env_set(key_ptr: ?[*]const u8, key_len: u64, val_ptr: ?[*]const u8, val_len: u64) u32 {
    if (key_ptr == null or key_len == 0) return 2;
    const key = key_ptr.?[0..key_len];
    const value = if (val_ptr) |p| p[0..val_len] else &[_]u8{};

    const key_z = std.heap.page_allocator.dupeZ(u8, key) catch return 2;
    defer std.heap.page_allocator.free(key_z);
    const val_z = std.heap.page_allocator.dupeZ(u8, value) catch return 2;
    defer std.heap.page_allocator.free(val_z);

    if (setenv(key_z.ptr, val_z.ptr, 1) != 0) return 2;
    return 0;
}

pub export fn sa_node_plugin_process_env_delete(key_ptr: ?[*]const u8, key_len: u64) u32 {
    if (key_ptr == null or key_len == 0) return 2;
    const key = key_ptr.?[0..key_len];
    const key_z = std.heap.page_allocator.dupeZ(u8, key) catch return 2;
    defer std.heap.page_allocator.free(key_z);

    if (unsetenv(key_z.ptr) != 0) return 2;
    return 0;
}

pub export fn sa_node_plugin_process_version(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const ver = "v20.11.1";
    const owned = std.heap.page_allocator.dupe(u8, ver) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_process_versions_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const versions = "{\"node\":\"20.11.1\",\"v8\":\"11.3.244.8-node.17\",\"uv\":\"1.46.0\",\"zlib\":\"1.3\",\"brotli\":\"1.0.9\",\"modules\":\"115\",\"napi\":\"9\",\"openssl\":\"3.0.12+quic\"}";
    const owned = std.heap.page_allocator.dupe(u8, versions) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

// --- Phase 2 Extensions: querystring, url, util, punycode ---

pub export fn sa_node_plugin_querystring_escape(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (data == null or len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const d = data.?[0..len];
    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();

    const hex_chars = "0123456789ABCDEF";
    for (d) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~') {
            out_list.append(c) catch return 2;
        } else {
            out_list.append('%') catch return 2;
            out_list.append(hex_chars[c >> 4]) catch return 2;
            out_list.append(hex_chars[c & 0x0F]) catch return 2;
        }
    }

    const slice = out_list.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_querystring_unescape(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (data == null or len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const d = data.?[0..len];
    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();

    var i: usize = 0;
    while (i < len) {
        const c = d[i];
        if (c == '%' and i + 2 < len) {
            const h1 = std.fmt.charToDigit(d[i + 1], 16) catch {
                out_list.append(c) catch return 2;
                i += 1;
                continue;
            };
            const h2 = std.fmt.charToDigit(d[i + 2], 16) catch {
                out_list.append(c) catch return 2;
                i += 1;
                continue;
            };
            const decoded = @as(u8, @intCast((h1 << 4) | h2));
            out_list.append(decoded) catch return 2;
            i += 3;
        } else if (c == '+') {
            out_list.append(' ') catch return 2;
            i += 1;
        } else {
            out_list.append(c) catch return 2;
            i += 1;
        }
    }

    const slice = out_list.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_querystring_parse(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (data == null or len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "{}") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const d = data.?[0..len];
    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();

    json.append('{') catch return 2;

    var first = true;
    var it = std.mem.tokenizeScalar(u8, d, '&');
    while (it.next()) |pair| {
        var pair_it = std.mem.splitScalar(u8, pair, '=');
        const raw_k = pair_it.next() orelse continue;
        const raw_v = pair_it.next() orelse "";

        // Unescape key
        var un_k_ptr: ?[*]const u8 = null;
        var un_k_len: u64 = 0;
        _ = sa_node_plugin_querystring_unescape(raw_k.ptr, raw_k.len, &un_k_ptr, &un_k_len);
        defer _ = sa_node_plugin_free_buffer(un_k_ptr, un_k_len);

        // Unescape val
        var un_v_ptr: ?[*]const u8 = null;
        var un_v_len: u64 = 0;
        _ = sa_node_plugin_querystring_unescape(raw_v.ptr, raw_v.len, &un_v_ptr, &un_v_len);
        defer _ = sa_node_plugin_free_buffer(un_v_ptr, un_v_len);

        const k_slice = un_k_ptr.?[0..un_k_len];
        const v_slice = un_v_ptr.?[0..un_v_len];

        if (!first) json.append(',') catch return 2;
        first = false;

        // Escape JSON quotes
        json.append('"') catch return 2;
        for (k_slice) |c| {
            if (c == '"' or c == '\\') json.append('\\') catch return 2;
            json.append(c) catch return 2;
        }
        json.appendSlice("\":\"") catch return 2;
        for (v_slice) |c| {
            if (c == '"' or c == '\\') json.append('\\') catch return 2;
            json.append(c) catch return 2;
        }
        json.append('"') catch return 2;
    }

    json.append('}') catch return 2;

    const slice = json.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_querystring_stringify(json_ptr: ?[*]const u8, json_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (json_ptr == null or json_len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const js = json_ptr.?[0..json_len];
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, js, .{}) catch return 2;
    defer parsed.deinit();

    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();

    switch (parsed.value) {
        .object => |obj| {
            var first = true;
            var it = obj.iterator();
            while (it.next()) |entry| {
                const k = entry.key_ptr.*;
                const v = entry.value_ptr.*;

                var v_buf: [128]u8 = undefined;
                const v_str: []const u8 = switch (v) {
                    .string => |s| s,
                    .integer => |i| std.fmt.bufPrint(&v_buf, "{d}", .{i}) catch "",
                    .float => |f| std.fmt.bufPrint(&v_buf, "{d}", .{f}) catch "",
                    .bool => |b| if (b) "true" else "false",
                    .null => "null",
                    else => "",
                };

                var esc_k_ptr: ?[*]const u8 = null;
                var esc_k_len: u64 = 0;
                _ = sa_node_plugin_querystring_escape(k.ptr, k.len, &esc_k_ptr, &esc_k_len);
                defer _ = sa_node_plugin_free_buffer(esc_k_ptr, esc_k_len);

                var esc_v_ptr: ?[*]const u8 = null;
                var esc_v_len: u64 = 0;
                _ = sa_node_plugin_querystring_escape(v_str.ptr, v_str.len, &esc_v_ptr, &esc_v_len);
                defer _ = sa_node_plugin_free_buffer(esc_v_ptr, esc_v_len);

                if (!first) out_list.append('&') catch return 2;
                first = false;

                out_list.appendSlice(esc_k_ptr.?[0..esc_k_len]) catch return 2;
                out_list.append('=') catch return 2;
                out_list.appendSlice(esc_v_ptr.?[0..esc_v_len]) catch return 2;
            }
        },
        else => return 2,
    }

    const slice = out_list.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_url_parse(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (data == null or len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "{}") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const raw = data.?[0..len];

    var protocol: []const u8 = "";
    var auth: []const u8 = "";
    var host: []const u8 = "";
    var hostname: []const u8 = "";
    var port: []const u8 = "";
    var pathname: []const u8 = "";
    var search: []const u8 = "";
    var hash: []const u8 = "";

    var rest = raw;

    // Parse protocol
    if (std.mem.indexOf(u8, rest, "://")) |idx| {
        protocol = rest[0 .. idx + 1]; // "http:"
        rest = rest[idx + 3 ..];
    } else if (std.mem.indexOfScalar(u8, rest, ':')) |idx| {
        // Mailto, file, etc.
        var is_proto = true;
        for (rest[0..idx]) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-' and c != '.') {
                is_proto = false;
                break;
            }
        }
        if (is_proto) {
            protocol = rest[0 .. idx + 1];
            rest = rest[idx + 1 ..];
        }
    }

    // Parse hash
    if (std.mem.indexOfScalar(u8, rest, '#')) |idx| {
        hash = rest[idx..];
        rest = rest[0..idx];
    }

    // Parse search
    if (std.mem.indexOfScalar(u8, rest, '?')) |idx| {
        search = rest[idx..];
        rest = rest[0..idx];
    }

    // Parse pathname & host
    if (rest.len > 0) {
        if (rest[0] == '/') {
            pathname = rest;
        } else {
            if (std.mem.indexOfScalar(u8, rest, '/')) |idx| {
                host = rest[0..idx];
                pathname = rest[idx..];
            } else {
                host = rest;
                pathname = "/";
            }
        }
    }

    // Parse auth & hostname from host
    if (host.len > 0) {
        if (std.mem.indexOfScalar(u8, host, '@')) |idx| {
            auth = host[0..idx];
            host = host[idx + 1 ..];
        }
        if (std.mem.indexOfScalar(u8, host, ':')) |idx| {
            hostname = host[0..idx];
            port = host[idx + 1 ..];
        } else {
            hostname = host;
        }
    }

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();

    json.appendSlice("{\"protocol\":") catch return 2;
    std.json.stringify(protocol, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"auth\":") catch return 2;
    std.json.stringify(auth, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"host\":") catch return 2;
    std.json.stringify(host, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"hostname\":") catch return 2;
    std.json.stringify(hostname, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"port\":") catch return 2;
    std.json.stringify(port, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"pathname\":") catch return 2;
    std.json.stringify(pathname, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"search\":") catch return 2;
    std.json.stringify(search, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"hash\":") catch return 2;
    std.json.stringify(hash, .{}, json.writer()) catch return 2;
    json.append('}') catch return 2;

    const slice = json.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_url_format(json_ptr: ?[*]const u8, json_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (json_ptr == null or json_len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const js = json_ptr.?[0..json_len];
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, js, .{}) catch return 2;
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();

    switch (parsed.value) {
        .object => |obj| {
            const protocol = if (obj.get("protocol")) |p| p.string else "";
            const auth = if (obj.get("auth")) |a| a.string else "";
            const host = if (obj.get("host")) |h| h.string else "";
            const hostname = if (obj.get("hostname")) |hn| hn.string else "";
            const port = if (obj.get("port")) |prt| prt.string else "";
            const pathname = if (obj.get("pathname")) |pt| pt.string else "";
            const search = if (obj.get("search")) |s| s.string else "";
            const hash = if (obj.get("hash")) |hsh| hsh.string else "";

            if (protocol.len > 0) out.appendSlice(protocol) catch return 2;

            if (protocol.len > 0 and (std.mem.eql(u8, protocol, "http:") or std.mem.eql(u8, protocol, "https:") or std.mem.eql(u8, protocol, "ftp:"))) {
                out.appendSlice("//") catch return 2;
            }

            if (auth.len > 0) {
                out.appendSlice(auth) catch return 2;
                out.append('@') catch return 2;
            }

            if (host.len > 0) {
                out.appendSlice(host) catch return 2;
            } else if (hostname.len > 0) {
                out.appendSlice(hostname) catch return 2;
                if (port.len > 0) {
                    out.append(':') catch return 2;
                    out.appendSlice(port) catch return 2;
                }
            }

            if (pathname.len > 0) {
                out.appendSlice(pathname) catch return 2;
            }
            if (search.len > 0) {
                out.appendSlice(search) catch return 2;
            }
            if (hash.len > 0) {
                out.appendSlice(hash) catch return 2;
            }
        },
        else => return 2,
    }

    const slice = out.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_url_resolve(from_ptr: ?[*]const u8, from_len: u64, to_ptr: ?[*]const u8, to_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const from = if (from_ptr) |p| p[0..from_len] else &[_]u8{};
    const to = if (to_ptr) |p| p[0..to_len] else &[_]u8{};

    if (std.mem.indexOf(u8, to, "://") != null) {
        const owned = std.heap.page_allocator.dupe(u8, to) catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }

    var from_js_ptr: ?[*]const u8 = null;
    var from_js_len: u64 = 0;
    _ = sa_node_plugin_url_parse(from.ptr, from.len, &from_js_ptr, &from_js_len);
    defer _ = sa_node_plugin_free_buffer(from_js_ptr, from_js_len);

    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, from_js_ptr.?[0..from_js_len], .{}) catch return 2;
    defer parsed.deinit();

    const obj = parsed.value.object;
    const protocol = obj.get("protocol").?.string;
    const auth = obj.get("auth").?.string;
    const host = obj.get("host").?.string;
    const pathname = obj.get("pathname").?.string;

    var new_path = std.ArrayList(u8).init(std.heap.page_allocator);
    defer new_path.deinit();

    if (to.len > 0 and to[0] == '/') {
        new_path.appendSlice(to) catch return 2;
    } else {
        const last_slash = std.mem.lastIndexOfScalar(u8, pathname, '/');
        if (last_slash) |idx| {
            new_path.appendSlice(pathname[0 .. idx + 1]) catch return 2;
        } else {
            new_path.append('/') catch return 2;
        }
        new_path.appendSlice(to) catch return 2;
    }

    const resolved_path = std.fs.path.resolve(std.heap.page_allocator, &.{new_path.items}) catch return 2;
    defer std.heap.page_allocator.free(resolved_path);

    var res = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer res.deinit();

    if (protocol.len > 0) res.appendSlice(protocol) catch return 2;
    if (protocol.len > 0 and (std.mem.eql(u8, protocol, "http:") or std.mem.eql(u8, protocol, "https:"))) {
        res.appendSlice("//") catch return 2;
    }
    if (auth.len > 0) {
        res.appendSlice(auth) catch return 2;
        res.append('@') catch return 2;
    }
    if (host.len > 0) res.appendSlice(host) catch return 2;
    res.appendSlice(resolved_path) catch return 2;

    const slice = res.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_util_format(format_ptr: ?[*]const u8, format_len: u64, args_json_ptr: ?[*]const u8, args_json_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const fmt = if (format_ptr) |p| p[0..format_len] else &[_]u8{};
    const args_js = if (args_json_ptr) |p| p[0..args_json_len] else "[]";

    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, args_js, .{}) catch return 2;
    defer parsed.deinit();

    const args = switch (parsed.value) {
        .array => |arr| arr.items,
        else => &[_]std.json.Value{},
    };

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();

    var arg_idx: usize = 0;
    var i: usize = 0;
    while (i < fmt.len) {
        if (fmt[i] == '%' and i + 1 < fmt.len) {
            const spec = fmt[i + 1];
            if (spec == '%') {
                out.append('%') catch return 2;
                i += 2;
                continue;
            }

            if (arg_idx < args.len) {
                const val = args[arg_idx];
                arg_idx += 1;

                if (spec == 's') {
                    switch (val) {
                        .string => |s| out.appendSlice(s) catch return 2,
                        else => std.json.stringify(val, .{}, out.writer()) catch return 2,
                    }
                } else if (spec == 'd') {
                    var num_buf: [64]u8 = undefined;
                    const num_str = switch (val) {
                        .integer => |iv| std.fmt.bufPrint(&num_buf, "{d}", .{iv}) catch "NaN",
                        .float => |fv| std.fmt.bufPrint(&num_buf, "{d}", .{fv}) catch "NaN",
                        else => "NaN",
                    };
                    out.appendSlice(num_str) catch return 2;
                } else if (spec == 'j') {
                    std.json.stringify(val, .{}, out.writer()) catch return 2;
                } else {
                    out.append('%') catch return 2;
                    out.append(spec) catch return 2;
                }
            } else {
                out.append('%') catch return 2;
                out.append(spec) catch return 2;
            }
            i += 2;
        } else {
            out.append(fmt[i]) catch return 2;
            i += 1;
        }
    }

    while (arg_idx < args.len) : (arg_idx += 1) {
        if (out.items.len > 0) out.append(' ') catch return 2;
        std.json.stringify(args[arg_idx], .{}, out.writer()) catch return 2;
    }

    const slice = out.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_util_inspect(json_ptr: ?[*]const u8, json_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const js = if (json_ptr) |p| p[0..json_len] else "null";
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, js, .{}) catch return 2;
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();

    std.json.stringify(parsed.value, .{ .whitespace = .indent_2 }, out.writer()) catch return 2;

    const slice = out.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

fn adaptBias(delta: u32, num_points: u32, first_time: bool) u32 {
    var d = delta;
    if (first_time) {
        d /= puny_damp;
    } else {
        d /= 2;
    }
    d += d / num_points;
    var k: u32 = 0;
    while (d > ((puny_base - puny_tmin) * puny_tmax) / 2) : (k += puny_base) {
        d /= (puny_base - puny_tmin);
    }
    return k + (((puny_base - puny_tmin + 1) * d) / (d + puny_skew));
}

const puny_base = 36;
const puny_tmin = 1;
const puny_tmax = 26;
const puny_skew = 38;
const puny_damp = 700;
const puny_initial_bias = 72;
const puny_initial_n = 128;

pub export fn sa_node_plugin_punycode_encode(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (data == null or len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const input = data.?[0..len];

    var code_points = std.ArrayList(u32).init(std.heap.page_allocator);
    defer code_points.deinit();

    var utf8_view = std.unicode.Utf8View.init(input) catch return 2;
    var utf8_it = utf8_view.iterator();
    while (utf8_it.nextCodepoint()) |cp| {
        code_points.append(cp) catch return 2;
    }

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();

    for (code_points.items) |cp| {
        if (cp < 128) {
            out.append(@as(u8, @intCast(cp))) catch return 2;
        }
    }

    const basic_len = out.items.len;
    if (basic_len > 0) {
        out.append('-') catch return 2;
    }

    var n: u32 = puny_initial_n;
    var delta: u32 = 0;
    var bias: u32 = puny_initial_bias;
    var h = basic_len;

    while (h < code_points.items.len) {
        var m: u32 = std.math.maxInt(u32);
        for (code_points.items) |cp| {
            if (cp >= n and cp < m) {
                m = cp;
            }
        }

        delta += (m - n) * @as(u32, @intCast(h + 1));
        n = m;

        for (code_points.items) |cp| {
            if (cp < n) {
                delta += 1;
            } else if (cp == n) {
                var q = delta;
                var k: u32 = puny_base;
                while (true) : (k += puny_base) {
                    const t = if (k <= bias + puny_tmin) puny_tmin else (if (k >= bias + puny_tmax) puny_tmax else k - bias);
                    if (q < t) break;
                    const char_val = t + ((q - t) % (puny_base - t));
                    const enc_char: u8 = if (char_val < 26) 'a' + @as(u8, @intCast(char_val)) else '0' + @as(u8, @intCast(char_val - 26));
                    out.append(enc_char) catch return 2;
                    q = (q - t) / (puny_base - t);
                }
                const enc_char: u8 = if (q < 26) 'a' + @as(u8, @intCast(q)) else '0' + @as(u8, @intCast(q - 26));
                out.append(enc_char) catch return 2;
                bias = adaptBias(delta, @as(u32, @intCast(h + 1)), h == basic_len);
                delta = 0;
                h += 1;
            }
        }
        delta += 1;
        n += 1;
    }

    const slice = out.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_punycode_decode(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (data == null or len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const input = data.?[0..len];

    var out_points = std.ArrayList(u32).init(std.heap.page_allocator);
    defer out_points.deinit();

    var basic_len: usize = 0;
    if (std.mem.lastIndexOfScalar(u8, input, '-')) |dash_idx| {
        basic_len = dash_idx;
        for (input[0..dash_idx]) |c| {
            if (c >= 128) return 2;
            out_points.append(c) catch return 2;
        }
    }

    var i: u32 = 0;
    var n: u32 = puny_initial_n;
    var bias: u32 = puny_initial_bias;
    var pos = if (basic_len > 0) basic_len + 1 else 0;

    while (pos < input.len) {
        const old_i = i;
        var w: u32 = 1;
        var k: u32 = puny_base;
        while (true) : (k += puny_base) {
            if (pos >= input.len) return 2;
            const c = input[pos];
            pos += 1;

            const digit: u32 = if (c >= 'a' and c <= 'z') c - 'a' else (if (c >= '0' and c <= '9') c - '0' + 26 else return 2);
            i += digit * w;

            const t = if (k <= bias + puny_tmin) puny_tmin else (if (k >= bias + puny_tmax) puny_tmax else k - bias);
            if (digit < t) break;
            w *= (puny_base - t);
        }

        const out_len_u32 = @as(u32, @intCast(out_points.items.len));
        bias = adaptBias(i - old_i, out_len_u32 + 1, old_i == 0);
        n += i / (out_len_u32 + 1);
        i %= (out_len_u32 + 1);

        out_points.insert(i, n) catch return 2;
        i += 1;
    }

    var out_bytes = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_bytes.deinit();

    for (out_points.items) |cp| {
        var buf: [4]u8 = undefined;
        const n_bytes = std.unicode.utf8Encode(@as(u21, @intCast(cp)), &buf) catch return 2;
        out_bytes.appendSlice(buf[0..n_bytes]) catch return 2;
    }

    const slice = out_bytes.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

// --- Phase 3 Extensions: os, path, util, crypto, zlib, buffer ---

pub export fn sa_node_plugin_os_available_parallelism(out_val: ?*u64) u32 {
    const count = sysconf(84); // _SC_NPROCESSORS_ONLN
    out_val.?.* = if (count > 0) @as(u64, @intCast(count)) else 1;
    return 0;
}

pub export fn sa_node_plugin_os_machine(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const uname = std.posix.uname();
    const machine = std.mem.sliceTo(&uname.machine, 0);
    const owned = std.heap.page_allocator.dupe(u8, machine) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_os_version(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const uname = std.posix.uname();
    const version = std.mem.sliceTo(&uname.version, 0);
    const owned = std.heap.page_allocator.dupe(u8, version) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

fn computeRelative(allocator: std.mem.Allocator, from: []const u8, to: []const u8) ![]const u8 {
    var from_parts = std.ArrayList([]const u8).init(allocator);
    defer from_parts.deinit();
    var to_parts = std.ArrayList([]const u8).init(allocator);
    defer to_parts.deinit();

    var from_it = std.mem.tokenizeScalar(u8, from, '/');
    while (from_it.next()) |part| {
        try from_parts.append(part);
    }
    var to_it = std.mem.tokenizeScalar(u8, to, '/');
    while (to_it.next()) |part| {
        try to_parts.append(part);
    }

    var common_idx: usize = 0;
    while (common_idx < from_parts.items.len and common_idx < to_parts.items.len) : (common_idx += 1) {
        if (!std.mem.eql(u8, from_parts.items[common_idx], to_parts.items[common_idx])) {
            break;
        }
    }

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    const ups = from_parts.items.len - common_idx;
    if (ups == 0 and common_idx == to_parts.items.len) {
        return try allocator.dupe(u8, "");
    }

    var i: usize = 0;
    while (i < ups) : (i += 1) {
        if (i > 0) try result.append('/');
        try result.appendSlice("..");
    }

    var j = common_idx;
    while (j < to_parts.items.len) : (j += 1) {
        if (result.items.len > 0) try result.append('/');
        try result.appendSlice(to_parts.items[j]);
    }

    return result.toOwnedSlice();
}

pub export fn sa_node_plugin_path_relative(from_ptr: ?[*]const u8, from_len: u64, to_ptr: ?[*]const u8, to_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const from = if (from_ptr) |p| p[0..from_len] else &[_]u8{};
    const to = if (to_ptr) |p| p[0..to_len] else &[_]u8{};

    const from_resolved = std.fs.path.resolve(std.heap.page_allocator, &.{from}) catch return 2;
    defer std.heap.page_allocator.free(from_resolved);
    const to_resolved = std.fs.path.resolve(std.heap.page_allocator, &.{to}) catch return 2;
    defer std.heap.page_allocator.free(to_resolved);

    const rel = computeRelative(std.heap.page_allocator, from_resolved, to_resolved) catch return 2;
    out_ptr.?.* = rel.ptr;
    out_len.?.* = rel.len;
    return 0;
}

pub export fn sa_node_plugin_path_format(json_ptr: ?[*]const u8, json_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (json_ptr == null or json_len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const js = json_ptr.?[0..json_len];
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, js, .{}) catch |err| {
        std.debug.print("JSON parse error: {}, string: '{s}', len: {d}\n", .{ err, js, json_len });
        return 2;
    };
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();

    switch (parsed.value) {
        .object => |obj| {
            const root = if (obj.get("root")) |r| r.string else "";
            const dir = if (obj.get("dir")) |d| d.string else "";
            const base = if (obj.get("base")) |b| b.string else "";
            const name = if (obj.get("name")) |n| n.string else "";
            const ext = if (obj.get("ext")) |e| e.string else "";

            if (dir.len > 0) {
                out.appendSlice(dir) catch return 2;
                if (dir[dir.len - 1] != '/') {
                    out.append('/') catch return 2;
                }
            } else if (root.len > 0) {
                out.appendSlice(root) catch return 2;
            }

            if (base.len > 0) {
                out.appendSlice(base) catch return 2;
            } else {
                if (name.len > 0) out.appendSlice(name) catch return 2;
                if (ext.len > 0) out.appendSlice(ext) catch return 2;
            }
        },
        else => return 2,
    }

    const slice = out.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_path_parse(path_ptr: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const path = if (path_ptr) |p| p[0..len] else &[_]u8{};

    const is_abs = std.fs.path.isAbsolute(path);
    const root: []const u8 = if (is_abs) "/" else "";

    const dir = std.fs.path.dirname(path) orelse "";
    const base = std.fs.path.basename(path);
    const ext = std.fs.path.extension(path);
    const name = if (ext.len > 0 and std.mem.endsWith(u8, base, ext)) base[0 .. base.len - ext.len] else base;

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();

    json.appendSlice("{\"root\":") catch return 2;
    std.json.stringify(root, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"dir\":") catch return 2;
    std.json.stringify(dir, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"base\":") catch return 2;
    std.json.stringify(base, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"ext\":") catch return 2;
    std.json.stringify(ext, .{}, json.writer()) catch return 2;
    json.appendSlice(",\"name\":") catch return 2;
    std.json.stringify(name, .{}, json.writer()) catch return 2;
    json.append('}') catch return 2;

    const slice = json.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

fn jsonDeepEqual(a: std.json.Value, b: std.json.Value) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |av| return b == .bool and av == b.bool,
        .integer => |av| {
            if (b == .integer) return av == b.integer;
            if (b == .float) return @as(f64, @floatFromInt(av)) == b.float;
            return false;
        },
        .float => |av| {
            if (b == .float) return av == b.float;
            if (b == .integer) return av == @as(f64, @floatFromInt(b.integer));
            return false;
        },
        .string => |av| return b == .string and std.mem.eql(u8, av, b.string),
        .array => |av| {
            if (b != .array) return false;
            const bv = b.array;
            if (av.items.len != bv.items.len) return false;
            for (av.items, 0..) |item, idx| {
                if (!jsonDeepEqual(item, bv.items[idx])) return false;
            }
            return true;
        },
        .object => |av| {
            if (b != .object) return false;
            const bv = b.object;
            if (av.count() != bv.count()) return false;
            var it = av.iterator();
            while (it.next()) |entry| {
                const key = entry.key_ptr.*;
                const b_val = bv.get(key) orelse return false;
                if (!jsonDeepEqual(entry.value_ptr.*, b_val)) return false;
            }
            return true;
        },
        else => return false,
    }
}

pub export fn sa_node_plugin_util_is_deep_strict_equal(a_json: ?[*]const u8, a_len: u64, b_json: ?[*]const u8, b_len: u64, out_bool: ?*u64) u32 {
    const aj = if (a_json) |p| p[0..a_len] else "null";
    const bj = if (b_json) |p| p[0..b_len] else "null";

    const parsed_a = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, aj, .{}) catch return 2;
    defer parsed_a.deinit();
    const parsed_b = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, bj, .{}) catch return 2;
    defer parsed_b.deinit();

    out_bool.?.* = if (jsonDeepEqual(parsed_a.value, parsed_b.value)) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_util_strip_vt_control_characters(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const d = if (data) |p| p[0..len] else &[_]u8{};
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < len) {
        if (d[i] == 0x1b and i + 1 < len) {
            if (d[i + 1] == '[') {
                i += 2;
                while (i < len) : (i += 1) {
                    const c = d[i];
                    if (c >= 0x40 and c <= 0x7E) {
                        i += 1;
                        break;
                    }
                }
            } else {
                i += 2;
            }
        } else {
            out.append(d[i]) catch return 2;
            i += 1;
        }
    }

    const slice = out.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_crypto_random_uuid(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);

    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    var buf: [36]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{s:0>2}{s:0>2}{s:0>2}{s:0>2}-{s:0>2}{s:0>2}-{s:0>2}{s:0>2}-{s:0>2}{s:0>2}-{s:0>2}{s:0>2}{s:0>2}{s:0>2}{s:0>2}{s:0>2}", .{
        std.fmt.fmtSliceHexLower(bytes[0..1]),
        std.fmt.fmtSliceHexLower(bytes[1..2]),
        std.fmt.fmtSliceHexLower(bytes[2..3]),
        std.fmt.fmtSliceHexLower(bytes[3..4]),
        std.fmt.fmtSliceHexLower(bytes[4..5]),
        std.fmt.fmtSliceHexLower(bytes[5..6]),
        std.fmt.fmtSliceHexLower(bytes[6..7]),
        std.fmt.fmtSliceHexLower(bytes[7..8]),
        std.fmt.fmtSliceHexLower(bytes[8..9]),
        std.fmt.fmtSliceHexLower(bytes[9..10]),
        std.fmt.fmtSliceHexLower(bytes[10..11]),
        std.fmt.fmtSliceHexLower(bytes[11..12]),
        std.fmt.fmtSliceHexLower(bytes[12..13]),
        std.fmt.fmtSliceHexLower(bytes[13..14]),
        std.fmt.fmtSliceHexLower(bytes[14..15]),
        std.fmt.fmtSliceHexLower(bytes[15..16]),
    }) catch return 2;

    const owned = std.heap.page_allocator.dupe(u8, &buf) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_crypto_timing_safe_equal(a_ptr: ?[*]const u8, a_len: u64, b_ptr: ?[*]const u8, b_len: u64, out_bool: ?*u64) u32 {
    if (a_len != b_len) {
        out_bool.?.* = 0;
        return 0;
    }
    if (a_len == 0) {
        out_bool.?.* = 1;
        return 0;
    }

    const a = a_ptr.?[0..a_len];
    const b = b_ptr.?[0..b_len];

    var result: u8 = 0;
    var i: usize = 0;
    while (i < a_len) : (i += 1) {
        result |= a[i] ^ b[i];
    }

    out_bool.?.* = if (result == 0) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_crypto_hmac(algo: ?[*]const u8, algo_len: u64, key: ?[*]const u8, key_len: u64, data: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const a = algo.?[0..algo_len];
    const k = key.?[0..key_len];
    const d = data.?[0..data_len];

    var mac_buf: [32]u8 = undefined;
    if (std.mem.eql(u8, a, "sha256") or std.mem.eql(u8, a, "SHA256")) {
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac_buf, d, k);
    } else {
        return 2;
    }

    var hex_buf: [64]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&mac_buf)}) catch return 2;
    const owned = std.heap.page_allocator.dupe(u8, hex) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_zlib_deflate(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const d = data.?[0..len];
    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();

    var compressor = std.compress.zlib.compressor(out_list.writer(), .{}) catch return 2;
    compressor.writer().writeAll(d) catch return 2;
    compressor.finish() catch return 2;

    const slice = out_list.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_zlib_inflate(data: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const d = data.?[0..len];
    var in_stream = std.io.fixedBufferStream(d);
    var decompressor = std.compress.zlib.decompressor(in_stream.reader());

    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();

    var temp_buf: [1024]u8 = undefined;
    while (true) {
        const bytes_read = decompressor.read(&temp_buf) catch return 2;
        if (bytes_read == 0) break;
        out_list.appendSlice(temp_buf[0..bytes_read]) catch return 2;
    }

    const slice = out_list.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_buffer_byte_length(data: ?[*]const u8, len: u64, out_len: ?*u64) u32 {
    _ = data;
    out_len.?.* = len;
    return 0;
}

pub export fn sa_node_plugin_buffer_concat(buffers_argv: ?*const anyopaque, buffers_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (buffers_len == 0) {
        const owned = std.heap.page_allocator.dupe(u8, "") catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }

    const slices: [*]const SaSlice = @ptrCast(@alignCast(buffers_argv.?));

    var total_len: u64 = 0;
    var i: usize = 0;
    while (i < buffers_len) : (i += 1) {
        total_len += slices[i].len;
    }

    const result = std.heap.page_allocator.alloc(u8, total_len) catch return 2;
    errdefer std.heap.page_allocator.free(result);

    var offset: usize = 0;
    i = 0;
    while (i < buffers_len) : (i += 1) {
        const src = slices[i].ptr[0..slices[i].len];
        @memcpy(result[offset .. offset + src.len], src);
        offset += src.len;
    }

    out_ptr.?.* = result.ptr;
    out_len.?.* = result.len;
    return 0;
}

// --- Phase 4: events & readline module ---

pub const EventEntry = struct {
    name: []const u8,
    listeners: u64,
    callbacks: std.ArrayList(?*anyopaque),
    once: std.ArrayList(bool),
};

pub const EventEmitter = struct {
    allocator: std.mem.Allocator,
    events: std.ArrayList(EventEntry),
    max_listeners: u32,

    fn init(allocator: std.mem.Allocator) !*EventEmitter {
        const self = try allocator.create(EventEmitter);
        self.* = .{
            .allocator = allocator,
            .events = std.ArrayList(EventEntry).init(allocator),
            .max_listeners = 10,
        };
        return self;
    }

    fn deinit(self: *EventEmitter) void {
        for (self.events.items) |*entry| {
            self.allocator.free(entry.name);
            entry.callbacks.deinit();
            entry.once.deinit();
        }
        self.events.deinit();
        self.allocator.destroy(self);
    }

    pub fn addListener(self: *EventEmitter, name: []const u8, callback: ?*anyopaque, prepend: bool, once: bool) !void {
        for (self.events.items) |*entry| {
            if (std.mem.eql(u8, entry.name, name)) {
                if (prepend) {
                    try entry.callbacks.insert(0, callback);
                    try entry.once.insert(0, once);
                } else {
                    try entry.callbacks.append(callback);
                    try entry.once.append(once);
                }
                entry.listeners = entry.callbacks.items.len;
                return;
            }
        }

        const duped = try self.allocator.dupe(u8, name);
        var callbacks = std.ArrayList(?*anyopaque).init(self.allocator);
        errdefer callbacks.deinit();
        var once_list = std.ArrayList(bool).init(self.allocator);
        errdefer once_list.deinit();
        try callbacks.append(callback);
        try once_list.append(once);
        try self.events.append(.{ .name = duped, .listeners = 1, .callbacks = callbacks, .once = once_list });
    }

    pub fn removeListener(self: *EventEmitter, name: []const u8, callback: ?*anyopaque) bool {
        for (self.events.items) |*entry| {
            if (std.mem.eql(u8, entry.name, name)) {
                var i: usize = 0;
                while (i < entry.callbacks.items.len) : (i += 1) {
                    if (entry.callbacks.items[i] == callback) {
                        _ = entry.callbacks.orderedRemove(i);
                        _ = entry.once.orderedRemove(i);
                        entry.listeners = entry.callbacks.items.len;
                        return true;
                    }
                }
            }
        }
        return false;
    }

    pub fn removeAll(self: *EventEmitter, name: []const u8) bool {
        for (self.events.items, 0..) |*entry, idx| {
            if (std.mem.eql(u8, entry.name, name)) {
                self.allocator.free(entry.name);
                entry.callbacks.deinit();
                entry.once.deinit();
                _ = self.events.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    pub fn listenerCount(self: *EventEmitter, name: []const u8) u64 {
        for (self.events.items) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.listeners;
        }
        return 0;
    }

    pub fn emit(self: *EventEmitter, name: []const u8) bool {
        for (self.events.items) |*entry| {
            if (std.mem.eql(u8, entry.name, name)) {
                const had_listeners = entry.callbacks.items.len > 0;
                var i: usize = entry.once.items.len;
                while (i > 0) {
                    i -= 1;
                    if (entry.once.items[i]) {
                        _ = entry.callbacks.orderedRemove(i);
                        _ = entry.once.orderedRemove(i);
                    }
                }
                entry.listeners = entry.callbacks.items.len;
                return had_listeners;
            }
        }
        return false;
    }
};

pub export fn sa_node_plugin_events_create() ?*anyopaque {
    const ee = EventEmitter.init(std.heap.page_allocator) catch return null;
    return @ptrCast(ee);
}

pub export fn sa_node_plugin_events_on(ee_ptr: ?*anyopaque, event_name: ?[*]const u8, event_len: u64, callback: ?*anyopaque) u32 {
    const ee: *EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return 2));
    const name = event_name.?[0..event_len];
    ee.addListener(name, callback, false, false) catch return 2;
    return 0;
}

pub export fn sa_node_plugin_events_emit(ee_ptr: ?*anyopaque, event_name: ?[*]const u8, event_len: u64, data: ?[*]const u8, data_len: u64) u32 {
    _ = data;
    _ = data_len;
    const ee: *EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return 2));
    const name = event_name.?[0..event_len];
    return if (ee.emit(name)) 0 else 1;
}

pub export fn sa_node_plugin_events_listener_count(ee_ptr: ?*anyopaque, event_name: ?[*]const u8, event_len: u64, out_count: ?*u64) u32 {
    const ee: *EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return 2));
    const name = event_name.?[0..event_len];
    out_count.?.* = ee.listenerCount(name);
    return 0;
}

pub export fn sa_node_plugin_events_free(ee_ptr: ?*anyopaque) u32 {
    if (ee_ptr) |ptr| {
        const ee: *EventEmitter = @ptrCast(@alignCast(ptr));
        ee.deinit();
    }
    return 0;
}

const ReadlineHandle = struct {};

pub export fn sa_node_plugin_readline_create() ?*anyopaque {
    const handle = std.heap.page_allocator.create(ReadlineHandle) catch return null;
    handle.* = .{};
    return @ptrCast(handle);
}

pub export fn sa_node_plugin_readline_question(rl: ?*anyopaque, query: ?[*]const u8, query_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = rl;
    const q = if (query) |p| p[0..query_len] else &[_]u8{};
    std.io.getStdOut().writer().writeAll(q) catch return 2;

    var buf = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer buf.deinit();

    const stdin = std.io.getStdIn().reader();
    stdin.streamUntilDelimiter(buf.writer(), '\n', null) catch |err| {
        if (err == error.EndOfStream) {} else return 2;
    };

    if (buf.items.len > 0 and buf.items[buf.items.len - 1] == '\r') {
        _ = buf.pop();
    }

    const slice = buf.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_readline_free(rl: ?*anyopaque) u32 {
    if (rl) |ptr| {
        const handle: *ReadlineHandle = @ptrCast(@alignCast(ptr));
        std.heap.page_allocator.destroy(handle);
    }
    return 0;
}

// --- Phase 4: stream module ---

pub const BasicStreamHandle = struct {
    allocator: std.mem.Allocator,
    data: std.ArrayList(u8),

    fn init(allocator: std.mem.Allocator) !*BasicStreamHandle {
        const handle = try allocator.create(BasicStreamHandle);
        handle.* = .{ .allocator = allocator, .data = std.ArrayList(u8).init(allocator) };
        return handle;
    }

    pub fn deinit(self: *BasicStreamHandle) void {
        self.data.deinit();
        self.allocator.destroy(self);
    }
};

pub export fn sa_node_plugin_stream_readable_new() ?*anyopaque {
    return @ptrCast(BasicStreamHandle.init(std.heap.page_allocator) catch return null);
}

pub export fn sa_node_plugin_stream_writable_new() ?*anyopaque {
    return @ptrCast(BasicStreamHandle.init(std.heap.page_allocator) catch return null);
}

pub export fn sa_node_plugin_stream_push(readable: ?*anyopaque, data: ?[*]const u8, data_len: u64) u32 {
    const handle: *BasicStreamHandle = @ptrCast(@alignCast(readable orelse return 2));
    if (data_len > 0) handle.data.appendSlice(data.?[0..data_len]) catch return 2;
    return 0;
}

pub export fn sa_node_plugin_stream_write(writable: ?*anyopaque, data: ?[*]const u8, data_len: u64) u32 {
    const handle: *BasicStreamHandle = @ptrCast(@alignCast(writable orelse return 2));
    if (data_len > 0) handle.data.appendSlice(data.?[0..data_len]) catch return 2;
    return 0;
}

// --- Phase 5: net & dns module ---

pub export fn sa_node_plugin_dns_lookup(hostname: ?[*]const u8, len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const host = hostname.?[0..len];
    const host_z = std.heap.page_allocator.dupeZ(u8, host) catch return 2;
    defer std.heap.page_allocator.free(host_z);

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();

    json.appendSlice("[") catch return 2;

    if (std.net.Address.resolveIp(host_z, 0)) |list| {
        switch (list.any.family) {
            std.posix.AF.INET => {
                const bytes = std.mem.asBytes(&list.in.sa.addr);
                json.writer().print("\"{d}.{d}.{d}.{d}\"", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch return 2;
            },
            std.posix.AF.INET6 => {
                var buf: [64]u8 = undefined;
                const ip_str = std.fmt.bufPrint(&buf, "{}", .{list}) catch return 2;
                const clean_ip = if (std.mem.lastIndexOfScalar(u8, ip_str, ']')) |end| ip_str[1..end] else ip_str;
                json.appendSlice("\"") catch return 2;
                json.appendSlice(clean_ip) catch return 2;
                json.appendSlice("\"") catch return 2;
            },
            else => return 2,
        }
    } else |_| {
        if (std.mem.eql(u8, host, "localhost")) {
            json.appendSlice("\"127.0.0.1\"") catch return 2;
        } else {
            return 2;
        }
    }

    json.appendSlice("]") catch return 2;

    const slice = json.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_dns_lookup_service(address_ptr: ?[*]const u8, len: u64, port: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const address_text = address_ptr.?[0..len];
    const address = std.net.Address.resolveIp(address_text, @as(u16, @intCast(port))) catch return 2;

    var host_buf: [1025]u8 = undefined;
    var serv_buf: [32]u8 = undefined;
    const rc = std.c.getnameinfo(
        &address.any,
        address.getOsSockLen(),
        &host_buf,
        host_buf.len,
        &serv_buf,
        serv_buf.len,
        .{},
    );
    if (@intFromEnum(rc) != 0) return 2;

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    defer json.deinit();
    json.appendSlice("{\"hostname\":") catch return 2;
    appendJsonString(&json, std.mem.sliceTo(&host_buf, 0)) catch return 2;
    json.appendSlice(",\"service\":") catch return 2;
    appendJsonString(&json, std.mem.sliceTo(&serv_buf, 0)) catch return 2;
    json.appendSlice("}") catch return 2;

    const slice = json.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_dns_resolve(hostname: ?[*]const u8, len: u64, rrtype: ?[*]const u8, rrtype_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const rr = rrtype.?[0..rrtype_len];
    if (std.ascii.eqlIgnoreCase(rr, "A")) return sa_node_plugin_dns_lookup(hostname, len, out_ptr, out_len);
    return 2;
}

const BlockListFamily = enum { ipv4, ipv6 };
const BlockListRuleKind = enum { address, range, subnet };
const net_socket_address_magic: u64 = 0x5341_4e45_5453_4144;
const net_blocklist_magic: u64 = 0x5341_4e45_5442_4c4b;

const BlockListAddress = struct {
    family: BlockListFamily,
    bytes: [16]u8,
    text: []u8,
};

const SaNetSocketAddress = struct {
    magic: u64 = net_socket_address_magic,
    allocator: std.mem.Allocator,
    family: BlockListFamily,
    bytes: [16]u8,
    text: []u8,
    port: u16,
    flowlabel: u32,

    fn deinit(self: *SaNetSocketAddress) void {
        self.magic = 0;
        self.allocator.free(self.text);
        self.allocator.destroy(self);
    }
};

const BlockListRule = struct {
    kind: BlockListRuleKind,
    family: BlockListFamily,
    start: [16]u8,
    end: [16]u8,
    prefix: u8,
    text: []u8,
};

const SaNetBlockList = struct {
    magic: u64 = net_blocklist_magic,
    allocator: std.mem.Allocator,
    rules: std.ArrayList(BlockListRule),

    fn init(allocator: std.mem.Allocator) !*SaNetBlockList {
        const handle = try allocator.create(SaNetBlockList);
        handle.* = .{ .allocator = allocator, .rules = std.ArrayList(BlockListRule).init(allocator) };
        return handle;
    }

    fn deinit(self: *SaNetBlockList) void {
        self.magic = 0;
        for (self.rules.items) |rule| self.allocator.free(rule.text);
        self.rules.deinit();
        self.allocator.destroy(self);
    }
};

fn blockListFamilyName(family: BlockListFamily) []const u8 {
    return if (family == .ipv4) "IPv4" else "IPv6";
}

fn blockListFamilyLen(family: BlockListFamily) usize {
    return if (family == .ipv4) 4 else 16;
}

fn blockListParseAddress(allocator: std.mem.Allocator, address_ptr: ?[*]const u8, address_len: u64) !BlockListAddress {
    const address = (address_ptr orelse return error.InvalidAddress)[0..address_len];
    var bytes: [16]u8 = .{0} ** 16;
    if (std.net.Address.parseIp4(address, 0)) |addr| {
        @memcpy(bytes[0..4], std.mem.asBytes(&addr.in.sa.addr));
        const text = try dgramAddressToOwnedHost(addr);
        errdefer allocator.free(text);
        return .{ .family = .ipv4, .bytes = bytes, .text = text };
    } else |_| {}
    if (std.net.Address.parseIp6(address, 0)) |addr| {
        @memcpy(bytes[0..16], addr.in6.sa.addr[0..16]);
        const text = try dgramAddressToOwnedHost(addr);
        errdefer allocator.free(text);
        return .{ .family = .ipv6, .bytes = bytes, .text = text };
    } else |_| {}
    return error.InvalidAddress;
}

fn blockListParseAddressForFamily(allocator: std.mem.Allocator, address: []const u8, family: BlockListFamily) !BlockListAddress {
    var bytes: [16]u8 = .{0} ** 16;
    switch (family) {
        .ipv4 => {
            const addr = try std.net.Address.parseIp4(address, 0);
            @memcpy(bytes[0..4], std.mem.asBytes(&addr.in.sa.addr));
            const text = try dgramAddressToOwnedHost(addr);
            errdefer allocator.free(text);
            return .{ .family = .ipv4, .bytes = bytes, .text = text };
        },
        .ipv6 => {
            const addr = try std.net.Address.parseIp6(address, 0);
            @memcpy(bytes[0..16], addr.in6.sa.addr[0..16]);
            const text = try dgramAddressToOwnedHost(addr);
            errdefer allocator.free(text);
            return .{ .family = .ipv6, .bytes = bytes, .text = text };
        },
    }
}

fn socketAddressFamilyFromText(family: []const u8) ?BlockListFamily {
    if (family.len == 0) return null;
    if (std.ascii.eqlIgnoreCase(family, "ipv4")) return .ipv4;
    if (std.ascii.eqlIgnoreCase(family, "ipv6")) return .ipv6;
    return null;
}

fn socketAddressDefaultAddress(family: BlockListFamily) []const u8 {
    return if (family == .ipv4) "127.0.0.1" else "::";
}

fn socketAddressCreate(address: []const u8, port: u64, family_text: []const u8, flowlabel: u64) !*SaNetSocketAddress {
    if (port > std.math.maxInt(u16) or flowlabel > std.math.maxInt(u32)) return error.InvalidSocketAddress;
    const allocator = std.heap.page_allocator;
    const explicit_family = socketAddressFamilyFromText(family_text);
    if (family_text.len != 0 and explicit_family == null) return error.InvalidSocketAddress;
    const family = explicit_family orelse .ipv4;
    const address_text = if (address.len == 0) socketAddressDefaultAddress(family) else address;
    const parsed = if (explicit_family) |f|
        try blockListParseAddressForFamily(allocator, address_text, f)
    else
        try blockListParseAddress(allocator, address_text.ptr, address_text.len);
    errdefer allocator.free(parsed.text);
    const handle = try allocator.create(SaNetSocketAddress);
    handle.* = .{
        .allocator = allocator,
        .family = parsed.family,
        .bytes = parsed.bytes,
        .text = parsed.text,
        .port = @intCast(port),
        .flowlabel = @intCast(flowlabel),
    };
    return handle;
}

fn socketAddressHandle(ptr: ?*anyopaque) ?*SaNetSocketAddress {
    const handle: *SaNetSocketAddress = @ptrCast(@alignCast(ptr orelse return null));
    if (handle.magic != net_socket_address_magic) return null;
    return handle;
}

fn blockListHandle(ptr: ?*anyopaque) ?*SaNetBlockList {
    const handle: *SaNetBlockList = @ptrCast(@alignCast(ptr orelse return null));
    if (handle.magic != net_blocklist_magic) return null;
    return handle;
}

fn blockListAddressFromSocketAddress(addr: *const SaNetSocketAddress) BlockListAddress {
    return .{ .family = addr.family, .bytes = addr.bytes, .text = addr.text };
}

fn blockListAddressFromNetAddress(allocator: std.mem.Allocator, addr: std.net.Address) !BlockListAddress {
    var bytes: [16]u8 = .{0} ** 16;
    switch (addr.any.family) {
        std.posix.AF.INET => {
            @memcpy(bytes[0..4], std.mem.asBytes(&addr.in.sa.addr));
            const text = try dgramAddressToOwnedHost(addr);
            errdefer allocator.free(text);
            return .{ .family = .ipv4, .bytes = bytes, .text = text };
        },
        std.posix.AF.INET6 => {
            @memcpy(bytes[0..16], addr.in6.sa.addr[0..16]);
            const text = try dgramAddressToOwnedHost(addr);
            errdefer allocator.free(text);
            return .{ .family = .ipv6, .bytes = bytes, .text = text };
        },
        else => return error.InvalidAddressFamily,
    }
}

fn blockListCompareAddress(family: BlockListFamily, a: [16]u8, b: [16]u8) std.math.Order {
    return std.mem.order(u8, a[0..blockListFamilyLen(family)], b[0..blockListFamilyLen(family)]);
}

fn blockListPrefixMatch(family: BlockListFamily, address: [16]u8, network: [16]u8, prefix: u8) bool {
    const max_bits: u8 = if (family == .ipv4) 32 else 128;
    if (prefix > max_bits) return false;
    const full_bytes: usize = prefix / 8;
    if (!std.mem.eql(u8, address[0..full_bytes], network[0..full_bytes])) return false;
    const remaining: u3 = @intCast(prefix % 8);
    if (remaining == 0) return true;
    const shift: u3 = @intCast(8 - @as(u8, remaining));
    const mask: u8 = @as(u8, 0xff) << shift;
    return (address[full_bytes] & mask) == (network[full_bytes] & mask);
}

fn blockListAppendRule(handle: *SaNetBlockList, rule: BlockListRule) !void {
    try handle.rules.insert(0, rule);
}

fn blockListMatchesRules(rules: []const BlockListRule, address: BlockListAddress) bool {
    for (rules) |rule| {
        if (rule.family != address.family) continue;
        const matched = switch (rule.kind) {
            .address => blockListCompareAddress(rule.family, address.bytes, rule.start) == .eq,
            .range => blockListCompareAddress(rule.family, address.bytes, rule.start) != .lt and blockListCompareAddress(rule.family, address.bytes, rule.end) != .gt,
            .subnet => blockListPrefixMatch(rule.family, address.bytes, rule.start, rule.prefix),
        };
        if (matched) return true;
    }
    return false;
}

fn blockListFreeRuleList(allocator: std.mem.Allocator, rules: *std.ArrayList(BlockListRule)) void {
    for (rules.items) |rule| allocator.free(rule.text);
    rules.clearRetainingCapacity();
}

fn blockListCopyRules(allocator: std.mem.Allocator, source: *const SaNetBlockList, dest: *std.ArrayList(BlockListRule)) !void {
    var next = std.ArrayList(BlockListRule).init(allocator);
    errdefer {
        for (next.items) |rule| allocator.free(rule.text);
        next.deinit();
    }
    try next.ensureTotalCapacity(source.rules.items.len);
    for (source.rules.items) |rule| {
        const text = try allocator.dupe(u8, rule.text);
        next.appendAssumeCapacity(.{
            .kind = rule.kind,
            .family = rule.family,
            .start = rule.start,
            .end = rule.end,
            .prefix = rule.prefix,
            .text = text,
        });
    }
    blockListFreeRuleList(allocator, dest);
    dest.deinit();
    dest.* = next;
}

pub export fn sa_node_plugin_net_blocklist_new(out_blocklist: ?*?*anyopaque) u32 {
    const out = out_blocklist orelse return 2;
    const handle = SaNetBlockList.init(std.heap.page_allocator) catch return 2;
    out.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_is_blocklist(blocklist_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const out = out_bool orelse return 2;
    out.* = if (blockListHandle(blocklist_ptr) != null) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_net_socket_address_new(address_ptr: ?[*]const u8, address_len: u64, port: u64, family_ptr: ?[*]const u8, family_len: u64, flowlabel: u64, out_addr: ?*?*anyopaque) u32 {
    const out = out_addr orelse return 2;
    const address = if (address_len == 0) "" else (address_ptr orelse return 2)[0..address_len];
    const family = if (family_len == 0) "" else (family_ptr orelse return 2)[0..family_len];
    const handle = socketAddressCreate(address, port, family, flowlabel) catch return 2;
    out.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_net_socket_address_parse(input_ptr: ?[*]const u8, input_len: u64, out_addr: ?*?*anyopaque) u32 {
    const out = out_addr orelse return 2;
    const input = (input_ptr orelse return 2)[0..input_len];
    if (input.len == 0) return 2;
    if (input[0] == '[') {
        const end = std.mem.indexOfScalar(u8, input, ']') orelse return 2;
        const port: u16 = if (end + 1 == input.len)
            0
        else blk: {
            if (input[end + 1] != ':') return 2;
            break :blk std.fmt.parseInt(u16, input[end + 2 ..], 10) catch return 2;
        };
        const handle = socketAddressCreate(input[1..end], port, "ipv6", 0) catch return 2;
        out.* = @ptrCast(handle);
        return 0;
    }
    const colon = std.mem.lastIndexOfScalar(u8, input, ':') orelse {
        const handle = socketAddressCreate(input, 0, "ipv4", 0) catch return 2;
        out.* = @ptrCast(handle);
        return 0;
    };
    if (std.mem.indexOfScalar(u8, input[0..colon], ':') != null) return 2;
    if (colon == 0) return 2;
    const port = std.fmt.parseInt(u16, input[colon + 1 ..], 10) catch return 2;
    const handle = socketAddressCreate(input[0..colon], port, "ipv4", 0) catch return 2;
    out.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_net_socket_address_is_socket_address(addr_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const out = out_bool orelse return 2;
    out.* = if (socketAddressHandle(addr_ptr) != null) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_net_socket_address_free(addr_ptr: ?*anyopaque) u32 {
    if (socketAddressHandle(addr_ptr)) |addr| addr.deinit();
    return 0;
}

pub export fn sa_node_plugin_net_socket_address_address(addr_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const addr = socketAddressHandle(addr_ptr) orelse return 2;
    const out_slot = out_ptr orelse return 2;
    const len_slot = out_len orelse return 2;
    const owned = addr.allocator.dupe(u8, addr.text) catch return 2;
    out_slot.* = owned.ptr;
    len_slot.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_net_socket_address_family(addr_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const addr = socketAddressHandle(addr_ptr) orelse return 2;
    const out_slot = out_ptr orelse return 2;
    const len_slot = out_len orelse return 2;
    const family = if (addr.family == .ipv4) "ipv4" else "ipv6";
    const owned = addr.allocator.dupe(u8, family) catch return 2;
    out_slot.* = owned.ptr;
    len_slot.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_net_socket_address_port(addr_ptr: ?*anyopaque, out_port: ?*u64) u32 {
    const addr = socketAddressHandle(addr_ptr) orelse return 2;
    (out_port orelse return 2).* = addr.port;
    return 0;
}

pub export fn sa_node_plugin_net_socket_address_flowlabel(addr_ptr: ?*anyopaque, out_flowlabel: ?*u64) u32 {
    const addr = socketAddressHandle(addr_ptr) orelse return 2;
    (out_flowlabel orelse return 2).* = addr.flowlabel;
    return 0;
}

pub export fn sa_node_plugin_net_socket_address_json(addr_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const addr = socketAddressHandle(addr_ptr) orelse return 2;
    const out_slot = out_ptr orelse return 2;
    const len_slot = out_len orelse return 2;
    var out = std.ArrayList(u8).init(addr.allocator);
    defer out.deinit();
    out.appendSlice("{\"address\":") catch return 2;
    appendJsonString(&out, addr.text) catch return 2;
    out.writer().print(",\"port\":{d},\"family\":", .{addr.port}) catch return 2;
    appendJsonString(&out, if (addr.family == .ipv4) "ipv4" else "ipv6") catch return 2;
    out.writer().print(",\"flowlabel\":{d}}}", .{addr.flowlabel}) catch return 2;
    const owned = out.toOwnedSlice() catch return 2;
    out_slot.* = owned.ptr;
    len_slot.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_free(blocklist_ptr: ?*anyopaque) u32 {
    if (blockListHandle(blocklist_ptr)) |handle| handle.deinit();
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_add_address(blocklist_ptr: ?*anyopaque, address_ptr: ?[*]const u8, address_len: u64) u32 {
    const handle = blockListHandle(blocklist_ptr) orelse return 2;
    const address = blockListParseAddress(handle.allocator, address_ptr, address_len) catch return 2;
    defer handle.allocator.free(address.text);
    const text = std.fmt.allocPrint(handle.allocator, "Address: {s} {s}", .{ blockListFamilyName(address.family), address.text }) catch return 2;
    const rule: BlockListRule = .{ .kind = .address, .family = address.family, .start = address.bytes, .end = address.bytes, .prefix = 0, .text = text };
    blockListAppendRule(handle, rule) catch {
        handle.allocator.free(text);
        return 2;
    };
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_add_address_handle(blocklist_ptr: ?*anyopaque, addr_ptr: ?*anyopaque) u32 {
    const handle = blockListHandle(blocklist_ptr) orelse return 2;
    const address = socketAddressHandle(addr_ptr) orelse return 2;
    const text = std.fmt.allocPrint(handle.allocator, "Address: {s} {s}", .{ blockListFamilyName(address.family), address.text }) catch return 2;
    const rule: BlockListRule = .{ .kind = .address, .family = address.family, .start = address.bytes, .end = address.bytes, .prefix = 0, .text = text };
    blockListAppendRule(handle, rule) catch {
        handle.allocator.free(text);
        return 2;
    };
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_add_range(blocklist_ptr: ?*anyopaque, start_ptr: ?[*]const u8, start_len: u64, end_ptr: ?[*]const u8, end_len: u64) u32 {
    const handle = blockListHandle(blocklist_ptr) orelse return 2;
    const start = blockListParseAddress(handle.allocator, start_ptr, start_len) catch return 2;
    defer handle.allocator.free(start.text);
    const end = blockListParseAddress(handle.allocator, end_ptr, end_len) catch return 2;
    defer handle.allocator.free(end.text);
    if (start.family != end.family) return 2;
    if (blockListCompareAddress(start.family, start.bytes, end.bytes) == .gt) return 2;
    const text = std.fmt.allocPrint(handle.allocator, "Range: {s} {s}-{s}", .{ blockListFamilyName(start.family), start.text, end.text }) catch return 2;
    const rule: BlockListRule = .{ .kind = .range, .family = start.family, .start = start.bytes, .end = end.bytes, .prefix = 0, .text = text };
    blockListAppendRule(handle, rule) catch {
        handle.allocator.free(text);
        return 2;
    };
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_add_range_handle(blocklist_ptr: ?*anyopaque, start_ptr: ?*anyopaque, end_ptr: ?*anyopaque) u32 {
    const handle = blockListHandle(blocklist_ptr) orelse return 2;
    const start = socketAddressHandle(start_ptr) orelse return 2;
    const end = socketAddressHandle(end_ptr) orelse return 2;
    if (start.family != end.family) return 2;
    if (blockListCompareAddress(start.family, start.bytes, end.bytes) == .gt) return 2;
    const text = std.fmt.allocPrint(handle.allocator, "Range: {s} {s}-{s}", .{ blockListFamilyName(start.family), start.text, end.text }) catch return 2;
    const rule: BlockListRule = .{ .kind = .range, .family = start.family, .start = start.bytes, .end = end.bytes, .prefix = 0, .text = text };
    blockListAppendRule(handle, rule) catch {
        handle.allocator.free(text);
        return 2;
    };
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_add_subnet(blocklist_ptr: ?*anyopaque, network_ptr: ?[*]const u8, network_len: u64, prefix: u32) u32 {
    const handle = blockListHandle(blocklist_ptr) orelse return 2;
    const network = blockListParseAddress(handle.allocator, network_ptr, network_len) catch return 2;
    defer handle.allocator.free(network.text);
    const max_prefix: u32 = if (network.family == .ipv4) 32 else 128;
    if (prefix > max_prefix) return 2;
    const text = std.fmt.allocPrint(handle.allocator, "Subnet: {s} {s}/{d}", .{ blockListFamilyName(network.family), network.text, prefix }) catch return 2;
    const rule: BlockListRule = .{ .kind = .subnet, .family = network.family, .start = network.bytes, .end = network.bytes, .prefix = @intCast(prefix), .text = text };
    blockListAppendRule(handle, rule) catch {
        handle.allocator.free(text);
        return 2;
    };
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_add_subnet_handle(blocklist_ptr: ?*anyopaque, network_ptr: ?*anyopaque, prefix: u32) u32 {
    const handle = blockListHandle(blocklist_ptr) orelse return 2;
    const network = socketAddressHandle(network_ptr) orelse return 2;
    const max_prefix: u32 = if (network.family == .ipv4) 32 else 128;
    if (prefix > max_prefix) return 2;
    const text = std.fmt.allocPrint(handle.allocator, "Subnet: {s} {s}/{d}", .{ blockListFamilyName(network.family), network.text, prefix }) catch return 2;
    const rule: BlockListRule = .{ .kind = .subnet, .family = network.family, .start = network.bytes, .end = network.bytes, .prefix = @intCast(prefix), .text = text };
    blockListAppendRule(handle, rule) catch {
        handle.allocator.free(text);
        return 2;
    };
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_check(blocklist_ptr: ?*anyopaque, address_ptr: ?[*]const u8, address_len: u64, out_bool: ?*u64) u32 {
    const handle = blockListHandle(blocklist_ptr) orelse return 2;
    const address = blockListParseAddress(handle.allocator, address_ptr, address_len) catch return 2;
    defer handle.allocator.free(address.text);
    for (handle.rules.items) |rule| {
        if (rule.family != address.family) continue;
        const matched = switch (rule.kind) {
            .address => blockListCompareAddress(rule.family, address.bytes, rule.start) == .eq,
            .range => blockListCompareAddress(rule.family, address.bytes, rule.start) != .lt and blockListCompareAddress(rule.family, address.bytes, rule.end) != .gt,
            .subnet => blockListPrefixMatch(rule.family, address.bytes, rule.start, rule.prefix),
        };
        if (matched) {
            (out_bool orelse return 2).* = 1;
            return 0;
        }
    }
    (out_bool orelse return 2).* = 0;
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_check_handle(blocklist_ptr: ?*anyopaque, addr_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const handle = blockListHandle(blocklist_ptr) orelse return 2;
    const address_handle = socketAddressHandle(addr_ptr) orelse return 2;
    const address = blockListAddressFromSocketAddress(address_handle);
    for (handle.rules.items) |rule| {
        if (rule.family != address.family) continue;
        const matched = switch (rule.kind) {
            .address => blockListCompareAddress(rule.family, address.bytes, rule.start) == .eq,
            .range => blockListCompareAddress(rule.family, address.bytes, rule.start) != .lt and blockListCompareAddress(rule.family, address.bytes, rule.end) != .gt,
            .subnet => blockListPrefixMatch(rule.family, address.bytes, rule.start, rule.prefix),
        };
        if (matched) {
            (out_bool orelse return 2).* = 1;
            return 0;
        }
    }
    (out_bool orelse return 2).* = 0;
    return 0;
}

pub export fn sa_node_plugin_net_blocklist_rules(blocklist_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle = blockListHandle(blocklist_ptr) orelse return 2;
    const out_slot = out_ptr orelse return 2;
    const len_slot = out_len orelse return 2;
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.append('[') catch return 2;
    for (handle.rules.items, 0..) |rule, i| {
        if (i != 0) out.append(',') catch return 2;
        appendJsonString(&out, rule.text) catch return 2;
    }
    out.append(']') catch return 2;
    const owned = out.toOwnedSlice() catch return 2;
    out_slot.* = owned.ptr;
    len_slot.* = owned.len;
    return 0;
}

pub const SaNetObject = struct {
    is_server: bool,
    allocator: std.mem.Allocator,
    stream: ?std.net.Stream,
    server: ?std.net.Server,
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,
    readable: bool = true,
    writable: bool = true,
    closed: bool = false,
    timeout_ms: u64 = 0,
    parent_server: ?*SaNetObject = null,
    counted_connection: bool = false,
    connection_count: u64 = 0,
    max_connections: u64 = 0,
    max_connections_set: bool = false,
    has_ref: bool = true,
    block_list: std.ArrayList(BlockListRule),
    auto_select_family_attempted_addresses: std.ArrayList([]u8),
    unix_path: ?[]u8 = null,

    fn markSocketClosed(self: *SaNetObject) void {
        if (!self.is_server and self.counted_connection) {
            if (self.parent_server) |server_obj| {
                if (server_obj.connection_count > 0) server_obj.connection_count -= 1;
            }
            self.counted_connection = false;
        }
        self.closed = true;
        self.readable = false;
        self.writable = false;
    }

    fn deinit(self: *SaNetObject) void {
        self.markSocketClosed();
        for (self.auto_select_family_attempted_addresses.items) |entry| {
            self.allocator.free(entry);
        }
        self.auto_select_family_attempted_addresses.deinit();
        blockListFreeRuleList(self.allocator, &self.block_list);
        self.block_list.deinit();
        if (self.is_server) {
            self.closeServerHandle();
        } else {
            if (self.stream) |str| {
                str.close();
            }
        }
        self.allocator.destroy(self);
    }

    fn closeServerHandle(self: *SaNetObject) void {
        if (self.server) |*srv| {
            var s = srv.*;
            s.deinit();
            self.server = null;
        }
        if (self.unix_path) |path| {
            netUnlinkUnixSocketPath(path);
            self.allocator.free(path);
            self.unix_path = null;
        }
    }
};

fn netUnlinkUnixSocketPath(path: []const u8) void {
    if (path.len == 0 or path[0] == 0) return;
    if (std.fs.path.isAbsolute(path)) {
        std.fs.deleteFileAbsolute(path) catch {};
    } else {
        std.fs.cwd().deleteFile(path) catch {};
    }
}

fn netAddressToAttemptString(addr: std.net.Address) ![]u8 {
    const allocator = std.heap.page_allocator;
    const host = try dgramAddressToOwnedHost(addr);
    defer allocator.free(host);
    return try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, addr.getPort() });
}

fn netAddressBlocked(allocator: std.mem.Allocator, rules: []const BlockListRule, address: std.net.Address) bool {
    if (rules.len == 0) return false;
    const block_address = blockListAddressFromNetAddress(allocator, address) catch return false;
    defer allocator.free(block_address.text);
    return blockListMatchesRules(rules, block_address);
}

fn netSetBlockList(dest: *std.ArrayList(BlockListRule), blocklist_ptr: ?*anyopaque, allocator: std.mem.Allocator) u32 {
    if (blocklist_ptr == null) {
        blockListFreeRuleList(allocator, dest);
        return 0;
    }
    const blocklist = blockListHandle(blocklist_ptr) orelse return 2;
    blockListCopyRules(allocator, blocklist, dest) catch return 2;
    return 0;
}

fn appendAddressJson(out: *std.ArrayList(u8), addr: std.net.Address) !void {
    const host = try dgramAddressToOwnedHost(addr);
    defer std.heap.page_allocator.free(host);
    const family = switch (addr.any.family) {
        std.posix.AF.INET => "IPv4",
        std.posix.AF.INET6 => "IPv6",
        else => "unknown",
    };
    try out.writer().print("{{\"address\":\"{s}\",\"port\":{d},\"family\":\"{s}\"}}", .{ host, addr.getPort(), family });
}

fn writeSocketAddressJson(fd: std.posix.socket_t, peer: bool, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var addr: std.net.Address = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    if (peer) {
        std.posix.getpeername(fd, &addr.any, &addr_len) catch return 2;
    } else {
        std.posix.getsockname(fd, &addr.any, &addr_len) catch return 2;
    }
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendAddressJson(&out, addr) catch return 2;
    const owned = out.toOwnedSlice() catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

fn getSocketAddress(fd: std.posix.socket_t, peer: bool) !std.net.Address {
    var addr: std.net.Address = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    if (peer) {
        try std.posix.getpeername(fd, &addr.any, &addr_len);
    } else {
        try std.posix.getsockname(fd, &addr.any, &addr_len);
    }
    return addr;
}

fn writeSocketAddressProperty(socket_ptr: ?*anyopaque, peer: bool, property: enum { address, family }, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    const stream = obj.stream orelse return 2;
    const addr = getSocketAddress(stream.handle, peer) catch return 2;
    const value = switch (property) {
        .address => dgramAddressToOwnedHost(addr) catch return 2,
        .family => std.heap.page_allocator.dupe(u8, switch (addr.any.family) {
            std.posix.AF.INET => "IPv4",
            std.posix.AF.INET6 => "IPv6",
            else => "unknown",
        }) catch return 2,
    };
    out_ptr.?.* = value.ptr;
    out_len.?.* = value.len;
    return 0;
}

fn writeSocketAddressPort(socket_ptr: ?*anyopaque, peer: bool, out_port: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    const stream = obj.stream orelse return 2;
    const addr = getSocketAddress(stream.handle, peer) catch return 2;
    out_port.?.* = addr.getPort();
    return 0;
}

fn netInitSocketObject(stream: std.net.Stream, timeout_ms: u64, attempted_address: ?std.net.Address, out: *?*anyopaque) u32 {
    const socket = std.heap.page_allocator.create(SaNetObject) catch return 2;
    socket.* = .{
        .is_server = false,
        .allocator = std.heap.page_allocator,
        .stream = stream,
        .server = null,
        .bytes_read = 0,
        .bytes_written = 0,
        .timeout_ms = timeout_ms,
        .block_list = std.ArrayList(BlockListRule).init(std.heap.page_allocator),
        .auto_select_family_attempted_addresses = std.ArrayList([]u8).init(std.heap.page_allocator),
    };
    if (attempted_address) |addr| {
        const attempt = netAddressToAttemptString(addr) catch {
            socket.deinit();
            return 2;
        };
        socket.auto_select_family_attempted_addresses.append(attempt) catch {
            std.heap.page_allocator.free(attempt);
            socket.deinit();
            return 2;
        };
    }
    out.* = @ptrCast(socket);
    return 0;
}

fn netParseRemoteAddress(host: []const u8, port: u64, family: u32) !std.net.Address {
    if (port > std.math.maxInt(u16)) return error.PortOutOfRange;
    const port16: u16 = @intCast(port);
    if (family == 4) {
        if (std.net.Address.parseIp4(host, port16)) |addr| return addr else |_| {}
    } else if (family == 6) {
        if (std.net.Address.parseIp6(host, port16)) |addr| return addr else |_| {}
    } else if (family == 0) {
        if (std.net.Address.parseIp(host, port16)) |addr| return addr else |_| {}
    } else {
        return error.InvalidAddressFamily;
    }

    const list = try std.net.getAddressList(std.heap.page_allocator, host, port16);
    defer list.deinit();
    for (list.addrs) |addr| {
        if (family == 4 and addr.any.family != std.posix.AF.INET) continue;
        if (family == 6 and addr.any.family != std.posix.AF.INET6) continue;
        return addr;
    }
    return error.HostLacksNetworkAddresses;
}

fn netResolveIpLiteral(host: []const u8, port: u64) !std.net.Address {
    if (port > std.math.maxInt(u16)) return error.PortOutOfRange;
    return std.net.Address.parseIp(host, @intCast(port));
}

fn netResolveAddress(host: []const u8, port: u64) !std.net.Address {
    if (netResolveIpLiteral(host, port)) |addr| return addr else |_| {}
    return netParseRemoteAddress(host, port, 0);
}

fn netParseLocalAddress(local_ptr: ?[*]const u8, local_len: u64, local_port: u64, family: std.posix.sa_family_t) !?std.net.Address {
    if (local_port > std.math.maxInt(u16)) return error.PortOutOfRange;
    if ((local_ptr == null or local_len == 0) and local_port == 0) return null;
    const port16: u16 = @intCast(local_port);
    if (family == std.posix.AF.INET6) {
        if (local_ptr == null or local_len == 0) return std.net.Address.initIp6(.{0} ** 16, port16, 0, 0);
        return try std.net.Address.parseIp6(local_ptr.?[0..local_len], port16);
    }
    if (local_ptr == null or local_len == 0) return std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port16);
    return try std.net.Address.parseIp4(local_ptr.?[0..local_len], port16);
}

fn netConnectAddressWithOptions(address: std.net.Address, local_ptr: ?[*]const u8, local_len: u64, local_port: u64, no_delay: u32, keep_alive: u32, keep_alive_initial_delay_secs: u32, timeout_ms: u64) !std.net.Stream {
    const sock_flags = std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC;
    const sockfd = try std.posix.socket(address.any.family, sock_flags, std.posix.IPPROTO.TCP);
    errdefer std.net.Stream.close(.{ .handle = sockfd });

    if (try netParseLocalAddress(local_ptr, local_len, local_port, address.any.family)) |local_address| {
        try std.posix.bind(sockfd, &local_address.any, local_address.getOsSockLen());
    }

    try std.posix.connect(sockfd, &address.any, address.getOsSockLen());
    const stream = std.net.Stream{ .handle = sockfd };

    if (no_delay != 0) {
        const value: c_int = 1;
        if (setSocketOptionRaw(stream.handle, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&value)) != 0) return error.SetSockOptError;
    }
    if (keep_alive != 0) {
        const value: c_int = 1;
        if (setSocketOptionRaw(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, std.mem.asBytes(&value)) != 0) return error.SetSockOptError;
        if (keep_alive_initial_delay_secs > 0) {
            const delay: c_int = @intCast(keep_alive_initial_delay_secs);
            if (setSocketOptionRaw(stream.handle, std.posix.IPPROTO.TCP, std.posix.TCP.KEEPIDLE, std.mem.asBytes(&delay)) != 0) return error.SetSockOptError;
        }
    }
    if (timeout_ms != 0) {
        const tv = timevalFromMs(timeout_ms);
        if (setSocketOptionRaw(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) != 0) return error.SetSockOptError;
        if (setSocketOptionRaw(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) != 0) return error.SetSockOptError;
    }
    return stream;
}

fn netConnectWithOptionalBlockList(host_ptr: ?[*]const u8, host_len: u64, port: u64, blocklist_ptr: ?*anyopaque, out_socket: ?*?*anyopaque) u32 {
    const out = out_socket orelse return 2;
    out.* = null;
    const host = host_ptr.?[0..host_len];
    const host_z = std.heap.page_allocator.dupeZ(u8, host) catch return 2;
    defer std.heap.page_allocator.free(host_z);

    const address = netResolveAddress(host_z, port) catch return 2;

    if (blocklist_ptr) |ptr| {
        const blocklist = blockListHandle(ptr) orelse return 2;
        if (netAddressBlocked(blocklist.allocator, blocklist.rules.items, address)) return 3;
    }

    const stream = std.net.tcpConnectToAddress(address) catch return 2;
    errdefer stream.close();
    return netInitSocketObject(stream, 0, address, out);
}

pub export fn sa_node_plugin_net_connect(host_ptr: ?[*]const u8, host_len: u64, port: u64, out_socket: ?*?*anyopaque) u32 {
    return netConnectWithOptionalBlockList(host_ptr, host_len, port, null, out_socket);
}

pub export fn sa_node_plugin_net_connect_blocklist(host_ptr: ?[*]const u8, host_len: u64, port: u64, blocklist_ptr: ?*anyopaque, out_socket: ?*?*anyopaque) u32 {
    return netConnectWithOptionalBlockList(host_ptr, host_len, port, blocklist_ptr, out_socket);
}

pub export fn sa_node_plugin_net_connect_options(host_ptr: ?[*]const u8, host_len: u64, port: u64, family: u32, local_ptr: ?[*]const u8, local_len: u64, local_port: u64, no_delay: u32, keep_alive: u32, keep_alive_initial_delay_secs: u32, timeout_ms: u64, blocklist_ptr: ?*anyopaque, out_socket: ?*?*anyopaque) u32 {
    const out = out_socket orelse return 2;
    out.* = null;
    const host = (host_ptr orelse return 2)[0..host_len];
    const address = netParseRemoteAddress(host, port, family) catch return 2;
    if (blocklist_ptr) |ptr| {
        const blocklist = blockListHandle(ptr) orelse return 2;
        if (netAddressBlocked(blocklist.allocator, blocklist.rules.items, address)) return 3;
    }
    const stream = netConnectAddressWithOptions(address, local_ptr, local_len, local_port, no_delay, keep_alive, keep_alive_initial_delay_secs, timeout_ms) catch return 2;
    errdefer stream.close();
    return netInitSocketObject(stream, timeout_ms, address, out);
}

pub export fn sa_node_plugin_net_connect_unix(path_ptr: ?[*]const u8, path_len: u64, out_socket: ?*?*anyopaque) u32 {
    const path = path_ptr.?[0..path_len];
    const stream = std.net.connectUnixSocket(path) catch return 2;

    const socket = std.heap.page_allocator.create(SaNetObject) catch return 2;
    socket.* = .{
        .is_server = false,
        .allocator = std.heap.page_allocator,
        .stream = stream,
        .server = null,
        .bytes_read = 0,
        .bytes_written = 0,
        .block_list = std.ArrayList(BlockListRule).init(std.heap.page_allocator),
        .auto_select_family_attempted_addresses = std.ArrayList([]u8).init(std.heap.page_allocator),
    };

    out_socket.?.* = @ptrCast(socket);
    return 0;
}

pub export fn sa_node_plugin_net_listen(host_ptr: ?[*]const u8, host_len: u64, port: u64, out_server: ?*?*anyopaque) u32 {
    const host = host_ptr.?[0..host_len];
    const host_z = std.heap.page_allocator.dupeZ(u8, host) catch return 2;
    defer std.heap.page_allocator.free(host_z);

    const address = if (std.mem.eql(u8, host, "0.0.0.0") or host.len == 0)
        std.net.Address.initIp4(.{ 0, 0, 0, 0 }, @as(u16, @intCast(port)))
    else
        std.net.Address.resolveIp(host_z, @as(u16, @intCast(port))) catch return 2;

    const server_impl = address.listen(.{ .reuse_address = true }) catch return 2;

    const server = std.heap.page_allocator.create(SaNetObject) catch return 2;
    server.* = .{
        .is_server = true,
        .allocator = std.heap.page_allocator,
        .stream = null,
        .server = server_impl,
        .readable = false,
        .writable = false,
        .bytes_read = 0,
        .bytes_written = 0,
        .block_list = std.ArrayList(BlockListRule).init(std.heap.page_allocator),
        .auto_select_family_attempted_addresses = std.ArrayList([]u8).init(std.heap.page_allocator),
    };

    out_server.?.* = @ptrCast(server);
    return 0;
}

pub export fn sa_node_plugin_net_listen_unix(path_ptr: ?[*]const u8, path_len: u64, out_server: ?*?*anyopaque) u32 {
    const path = path_ptr.?[0..path_len];
    const address = std.net.Address.initUnix(path) catch return 2;
    var server_impl = address.listen(.{}) catch return 2;
    errdefer server_impl.deinit();

    const owned_path = std.heap.page_allocator.dupe(u8, path) catch return 2;
    errdefer std.heap.page_allocator.free(owned_path);

    const server = std.heap.page_allocator.create(SaNetObject) catch return 2;
    server.* = .{
        .is_server = true,
        .allocator = std.heap.page_allocator,
        .stream = null,
        .server = server_impl,
        .readable = false,
        .writable = false,
        .bytes_read = 0,
        .bytes_written = 0,
        .block_list = std.ArrayList(BlockListRule).init(std.heap.page_allocator),
        .unix_path = owned_path,
        .auto_select_family_attempted_addresses = std.ArrayList([]u8).init(std.heap.page_allocator),
    };

    out_server.?.* = @ptrCast(server);
    return 0;
}

pub export fn sa_node_plugin_net_accept(server_ptr: ?*anyopaque, out_socket: ?*?*anyopaque) u32 {
    const server: *SaNetObject = @ptrCast(@alignCast(server_ptr orelse return 2));
    if (!server.is_server or server.closed) return 2;
    const connection = if (server.server) |*server_impl| server_impl.accept() catch return 2 else return 2;

    if (netAddressBlocked(server.allocator, server.block_list.items, connection.address)) {
        connection.stream.close();
        if (out_socket) |slot| slot.* = null;
        return 3;
    }

    if (server.max_connections_set and server.connection_count >= server.max_connections) {
        connection.stream.close();
        if (out_socket) |slot| slot.* = null;
        return 3;
    }

    const socket = std.heap.page_allocator.create(SaNetObject) catch return 2;
    socket.* = .{
        .is_server = false,
        .allocator = std.heap.page_allocator,
        .stream = connection.stream,
        .server = null,
        .bytes_read = 0,
        .bytes_written = 0,
        .parent_server = server,
        .counted_connection = true,
        .block_list = std.ArrayList(BlockListRule).init(std.heap.page_allocator),
        .auto_select_family_attempted_addresses = std.ArrayList([]u8).init(std.heap.page_allocator),
    };
    server.connection_count += 1;

    out_socket.?.* = @ptrCast(socket);
    return 0;
}

pub export fn sa_node_plugin_net_server_set_blocklist(server_ptr: ?*anyopaque, blocklist_ptr: ?*anyopaque) u32 {
    const server: *SaNetObject = @ptrCast(@alignCast(server_ptr orelse return 2));
    if (!server.is_server) return 2;
    return netSetBlockList(&server.block_list, blocklist_ptr, server.allocator);
}

pub export fn sa_node_plugin_net_write(socket_ptr: ?*anyopaque, data: ?[*]const u8, data_len: u64) u32 {
    const socket: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (socket.is_server or socket.closed or !socket.writable) return 2;
    const d = data.?[0..data_len];
    socket.stream.?.writer().writeAll(d) catch return 2;
    socket.bytes_written +|= data_len;
    return 0;
}

pub export fn sa_node_plugin_net_read(socket_ptr: ?*anyopaque, max_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const socket: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (socket.is_server or socket.closed or !socket.readable) return 2;
    const buf = std.heap.page_allocator.alloc(u8, max_len) catch return 2;
    errdefer std.heap.page_allocator.free(buf);

    const n = socket.stream.?.reader().read(buf) catch return 2;
    if (n == 0) {
        std.heap.page_allocator.free(buf);
        socket.readable = false;
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return 0;
    }
    socket.bytes_read +|= @intCast(n);

    const owned = std.heap.page_allocator.realloc(buf, n) catch buf[0..n];
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_net_end(socket_ptr: ?*anyopaque) u32 {
    if (socket_ptr) |ptr| {
        const obj: *SaNetObject = @ptrCast(@alignCast(ptr));
        obj.deinit();
    }
    return 0;
}

pub export fn sa_node_plugin_net_server_get_connections(server_ptr: ?*anyopaque, out_count: ?*u64) u32 {
    const server: *SaNetObject = @ptrCast(@alignCast(server_ptr orelse return 2));
    if (!server.is_server) return 2;
    out_count.?.* = server.connection_count;
    return 0;
}

pub export fn sa_node_plugin_net_server_listening(server_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const server: *SaNetObject = @ptrCast(@alignCast(server_ptr orelse return 2));
    if (!server.is_server) return 2;
    out_bool.?.* = if (!server.closed and server.server != null) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_net_server_close(server_ptr: ?*anyopaque) u32 {
    const server: *SaNetObject = @ptrCast(@alignCast(server_ptr orelse return 2));
    if (!server.is_server) return 2;
    server.closeServerHandle();
    server.closed = true;
    server.readable = false;
    server.writable = false;
    return 0;
}

pub export fn sa_node_plugin_net_server_set_max_connections(server_ptr: ?*anyopaque, max_connections: u64) u32 {
    const server: *SaNetObject = @ptrCast(@alignCast(server_ptr orelse return 2));
    if (!server.is_server) return 2;
    server.max_connections = max_connections;
    server.max_connections_set = true;
    return 0;
}

pub export fn sa_node_plugin_net_server_get_max_connections(server_ptr: ?*anyopaque, out_max_connections: ?*u64) u32 {
    const server: *SaNetObject = @ptrCast(@alignCast(server_ptr orelse return 2));
    if (!server.is_server) return 2;
    out_max_connections.?.* = server.max_connections;
    return 0;
}

pub export fn sa_node_plugin_net_ref(handle_ptr: ?*anyopaque) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(handle_ptr orelse return 2));
    obj.has_ref = true;
    return 0;
}

pub export fn sa_node_plugin_net_unref(handle_ptr: ?*anyopaque) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(handle_ptr orelse return 2));
    obj.has_ref = false;
    return 0;
}

pub export fn sa_node_plugin_net_has_ref(handle_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(handle_ptr orelse return 2));
    (out_bool orelse return 2).* = if (obj.has_ref) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_net_address(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) {
        const server = obj.server orelse return 2;
        var out = std.ArrayList(u8).init(std.heap.page_allocator);
        defer out.deinit();
        appendAddressJson(&out, server.listen_address) catch return 2;
        const owned = out.toOwnedSlice() catch return 2;
        out_ptr.?.* = owned.ptr;
        out_len.?.* = owned.len;
        return 0;
    }
    const stream = obj.stream orelse return 2;
    return writeSocketAddressJson(stream.handle, false, out_ptr, out_len);
}

pub export fn sa_node_plugin_net_server_address(server_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(server_ptr orelse return 2));
    if (!obj.is_server) return 2;
    return sa_node_plugin_net_address(server_ptr, out_ptr, out_len);
}

pub export fn sa_node_plugin_net_remote_address(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const stream = obj.stream orelse return 2;
    return writeSocketAddressJson(stream.handle, true, out_ptr, out_len);
}

pub export fn sa_node_plugin_net_local_address(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeSocketAddressProperty(socket_ptr, false, .address, out_ptr, out_len);
}

pub export fn sa_node_plugin_net_local_family(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeSocketAddressProperty(socket_ptr, false, .family, out_ptr, out_len);
}

pub export fn sa_node_plugin_net_local_port(socket_ptr: ?*anyopaque, out_port: ?*u64) u32 {
    return writeSocketAddressPort(socket_ptr, false, out_port);
}

pub export fn sa_node_plugin_net_remote_address_value(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeSocketAddressProperty(socket_ptr, true, .address, out_ptr, out_len);
}

pub export fn sa_node_plugin_net_remote_family(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeSocketAddressProperty(socket_ptr, true, .family, out_ptr, out_len);
}

pub export fn sa_node_plugin_net_remote_port(socket_ptr: ?*anyopaque, out_port: ?*u64) u32 {
    return writeSocketAddressPort(socket_ptr, true, out_port);
}

pub export fn sa_node_plugin_net_bytes_read(socket_ptr: ?*anyopaque, out_bytes: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    out_bytes.?.* = obj.bytes_read;
    return 0;
}

pub export fn sa_node_plugin_net_bytes_written(socket_ptr: ?*anyopaque, out_bytes: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    out_bytes.?.* = obj.bytes_written;
    return 0;
}

pub export fn sa_node_plugin_net_buffer_size(socket_ptr: ?*anyopaque, out_size: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    (out_size orelse return 2).* = 0;
    return 0;
}

pub export fn sa_node_plugin_net_connecting(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    (out_bool orelse return 2).* = 0;
    return 0;
}

pub export fn sa_node_plugin_net_auto_select_family_attempted_addresses(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    const ptr_slot = out_ptr orelse return 2;
    const len_slot = out_len orelse return 2;
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.append('[') catch return 2;
    for (obj.auto_select_family_attempted_addresses.items, 0..) |entry, i| {
        if (i != 0) out.append(',') catch return 2;
        appendJsonString(&out, entry) catch return 2;
    }
    out.append(']') catch return 2;
    const owned = out.toOwnedSlice() catch return 2;
    ptr_slot.* = owned.ptr;
    len_slot.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_net_pending(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    out_bool.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_net_ready_state(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    const state = if (obj.closed or (!obj.readable and !obj.writable))
        "closed"
    else if (obj.readable and obj.writable)
        "open"
    else if (obj.readable)
        "readOnly"
    else
        "writeOnly";
    const owned = std.heap.page_allocator.dupe(u8, state) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

fn timevalFromMs(ms: u64) std.posix.timeval {
    return .{
        .sec = @intCast(ms / 1000),
        .usec = @intCast((ms % 1000) * 1000),
    };
}

pub export fn sa_node_plugin_net_set_timeout(socket_ptr: ?*anyopaque, timeout_ms: u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server or obj.closed) return 2;
    const stream = obj.stream orelse return 2;
    const tv = timevalFromMs(timeout_ms);
    if (setSocketOptionRaw(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) != 0) return 2;
    if (setSocketOptionRaw(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) != 0) return 2;
    obj.timeout_ms = timeout_ms;
    return 0;
}

pub export fn sa_node_plugin_net_get_timeout(socket_ptr: ?*anyopaque, out_timeout_ms: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    out_timeout_ms.?.* = obj.timeout_ms;
    return 0;
}

pub export fn sa_node_plugin_net_readable(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    out_bool.?.* = if (!obj.closed and obj.readable) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_net_writable(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    out_bool.?.* = if (!obj.closed and obj.writable) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_net_closed(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    out_bool.?.* = if (obj.closed) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_net_destroyed(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    out_bool.?.* = if (obj.closed) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_net_destroy(socket_ptr: ?*anyopaque) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server) return 2;
    if (!obj.closed) {
        if (obj.stream) |stream| {
            stream.close();
            obj.stream = null;
        }
        obj.markSocketClosed();
    }
    return 0;
}

const PosixLinger = extern struct {
    l_onoff: c_int,
    l_linger: c_int,
};

pub export fn sa_node_plugin_net_reset_and_destroy(socket_ptr: ?*anyopaque) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server or obj.closed) return 2;
    const stream = obj.stream orelse return 2;
    const linger = PosixLinger{ .l_onoff = 1, .l_linger = 0 };
    if (setSocketOptionRaw(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&linger)) != 0) return 2;
    obj.deinit();
    return 0;
}

pub export fn sa_node_plugin_net_set_no_delay(socket_ptr: ?*anyopaque, enable: u32) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const stream = obj.stream orelse return 2;
    const value: c_int = if (enable != 0) 1 else 0;
    return setSocketOptionRaw(stream.handle, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&value));
}

pub export fn sa_node_plugin_net_set_keep_alive(socket_ptr: ?*anyopaque, enable: u32, initial_delay_secs: u32) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const stream = obj.stream orelse return 2;
    const value: c_int = if (enable != 0) 1 else 0;
    if (setSocketOptionRaw(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, std.mem.asBytes(&value)) != 0) return 2;
    if (enable != 0 and initial_delay_secs > 0) {
        const delay: c_int = @intCast(initial_delay_secs);
        if (setSocketOptionRaw(stream.handle, std.posix.IPPROTO.TCP, std.posix.TCP.KEEPIDLE, std.mem.asBytes(&delay)) != 0) return 2;
    }
    return 0;
}

fn socketSetBuffer(fd: std.posix.socket_t, optname: u32, size: u32) u32 {
    if (size == 0) return 2;
    const value: c_int = @intCast(size);
    return setSocketOptionRaw(fd, std.posix.SOL.SOCKET, @intCast(optname), std.mem.asBytes(&value));
}

fn socketGetBuffer(fd: std.posix.socket_t, optname: u32, out_size: ?*u64) u32 {
    var value: c_int = 0;
    var value_len: std.posix.socklen_t = @sizeOf(c_int);
    if (getsockopt(fd, std.posix.SOL.SOCKET, @intCast(optname), &value, &value_len) != 0) return 2;
    if (value_len != @sizeOf(c_int)) return 2;
    out_size.?.* = @intCast(value);
    return 0;
}

const TypeOfServiceOption = struct {
    level: c_int,
    option: c_int,
};

fn socketTypeOfServiceOption(fd: std.posix.socket_t) !TypeOfServiceOption {
    const addr = try getSocketAddress(fd, false);
    return switch (addr.any.family) {
        std.posix.AF.INET => .{ .level = std.posix.IPPROTO.IP, .option = std.os.linux.IP.TOS },
        std.posix.AF.INET6 => .{ .level = std.posix.IPPROTO.IPV6, .option = std.os.linux.IPV6.TCLASS },
        else => error.UnsupportedAddressFamily,
    };
}

pub export fn sa_node_plugin_net_set_recv_buffer_size(socket_ptr: ?*anyopaque, size: u32) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const stream = obj.stream orelse return 2;
    return socketSetBuffer(stream.handle, std.posix.SO.RCVBUF, size);
}

pub export fn sa_node_plugin_net_set_send_buffer_size(socket_ptr: ?*anyopaque, size: u32) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const stream = obj.stream orelse return 2;
    return socketSetBuffer(stream.handle, std.posix.SO.SNDBUF, size);
}

pub export fn sa_node_plugin_net_get_recv_buffer_size(socket_ptr: ?*anyopaque, out_size: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const stream = obj.stream orelse return 2;
    return socketGetBuffer(stream.handle, std.posix.SO.RCVBUF, out_size);
}

pub export fn sa_node_plugin_net_get_send_buffer_size(socket_ptr: ?*anyopaque, out_size: ?*u64) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const stream = obj.stream orelse return 2;
    return socketGetBuffer(stream.handle, std.posix.SO.SNDBUF, out_size);
}

pub export fn sa_node_plugin_net_set_type_of_service(socket_ptr: ?*anyopaque, tos: u32) u32 {
    if (tos > 255) return 2;
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server or obj.closed) return 2;
    const stream = obj.stream orelse return 2;
    const opt = socketTypeOfServiceOption(stream.handle) catch return 2;
    const value: c_int = @intCast(tos);
    return setSocketOptionRaw(stream.handle, opt.level, opt.option, std.mem.asBytes(&value));
}

pub export fn sa_node_plugin_net_get_type_of_service(socket_ptr: ?*anyopaque, out_tos: ?*u64) u32 {
    const out = out_tos orelse return 2;
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (obj.is_server or obj.closed) return 2;
    const stream = obj.stream orelse return 2;
    const opt = socketTypeOfServiceOption(stream.handle) catch return 2;
    var value: c_int = 0;
    var value_len: std.posix.socklen_t = @sizeOf(c_int);
    if (getsockopt(stream.handle, opt.level, opt.option, &value, &value_len) != 0) return 2;
    if (value_len != @sizeOf(c_int) or value < 0) return 2;
    out.* = @intCast(value);
    return 0;
}

pub export fn sa_node_plugin_net_shutdown_write(socket_ptr: ?*anyopaque) u32 {
    const obj: *SaNetObject = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const stream = obj.stream orelse return 2;
    std.posix.shutdown(stream.handle, .send) catch return 2;
    obj.writable = false;
    return 0;
}

pub const SaDgramSocket = struct {
    allocator: std.mem.Allocator,
    fd: std.posix.socket_t,
    family: std.posix.sa_family_t,
    connected: bool,
    has_ref: bool = true,
    send_block_list: std.ArrayList(BlockListRule),
    receive_block_list: std.ArrayList(BlockListRule),

    fn deinit(self: *SaDgramSocket) void {
        blockListFreeRuleList(self.allocator, &self.send_block_list);
        self.send_block_list.deinit();
        blockListFreeRuleList(self.allocator, &self.receive_block_list);
        self.receive_block_list.deinit();
        std.posix.close(self.fd);
        self.allocator.destroy(self);
    }
};

fn parseDgramAddressFamily(host_ptr: ?[*]const u8, host_len: u64, port: u64, family: std.posix.sa_family_t) !std.net.Address {
    if (port > std.math.maxInt(u16)) return error.PortOutOfRange;
    const host = host_ptr.?[0..host_len];
    if (family == std.posix.AF.INET6) {
        if (host.len == 0 or std.mem.eql(u8, host, "::")) {
            return std.net.Address.initIp6(.{0} ** 16, @as(u16, @intCast(port)), 0, 0);
        }
        return std.net.Address.parseIp6(host, @as(u16, @intCast(port))) catch
            std.net.Address.resolveIp6(host, @as(u16, @intCast(port)));
    }
    if (host.len == 0 or std.mem.eql(u8, host, "0.0.0.0")) {
        return std.net.Address.initIp4(.{ 0, 0, 0, 0 }, @as(u16, @intCast(port)));
    }
    return std.net.Address.resolveIp(host, @as(u16, @intCast(port))) catch
        std.net.Address.parseIp(host, @as(u16, @intCast(port)));
}

fn parseDgramAddress(host_ptr: ?[*]const u8, host_len: u64, port: u64) !std.net.Address {
    return parseDgramAddressFamily(host_ptr, host_len, port, std.posix.AF.INET);
}

fn dgramAddressToOwnedHost(addr: std.net.Address) ![]u8 {
    const allocator = std.heap.page_allocator;
    switch (addr.any.family) {
        std.posix.AF.INET => {
            const bytes = std.mem.asBytes(&addr.in.sa.addr);
            return try std.fmt.allocPrint(allocator, "{}.{}.{}.{}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
        },
        std.posix.AF.INET6 => {
            if (std.mem.eql(u8, addr.in6.sa.addr[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
                return try std.fmt.allocPrint(allocator, "{}.{}.{}.{}", .{
                    addr.in6.sa.addr[12],
                    addr.in6.sa.addr[13],
                    addr.in6.sa.addr[14],
                    addr.in6.sa.addr[15],
                });
            }
            const with_port = try std.fmt.allocPrint(allocator, "{}", .{addr});
            defer allocator.free(with_port);
            if (with_port.len >= 2 and with_port[0] == '[') {
                if (std.mem.lastIndexOfScalar(u8, with_port, ']')) |end| {
                    return try allocator.dupe(u8, with_port[1..end]);
                }
            }
            return try allocator.dupe(u8, with_port);
        },
        else => return error.InvalidAddressFamily,
    }
}

fn parseIpv4AddressBytes(host_ptr: ?[*]const u8, host_len: u64) ![4]u8 {
    const host = host_ptr.?[0..host_len];
    const addr = try std.net.Address.parseIp4(host, 0);
    return std.mem.asBytes(&addr.in.sa.addr).*;
}

fn parseOptionalIpv4AddressBytes(host_ptr: ?[*]const u8, host_len: u64) ![4]u8 {
    if (host_ptr == null or host_len == 0) return .{ 0, 0, 0, 0 };
    return parseIpv4AddressBytes(host_ptr, host_len);
}

fn ipv4BytesToInAddr(bytes: [4]u8) InAddr {
    return .{ .s_addr = bytes };
}

fn parseIpv6AddressBytes(host_ptr: ?[*]const u8, host_len: u64) ![16]u8 {
    const host = host_ptr.?[0..host_len];
    const addr = try std.net.Address.parseIp6(host, 0);
    return addr.in6.sa.addr;
}

fn parseInterfaceIndex(iface_ptr: ?[*]const u8, iface_len: u64) u32 {
    if (iface_ptr == null or iface_len == 0) return 0;
    const iface = iface_ptr.?[0..iface_len];
    return std.fmt.parseInt(u32, iface, 10) catch 0;
}

fn setSocketOptionRaw(fd: std.posix.socket_t, level: c_int, optname: c_int, bytes: []const u8) u32 {
    if (setsockopt(fd, level, optname, bytes.ptr, @intCast(bytes.len)) != 0) return 2;
    return 0;
}

fn dgramAddressBlocked(allocator: std.mem.Allocator, rules: []const BlockListRule, address: std.net.Address) bool {
    if (rules.len == 0) return false;
    const block_address = blockListAddressFromNetAddress(allocator, address) catch return false;
    defer allocator.free(block_address.text);
    return blockListMatchesRules(rules, block_address);
}

fn dgramSetBlockList(dest: *std.ArrayList(BlockListRule), blocklist_ptr: ?*anyopaque, allocator: std.mem.Allocator) u32 {
    if (blocklist_ptr == null) {
        blockListFreeRuleList(allocator, dest);
        return 0;
    }
    const blocklist = blockListHandle(blocklist_ptr) orelse return 2;
    blockListCopyRules(allocator, blocklist, dest) catch return 2;
    return 0;
}

fn dgramCreateSocketWithOptions(family: std.posix.sa_family_t, reuse_addr: bool, reuse_port: bool, ipv6_only: bool, recv_buffer_size: u32, send_buffer_size: u32) !*SaDgramSocket {
    if (family != std.posix.AF.INET and family != std.posix.AF.INET6) return error.InvalidAddressFamily;
    const fd = try std.posix.socket(family, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.UDP);
    errdefer std.posix.close(fd);

    const on: c_int = 1;
    if (reuse_addr) try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&on));
    if (reuse_port) {
        if (@hasDecl(std.posix.SO, "REUSEPORT")) {
            try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&on));
        } else return error.UnsupportedReusePort;
    }
    if (ipv6_only) {
        if (family != std.posix.AF.INET6) return error.InvalidAddressFamily;
        try std.posix.setsockopt(fd, std.posix.IPPROTO.IPV6, std.os.linux.IPV6.V6ONLY, std.mem.asBytes(&on));
    }
    if (recv_buffer_size != 0) {
        if (dgramSetSocketBuffer(fd, std.posix.SO.RCVBUF, recv_buffer_size) != 0) return error.InvalidRecvBufferSize;
    }
    if (send_buffer_size != 0) {
        if (dgramSetSocketBuffer(fd, std.posix.SO.SNDBUF, send_buffer_size) != 0) return error.InvalidSendBufferSize;
    }

    const socket = std.heap.page_allocator.create(SaDgramSocket) catch {
        return error.OutOfMemory;
    };
    socket.* = .{
        .allocator = std.heap.page_allocator,
        .fd = fd,
        .family = family,
        .connected = false,
        .has_ref = true,
        .send_block_list = std.ArrayList(BlockListRule).init(std.heap.page_allocator),
        .receive_block_list = std.ArrayList(BlockListRule).init(std.heap.page_allocator),
    };
    return socket;
}

pub export fn sa_node_plugin_dgram_create() ?*anyopaque {
    const socket = dgramCreateSocketWithOptions(std.posix.AF.INET, false, false, false, 0, 0) catch return null;
    return @ptrCast(socket);
}

pub export fn sa_node_plugin_dgram_create_udp6() ?*anyopaque {
    const socket = dgramCreateSocketWithOptions(std.posix.AF.INET6, false, false, false, 0, 0) catch return null;
    return @ptrCast(socket);
}

pub export fn sa_node_plugin_dgram_create_options(socket_type: u32, reuse_addr: u32, reuse_port: u32, ipv6_only: u32, recv_buffer_size: u32, send_buffer_size: u32, out_socket: ?*?*anyopaque) u32 {
    const out = out_socket orelse return 2;
    const family: std.posix.sa_family_t = switch (socket_type) {
        4 => std.posix.AF.INET,
        6 => std.posix.AF.INET6,
        else => return 2,
    };
    const socket = dgramCreateSocketWithOptions(family, reuse_addr != 0, reuse_port != 0, ipv6_only != 0, recv_buffer_size, send_buffer_size) catch return 2;
    out.* = @ptrCast(socket);
    return 0;
}

pub export fn sa_node_plugin_dgram_bind(socket_ptr: ?*anyopaque, host_ptr: ?[*]const u8, host_len: u64, port: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const address = parseDgramAddressFamily(host_ptr, host_len, port, socket.family) catch return 2;
    std.posix.bind(socket.fd, &address.any, address.getOsSockLen()) catch return 2;
    return 0;
}

pub export fn sa_node_plugin_dgram_send(socket_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64, host_ptr: ?[*]const u8, host_len: u64, port: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const address = parseDgramAddressFamily(host_ptr, host_len, port, socket.family) catch return 2;
    if (dgramAddressBlocked(socket.allocator, socket.send_block_list.items, address)) return 2;
    const data = data_ptr.?[0..data_len];
    _ = std.posix.sendto(socket.fd, data, 0, &address.any, address.getOsSockLen()) catch return 2;
    return 0;
}

pub export fn sa_node_plugin_dgram_connect(socket_ptr: ?*anyopaque, host_ptr: ?[*]const u8, host_len: u64, port: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const address = parseDgramAddressFamily(host_ptr, host_len, port, socket.family) catch return 2;
    if (dgramAddressBlocked(socket.allocator, socket.send_block_list.items, address)) return 2;
    std.posix.connect(socket.fd, &address.any, address.getOsSockLen()) catch return 2;
    socket.connected = true;
    return 0;
}

pub export fn sa_node_plugin_dgram_disconnect(socket_ptr: ?*anyopaque) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    var addr: std.posix.sockaddr = .{ .family = std.posix.AF.UNSPEC, .data = [_]u8{0} ** 14 };
    std.posix.connect(socket.fd, &addr, @sizeOf(std.posix.sockaddr)) catch return 2;
    socket.connected = false;
    return 0;
}

pub export fn sa_node_plugin_dgram_send_connected(socket_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (!socket.connected) return 2;
    const peer = getSocketAddress(socket.fd, true) catch return 2;
    if (dgramAddressBlocked(socket.allocator, socket.send_block_list.items, peer)) return 2;
    const data = data_ptr.?[0..data_len];
    _ = std.posix.send(socket.fd, data, 0) catch return 2;
    return 0;
}

pub export fn sa_node_plugin_dgram_set_send_blocklist(socket_ptr: ?*anyopaque, blocklist_ptr: ?*anyopaque) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    return dgramSetBlockList(&socket.send_block_list, blocklist_ptr, socket.allocator);
}

pub export fn sa_node_plugin_dgram_set_receive_blocklist(socket_ptr: ?*anyopaque, blocklist_ptr: ?*anyopaque) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    return dgramSetBlockList(&socket.receive_block_list, blocklist_ptr, socket.allocator);
}

pub export fn sa_node_plugin_dgram_address(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    return writeSocketAddressJson(socket.fd, false, out_ptr, out_len);
}

pub export fn sa_node_plugin_dgram_remote_address(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    return writeSocketAddressJson(socket.fd, true, out_ptr, out_len);
}

pub export fn sa_node_plugin_dgram_ref(socket_ptr: ?*anyopaque) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    socket.has_ref = true;
    return 0;
}

pub export fn sa_node_plugin_dgram_unref(socket_ptr: ?*anyopaque) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    socket.has_ref = false;
    return 0;
}

pub export fn sa_node_plugin_dgram_has_ref(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    (out_bool orelse return 2).* = if (socket.has_ref) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_dgram_set_broadcast(socket_ptr: ?*anyopaque, enable: u32) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const value: c_int = if (enable != 0) 1 else 0;
    std.posix.setsockopt(socket.fd, std.posix.SOL.SOCKET, std.posix.SO.BROADCAST, std.mem.asBytes(&value)) catch return 2;
    return 0;
}

pub export fn sa_node_plugin_dgram_set_ttl(socket_ptr: ?*anyopaque, ttl: u32) u32 {
    if (ttl == 0 or ttl > 255) return 2;
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const value: c_int = @intCast(ttl);
    std.posix.setsockopt(socket.fd, std.posix.IPPROTO.IP, std.os.linux.IP.TTL, std.mem.asBytes(&value)) catch return 2;
    return 0;
}

pub export fn sa_node_plugin_dgram_set_multicast_ttl(socket_ptr: ?*anyopaque, ttl: u32) u32 {
    if (ttl > 255) return 2;
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const value: c_int = @intCast(ttl);
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IP, std.os.linux.IP.MULTICAST_TTL, std.mem.asBytes(&value));
}

pub export fn sa_node_plugin_dgram_set_multicast_loopback(socket_ptr: ?*anyopaque, enable: u32) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const value: u8 = if (enable != 0) 1 else 0;
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IP, std.os.linux.IP.MULTICAST_LOOP, std.mem.asBytes(&value));
}

pub export fn sa_node_plugin_dgram_set_multicast_interface(socket_ptr: ?*anyopaque, iface_ptr: ?[*]const u8, iface_len: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const iface = parseIpv4AddressBytes(iface_ptr, iface_len) catch return 2;
    const in_addr = ipv4BytesToInAddr(iface);
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IP, std.os.linux.IP.MULTICAST_IF, std.mem.asBytes(&in_addr));
}

pub export fn sa_node_plugin_dgram_set_multicast_interface6(socket_ptr: ?*anyopaque, iface_index: u32) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (socket.family != std.posix.AF.INET6) return 2;
    const value: c_uint = iface_index;
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IPV6, std.os.linux.IPV6.MULTICAST_IF, std.mem.asBytes(&value));
}

pub export fn sa_node_plugin_dgram_set_multicast_hops6(socket_ptr: ?*anyopaque, hops: u32) u32 {
    if (hops > 255) return 2;
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (socket.family != std.posix.AF.INET6) return 2;
    const value: c_int = @intCast(hops);
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IPV6, std.os.linux.IPV6.MULTICAST_HOPS, std.mem.asBytes(&value));
}

pub export fn sa_node_plugin_dgram_set_multicast_loopback6(socket_ptr: ?*anyopaque, enable: u32) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (socket.family != std.posix.AF.INET6) return 2;
    const value: c_uint = if (enable != 0) 1 else 0;
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IPV6, std.os.linux.IPV6.MULTICAST_LOOP, std.mem.asBytes(&value));
}

pub export fn sa_node_plugin_dgram_add_membership(socket_ptr: ?*anyopaque, multicast_ptr: ?[*]const u8, multicast_len: u64, iface_ptr: ?[*]const u8, iface_len: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const multicast = parseIpv4AddressBytes(multicast_ptr, multicast_len) catch return 2;
    const iface = parseOptionalIpv4AddressBytes(iface_ptr, iface_len) catch return 2;
    const req: IpMreq = .{ .imr_multiaddr = ipv4BytesToInAddr(multicast), .imr_interface = ipv4BytesToInAddr(iface) };
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IP, std.os.linux.IP.ADD_MEMBERSHIP, std.mem.asBytes(&req));
}

pub export fn sa_node_plugin_dgram_drop_membership(socket_ptr: ?*anyopaque, multicast_ptr: ?[*]const u8, multicast_len: u64, iface_ptr: ?[*]const u8, iface_len: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const multicast = parseIpv4AddressBytes(multicast_ptr, multicast_len) catch return 2;
    const iface = parseOptionalIpv4AddressBytes(iface_ptr, iface_len) catch return 2;
    const req: IpMreq = .{ .imr_multiaddr = ipv4BytesToInAddr(multicast), .imr_interface = ipv4BytesToInAddr(iface) };
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IP, std.os.linux.IP.DROP_MEMBERSHIP, std.mem.asBytes(&req));
}

pub export fn sa_node_plugin_dgram_add_source_specific_membership(socket_ptr: ?*anyopaque, source_ptr: ?[*]const u8, source_len: u64, multicast_ptr: ?[*]const u8, multicast_len: u64, iface_ptr: ?[*]const u8, iface_len: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (socket.family != std.posix.AF.INET) return 2;
    const source = parseIpv4AddressBytes(source_ptr, source_len) catch return 2;
    const multicast = parseIpv4AddressBytes(multicast_ptr, multicast_len) catch return 2;
    const iface = parseOptionalIpv4AddressBytes(iface_ptr, iface_len) catch return 2;
    const req: IpMreqSource = .{ .imr_multiaddr = ipv4BytesToInAddr(multicast), .imr_interface = ipv4BytesToInAddr(iface), .imr_sourceaddr = ipv4BytesToInAddr(source) };
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IP, std.os.linux.IP.ADD_SOURCE_MEMBERSHIP, std.mem.asBytes(&req));
}

pub export fn sa_node_plugin_dgram_drop_source_specific_membership(socket_ptr: ?*anyopaque, source_ptr: ?[*]const u8, source_len: u64, multicast_ptr: ?[*]const u8, multicast_len: u64, iface_ptr: ?[*]const u8, iface_len: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (socket.family != std.posix.AF.INET) return 2;
    const source = parseIpv4AddressBytes(source_ptr, source_len) catch return 2;
    const multicast = parseIpv4AddressBytes(multicast_ptr, multicast_len) catch return 2;
    const iface = parseOptionalIpv4AddressBytes(iface_ptr, iface_len) catch return 2;
    const req: IpMreqSource = .{ .imr_multiaddr = ipv4BytesToInAddr(multicast), .imr_interface = ipv4BytesToInAddr(iface), .imr_sourceaddr = ipv4BytesToInAddr(source) };
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IP, std.os.linux.IP.DROP_SOURCE_MEMBERSHIP, std.mem.asBytes(&req));
}

pub export fn sa_node_plugin_dgram_add_membership6(socket_ptr: ?*anyopaque, multicast_ptr: ?[*]const u8, multicast_len: u64, iface_ptr: ?[*]const u8, iface_len: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (socket.family != std.posix.AF.INET6) return 2;
    const multicast = parseIpv6AddressBytes(multicast_ptr, multicast_len) catch return 2;
    const req: Ipv6Mreq = .{ .ipv6mr_multiaddr = multicast, .ipv6mr_interface = parseInterfaceIndex(iface_ptr, iface_len) };
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IPV6, std.os.linux.IPV6.ADD_MEMBERSHIP, std.mem.asBytes(&req));
}

pub export fn sa_node_plugin_dgram_drop_membership6(socket_ptr: ?*anyopaque, multicast_ptr: ?[*]const u8, multicast_len: u64, iface_ptr: ?[*]const u8, iface_len: u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    if (socket.family != std.posix.AF.INET6) return 2;
    const multicast = parseIpv6AddressBytes(multicast_ptr, multicast_len) catch return 2;
    const req: Ipv6Mreq = .{ .ipv6mr_multiaddr = multicast, .ipv6mr_interface = parseInterfaceIndex(iface_ptr, iface_len) };
    return setSocketOptionRaw(socket.fd, std.posix.IPPROTO.IPV6, std.os.linux.IPV6.DROP_MEMBERSHIP, std.mem.asBytes(&req));
}

fn dgramSetSocketBuffer(fd: std.posix.socket_t, optname: u32, size: u32) u32 {
    if (size == 0) return 2;
    const value: c_int = @intCast(size);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, optname, std.mem.asBytes(&value)) catch return 2;
    return 0;
}

fn dgramGetSocketBuffer(fd: std.posix.socket_t, optname: u32, out_size: ?*u64) u32 {
    var value: c_int = 0;
    var value_len: std.posix.socklen_t = @sizeOf(c_int);
    if (getsockopt(fd, std.posix.SOL.SOCKET, @intCast(optname), &value, &value_len) != 0) return 2;
    if (value_len != @sizeOf(c_int)) return 2;
    out_size.?.* = @intCast(value);
    return 0;
}

pub export fn sa_node_plugin_dgram_set_recv_buffer_size(socket_ptr: ?*anyopaque, size: u32) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    return dgramSetSocketBuffer(socket.fd, std.posix.SO.RCVBUF, size);
}

pub export fn sa_node_plugin_dgram_set_send_buffer_size(socket_ptr: ?*anyopaque, size: u32) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    return dgramSetSocketBuffer(socket.fd, std.posix.SO.SNDBUF, size);
}

pub export fn sa_node_plugin_dgram_get_recv_buffer_size(socket_ptr: ?*anyopaque, out_size: ?*u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    return dgramGetSocketBuffer(socket.fd, std.posix.SO.RCVBUF, out_size);
}

pub export fn sa_node_plugin_dgram_get_send_buffer_size(socket_ptr: ?*anyopaque, out_size: ?*u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    return dgramGetSocketBuffer(socket.fd, std.posix.SO.SNDBUF, out_size);
}

pub export fn sa_node_plugin_dgram_get_send_queue_size(socket_ptr: ?*anyopaque, out_size: ?*u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    _ = socket;
    (out_size orelse return 2).* = 0;
    return 0;
}

pub export fn sa_node_plugin_dgram_get_send_queue_count(socket_ptr: ?*anyopaque, out_count: ?*u64) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    _ = socket;
    (out_count orelse return 2).* = 0;
    return 0;
}

pub export fn sa_node_plugin_dgram_recv(
    socket_ptr: ?*anyopaque,
    max_len: u64,
    out_ptr: ?*?[*]const u8,
    out_len: ?*u64,
    out_host_ptr: ?*?[*]const u8,
    out_host_len: ?*u64,
    out_port: ?*u64,
) u32 {
    const socket: *SaDgramSocket = @ptrCast(@alignCast(socket_ptr orelse return 2));
    const buf = std.heap.page_allocator.alloc(u8, max_len) catch return 2;
    errdefer std.heap.page_allocator.free(buf);

    var src_addr: std.net.Address = undefined;
    var src_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    const n = while (true) {
        src_len = @sizeOf(std.posix.sockaddr.storage);
        const read_len = std.posix.recvfrom(socket.fd, buf, 0, &src_addr.any, &src_len) catch return 2;
        if (!dgramAddressBlocked(socket.allocator, socket.receive_block_list.items, src_addr)) break read_len;
    };
    const owned = std.heap.page_allocator.alloc(u8, n) catch return 2;
    @memcpy(owned[0..n], buf[0..n]);
    std.heap.page_allocator.free(buf);
    const host = dgramAddressToOwnedHost(src_addr) catch return 2;

    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    out_host_ptr.?.* = host.ptr;
    out_host_len.?.* = host.len;
    out_port.?.* = src_addr.getPort();
    return 0;
}

pub export fn sa_node_plugin_dgram_close(socket_ptr: ?*anyopaque) u32 {
    if (socket_ptr) |ptr| {
        const socket: *SaDgramSocket = @ptrCast(@alignCast(ptr));
        socket.deinit();
    }
    return 0;
}

// --- Phase 6: fs read-only utilities ---

pub export fn sa_node_plugin_fs_stat(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    var file = if (std.fs.path.isAbsolute(path_z))
        std.fs.openFileAbsolute(path_z, .{}) catch return 2
    else
        std.fs.cwd().openFile(path_z, .{}) catch return 2;
    defer file.close();

    const stat = file.stat() catch return 2;

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();

    const is_file = stat.kind == .file;
    const is_dir = stat.kind == .directory;
    const is_symlink = stat.kind == .sym_link;

    var out_buf: [512]u8 = undefined;
    const item = std.fmt.bufPrint(&out_buf, "{{\"size\":{d},\"mtime\":{d},\"atime\":{d},\"ctime\":{d},\"isFile\":{s},\"isDirectory\":{s},\"isSymbolicLink\":{s},\"mode\":{d}}}", .{
        stat.size, stat.mtime, stat.mtime, stat.mtime, // Zig stat only has mtime easily
        if (is_file) "true" else "false", if (is_dir) "true" else "false", if (is_symlink) "true" else "false", 0o644, // dummy mode
    }) catch return 2;
    json.appendSlice(item) catch return 2;

    const slice = json.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_fs_lstat(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_fs_stat(path_ptr, path_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_fs_readdir(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    var dir = if (std.fs.path.isAbsolute(path_z))
        std.fs.openDirAbsolute(path_z, .{ .iterate = true }) catch return 2
    else
        std.fs.cwd().openDir(path_z, .{ .iterate = true }) catch return 2;
    defer dir.close();

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();

    json.appendSlice("[") catch return 2;

    var first = true;
    var it = dir.iterate();
    while (it.next() catch return 2) |entry| {
        if (!first) json.appendSlice(",") catch return 2;
        first = false;
        json.appendSlice("\"") catch return 2;
        json.appendSlice(entry.name) catch return 2;
        json.appendSlice("\"") catch return 2;
    }

    json.appendSlice("]") catch return 2;

    const slice = json.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_fs_readdir_with_types(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    var dir = if (std.fs.path.isAbsolute(path_z))
        std.fs.openDirAbsolute(path_z, .{ .iterate = true }) catch return 2
    else
        std.fs.cwd().openDir(path_z, .{ .iterate = true }) catch return 2;
    defer dir.close();

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();

    json.appendSlice("[") catch return 2;

    var first = true;
    var it = dir.iterate();
    while (it.next() catch return 2) |entry| {
        if (!first) json.appendSlice(",") catch return 2;
        first = false;
        const type_str = switch (entry.kind) {
            .file => "1",
            .directory => "2",
            .sym_link => "3",
            else => "0",
        };
        json.appendSlice("{\"name\":\"") catch return 2;
        json.appendSlice(entry.name) catch return 2;
        json.appendSlice("\",\"type\":") catch return 2;
        json.appendSlice(type_str) catch return 2;
        json.appendSlice("}") catch return 2;
    }

    json.appendSlice("]") catch return 2;

    const slice = json.toOwnedSlice() catch return 2;
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_fs_readlink(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const target = if (std.fs.path.isAbsolute(path_z))
        std.fs.readLinkAbsolute(path_z, &buf) catch return 2
    else
        std.fs.cwd().readLink(path_z, &buf) catch return 2;

    const owned = std.heap.page_allocator.dupe(u8, target) catch return 2;
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_fs_realpath(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    const resolved = std.fs.path.resolve(std.heap.page_allocator, &.{path_z}) catch return 2;
    out_ptr.?.* = resolved.ptr;
    out_len.?.* = resolved.len;
    return 0;
}

pub export fn sa_node_plugin_fs_exists(path_ptr: ?[*]const u8, path_len: u64, out_bool: ?*u32) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    var exists = false;
    if (std.fs.path.isAbsolute(path_z)) {
        if (std.fs.openFileAbsolute(path_z, .{})) |file| {
            file.close();
            exists = true;
        } else |_| {}
    } else {
        if (std.fs.cwd().openFile(path_z, .{})) |file| {
            file.close();
            exists = true;
        } else |_| {}
    }
    out_bool.?.* = if (exists) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_fs_access(path_ptr: ?[*]const u8, path_len: u64, mode: u32, out_bool: ?*u32) u32 {
    _ = mode;
    return sa_node_plugin_fs_exists(path_ptr, path_len, out_bool);
}

pub export fn sa_node_plugin_fs_read_file(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    var file = if (std.fs.path.isAbsolute(path_z))
        std.fs.openFileAbsolute(path_z, .{}) catch return 2
    else
        std.fs.cwd().openFile(path_z, .{}) catch return 2;
    defer file.close();

    const size = (file.stat() catch return 2).size;
    const buf = std.heap.page_allocator.alloc(u8, size) catch return 2;
    errdefer std.heap.page_allocator.free(buf);

    const bytes_read = file.readAll(buf) catch return 2;
    if (bytes_read != size) return 2;

    out_ptr.?.* = buf.ptr;
    out_len.?.* = size;
    return 0;
}

pub export fn sa_node_plugin_fs_write_file(path_ptr: ?[*]const u8, path_len: u64, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    const data = if (data_ptr) |p| p[0..data_len] else &[_]u8{};

    var file = if (std.fs.path.isAbsolute(path_z))
        std.fs.createFileAbsolute(path_z, .{}) catch return 2
    else
        std.fs.cwd().createFile(path_z, .{}) catch return 2;
    defer file.close();

    file.writeAll(data) catch return 2;
    return 0;
}

pub export fn sa_node_plugin_fs_mkdir(path_ptr: ?[*]const u8, path_len: u64, recursive: u8) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    const is_abs = std.fs.path.isAbsolute(path_z);
    if (recursive != 0) {
        if (is_abs) {
            var root_dir = std.fs.openDirAbsolute("/", .{}) catch return 2;
            defer root_dir.close();
            root_dir.makePath(path_z[1..]) catch return 2;
        } else {
            std.fs.cwd().makePath(path_z) catch return 2;
        }
    } else {
        if (is_abs) {
            std.fs.makeDirAbsolute(path_z) catch return 2;
        } else {
            std.fs.cwd().makeDir(path_z) catch return 2;
        }
    }
    return 0;
}

pub export fn sa_node_plugin_fs_rmdir(path_ptr: ?[*]const u8, path_len: u64) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    if (std.fs.path.isAbsolute(path_z)) {
        std.fs.deleteDirAbsolute(path_z) catch return 2;
    } else {
        std.fs.cwd().deleteDir(path_z) catch return 2;
    }
    return 0;
}

pub export fn sa_node_plugin_fs_unlink(path_ptr: ?[*]const u8, path_len: u64) u32 {
    const path = path_ptr.?[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return 2;
    defer std.heap.page_allocator.free(path_z);

    if (std.fs.path.isAbsolute(path_z)) {
        std.fs.deleteFileAbsolute(path_z) catch return 2;
    } else {
        std.fs.cwd().deleteFile(path_z) catch return 2;
    }
    return 0;
}

pub export fn sa_node_plugin_fs_rename(old_ptr: ?[*]const u8, old_len: u64, new_ptr: ?[*]const u8, new_len: u64) u32 {
    const old = old_ptr.?[0..old_len];
    const old_z = std.heap.page_allocator.dupeZ(u8, old) catch return 2;
    defer std.heap.page_allocator.free(old_z);

    const new = new_ptr.?[0..new_len];
    const new_z = std.heap.page_allocator.dupeZ(u8, new) catch return 2;
    defer std.heap.page_allocator.free(new_z);

    if (std.fs.path.isAbsolute(old_z) and std.fs.path.isAbsolute(new_z)) {
        std.fs.renameAbsolute(old_z, new_z) catch return 2;
    } else {
        std.fs.cwd().rename(old_z, new_z) catch return 2;
    }
    return 0;
}

pub export fn sa_node_plugin_fs_copy_file(src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64) u32 {
    const src = src_ptr.?[0..src_len];
    const src_z = std.heap.page_allocator.dupeZ(u8, src) catch return 2;
    defer std.heap.page_allocator.free(src_z);

    const dst = dst_ptr.?[0..dst_len];
    const dst_z = std.heap.page_allocator.dupeZ(u8, dst) catch return 2;
    defer std.heap.page_allocator.free(dst_z);

    if (std.fs.path.isAbsolute(src_z) and std.fs.path.isAbsolute(dst_z)) {
        std.fs.copyFileAbsolute(src_z, dst_z, .{}) catch return 2;
    } else {
        std.fs.cwd().copyFile(src_z, std.fs.cwd(), dst_z, .{}) catch return 2;
    }
    return 0;
}

pub export fn sa_node_plugin_process_exec(
    argv_ptr: ?*const anyopaque,
    argv_len: u64,
    cwd_ptr: ?[*]const u8,
    cwd_len: u64,
    out_code: ?*u32,
    out_stdout_ptr: ?*?[*]const u8,
    out_stdout_len: ?*u64,
    out_stderr_ptr: ?*?[*]const u8,
    out_stderr_len: ?*u64,
) u32 {
    const allocator = std.heap.page_allocator;
    if (argv_len == 0 or argv_ptr == null) return 2;

    const slices: [*]const SaSlice = @ptrCast(@alignCast(argv_ptr.?));
    var argv = allocator.alloc([]const u8, argv_len) catch return 2;
    defer allocator.free(argv);

    var i: usize = 0;
    while (i < argv_len) : (i += 1) {
        argv[i] = slices[i].ptr[0..slices[i].len];
    }

    var cwd: ?[]const u8 = null;
    if (cwd_ptr) |ptr| {
        if (cwd_len > 0) {
            cwd = ptr[0..cwd_len];
        }
    }

    const run_res = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = cwd,
        .max_output_bytes = 10 * 1024 * 1024,
    }) catch return 2;

    switch (run_res.term) {
        .Exited => |code| out_code.?.* = code,
        else => out_code.?.* = 1,
    }

    out_stdout_ptr.?.* = run_res.stdout.ptr;
    out_stdout_len.?.* = run_res.stdout.len;
    out_stderr_ptr.?.* = run_res.stderr.ptr;
    out_stderr_len.?.* = run_res.stderr.len;

    return 0;
}

// --- Console Module ---
var console_timers = std.StringHashMap(i64).init(std.heap.page_allocator);

pub export fn sa_node_plugin_console_log(data_ptr: ?[*]const u8, data_len: u64) u32 {
    if (data_ptr) |ptr| {
        const slice = ptr[0..data_len];
        std.io.getStdOut().writeAll(slice) catch return 2;
        std.io.getStdOut().writeAll("\n") catch return 2;
    }
    return 0;
}

pub export fn sa_node_plugin_console_error(data_ptr: ?[*]const u8, data_len: u64) u32 {
    if (data_ptr) |ptr| {
        const slice = ptr[0..data_len];
        std.io.getStdErr().writeAll(slice) catch return 2;
        std.io.getStdErr().writeAll("\n") catch return 2;
    }
    return 0;
}

pub export fn sa_node_plugin_console_time(label_ptr: ?[*]const u8, label_len: u64) u32 {
    if (label_ptr) |ptr| {
        const label = ptr[0..label_len];
        const label_dup = std.heap.page_allocator.dupe(u8, label) catch return 2;
        console_timers.put(label_dup, std.time.milliTimestamp()) catch return 2;
    }
    return 0;
}

pub export fn sa_node_plugin_console_time_end(label_ptr: ?[*]const u8, label_len: u64, out_ms: ?*f64) u32 {
    if (label_ptr) |ptr| {
        const label = ptr[0..label_len];
        if (console_timers.fetchRemove(label)) |kv| {
            const start = kv.value;
            const elapsed = @as(f64, @floatFromInt(std.time.milliTimestamp() - start));
            if (out_ms) |slot| slot.* = elapsed;
            std.heap.page_allocator.free(kv.key);
            return 0;
        }
    }
    return 2;
}

pub export fn sa_node_plugin_console_clear() u32 {
    std.io.getStdOut().writeAll("\x1b[2J\x1b[H") catch return 2;
    return 0;
}

// --- Timers Module ---
pub export fn sa_node_plugin_timers_sleep(ms: u64) u32 {
    std.time.sleep(ms * std.time.ns_per_ms);
    return 0;
}

// --- String Decoder Module ---
pub const StringDecoder = struct {
    allocator: std.mem.Allocator,
    buf: [4]u8 = undefined,
    buf_len: u8 = 0,

    fn init(allocator: std.mem.Allocator) !*StringDecoder {
        const self = try allocator.create(StringDecoder);
        self.* = .{
            .allocator = allocator,
            .buf_len = 0,
        };
        return self;
    }

    fn write(self: *StringDecoder, chunk: []const u8) ![]const u8 {
        var out = std.ArrayList(u8).init(self.allocator);
        errdefer out.deinit();

        var i: usize = 0;
        if (self.buf_len > 0) {
            const needed = try utf8SequenceLength(self.buf[0]);
            while (self.buf_len < needed and i < chunk.len) {
                self.buf[self.buf_len] = chunk[i];
                self.buf_len += 1;
                i += 1;
            }
            if (self.buf_len == needed) {
                try out.appendSlice(self.buf[0..needed]);
                self.buf_len = 0;
            } else {
                return try out.toOwnedSlice();
            }
        }

        var start = i;
        while (i < chunk.len) {
            const len = try utf8SequenceLength(chunk[i]);
            if (i + len <= chunk.len) {
                i += len;
            } else {
                try out.appendSlice(chunk[start..i]);
                const tail_len = chunk.len - i;
                @memcpy(self.buf[0..tail_len], chunk[i..]);
                self.buf_len = @intCast(tail_len);
                i = chunk.len;
                start = i;
            }
        }
        if (start < chunk.len) {
            try out.appendSlice(chunk[start..]);
        }
        return try out.toOwnedSlice();
    }

    fn end(self: *StringDecoder, chunk: []const u8) ![]const u8 {
        const written = try self.write(chunk);
        var out = std.ArrayList(u8).init(self.allocator);
        errdefer out.deinit();
        try out.appendSlice(written);
        self.allocator.free(written);
        if (self.buf_len > 0) {
            try out.appendSlice("\xEF\xBF\xBD");
            self.buf_len = 0;
        }
        return try out.toOwnedSlice();
    }

    fn deinit(self: *StringDecoder) void {
        self.allocator.destroy(self);
    }
};

fn utf8SequenceLength(lead: u8) !u8 {
    if (lead & 0x80 == 0) return 1;
    if (lead & 0xE0 == 0xC0) return 2;
    if (lead & 0xF0 == 0xE0) return 3;
    if (lead & 0xF8 == 0xF0) return 4;
    return error.InvalidUtf8;
}

pub export fn sa_node_plugin_string_decoder_create() ?*anyopaque {
    const sd = StringDecoder.init(std.heap.page_allocator) catch return null;
    return @ptrCast(sd);
}

pub export fn sa_node_plugin_string_decoder_write(sd_ptr: ?*anyopaque, chunk_ptr: ?[*]const u8, chunk_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const sd = @as(*StringDecoder, @ptrCast(@alignCast(sd_ptr orelse return 2)));
    const chunk = chunk_ptr.?[0..chunk_len];
    const decoded = sd.write(chunk) catch return 2;
    out_ptr.?.* = decoded.ptr;
    out_len.?.* = decoded.len;
    return 0;
}

pub export fn sa_node_plugin_string_decoder_end(sd_ptr: ?*anyopaque, chunk_ptr: ?[*]const u8, chunk_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const sd = @as(*StringDecoder, @ptrCast(@alignCast(sd_ptr orelse return 2)));
    const chunk = if (chunk_len == 0) "" else (chunk_ptr orelse return 2)[0..chunk_len];
    const decoded = sd.end(chunk) catch return 2;
    out_ptr.?.* = decoded.ptr;
    out_len.?.* = decoded.len;
    return 0;
}

pub export fn sa_node_plugin_string_decoder_free(sd_ptr: ?*anyopaque) u32 {
    if (sd_ptr) |ptr| {
        const sd = @as(*StringDecoder, @ptrCast(@alignCast(ptr)));
        sd.deinit();
    }
    return 0;
}
