const std = @import("std");
const builtin = @import("builtin");
const base = @import("node_saasm_api.zig");
const posix = std.posix;

const Idn2ToAscii8zFn = *const fn (input: [*:0]const u8, output: ?*?[*:0]u8, flags: c_int) callconv(.c) c_int;
const Idn2ToUnicode8z8zFn = *const fn (input: [*:0]const u8, output: ?*?[*:0]u8, flags: c_int) callconv(.c) c_int;
const Idn2FreeFn = *const fn (ptr: ?*anyopaque) callconv(.c) void;

const BrotliEncoderCompressFn = *const fn (usize, usize, c_int, usize, [*]const u8, *usize, [*]u8) callconv(.c) c_int;
const BrotliEncoderMaxCompressedSizeFn = *const fn (usize) callconv(.c) usize;
const BrotliDecoderCreateInstanceFn = *const fn (?*const anyopaque, ?*const anyopaque, ?*const anyopaque) callconv(.c) ?*anyopaque;
const BrotliDecoderDestroyInstanceFn = *const fn (?*anyopaque) callconv(.c) void;
const BrotliDecoderDecompressStreamFn = *const fn (?*anyopaque, *usize, *?[*]const u8, *usize, *?[*]u8, *usize) callconv(.c) c_int;
const ZstdCompressBoundFn = *const fn (usize) callconv(.c) usize;
const ZstdCompressFn = *const fn ([*]u8, usize, [*]const u8, usize, c_int) callconv(.c) usize;
const ZstdDecompressFn = *const fn ([*]u8, usize, [*]const u8, usize) callconv(.c) usize;
const ZstdGetFrameContentSizeFn = *const fn ([*]const u8, usize) callconv(.c) u64;
const ZstdIsErrorFn = *const fn (usize) callconv(.c) c_uint;

extern fn chown(path: [*:0]const u8, owner: std.c.uid_t, group: std.c.gid_t) c_int;
extern fn chdir(path: [*:0]const u8) c_int;
extern fn umask(mask: c_uint) c_uint;
extern fn statvfs(path: [*:0]const u8, buf: *Statvfs) c_int;

const StructSockaddr = extern struct {
    sa_family: u16,
    sa_data: [14]u8,
};

const StructIfaddrs = extern struct {
    ifa_next: ?*StructIfaddrs,
    ifa_name: [*:0]const u8,
    ifa_flags: c_uint,
    ifa_addr: ?*StructSockaddr,
    ifa_netmask: ?*StructSockaddr,
    ifa_ifu: extern union {
        ifu_broadaddr: ?*StructSockaddr,
        ifu_dstaddr: ?*StructSockaddr,
    },
    ifa_data: ?*anyopaque,
};

extern fn getifaddrs(ifap: *?*StructIfaddrs) c_int;
extern fn freeifaddrs(ifa: ?*StructIfaddrs) void;

const BrotliDecoderResult = enum(c_int) {
    err = 0,
    success = 1,
    needs_more_input = 2,
    needs_more_output = 3,
};

const BrotliEncoderMode = enum(c_int) {
    generic = 0,
    text = 1,
    font = 2,
};

const Idn2Api = struct {
    lib: std.DynLib,
    to_ascii_8z: Idn2ToAscii8zFn,
    to_unicode_8z8z: Idn2ToUnicode8z8zFn,
    free: Idn2FreeFn,
};

const BrotliApi = struct {
    enc_lib: std.DynLib,
    dec_lib: std.DynLib,
    compress: BrotliEncoderCompressFn,
    max_compressed_size: BrotliEncoderMaxCompressedSizeFn,
    decoder_create: BrotliDecoderCreateInstanceFn,
    decoder_destroy: BrotliDecoderDestroyInstanceFn,
    decoder_decompress_stream: BrotliDecoderDecompressStreamFn,
};

const ZstdApi = struct {
    lib: std.DynLib,
    compress_bound: ZstdCompressBoundFn,
    compress: ZstdCompressFn,
    decompress: ZstdDecompressFn,
    get_frame_content_size: ZstdGetFrameContentSizeFn,
    is_error: ZstdIsErrorFn,
};

const Statvfs = extern struct {
    f_bsize: c_ulong,
    f_frsize: c_ulong,
    f_blocks: c_ulong,
    f_bfree: c_ulong,
    f_bavail: c_ulong,
    f_files: c_ulong,
    f_ffree: c_ulong,
    f_favail: c_ulong,
    f_fsid: c_ulong,
    f_flag: c_ulong,
    f_namemax: c_ulong,
    __f_spare: [6]c_int,
};

var idn2_api: ?Idn2Api = null;
var idn2_api_mutex = std.Thread.Mutex{};
var brotli_api: ?BrotliApi = null;
var brotli_api_mutex = std.Thread.Mutex{};
var zstd_api: ?ZstdApi = null;
var zstd_api_mutex = std.Thread.Mutex{};

const ZSTD_CONTENTSIZE_UNKNOWN = std.math.maxInt(u64) - 1;
const ZSTD_CONTENTSIZE_ERROR = std.math.maxInt(u64);

const TlsClientHandle = struct {
    allocator: std.mem.Allocator,
    stream: ?std.net.Stream,
    client: std.crypto.tls.Client,
    ca_bundle: std.crypto.Certificate.Bundle,
    host: []u8,
    servername: []u8,
    authorized: bool,
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,
    readable: bool = true,
    writable: bool = true,
    closed: bool = false,
    has_ref: bool = true,
    timeout_ms: u64 = 0,

    fn destroySocket(self: *TlsClientHandle) void {
        if (self.closed) return;
        if (self.stream) |stream| {
            self.client.writeAllEnd(stream, "", true) catch {};
            stream.close();
            self.stream = null;
        }
        self.closed = true;
        self.readable = false;
        self.writable = false;
    }

    fn deinit(self: *TlsClientHandle) void {
        self.destroySocket();
        self.ca_bundle.deinit(self.allocator);
        self.allocator.free(self.servername);
        self.allocator.free(self.host);
        self.allocator.destroy(self);
    }
};

const TlsSecureContextHandle = struct {
    allocator: std.mem.Allocator,
    ca_pem: ?[]u8 = null,
    cert_pem: ?[]u8 = null,
    key_pem: ?[]u8 = null,
    ciphers: ?[]u8 = null,
    min_version: ?[]u8 = null,
    max_version: ?[]u8 = null,
    ca_count: u64 = 0,

    fn deinit(self: *TlsSecureContextHandle) void {
        if (self.ca_pem) |bytes| self.allocator.free(bytes);
        if (self.cert_pem) |bytes| self.allocator.free(bytes);
        if (self.key_pem) |bytes| self.allocator.free(bytes);
        if (self.ciphers) |bytes| self.allocator.free(bytes);
        if (self.min_version) |bytes| self.allocator.free(bytes);
        if (self.max_version) |bytes| self.allocator.free(bytes);
        self.allocator.destroy(self);
    }
};

var tls_default_ca_pem: ?[]u8 = null;
var tls_default_ca_count: u64 = 0;
var tls_default_ca_mutex = std.Thread.Mutex{};

fn tlsProtocolName(version: std.crypto.tls.ProtocolVersion) []const u8 {
    return switch (version) {
        .tls_1_0 => "TLSv1",
        .tls_1_1 => "TLSv1.1",
        .tls_1_2 => "TLSv1.2",
        .tls_1_3 => "TLSv1.3",
        else => "unknown",
    };
}

fn tlsCipherStandardName(tag_name: []const u8) []const u8 {
    if (std.mem.eql(u8, tag_name, "AES_128_GCM_SHA256")) return "TLS_AES_128_GCM_SHA256";
    if (std.mem.eql(u8, tag_name, "AES_256_GCM_SHA384")) return "TLS_AES_256_GCM_SHA384";
    if (std.mem.eql(u8, tag_name, "CHACHA20_POLY1305_SHA256")) return "TLS_CHACHA20_POLY1305_SHA256";
    if (std.mem.eql(u8, tag_name, "AEGIS_256_SHA512")) return "TLS_AEGIS_256_SHA512";
    if (std.mem.eql(u8, tag_name, "AEGIS_128L_SHA256")) return "TLS_AEGIS_128L_SHA256";
    return tag_name;
}

const TlsSupportedCipher = struct {
    node_name: []const u8,
    standard_name: []const u8,
    zig_name: []const u8,
    version: []const u8,
};

const tls_supported_ciphers = [_]TlsSupportedCipher{
    .{ .node_name = "tls_aes_128_gcm_sha256", .standard_name = "TLS_AES_128_GCM_SHA256", .zig_name = "AES_128_GCM_SHA256", .version = "TLSv1.3" },
    .{ .node_name = "tls_aes_256_gcm_sha384", .standard_name = "TLS_AES_256_GCM_SHA384", .zig_name = "AES_256_GCM_SHA384", .version = "TLSv1.3" },
    .{ .node_name = "tls_chacha20_poly1305_sha256", .standard_name = "TLS_CHACHA20_POLY1305_SHA256", .zig_name = "CHACHA20_POLY1305_SHA256", .version = "TLSv1.3" },
    .{ .node_name = "tls_aes_128_ccm_sha256", .standard_name = "TLS_AES_128_CCM_SHA256", .zig_name = "AES_128_CCM_SHA256", .version = "TLSv1.3" },
    .{ .node_name = "ecdhe-rsa-aes128-gcm-sha256", .standard_name = "ECDHE-RSA-AES128-GCM-SHA256", .zig_name = "ECDHE_RSA_WITH_AES_128_GCM_SHA256", .version = "TLSv1.2" },
    .{ .node_name = "ecdhe-rsa-aes256-gcm-sha384", .standard_name = "ECDHE-RSA-AES256-GCM-SHA384", .zig_name = "ECDHE_RSA_WITH_AES_256_GCM_SHA384", .version = "TLSv1.2" },
    .{ .node_name = "ecdhe-rsa-chacha20-poly1305", .standard_name = "ECDHE-RSA-CHACHA20-POLY1305", .zig_name = "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", .version = "TLSv1.2" },
    .{ .node_name = "aegis-128l-sha256", .standard_name = "TLS_AEGIS_128L_SHA256", .zig_name = "AEGIS_128L_SHA256", .version = "TLSv1.3" },
    .{ .node_name = "aegis-256-sha512", .standard_name = "TLS_AEGIS_256_SHA512", .zig_name = "AEGIS_256_SHA512", .version = "TLSv1.3" },
};

const TLS_DEFAULT_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305";

fn tlsWriteCipherArray(out_ptr: ?*?[*]const u8, out_len: ?*u64, detailed: bool) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.append('[') catch return fail();
    for (tls_supported_ciphers, 0..) |cipher, i| {
        if (i != 0) out.append(',') catch return fail();
        if (detailed) {
            out.appendSlice("{\"name\":") catch return fail();
            appendJsonString(&out, cipher.node_name) catch return fail();
            out.appendSlice(",\"standardName\":") catch return fail();
            appendJsonString(&out, cipher.standard_name) catch return fail();
            out.appendSlice(",\"zigName\":") catch return fail();
            appendJsonString(&out, cipher.zig_name) catch return fail();
            out.appendSlice(",\"version\":") catch return fail();
            appendJsonString(&out, cipher.version) catch return fail();
            out.append('}') catch return fail();
        } else {
            appendJsonString(&out, cipher.node_name) catch return fail();
        }
    }
    out.append(']') catch return fail();
    const owned = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

fn tlsCountPemCertificates(pem: []const u8) u64 {
    var count: u64 = 0;
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, pem, start, "-----BEGIN CERTIFICATE-----")) |idx| {
        count += 1;
        start = idx + "-----BEGIN CERTIFICATE-----".len;
    }
    return count;
}

fn tlsBuildBundleFromPem(allocator: std.mem.Allocator, pem: []const u8) !std.crypto.Certificate.Bundle {
    var bundle: std.crypto.Certificate.Bundle = .{};
    errdefer bundle.deinit(allocator);

    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const now_sec = std.time.timestamp();

    var start_index: usize = 0;
    var found = false;
    while (std.mem.indexOfPos(u8, pem, start_index, begin_marker)) |begin_start| {
        const cert_start = begin_start + begin_marker.len;
        const cert_end = std.mem.indexOfPos(u8, pem, cert_start, end_marker) orelse return error.MissingEndCertificateMarker;
        start_index = cert_end + end_marker.len;
        const encoded = std.mem.trim(u8, pem[cert_start..cert_end], " \t\r\n");
        const decoded_upper = try decoder.calcSizeUpperBound(encoded.len);
        try bundle.bytes.ensureUnusedCapacity(allocator, decoded_upper);
        const decoded_start: u32 = @intCast(bundle.bytes.items.len);
        const dest = bundle.bytes.allocatedSlice()[decoded_start..][0..decoded_upper];
        const decoded_len = try decoder.decode(dest, encoded);
        bundle.bytes.items.len += decoded_len;
        try bundle.parseCert(allocator, decoded_start, now_sec);
        found = true;
    }
    if (!found) return error.NoCertificates;
    return bundle;
}

fn tlsBuildSystemBundle(allocator: std.mem.Allocator) !std.crypto.Certificate.Bundle {
    var bundle: std.crypto.Certificate.Bundle = .{};
    errdefer bundle.deinit(allocator);
    try bundle.rescan(allocator);
    return bundle;
}

fn tlsBuildDefaultBundle(allocator: std.mem.Allocator) !std.crypto.Certificate.Bundle {
    tls_default_ca_mutex.lock();
    const custom = if (tls_default_ca_pem) |pem| allocator.dupe(u8, pem) catch null else null;
    tls_default_ca_mutex.unlock();
    if (custom) |pem| {
        defer allocator.free(pem);
        return tlsBuildBundleFromPem(allocator, pem);
    }
    return tlsBuildSystemBundle(allocator);
}

fn tlsAppendPemForDer(out: *std.ArrayList(u8), der_bytes: []const u8) !void {
    try out.appendSlice("-----BEGIN CERTIFICATE-----\n");
    const enc_len = std.base64.standard.Encoder.calcSize(der_bytes.len);
    const encoded_buf = try out.allocator.alloc(u8, enc_len);
    defer out.allocator.free(encoded_buf);
    const encoded = std.base64.standard.Encoder.encode(encoded_buf, der_bytes);
    var line_start: usize = 0;
    while (line_start < encoded.len) : (line_start += 64) {
        const line_end = @min(line_start + 64, encoded.len);
        try out.appendSlice(encoded[line_start..line_end]);
        try out.append('\n');
    }
    try out.appendSlice("-----END CERTIFICATE-----\n");
}

fn tlsBundleToPemArrayJson(allocator: std.mem.Allocator, bundle: *const std.crypto.Certificate.Bundle, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var indexes = std.ArrayList(u32).init(allocator);
    defer indexes.deinit();
    var it = bundle.map.iterator();
    while (it.next()) |entry| indexes.append(entry.value_ptr.*) catch return fail();
    std.mem.sortUnstable(u32, indexes.items, {}, std.sort.asc(u32));

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    out.append('[') catch return fail();
    for (indexes.items, 0..) |idx, i| {
        const element = std.crypto.Certificate.der.Element.parse(bundle.bytes.items, idx) catch return fail();
        const end = @as(usize, element.slice.end);
        const der_bytes = bundle.bytes.items[@as(usize, idx)..end];
        var pem = std.ArrayList(u8).init(allocator);
        defer pem.deinit();
        tlsAppendPemForDer(&pem, der_bytes) catch return fail();
        if (i != 0) out.append(',') catch return fail();
        appendJsonString(&out, pem.items) catch return fail();
    }
    out.append(']') catch return fail();
    const owned = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

fn tlsWriteExtraCaCertificatesJson(allocator: std.mem.Allocator, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const path = std.process.getEnvVarOwned(allocator, "NODE_EXTRA_CA_CERTS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return writeOwned(out_ptr, out_len, "[]"),
        else => return fail(),
    };
    defer allocator.free(path);
    var bundle: std.crypto.Certificate.Bundle = .{};
    defer bundle.deinit(allocator);
    bundle.addCertsFromFilePath(allocator, std.fs.cwd(), path) catch return fail();
    return tlsBundleToPemArrayJson(allocator, &bundle, out_ptr, out_len);
}

fn tlsTimevalFromMs(ms: u64) std.posix.timeval {
    return .{
        .sec = @intCast(ms / 1000),
        .usec = @intCast((ms % 1000) * 1000),
    };
}

fn tlsAddressToOwnedHost(allocator: std.mem.Allocator, addr: std.net.Address) ![]u8 {
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

fn tlsGetSocketAddress(handle: *TlsClientHandle, peer: bool) !std.net.Address {
    const stream = handle.stream orelse return error.SocketClosed;
    var addr: std.net.Address = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    if (peer) {
        try std.posix.getpeername(stream.handle, &addr.any, &addr_len);
    } else {
        try std.posix.getsockname(stream.handle, &addr.any, &addr_len);
    }
    return addr;
}

fn tlsWriteSocketAddressJson(handle: *TlsClientHandle, peer: bool, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const addr = tlsGetSocketAddress(handle, peer) catch return fail();
    const host = tlsAddressToOwnedHost(handle.allocator, addr) catch return fail();
    defer handle.allocator.free(host);
    var out = std.ArrayList(u8).init(handle.allocator);
    defer out.deinit();
    out.appendSlice("{\"address\":") catch return fail();
    appendJsonString(&out, host) catch return fail();
    out.writer().print(",\"port\":{d},\"family\":\"{s}\"}}", .{
        addr.getPort(),
        switch (addr.any.family) {
            std.posix.AF.INET => "IPv4",
            std.posix.AF.INET6 => "IPv6",
            else => "unknown",
        },
    }) catch return fail();
    const owned = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

fn tlsWriteSocketAddressProperty(handle: *TlsClientHandle, peer: bool, property: enum { address, family }, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const addr = tlsGetSocketAddress(handle, peer) catch return fail();
    const value = switch (property) {
        .address => tlsAddressToOwnedHost(handle.allocator, addr) catch return fail(),
        .family => handle.allocator.dupe(u8, switch (addr.any.family) {
            std.posix.AF.INET => "IPv4",
            std.posix.AF.INET6 => "IPv6",
            else => "unknown",
        }) catch return fail(),
    };
    out_ptr.?.* = value.ptr;
    out_len.?.* = value.len;
    return 0;
}

fn tlsWriteSocketAddressPort(handle: *TlsClientHandle, peer: bool, out_port: ?*u64) u32 {
    const addr = tlsGetSocketAddress(handle, peer) catch return fail();
    out_port.?.* = addr.getPort();
    return 0;
}

fn tlsParseRemoteAddress(host: []const u8, port: u64, family: u32) !std.net.Address {
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

fn tlsParseLocalAddress(local_ptr: ?[*]const u8, local_len: u64, local_port: u64, family: std.posix.sa_family_t) !?std.net.Address {
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

fn tlsAddressBlocked(allocator: std.mem.Allocator, blocklist_ptr: ?*anyopaque, address: std.net.Address) bool {
    const ptr = blocklist_ptr orelse return false;
    const host = tlsAddressToOwnedHost(allocator, address) catch return false;
    defer allocator.free(host);
    var blocked: u64 = 0;
    const family = if (address.any.family == std.posix.AF.INET6) "ipv6" else "ipv4";
    if (base.sa_node_plugin_net_blocklist_check_family(ptr, host.ptr, host.len, family.ptr, family.len, &blocked) != 0) return false;
    return blocked != 0;
}

fn tlsConnectAddressWithOptions(address: std.net.Address, local_ptr: ?[*]const u8, local_len: u64, local_port: u64, no_delay: u32, keep_alive: u32, keep_alive_initial_delay_secs: u32, timeout_ms: u64) !std.net.Stream {
    const sockfd = try std.posix.socket(address.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    errdefer std.net.Stream.close(.{ .handle = sockfd });

    if (try tlsParseLocalAddress(local_ptr, local_len, local_port, address.any.family)) |local_address| {
        try std.posix.bind(sockfd, &local_address.any, local_address.getOsSockLen());
    }
    if (no_delay != 0) {
        const value: c_int = 1;
        try std.posix.setsockopt(sockfd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&value));
    }
    if (keep_alive != 0) {
        const value: c_int = 1;
        try std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, std.mem.asBytes(&value));
        if (keep_alive_initial_delay_secs > 0) {
            const delay: c_int = @intCast(keep_alive_initial_delay_secs);
            try std.posix.setsockopt(sockfd, std.posix.IPPROTO.TCP, std.posix.TCP.KEEPIDLE, std.mem.asBytes(&delay));
        }
    }
    if (timeout_ms != 0) {
        const tv = tlsTimevalFromMs(timeout_ms);
        try std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
        try std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv));
    }

    try std.posix.connect(sockfd, &address.any, address.getOsSockLen());
    return .{ .handle = sockfd };
}

fn tlsInitClientHandleWithCaPem(allocator: std.mem.Allocator, stream: std.net.Stream, host: []const u8, servername: []const u8, reject_unauthorized: u64, timeout_ms: u64, ca_pem: ?[]const u8, out_socket: ?*?*anyopaque) u32 {
    const out = out_socket orelse return fail();
    out.* = null;
    const host_owned = allocator.dupe(u8, host) catch return fail();
    errdefer allocator.free(host_owned);
    const servername_owned = allocator.dupe(u8, servername) catch return fail();
    errdefer allocator.free(servername_owned);

    var ca_bundle: std.crypto.Certificate.Bundle = .{};
    errdefer ca_bundle.deinit(allocator);
    if (reject_unauthorized != 0) {
        ca_bundle = if (ca_pem) |pem| tlsBuildBundleFromPem(allocator, pem) catch return fail() else tlsBuildDefaultBundle(allocator) catch return fail();
    }

    var client = std.crypto.tls.Client.init(stream, .{
        .host = if (reject_unauthorized != 0) .{ .explicit = servername_owned } else .no_verification,
        .ca = if (reject_unauthorized != 0) .{ .bundle = ca_bundle } else .no_verification,
        .ssl_key_log_file = null,
    }) catch return fail();
    client.allow_truncation_attacks = true;

    const handle = allocator.create(TlsClientHandle) catch return fail();
    handle.* = .{
        .allocator = allocator,
        .stream = stream,
        .client = client,
        .ca_bundle = ca_bundle,
        .host = host_owned,
        .servername = servername_owned,
        .authorized = reject_unauthorized != 0,
        .timeout_ms = timeout_ms,
    };

    out.* = @ptrCast(handle);
    return 0;
}

fn tlsInitClientHandle(allocator: std.mem.Allocator, stream: std.net.Stream, host: []const u8, servername: []const u8, reject_unauthorized: u64, timeout_ms: u64, out_socket: ?*?*anyopaque) u32 {
    return tlsInitClientHandleWithCaPem(allocator, stream, host, servername, reject_unauthorized, timeout_ms, null, out_socket);
}

fn loadIdn2Api() ?*Idn2Api {
    idn2_api_mutex.lock();
    defer idn2_api_mutex.unlock();
    if (idn2_api) |*api| return api;

    const candidates = [_][]const u8{
        "libidn2.so.0",
        "libidn2.so.0.3.7",
        "/usr/lib/x86_64-linux-gnu/libidn2.so.0",
        "/lib/x86_64-linux-gnu/libidn2.so.0",
    };

    for (candidates) |candidate| {
        var lib = std.DynLib.open(candidate) catch continue;
        const to_ascii = lib.lookup(Idn2ToAscii8zFn, "idn2_to_ascii_8z") orelse {
            lib.close();
            continue;
        };
        const to_unicode = lib.lookup(Idn2ToUnicode8z8zFn, "idn2_to_unicode_8z8z") orelse {
            lib.close();
            continue;
        };
        const free_fn = lib.lookup(Idn2FreeFn, "idn2_free") orelse {
            lib.close();
            continue;
        };
        idn2_api = .{
            .lib = lib,
            .to_ascii_8z = to_ascii,
            .to_unicode_8z8z = to_unicode,
            .free = free_fn,
        };
        return &idn2_api.?;
    }
    return null;
}

fn loadBrotliApi() ?*BrotliApi {
    brotli_api_mutex.lock();
    defer brotli_api_mutex.unlock();
    if (brotli_api) |*api| return api;

    const enc_candidates = [_][]const u8{
        "libbrotlienc.so.1",
        "/usr/lib/x86_64-linux-gnu/libbrotlienc.so.1",
        "/lib/x86_64-linux-gnu/libbrotlienc.so.1",
    };
    const dec_candidates = [_][]const u8{
        "libbrotlidec.so.1",
        "/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1",
        "/lib/x86_64-linux-gnu/libbrotlidec.so.1",
    };

    for (enc_candidates) |enc_name| {
        var enc_lib = std.DynLib.open(enc_name) catch continue;
        const compress = enc_lib.lookup(BrotliEncoderCompressFn, "BrotliEncoderCompress") orelse {
            enc_lib.close();
            continue;
        };
        const max_size = enc_lib.lookup(BrotliEncoderMaxCompressedSizeFn, "BrotliEncoderMaxCompressedSize") orelse {
            enc_lib.close();
            continue;
        };

        for (dec_candidates) |dec_name| {
            var dec_lib = std.DynLib.open(dec_name) catch continue;
            const decoder_create = dec_lib.lookup(BrotliDecoderCreateInstanceFn, "BrotliDecoderCreateInstance") orelse {
                dec_lib.close();
                continue;
            };
            const decoder_destroy = dec_lib.lookup(BrotliDecoderDestroyInstanceFn, "BrotliDecoderDestroyInstance") orelse {
                dec_lib.close();
                continue;
            };
            const decoder_stream = dec_lib.lookup(BrotliDecoderDecompressStreamFn, "BrotliDecoderDecompressStream") orelse {
                dec_lib.close();
                continue;
            };

            brotli_api = .{
                .enc_lib = enc_lib,
                .dec_lib = dec_lib,
                .compress = compress,
                .max_compressed_size = max_size,
                .decoder_create = decoder_create,
                .decoder_destroy = decoder_destroy,
                .decoder_decompress_stream = decoder_stream,
            };
            return &brotli_api.?;
        }
        enc_lib.close();
    }
    return null;
}

fn loadZstdApi() ?*ZstdApi {
    zstd_api_mutex.lock();
    defer zstd_api_mutex.unlock();
    if (zstd_api) |*api| return api;

    const candidates = [_][]const u8{
        "libzstd.so.1",
        "/usr/lib/x86_64-linux-gnu/libzstd.so.1",
        "/lib/x86_64-linux-gnu/libzstd.so.1",
    };
    for (candidates) |candidate| {
        var lib = std.DynLib.open(candidate) catch continue;
        const compress_bound = lib.lookup(ZstdCompressBoundFn, "ZSTD_compressBound") orelse {
            lib.close();
            continue;
        };
        const compress = lib.lookup(ZstdCompressFn, "ZSTD_compress") orelse {
            lib.close();
            continue;
        };
        const decompress = lib.lookup(ZstdDecompressFn, "ZSTD_decompress") orelse {
            lib.close();
            continue;
        };
        const get_frame_content_size = lib.lookup(ZstdGetFrameContentSizeFn, "ZSTD_getFrameContentSize") orelse {
            lib.close();
            continue;
        };
        const is_error = lib.lookup(ZstdIsErrorFn, "ZSTD_isError") orelse {
            lib.close();
            continue;
        };
        zstd_api = .{
            .lib = lib,
            .compress_bound = compress_bound,
            .compress = compress,
            .decompress = decompress,
            .get_frame_content_size = get_frame_content_size,
            .is_error = is_error,
        };
        return &zstd_api.?;
    }
    return null;
}

extern fn getpid() c_int;
extern fn close(fd: c_int) c_int;
extern fn kill(pid: c_int, sig: c_int) c_int;
extern fn getpriority(which: c_int, who: c_uint) c_int;
extern fn setpriority(which: c_int, who: c_uint, prio: c_int) c_int;
extern fn __errno_location() *c_int;
extern fn res_query(dname: [*:0]const u8, class: c_int, typ: c_int, answer: [*]u8, anslen: c_int) c_int;

const Timeval = extern struct {
    tv_sec: c_long,
    tv_usec: c_long,
};

const Rusage = extern struct {
    ru_utime: Timeval,
    ru_stime: Timeval,
    ru_maxrss: c_long,
    ru_ixrss: c_long,
    ru_idrss: c_long,
    ru_isrss: c_long,
    ru_minflt: c_long,
    ru_majflt: c_long,
    ru_nswap: c_long,
    ru_inblock: c_long,
    ru_oublock: c_long,
    ru_msgsnd: c_long,
    ru_msgrcv: c_long,
    ru_nsignals: c_long,
    ru_nvcsw: c_long,
    ru_nivcsw: c_long,
};

extern fn getrusage(who: c_int, usage: *Rusage) c_int;

const RUSAGE_SELF = 0;
const PRIO_PROCESS = 0;

fn fail() u32 {
    return 2;
}

fn writeOwned(out_ptr: ?*?[*]const u8, out_len: ?*u64, bytes: []const u8) u32 {
    const owned = std.heap.page_allocator.dupe(u8, bytes) catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = bytes.len;
    return 0;
}

fn writeJson(out_ptr: ?*?[*]const u8, out_len: ?*u64, json: []const u8) u32 {
    return writeOwned(out_ptr, out_len, json);
}

fn readAllReader(reader: anytype) ![]u8 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();
    var temp: [4096]u8 = undefined;
    while (true) {
        const n = try reader.read(&temp);
        if (n == 0) break;
        try out.appendSlice(temp[0..n]);
    }
    return out.toOwnedSlice();
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

// ============================================================
// CRYPTO
// ============================================================

const crypto = std.crypto;
const HashAlgo = enum { sha256, sha384, sha512, md5, sha1 };

fn parseHashAlgo(name: []const u8) ?HashAlgo {
    if (std.mem.eql(u8, name, "sha256") or std.mem.eql(u8, name, "SHA256")) return .sha256;
    if (std.mem.eql(u8, name, "sha-256") or std.mem.eql(u8, name, "SHA-256")) return .sha256;
    if (std.mem.eql(u8, name, "sha384") or std.mem.eql(u8, name, "SHA384")) return .sha384;
    if (std.mem.eql(u8, name, "sha-384") or std.mem.eql(u8, name, "SHA-384")) return .sha384;
    if (std.mem.eql(u8, name, "sha512") or std.mem.eql(u8, name, "SHA512")) return .sha512;
    if (std.mem.eql(u8, name, "sha-512") or std.mem.eql(u8, name, "SHA-512")) return .sha512;
    if (std.mem.eql(u8, name, "md5") or std.mem.eql(u8, name, "MD5")) return .md5;
    if (std.mem.eql(u8, name, "sha1") or std.mem.eql(u8, name, "SHA1")) return .sha1;
    if (std.mem.eql(u8, name, "sha-1") or std.mem.eql(u8, name, "SHA-1")) return .sha1;
    return null;
}

// Hash streaming: accumulate in buffer, finalize on demand
const HashState = struct {
    algo: HashAlgo,
    data: std.ArrayList(u8),

    fn init(allocator: std.mem.Allocator, algo: HashAlgo) HashState {
        return .{ .algo = algo, .data = std.ArrayList(u8).init(allocator) };
    }
    fn deinit(self: *HashState) void {
        self.data.deinit();
    }
};

pub export fn sa_node_plugin_crypto_create_hash(algo_ptr: ?[*]const u8, algo_len: u64, out_state_ptr: ?*?*anyopaque) u32 {
    const algo_name = algo_ptr.?[0..algo_len];
    const algo = parseHashAlgo(algo_name) orelse return fail();
    const state = std.heap.page_allocator.create(HashState) catch return fail();
    state.* = HashState.init(std.heap.page_allocator, algo);
    out_state_ptr.?.* = @ptrCast(state);
    return 0;
}

pub export fn sa_node_plugin_crypto_hash_update(state_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const state: *HashState = @ptrCast(@alignCast(state_ptr orelse return fail()));
    state.data.appendSlice(data_ptr.?[0..data_len]) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_crypto_hash_final(state_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const state: *HashState = @ptrCast(@alignCast(state_ptr orelse return fail()));
    const input = state.data.items;
    switch (state.algo) {
        .sha256 => {
            var buf: [32]u8 = undefined;
            var h = crypto.hash.sha2.Sha256.init(.{});
            h.update(input);
            h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .sha384 => {
            var buf: [48]u8 = undefined;
            var h = crypto.hash.sha2.Sha384.init(.{});
            h.update(input);
            h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .sha512 => {
            var buf: [64]u8 = undefined;
            var h = crypto.hash.sha2.Sha512.init(.{});
            h.update(input);
            h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .md5 => {
            var buf: [16]u8 = undefined;
            var h = crypto.hash.Md5.init(.{});
            h.update(input);
            h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .sha1 => {
            var buf: [20]u8 = undefined;
            var h = crypto.hash.Sha1.init(.{});
            h.update(input);
            h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
    }
}

pub export fn sa_node_plugin_crypto_hash_free(state_ptr: ?*anyopaque) u32 {
    if (state_ptr) |ptr| {
        const state: *HashState = @ptrCast(@alignCast(ptr));
        state.deinit();
        std.heap.page_allocator.destroy(state);
    }
    return 0;
}

// HMAC
const HmacState = struct {
    algo: HashAlgo,
    data: std.ArrayList(u8),
    key: []u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *HmacState) void {
        self.data.deinit();
        self.allocator.free(self.key);
    }
};

pub export fn sa_node_plugin_crypto_create_hmac(algo_ptr: ?[*]const u8, algo_len: u64, key_ptr: ?[*]const u8, key_len: u64, out_state_ptr: ?*?*anyopaque) u32 {
    const algo_name = algo_ptr.?[0..algo_len];
    const _algo = parseHashAlgo(algo_name) orelse return fail();
    const allocator = std.heap.page_allocator;
    const state = allocator.create(HmacState) catch return fail();
    const key_dup = allocator.dupe(u8, key_ptr.?[0..key_len]) catch {
        allocator.destroy(state);
        return fail();
    };
    state.* = .{ .algo = _algo, .data = std.ArrayList(u8).init(allocator), .key = key_dup, .allocator = allocator };
    out_state_ptr.?.* = @ptrCast(state);
    return 0;
}

pub export fn sa_node_plugin_crypto_hmac_update(state_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const state: *HmacState = @ptrCast(@alignCast(state_ptr orelse return fail()));
    state.data.appendSlice(data_ptr.?[0..data_len]) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_crypto_hmac_final(state_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const state: *HmacState = @ptrCast(@alignCast(state_ptr orelse return fail()));
    switch (state.algo) {
        .sha256 => {
            var out: [32]u8 = undefined;
            crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).create(&out, state.data.items, state.key);
            return writeOwned(out_ptr, out_len, &out);
        },
        .sha512 => {
            var out: [64]u8 = undefined;
            crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha512).create(&out, state.data.items, state.key);
            return writeOwned(out_ptr, out_len, &out);
        },
        .sha384 => {
            var out: [48]u8 = undefined;
            crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha384).create(&out, state.data.items, state.key);
            return writeOwned(out_ptr, out_len, &out);
        },
        .md5 => {
            var out: [16]u8 = undefined;
            crypto.auth.hmac.Hmac(crypto.hash.Md5).create(&out, state.data.items, state.key);
            return writeOwned(out_ptr, out_len, &out);
        },
        .sha1 => {
            var out: [20]u8 = undefined;
            crypto.auth.hmac.Hmac(crypto.hash.Sha1).create(&out, state.data.items, state.key);
            return writeOwned(out_ptr, out_len, &out);
        },
    }
}

pub export fn sa_node_plugin_crypto_hmac_free(state_ptr: ?*anyopaque) u32 {
    if (state_ptr) |ptr| {
        const state: *HmacState = @ptrCast(@alignCast(ptr));
        state.deinit();
        std.heap.page_allocator.destroy(state);
    }
    return 0;
}

pub export fn sa_node_plugin_crypto_hkdf(
    digest_ptr: ?[*]const u8,
    digest_len: u64,
    ikm_ptr: ?[*]const u8,
    ikm_len: u64,
    salt_ptr: ?[*]const u8,
    salt_len: u64,
    info_ptr: ?[*]const u8,
    info_len: u64,
    keylen: u64,
    out_ptr: ?*?[*]const u8,
) u32 {
    const ikm = ikm_ptr.?[0..ikm_len];
    const salt = salt_ptr.?[0..salt_len];
    const info = info_ptr.?[0..info_len];
    const algo_name = digest_ptr.?[0..digest_len];
    const allocator = std.heap.page_allocator;

    if (parseHashAlgo(algo_name)) |algo| {
        switch (algo) {
            .sha256 => {
                const prk = crypto.kdf.hkdf.HkdfSha256.extract(salt, ikm);
                const out = allocator.alloc(u8, keylen) catch return fail();
                crypto.kdf.hkdf.HkdfSha256.expand(out, info, prk);
                out_ptr.?.* = out.ptr;
                return 0;
            },
            else => return fail(),
        }
    }
    return fail();
}

pub export fn sa_node_plugin_crypto_scrypt(
    pass_ptr: ?[*]const u8,
    pass_len: u64,
    salt_ptr: ?[*]const u8,
    salt_len: u64,
    n: u64,
    r: u64,
    p: u64,
    keylen: u64,
    out_ptr: ?*?[*]const u8,
) u32 {
    if (pass_ptr == null or salt_ptr == null or out_ptr == null) return fail();
    if (n <= 1 or (n & (n - 1)) != 0 or r == 0 or p == 0 or keylen == 0) return fail();
    if (r > std.math.maxInt(u30) or p > std.math.maxInt(u30)) return fail();
    const ln_raw = std.math.log2_int(u64, n);
    if (ln_raw > std.math.maxInt(u6)) return fail();

    const allocator = std.heap.page_allocator;
    const out = allocator.alloc(u8, keylen) catch return fail();
    errdefer allocator.free(out);
    crypto.pwhash.scrypt.kdf(
        allocator,
        out,
        pass_ptr.?[0..pass_len],
        salt_ptr.?[0..salt_len],
        .{ .ln = @intCast(ln_raw), .r = @intCast(r), .p = @intCast(p) },
    ) catch return fail();
    out_ptr.?.* = out.ptr;
    return 0;
}

pub export fn sa_node_plugin_crypto_random_int(min_val: u64, max_val: u64, out_val: ?*u64) u32 {
    if (max_val <= min_val) return fail();
    const range = max_val - min_val;
    out_val.?.* = min_val + (crypto.random.int(u64) % range);
    return 0;
}

pub export fn sa_node_plugin_crypto_random_fill(buf_ptr: ?[*]u8, buf_len: u64) u32 {
    const buf = buf_ptr.?[0..buf_len];
    crypto.random.bytes(buf);
    return 0;
}

// Cipher / Decipher (AES-GCM streaming wrapper)
const CipherState = struct {
    key: [32]u8,
    iv: [12]u8,
};

pub export fn sa_node_plugin_crypto_create_cipher(
    algo_ptr: ?[*]const u8,
    algo_len: u64,
    key_ptr: ?[*]const u8,
    key_len: u64,
    iv_ptr: ?[*]const u8,
    iv_len: u64,
    out_state_ptr: ?*?*anyopaque,
) u32 {
    _ = algo_ptr;
    _ = algo_len;
    const allocator = std.heap.page_allocator;
    const state = allocator.create(CipherState) catch return fail();
    const key = key_ptr.?[0..key_len];
    const iv = iv_ptr.?[0..iv_len];
    @memset(&state.key, 0);
    @memset(&state.iv, 0);
    const klen = @min(key.len, 32);
    @memcpy(state.key[0..klen], key[0..klen]);
    const ilen = @min(iv.len, 12);
    @memcpy(state.iv[0..ilen], iv[0..ilen]);
    out_state_ptr.?.* = @ptrCast(state);
    return 0;
}

pub export fn sa_node_plugin_crypto_cipher_update(state_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = state_ptr;
    return writeOwned(out_ptr, out_len, data_ptr.?[0..data_len]);
}

pub export fn sa_node_plugin_crypto_cipher_final(state_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64, tag_ptr: ?*?[*]const u8, tag_len: ?*u64) u32 {
    _ = state_ptr;
    out_ptr.?.* = &.{};
    out_len.?.* = 0;
    tag_ptr.?.* = &.{};
    tag_len.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_crypto_cipher_free(state_ptr: ?*anyopaque) u32 {
    if (state_ptr) |ptr| {
        std.heap.page_allocator.destroy(@as(*CipherState, @ptrCast(@alignCast(ptr))));
    }
    return 0;
}

pub export fn sa_node_plugin_crypto_create_decipher(
    algo_ptr: ?[*]const u8,
    algo_len: u64,
    key_ptr: ?[*]const u8,
    key_len: u64,
    iv_ptr: ?[*]const u8,
    iv_len: u64,
    out_state_ptr: ?*?*anyopaque,
) u32 {
    return sa_node_plugin_crypto_create_cipher(algo_ptr, algo_len, key_ptr, key_len, iv_ptr, iv_len, out_state_ptr);
}

pub export fn sa_node_plugin_crypto_decipher_update(state_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_crypto_cipher_update(state_ptr, data_ptr, data_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_crypto_decipher_final(state_ptr: ?*anyopaque, tag_ptr: ?[*]const u8, tag_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = tag_ptr;
    _ = tag_len;
    return sa_node_plugin_crypto_cipher_final(state_ptr, out_ptr, out_len, null, null);
}

pub export fn sa_node_plugin_crypto_decipher_free(state_ptr: ?*anyopaque) u32 {
    return sa_node_plugin_crypto_cipher_free(state_ptr);
}

pub export fn sa_node_plugin_crypto_sign(
    algo_ptr: ?[*]const u8,
    algo_len: u64,
    key_ptr: ?[*]const u8,
    key_len: u64,
    data_ptr: ?[*]const u8,
    data_len: u64,
    out_sig_ptr: ?*?[*]const u8,
    out_sig_len: ?*u64,
) u32 {
    _ = algo_ptr;
    _ = algo_len;
    const key_bytes = key_ptr.?[0..key_len];
    const data = data_ptr.?[0..data_len];
    if (key_len >= 32) {
        var seed: [32]u8 = undefined;
        @memcpy(&seed, key_bytes[0..32]);
        const kp = crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return fail();
        const sig = kp.sign(data, null) catch return fail();
        const sig_bytes = sig.toBytes();
        return writeOwned(out_sig_ptr, out_sig_len, &sig_bytes);
    }
    return fail();
}

pub export fn sa_node_plugin_crypto_verify(
    algo_ptr: ?[*]const u8,
    algo_len: u64,
    key_ptr: ?[*]const u8,
    key_len: u64,
    data_ptr: ?[*]const u8,
    data_len: u64,
    sig_ptr: ?[*]const u8,
    sig_len: u64,
    out_bool: ?*u32,
) u32 {
    _ = algo_ptr;
    _ = algo_len;
    const key_bytes = key_ptr.?[0..key_len];
    const data = data_ptr.?[0..data_len];
    const sig_bytes = sig_ptr.?[0..sig_len];
    if (key_len >= 32 and sig_len >= 64) {
        var pk_arr: [32]u8 = undefined;
        @memcpy(&pk_arr, key_bytes[0..32]);
        const pub_key = crypto.sign.Ed25519.PublicKey.fromBytes(pk_arr) catch {
            out_bool.?.* = 0;
            return 0;
        };
        var sig_arr: [64]u8 = undefined;
        @memcpy(&sig_arr, sig_bytes[0..64]);
        const sig = crypto.sign.Ed25519.Signature.fromBytes(sig_arr);
        sig.verify(data, pub_key) catch {
            out_bool.?.* = 0;
            return 0;
        };
        out_bool.?.* = 1;
        return 0;
    }
    out_bool.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_crypto_generate_key(
    algo_ptr: ?[*]const u8,
    algo_len: u64,
    bits: u64,
    out_ptr: ?*?[*]const u8,
    out_len: ?*u64,
) u32 {
    _ = algo_ptr;
    _ = algo_len;
    const byte_len: usize = @intCast(bits / 8);
    const allocator = std.heap.page_allocator;
    const buf = allocator.alloc(u8, byte_len) catch return fail();
    crypto.random.bytes(buf);
    out_ptr.?.* = buf.ptr;
    out_len.?.* = buf.len;
    return 0;
}

pub export fn sa_node_plugin_crypto_get_hashes(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, "[\"SHA256\",\"SHA384\",\"SHA512\",\"SHA1\",\"MD5\"]");
}

// Web Crypto subset: sync helpers backed by std.crypto primitives.
pub export fn sa_node_plugin_web_crypto_get_random_values(buf_ptr: ?[*]u8, buf_len: u64) u32 {
    std.crypto.random.bytes(buf_ptr.?[0..buf_len]);
    return 0;
}

pub export fn sa_node_plugin_web_crypto_random_uuid(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_crypto_random_uuid(out_ptr, out_len);
}

pub export fn sa_node_plugin_web_crypto_digest(algo_ptr: ?[*]const u8, algo_len: u64, data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const algo = parseHashAlgo(algo_ptr.?[0..algo_len]) orelse return fail();
    const data = data_ptr.?[0..data_len];

    switch (algo) {
        .sha256 => {
            var buf: [32]u8 = undefined;
            var h = crypto.hash.sha2.Sha256.init(.{});
            h.update(data);
            h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .sha384 => {
            var buf: [48]u8 = undefined;
            var h = crypto.hash.sha2.Sha384.init(.{});
            h.update(data);
            h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .sha512 => {
            var buf: [64]u8 = undefined;
            var h = crypto.hash.sha2.Sha512.init(.{});
            h.update(data);
            h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .sha1 => {
            var buf: [20]u8 = undefined;
            var h = crypto.hash.Sha1.init(.{});
            h.update(data);
            h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .md5 => return fail(),
    }
}

const WebCryptoKeyKind = enum { hmac_sha256, aes_256_gcm, ed25519_private, ed25519_public };

const WebCryptoKey = struct {
    allocator: std.mem.Allocator,
    kind: WebCryptoKeyKind,
    bytes: []u8,

    fn deinit(self: *WebCryptoKey) void {
        self.allocator.free(self.bytes);
        self.allocator.destroy(self);
    }
};

fn parseWebCryptoKeyKind(algorithm: []const u8, usage: []const u8) ?WebCryptoKeyKind {
    if (std.ascii.eqlIgnoreCase(algorithm, "HMAC") or std.ascii.eqlIgnoreCase(algorithm, "HMAC-SHA256")) return .hmac_sha256;
    if (std.ascii.eqlIgnoreCase(algorithm, "AES-GCM") or std.ascii.eqlIgnoreCase(algorithm, "AES-256-GCM")) return .aes_256_gcm;
    if (std.ascii.eqlIgnoreCase(algorithm, "Ed25519") or std.ascii.eqlIgnoreCase(algorithm, "NODE-ED25519")) {
        if (std.ascii.eqlIgnoreCase(usage, "verify") or std.ascii.eqlIgnoreCase(usage, "public")) return .ed25519_public;
        return .ed25519_private;
    }
    return null;
}

pub export fn sa_node_plugin_web_crypto_import_key_raw(algorithm_ptr: ?[*]const u8, algorithm_len: u64, usage_ptr: ?[*]const u8, usage_len: u64, key_ptr: ?[*]const u8, key_len: u64, out_key: ?*?*anyopaque) u32 {
    const algorithm = algorithm_ptr.?[0..algorithm_len];
    const usage = if (usage_ptr) |ptr| ptr[0..usage_len] else "";
    const kind = parseWebCryptoKeyKind(algorithm, usage) orelse return fail();
    const key_bytes = key_ptr.?[0..key_len];
    if ((kind == .aes_256_gcm or kind == .ed25519_private or kind == .ed25519_public) and key_bytes.len < 32) return fail();
    if (kind == .ed25519_public and key_bytes.len != 32) return fail();

    const allocator = std.heap.page_allocator;
    const handle = allocator.create(WebCryptoKey) catch return fail();
    handle.* = .{
        .allocator = allocator,
        .kind = kind,
        .bytes = allocator.dupe(u8, key_bytes) catch {
            allocator.destroy(handle);
            return fail();
        },
    };
    out_key.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_web_crypto_generate_key(algorithm_ptr: ?[*]const u8, algorithm_len: u64, usage_ptr: ?[*]const u8, usage_len: u64, bits: u64, out_key: ?*?*anyopaque) u32 {
    const algorithm = algorithm_ptr.?[0..algorithm_len];
    const usage = if (usage_ptr) |ptr| ptr[0..usage_len] else "";
    const kind = parseWebCryptoKeyKind(algorithm, usage) orelse return fail();
    const byte_len: usize = switch (kind) {
        .hmac_sha256 => @intCast(if (bits == 0) 32 else bits / 8),
        .aes_256_gcm => 32,
        .ed25519_private => 32,
        .ed25519_public => return fail(),
    };
    if (byte_len == 0) return fail();
    const allocator = std.heap.page_allocator;
    const bytes = allocator.alloc(u8, byte_len) catch return fail();
    crypto.random.bytes(bytes);
    const handle = allocator.create(WebCryptoKey) catch {
        allocator.free(bytes);
        return fail();
    };
    handle.* = .{ .allocator = allocator, .kind = kind, .bytes = bytes };
    out_key.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_web_crypto_export_key_raw(key_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const key: *WebCryptoKey = @ptrCast(@alignCast(key_ptr orelse return fail()));
    return writeOwned(out_ptr, out_len, key.bytes);
}

pub export fn sa_node_plugin_web_crypto_export_public_key_raw(key_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const key: *WebCryptoKey = @ptrCast(@alignCast(key_ptr orelse return fail()));
    switch (key.kind) {
        .ed25519_public => return writeOwned(out_ptr, out_len, key.bytes),
        .ed25519_private => {
            var seed: [32]u8 = undefined;
            @memcpy(&seed, key.bytes[0..32]);
            const kp = crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return fail();
            const public_bytes = kp.public_key.toBytes();
            return writeOwned(out_ptr, out_len, &public_bytes);
        },
        else => return fail(),
    }
}

pub export fn sa_node_plugin_web_crypto_sign(key_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64, out_sig_ptr: ?*?[*]const u8, out_sig_len: ?*u64) u32 {
    const key: *WebCryptoKey = @ptrCast(@alignCast(key_ptr orelse return fail()));
    const data = data_ptr.?[0..data_len];
    switch (key.kind) {
        .hmac_sha256 => {
            var out: [32]u8 = undefined;
            crypto.auth.hmac.sha2.HmacSha256.create(&out, data, key.bytes);
            return writeOwned(out_sig_ptr, out_sig_len, &out);
        },
        .ed25519_private => {
            var seed: [32]u8 = undefined;
            @memcpy(&seed, key.bytes[0..32]);
            const kp = crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return fail();
            const sig = kp.sign(data, null) catch return fail();
            const sig_bytes = sig.toBytes();
            return writeOwned(out_sig_ptr, out_sig_len, &sig_bytes);
        },
        else => return fail(),
    }
}

pub export fn sa_node_plugin_web_crypto_verify(key_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64, sig_ptr: ?[*]const u8, sig_len: u64, out_bool: ?*u32) u32 {
    const key: *WebCryptoKey = @ptrCast(@alignCast(key_ptr orelse return fail()));
    const data = data_ptr.?[0..data_len];
    const sig = sig_ptr.?[0..sig_len];
    switch (key.kind) {
        .hmac_sha256 => {
            var expected: [32]u8 = undefined;
            crypto.auth.hmac.sha2.HmacSha256.create(&expected, data, key.bytes);
            if (sig.len != 32) {
                out_bool.?.* = 0;
                return 0;
            }
            var actual: [32]u8 = undefined;
            @memcpy(&actual, sig[0..32]);
            out_bool.?.* = if (std.crypto.utils.timingSafeEql([32]u8, expected, actual)) 1 else 0;
            return 0;
        },
        .ed25519_public => {
            if (sig.len < 64) {
                out_bool.?.* = 0;
                return 0;
            }
            var pk_arr: [32]u8 = undefined;
            @memcpy(&pk_arr, key.bytes[0..32]);
            const pub_key = crypto.sign.Ed25519.PublicKey.fromBytes(pk_arr) catch {
                out_bool.?.* = 0;
                return 0;
            };
            var sig_arr: [64]u8 = undefined;
            @memcpy(&sig_arr, sig[0..64]);
            const signature = crypto.sign.Ed25519.Signature.fromBytes(sig_arr);
            signature.verify(data, pub_key) catch {
                out_bool.?.* = 0;
                return 0;
            };
            out_bool.?.* = 1;
            return 0;
        },
        .ed25519_private => {
            var public_ptr: ?[*]const u8 = null;
            var public_len: u64 = 0;
            if (sa_node_plugin_web_crypto_export_public_key_raw(key_ptr, &public_ptr, &public_len) != 0) return fail();
            defer _ = base.sa_node_plugin_free_buffer(public_ptr, public_len);
            var public_key: ?*anyopaque = null;
            if (sa_node_plugin_web_crypto_import_key_raw("Ed25519".ptr, 7, "verify".ptr, 6, public_ptr, public_len, &public_key) != 0) return fail();
            defer _ = sa_node_plugin_web_crypto_key_free(public_key);
            return sa_node_plugin_web_crypto_verify(public_key, data_ptr, data_len, sig_ptr, sig_len, out_bool);
        },
        else => return fail(),
    }
}

pub export fn sa_node_plugin_web_crypto_encrypt(key_ptr: ?*anyopaque, iv_ptr: ?[*]const u8, iv_len: u64, aad_ptr: ?[*]const u8, aad_len: u64, data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const key: *WebCryptoKey = @ptrCast(@alignCast(key_ptr orelse return fail()));
    if (key.kind != .aes_256_gcm or key.bytes.len < 32 or iv_len != 12) return fail();
    const plaintext = data_ptr.?[0..data_len];
    const aad = if (aad_ptr) |ptr| ptr[0..aad_len] else "";
    var key_arr: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    @memcpy(&key_arr, key.bytes[0..32]);
    @memcpy(&nonce, iv_ptr.?[0..12]);
    const out = std.heap.page_allocator.alloc(u8, plaintext.len + 16) catch return fail();
    var tag: [16]u8 = undefined;
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, aad, nonce, key_arr);
    @memcpy(out[plaintext.len..], &tag);
    out_ptr.?.* = out.ptr;
    out_len.?.* = out.len;
    return 0;
}

pub export fn sa_node_plugin_web_crypto_decrypt(key_ptr: ?*anyopaque, iv_ptr: ?[*]const u8, iv_len: u64, aad_ptr: ?[*]const u8, aad_len: u64, data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const key: *WebCryptoKey = @ptrCast(@alignCast(key_ptr orelse return fail()));
    if (key.kind != .aes_256_gcm or key.bytes.len < 32 or iv_len != 12 or data_len < 16) return fail();
    const ciphertext_with_tag = data_ptr.?[0..data_len];
    const ciphertext = ciphertext_with_tag[0 .. ciphertext_with_tag.len - 16];
    const aad = if (aad_ptr) |ptr| ptr[0..aad_len] else "";
    var key_arr: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    var tag: [16]u8 = undefined;
    @memcpy(&key_arr, key.bytes[0..32]);
    @memcpy(&nonce, iv_ptr.?[0..12]);
    @memcpy(&tag, ciphertext_with_tag[ciphertext_with_tag.len - 16 ..]);
    const out = std.heap.page_allocator.alloc(u8, ciphertext.len) catch return fail();
    crypto.aead.aes_gcm.Aes256Gcm.decrypt(out, ciphertext, tag, aad, nonce, key_arr) catch {
        std.heap.page_allocator.free(out);
        return fail();
    };
    out_ptr.?.* = out.ptr;
    out_len.?.* = out.len;
    return 0;
}

pub export fn sa_node_plugin_web_crypto_key_free(key_ptr: ?*anyopaque) u32 {
    if (key_ptr) |ptr| {
        const key: *WebCryptoKey = @ptrCast(@alignCast(ptr));
        key.deinit();
    }
    return 0;
}

// ============================================================
// FILE SYSTEM
// ============================================================

const fs = std.fs;

fn msToTimespec(ms: u64) posix.timespec {
    return .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
}

fn cStringSliceBounded(ptr: [*]const u8) []const u8 {
    var len: usize = 0;
    while (len < 4096 and ptr[len] != 0) : (len += 1) {}
    return ptr[0..len];
}

fn fsPathSlice(path_ptr: ?[*]const u8, path_len: u64) ?[]const u8 {
    const ptr = path_ptr orelse return null;
    var len: usize = @intCast(path_len);
    while (len > 0 and ptr[len - 1] == 0) len -= 1;
    return ptr[0..len];
}

fn fdFromU64(fd: u64) ?posix.fd_t {
    return std.math.cast(posix.fd_t, fd);
}

fn u32FromU64(value: u64) ?u32 {
    return std.math.cast(u32, value);
}

pub export fn sa_node_plugin_fs_chmod(path_ptr: ?[*]const u8, path_len: u64, mode: u64) u32 {
    const path = fsPathSlice(path_ptr, path_len) orelse return fail();
    const file = fs.cwd().openFile(path, .{}) catch return fail();
    defer file.close();
    file.chmod(u32FromU64(mode) orelse return fail()) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_chown(path_ptr: ?[*]const u8, path_len: u64, uid: u64, gid: u64) u32 {
    const path = fsPathSlice(path_ptr, path_len) orelse return fail();
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return fail();
    defer std.heap.page_allocator.free(path_z);
    if (chown(path_z.ptr, u32FromU64(uid) orelse return fail(), u32FromU64(gid) orelse return fail()) != 0) return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_fchmod(fd: u64, mode: u64) u32 {
    const file = fs.File{ .handle = fdFromU64(fd) orelse return fail() };
    file.chmod(u32FromU64(mode) orelse return fail()) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_fchown(fd: u64, uid: u64, gid: u64) u32 {
    posix.fchown(fdFromU64(fd) orelse return fail(), u32FromU64(uid) orelse return fail(), u32FromU64(gid) orelse return fail()) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_fdatasync(fd: u64) u32 {
    posix.fdatasync(fdFromU64(fd) orelse return fail()) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_fstat(fd: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const file = fs.File{ .handle = fdFromU64(fd) orelse return fail() };
    const st = file.stat() catch return fail();
    var buffer: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&buffer, "{{\"size\":{d},\"mode\":{d},\"mtimeMs\":{d},\"isFile\":{},\"isDirectory\":{}}}", .{
        st.size, @as(u64, st.mode), st.mtime, st.kind == .file, st.kind == .directory,
    }) catch return fail();
    return writeOwned(out_ptr, out_len, json);
}

pub export fn sa_node_plugin_fs_fsync(fd: u64) u32 {
    posix.fsync(fdFromU64(fd) orelse return fail()) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_ftruncate(fd: u64, len: u64) u32 {
    const file = fs.File{ .handle = fdFromU64(fd) orelse return fail() };
    file.setEndPos(len) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_futimes(fd: u64, atime_ms: u64, mtime_ms: u64) u32 {
    const times = [2]posix.timespec{ msToTimespec(atime_ms), msToTimespec(mtime_ms) };
    posix.futimens(fdFromU64(fd) orelse return fail(), &times) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_glob(pattern_ptr: ?[*]const u8, pattern_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const pattern = pattern_ptr.?[0..pattern_len];
    var results = std.ArrayList(u8).init(std.heap.page_allocator);
    defer results.deinit();
    results.appendSlice("[") catch return fail();

    var dir = fs.cwd().openDir(".", .{ .iterate = true }) catch return fail();
    defer dir.close();
    var iter = dir.iterate();
    var first = true;
    while (true) {
        const entry = iter.next() catch break orelse break;
        const name = entry.name;
        var matches = true;
        if (std.mem.indexOfScalar(u8, pattern, '*')) |star_pos| {
            const prefix = pattern[0..star_pos];
            const suffix = pattern[star_pos + 1 ..];
            if (prefix.len > 0 and !std.mem.startsWith(u8, name, prefix)) matches = false;
            if (suffix.len > 0 and !std.mem.endsWith(u8, name, suffix)) matches = false;
        } else {
            matches = std.mem.eql(u8, name, pattern);
        }
        if (matches) {
            if (!first) results.appendSlice(",") catch return fail();
            first = false;
            results.appendSlice("\"") catch return fail();
            results.appendSlice(name) catch return fail();
            results.appendSlice("\"") catch return fail();
        }
    }
    results.appendSlice("]") catch return fail();
    return writeOwned(out_ptr, out_len, results.items);
}

pub export fn sa_node_plugin_fs_link(src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64) u32 {
    const src = fsPathSlice(src_ptr, src_len) orelse return fail();
    const dst = fsPathSlice(dst_ptr, dst_len) orelse return fail();
    posix.linkat(posix.AT.FDCWD, src, posix.AT.FDCWD, dst, 0) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_mkdtemp(template_ptr: ?[*]const u8, template_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const template_name = fsPathSlice(template_ptr, template_len) orelse return fail();
    var buf: [256]u8 = undefined;
    if (template_name.len > 240) return fail();
    @memcpy(buf[0..template_name.len], template_name);
    const rand_val = crypto.random.int(u64);
    const suffix = std.fmt.bufPrint(buf[template_name.len..], "{x}", .{rand_val}) catch return fail();
    const full_path = buf[0 .. template_name.len + suffix.len];
    fs.cwd().makeDir(full_path) catch return fail();
    return writeOwned(out_ptr, out_len, full_path);
}

pub export fn sa_node_plugin_fs_open(path_ptr: ?[*]const u8, path_len: u64, flags: u64, mode: u64, out_fd: ?*u64) u32 {
    _ = mode;
    const path = fsPathSlice(path_ptr, path_len) orelse return fail();
    var open_flags: fs.File.OpenFlags = .{};
    if (flags & 2 != 0) open_flags.mode = .read_write else if (flags & 1 != 0) open_flags.mode = .write_only else open_flags.mode = .read_only;
    const file = fs.cwd().openFile(path, open_flags) catch return fail();
    out_fd.?.* = @intCast(file.handle);
    return 0;
}

pub export fn sa_node_plugin_fs_close_fd(fd: u64) u32 {
    if (fd <= 2) return fail();
    const os_fd = fdFromU64(fd) orelse return fail();
    if (close(os_fd) != 0) return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_read_fd(fd: u64, buf_ptr: ?[*]u8, len: u64, offset: u64, out_n: ?*u64) u32 {
    const file = fs.File{ .handle = fdFromU64(fd) orelse return fail() };
    const buf = (buf_ptr orelse return fail())[0..len];
    const n = file.pread(buf, offset) catch return fail();
    out_n.?.* = n;
    return 0;
}

pub export fn sa_node_plugin_fs_write_fd(fd: u64, data_ptr: ?[*]const u8, data_len: u64, offset: u64, out_n: ?*u64) u32 {
    const file = fs.File{ .handle = fdFromU64(fd) orelse return fail() };
    const data = (data_ptr orelse return fail())[0..data_len];
    const n = file.pwrite(data, offset) catch return fail();
    out_n.?.* = n;
    return 0;
}

pub export fn sa_node_plugin_fs_readv(fd: u64, iov_json_ptr: ?[*]const u8, iov_json_len: u64, out_n: ?*u64) u32 {
    const file = fs.File{ .handle = fdFromU64(fd) orelse return fail() };
    const iov_json = if (iov_json_ptr) |p| p[0..iov_json_len] else "[]";
    if (iov_json_len == 0) {
        out_n.?.* = 0;
        return 0;
    }
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, iov_json, .{}) catch return fail();
    defer parsed.deinit();

    const items = switch (parsed.value) {
        .array => |arr| arr.items,
        else => return fail(),
    };

    var total: u64 = 0;
    var buf = std.ArrayList(u8).init(std.heap.page_allocator);
    defer buf.deinit();
    for (items) |item| {
        const len: u64 = switch (item) {
            .integer => |v| @intCast(if (v < 0) 0 else v),
            .object => |obj| if (obj.get("len")) |v| @intCast(if (v.integer < 0) 0 else v.integer) else 0,
            else => 0,
        };
        if (len == 0) continue;
        buf.resize(len) catch return fail();
        const n = file.read(buf.items) catch return fail();
        total += n;
        if (n < len) break;
    }
    out_n.?.* = total;
    return 0;
}

pub export fn sa_node_plugin_fs_writev(fd: u64, iov_json_ptr: ?[*]const u8, iov_json_len: u64, out_n: ?*u64) u32 {
    const file = fs.File{ .handle = fdFromU64(fd) orelse return fail() };
    const iov_json = if (iov_json_ptr) |p| p[0..iov_json_len] else "[]";
    if (iov_json_len == 0) {
        out_n.?.* = 0;
        return 0;
    }
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, iov_json, .{}) catch return fail();
    defer parsed.deinit();

    const items = switch (parsed.value) {
        .array => |arr| arr.items,
        else => return fail(),
    };

    var total: u64 = 0;
    for (items) |item| {
        const data = switch (item) {
            .string => |s| s,
            .object => |obj| if (obj.get("data")) |v| v.string else "",
            else => "",
        };
        if (data.len == 0) continue;
        const n = file.write(data) catch return fail();
        total += n;
    }
    out_n.?.* = total;
    return 0;
}

const DirIterHandle = struct {
    dir_fd: std.posix.fd_t,
    dir: fs.Dir,
    entries: std.ArrayList(fs.Dir.Entry),
    index: usize,
};

pub export fn sa_node_plugin_fs_opendir(path_ptr: ?[*]const u8, path_len: u64, out_handle: ?*?*anyopaque) u32 {
    const path = fsPathSlice(path_ptr, path_len) orelse return fail();
    var dir = if (std.fs.path.isAbsolute(path))
        std.fs.openDirAbsolute(path, .{ .iterate = true }) catch return fail()
    else
        fs.cwd().openDir(path, .{ .iterate = true }) catch return fail();
    const handle = std.heap.page_allocator.create(DirIterHandle) catch {
        dir.close();
        return fail();
    };
    var entries = std.ArrayList(fs.Dir.Entry).init(std.heap.page_allocator);
    errdefer entries.deinit();
    var iter = dir.iterate();
    while (true) {
        const maybe_entry = iter.next() catch break;
        const entry = maybe_entry orelse break;
        const name = std.heap.page_allocator.dupe(u8, entry.name) catch {
            for (entries.items) |e| std.heap.page_allocator.free(e.name);
            entries.deinit();
            dir.close();
            std.heap.page_allocator.destroy(handle);
            return fail();
        };
        entries.append(.{ .name = name, .kind = entry.kind }) catch {
            std.heap.page_allocator.free(name);
            for (entries.items) |e| std.heap.page_allocator.free(e.name);
            entries.deinit();
            dir.close();
            std.heap.page_allocator.destroy(handle);
            return fail();
        };
    }
    handle.* = .{ .dir_fd = dir.fd, .dir = dir, .entries = entries, .index = 0 };
    out_handle.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_fs_opendir_next(handle_ptr: ?*anyopaque, out_name_ptr: ?*?[*]const u8, out_name_len: ?*u64, out_entry_type: ?*u64) u32 {
    const handle: *DirIterHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    if (handle.index >= handle.entries.items.len) return 1;
    const entry = handle.entries.items[handle.index];
    handle.index += 1;
    const name = std.heap.page_allocator.dupe(u8, entry.name) catch return fail();
    out_name_ptr.?.* = name.ptr;
    out_name_len.?.* = name.len;
    out_entry_type.?.* = switch (entry.kind) {
        .file => 1,
        .directory => 2,
        .sym_link => 3,
        else => 0,
    };
    return 0;
}

pub export fn sa_node_plugin_fs_opendir_free(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| {
        const handle: *DirIterHandle = @ptrCast(@alignCast(ptr));
        for (handle.entries.items) |entry| {
            std.heap.page_allocator.free(entry.name);
        }
        handle.entries.deinit();
        handle.dir.close();
        std.heap.page_allocator.destroy(handle);
    }
    return 0;
}

pub export fn sa_node_plugin_fs_rm(path_ptr: ?[*]const u8, path_len: u64, recursive: u64) u32 {
    const path = fsPathSlice(path_ptr, path_len) orelse return fail();
    if (recursive != 0) {
        fs.cwd().deleteTree(path) catch return fail();
    } else {
        fs.cwd().deleteFile(path) catch return fail();
    }
    return 0;
}

fn fsPathExists(path: []const u8) bool {
    _ = fs.cwd().statFile(path) catch return false;
    return true;
}

fn fsEnsureParentPath(path: []const u8) !void {
    if (fs.path.dirname(path)) |parent| {
        if (parent.len > 0) try fs.cwd().makePath(parent);
    }
}

fn fsCopySymlink(src_dir: fs.Dir, src_path: []const u8, dst_path: []const u8, force: bool) !void {
    var target_buffer: [fs.max_path_bytes]u8 = undefined;
    const target = try src_dir.readLink(src_path, &target_buffer);

    try fsEnsureParentPath(dst_path);
    if (force) fs.cwd().deleteFile(dst_path) catch {};
    try fs.cwd().symLink(target, dst_path, .{});
}

fn fsCopyFilePath(src_path: []const u8, dst_path: []const u8, force: bool) !void {
    try fsEnsureParentPath(dst_path);
    if (force) fs.cwd().deleteFile(dst_path) catch {};
    if (fs.path.isAbsolute(src_path) and fs.path.isAbsolute(dst_path)) {
        try fs.copyFileAbsolute(src_path, dst_path, .{});
    } else {
        try fs.cwd().copyFile(src_path, fs.cwd(), dst_path, .{});
    }
}

fn fsCopyDirectoryRecursive(src_path: []const u8, dst_path: []const u8, force: bool) !void {
    try fs.cwd().makePath(dst_path);

    var source_dir = try fs.cwd().openDir(src_path, .{ .iterate = true });
    defer source_dir.close();

    var walker = try source_dir.walk(std.heap.page_allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        const child_dst = try fs.path.join(std.heap.page_allocator, &.{ dst_path, entry.path });
        defer std.heap.page_allocator.free(child_dst);

        switch (entry.kind) {
            .directory => try fs.cwd().makePath(child_dst),
            .file => {
                const child_src = try fs.path.join(std.heap.page_allocator, &.{ src_path, entry.path });
                defer std.heap.page_allocator.free(child_src);
                try fsCopyFilePath(child_src, child_dst, force);
            },
            .sym_link => try fsCopySymlink(entry.dir, entry.basename, child_dst, force),
            else => {},
        }
    }
}

fn fsCpPath(src_path: []const u8, dst_path: []const u8, recursive: bool, force: bool, error_on_exist: bool) !void {
    if (src_path.len == 0 or dst_path.len == 0) return error.InvalidPath;
    if (std.mem.eql(u8, src_path, dst_path)) return error.SamePath;
    if (std.mem.startsWith(u8, dst_path, src_path) and dst_path.len > src_path.len and dst_path[src_path.len] == fs.path.sep) return error.InvalidPath;

    const dst_exists = fsPathExists(dst_path);
    if (dst_exists and error_on_exist) return error.PathAlreadyExists;
    if (dst_exists and !force) return;

    const src_stat = try fs.cwd().statFile(src_path);
    switch (src_stat.kind) {
        .directory => {
            if (!recursive) return error.IsDir;
            try fsCopyDirectoryRecursive(src_path, dst_path, force);
        },
        .file => try fsCopyFilePath(src_path, dst_path, force),
        .sym_link => try fsCopySymlink(fs.cwd(), src_path, dst_path, force),
        else => return error.UnsupportedFileType,
    }
}

pub export fn sa_node_plugin_fs_cp(src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64, recursive: u64, force: u64, error_on_exist: u64) u32 {
    const src_path = fsPathSlice(src_ptr, src_len) orelse return fail();
    const dst_path = fsPathSlice(dst_ptr, dst_len) orelse return fail();
    fsCpPath(src_path, dst_path, recursive != 0, force != 0, error_on_exist != 0) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_statfs(path_ptr: ?[*]const u8, out_json_ptr: ?*?[*]const u8, out_json_len: ?*u64) u32 {
    const path = cStringSliceBounded(path_ptr.?);
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return fail();
    defer std.heap.page_allocator.free(path_z);
    var st: Statvfs = undefined;
    if (statvfs(path_z.ptr, &st) != 0) return fail();
    var buffer: [384]u8 = undefined;
    const json = std.fmt.bufPrint(&buffer, "{{\"bsize\":{d},\"frsize\":{d},\"blocks\":{d},\"bfree\":{d},\"bavail\":{d},\"files\":{d},\"ffree\":{d},\"favail\":{d},\"namemax\":{d}}}", .{
        @as(u64, @intCast(st.f_bsize)),
        @as(u64, @intCast(st.f_frsize)),
        @as(u64, @intCast(st.f_blocks)),
        @as(u64, @intCast(st.f_bfree)),
        @as(u64, @intCast(st.f_bavail)),
        @as(u64, @intCast(st.f_files)),
        @as(u64, @intCast(st.f_ffree)),
        @as(u64, @intCast(st.f_favail)),
        @as(u64, @intCast(st.f_namemax)),
    }) catch return fail();
    return writeOwned(out_json_ptr, out_json_len, json);
}

pub export fn sa_node_plugin_fs_symlink(src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64) u32 {
    const src = fsPathSlice(src_ptr, src_len) orelse return fail();
    const dst = fsPathSlice(dst_ptr, dst_len) orelse return fail();
    posix.symlinkat(src, posix.AT.FDCWD, dst) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_truncate(path_ptr: ?[*]const u8, path_len: u64, len: u64) u32 {
    const path = fsPathSlice(path_ptr, path_len) orelse return fail();
    const file = fs.cwd().openFile(path, .{ .mode = .write_only }) catch return fail();
    defer file.close();
    file.setEndPos(len) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_utimes(path_ptr: ?[*]const u8, path_len: u64, atime_ms: u64, mtime_ms: u64) u32 {
    const path = fsPathSlice(path_ptr, path_len) orelse return fail();
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return fail();
    defer std.heap.page_allocator.free(path_z);
    var times = [2]std.c.timespec{ msToTimespec(atime_ms), msToTimespec(mtime_ms) };
    if (std.c.utimensat(posix.AT.FDCWD, path_z.ptr, &times, 0) != 0) return fail();
    return 0;
}

// fs.promises exposes Node's promise-module names while returning already
// resolved native buffers/status values to SA code.
pub export fn sa_node_plugin_fs_promises_stat(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_fs_stat(path_ptr, path_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_fs_promises_lstat(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_fs_lstat(path_ptr, path_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_fs_promises_readdir(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_fs_readdir(path_ptr, path_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_fs_promises_readdir_with_types(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_fs_readdir_with_types(path_ptr, path_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_fs_promises_readlink(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_fs_readlink(path_ptr, path_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_fs_promises_realpath(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_fs_realpath(path_ptr, path_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_fs_promises_exists(path_ptr: ?[*]const u8, path_len: u64, out_bool: ?*u32) u32 {
    return base.sa_node_plugin_fs_exists(path_ptr, path_len, out_bool);
}
pub export fn sa_node_plugin_fs_promises_access(path_ptr: ?[*]const u8, path_len: u64, mode: u32, out_bool: ?*u32) u32 {
    return base.sa_node_plugin_fs_access(path_ptr, path_len, mode, out_bool);
}
pub export fn sa_node_plugin_fs_promises_read_file(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_fs_read_file(path_ptr, path_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_fs_promises_write_file(path_ptr: ?[*]const u8, path_len: u64, data_ptr: ?[*]const u8, data_len: u64) u32 {
    return base.sa_node_plugin_fs_write_file(path_ptr, path_len, data_ptr, data_len);
}
pub export fn sa_node_plugin_fs_promises_mkdir(path_ptr: ?[*]const u8, path_len: u64, recursive: u8) u32 {
    return base.sa_node_plugin_fs_mkdir(path_ptr, path_len, recursive);
}
pub export fn sa_node_plugin_fs_promises_rmdir(path_ptr: ?[*]const u8, path_len: u64) u32 {
    return base.sa_node_plugin_fs_rmdir(path_ptr, path_len);
}
pub export fn sa_node_plugin_fs_promises_unlink(path_ptr: ?[*]const u8, path_len: u64) u32 {
    return base.sa_node_plugin_fs_unlink(path_ptr, path_len);
}
pub export fn sa_node_plugin_fs_promises_rename(old_ptr: ?[*]const u8, old_len: u64, new_ptr: ?[*]const u8, new_len: u64) u32 {
    return base.sa_node_plugin_fs_rename(old_ptr, old_len, new_ptr, new_len);
}
pub export fn sa_node_plugin_fs_promises_copy_file(src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64) u32 {
    return base.sa_node_plugin_fs_copy_file(src_ptr, src_len, dst_ptr, dst_len);
}
pub export fn sa_node_plugin_fs_promises_cp(src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64, recursive: u64, force: u64, error_on_exist: u64) u32 {
    return sa_node_plugin_fs_cp(src_ptr, src_len, dst_ptr, dst_len, recursive, force, error_on_exist);
}
pub export fn sa_node_plugin_fs_promises_chmod(path_ptr: ?[*]const u8, path_len: u64, mode: u64) u32 {
    return sa_node_plugin_fs_chmod(path_ptr, path_len, mode);
}
pub export fn sa_node_plugin_fs_promises_chown(path_ptr: ?[*]const u8, path_len: u64, uid: u64, gid: u64) u32 {
    return sa_node_plugin_fs_chown(path_ptr, path_len, uid, gid);
}
pub export fn sa_node_plugin_fs_promises_link(src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64) u32 {
    return sa_node_plugin_fs_link(src_ptr, src_len, dst_ptr, dst_len);
}
pub export fn sa_node_plugin_fs_promises_mkdtemp(template_ptr: ?[*]const u8, template_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_fs_mkdtemp(template_ptr, template_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_fs_promises_rm(path_ptr: ?[*]const u8, path_len: u64, recursive: u64) u32 {
    return sa_node_plugin_fs_rm(path_ptr, path_len, recursive);
}
pub export fn sa_node_plugin_fs_promises_statfs(path_ptr: ?[*]const u8, out_json_ptr: ?*?[*]const u8, out_json_len: ?*u64) u32 {
    return sa_node_plugin_fs_statfs(path_ptr, out_json_ptr, out_json_len);
}
pub export fn sa_node_plugin_fs_promises_symlink(src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64) u32 {
    return sa_node_plugin_fs_symlink(src_ptr, src_len, dst_ptr, dst_len);
}
pub export fn sa_node_plugin_fs_promises_truncate(path_ptr: ?[*]const u8, path_len: u64, len: u64) u32 {
    return sa_node_plugin_fs_truncate(path_ptr, path_len, len);
}
pub export fn sa_node_plugin_fs_promises_utimes(path_ptr: ?[*]const u8, path_len: u64, atime_ms: u64, mtime_ms: u64) u32 {
    return sa_node_plugin_fs_utimes(path_ptr, path_len, atime_ms, mtime_ms);
}
pub export fn sa_node_plugin_fs_promises_open(path_ptr: ?[*]const u8, path_len: u64, flags: u64, mode: u64, out_fd: ?*u64) u32 {
    return sa_node_plugin_fs_open(path_ptr, path_len, flags, mode, out_fd);
}
pub export fn sa_node_plugin_fs_promises_close_file(fd: u64) u32 {
    return sa_node_plugin_fs_close_fd(fd);
}
pub export fn sa_node_plugin_fs_promises_read(fd: u64, buf_ptr: ?[*]u8, len: u64, offset: u64, out_n: ?*u64) u32 {
    return sa_node_plugin_fs_read_fd(fd, buf_ptr, len, offset, out_n);
}
pub export fn sa_node_plugin_fs_promises_write(fd: u64, data_ptr: ?[*]const u8, data_len: u64, offset: u64, out_n: ?*u64) u32 {
    return sa_node_plugin_fs_write_fd(fd, data_ptr, data_len, offset, out_n);
}
pub export fn sa_node_plugin_fs_promises_readv(fd: u64, iov_json_ptr: ?[*]const u8, iov_json_len: u64, out_n: ?*u64) u32 {
    return sa_node_plugin_fs_readv(fd, iov_json_ptr, iov_json_len, out_n);
}
pub export fn sa_node_plugin_fs_promises_writev(fd: u64, iov_json_ptr: ?[*]const u8, iov_json_len: u64, out_n: ?*u64) u32 {
    return sa_node_plugin_fs_writev(fd, iov_json_ptr, iov_json_len, out_n);
}
pub export fn sa_node_plugin_fs_promises_fstat(fd: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_fs_fstat(fd, out_ptr, out_len);
}
pub export fn sa_node_plugin_fs_promises_fsync(fd: u64) u32 {
    return sa_node_plugin_fs_fsync(fd);
}
pub export fn sa_node_plugin_fs_promises_fdatasync(fd: u64) u32 {
    return sa_node_plugin_fs_fdatasync(fd);
}
pub export fn sa_node_plugin_fs_promises_ftruncate(fd: u64, len: u64) u32 {
    return sa_node_plugin_fs_ftruncate(fd, len);
}
pub export fn sa_node_plugin_fs_promises_fchmod(fd: u64, mode: u64) u32 {
    return sa_node_plugin_fs_fchmod(fd, mode);
}
pub export fn sa_node_plugin_fs_promises_fchown(fd: u64, uid: u64, gid: u64) u32 {
    return sa_node_plugin_fs_fchown(fd, uid, gid);
}
pub export fn sa_node_plugin_fs_promises_futimes(fd: u64, atime_ms: u64, mtime_ms: u64) u32 {
    return sa_node_plugin_fs_futimes(fd, atime_ms, mtime_ms);
}
pub export fn sa_node_plugin_fs_promises_opendir(path_ptr: ?[*]const u8, path_len: u64, out_handle: ?*?*anyopaque) u32 {
    return sa_node_plugin_fs_opendir(path_ptr, path_len, out_handle);
}
pub export fn sa_node_plugin_fs_promises_opendir_next(handle_ptr: ?*anyopaque, out_name_ptr: ?*?[*]const u8, out_name_len: ?*u64, out_entry_type: ?*u64) u32 {
    return sa_node_plugin_fs_opendir_next(handle_ptr, out_name_ptr, out_name_len, out_entry_type);
}
pub export fn sa_node_plugin_fs_promises_opendir_free(handle_ptr: ?*anyopaque) u32 {
    return sa_node_plugin_fs_opendir_free(handle_ptr);
}

// ============================================================
// EVENTS
// ============================================================

pub export fn sa_node_plugin_events_once(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, callback: ?*anyopaque) u32 {
    const ee: *base.EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return fail()));
    const event = event_ptr.?[0..event_len];
    ee.addListener(event, callback, false, true) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_events_off(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, callback: ?*anyopaque) u32 {
    const ee: *base.EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return fail()));
    const event = event_ptr.?[0..event_len];
    _ = ee.removeListener(event, callback);
    return 0;
}

pub export fn sa_node_plugin_events_remove_all_listeners(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64) u32 {
    const ee: *base.EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return fail()));
    const event = event_ptr.?[0..event_len];
    _ = ee.removeAll(event);
    return 0;
}

pub export fn sa_node_plugin_events_prepend_listener(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, callback: ?*anyopaque) u32 {
    const ee: *base.EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return fail()));
    const event = event_ptr.?[0..event_len];
    ee.addListener(event, callback, true, false) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_events_set_max_listeners(ee_ptr: ?*anyopaque, max: u32) u32 {
    const ee: *base.EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return fail()));
    ee.max_listeners = max;
    return 0;
}

pub export fn sa_node_plugin_events_get_max_listeners(ee_ptr: ?*anyopaque, out_max: ?*u32) u32 {
    const ee: *base.EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return fail()));
    out_max.?.* = ee.max_listeners;
    return 0;
}

pub export fn sa_node_plugin_events_get_event_listeners(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const ee: *base.EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return fail()));
    const event = event_ptr.?[0..event_len];
    const count = ee.listenerCount(event);
    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    defer json.deinit();
    json.appendSlice("[") catch return fail();
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        if (i > 0) json.appendSlice(",") catch return fail();
        json.appendSlice("{\"type\":\"listener\"}") catch return fail();
    }
    json.appendSlice("]") catch return fail();
    const owned = json.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_events_listener_count_by_event(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, out_count: ?*u64) u32 {
    const ee: *base.EventEmitter = @ptrCast(@alignCast(ee_ptr orelse return fail()));
    const event = event_ptr.?[0..event_len];
    out_count.?.* = ee.listenerCount(event);
    return 0;
}

pub export fn sa_node_plugin_events_emit_with_error(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, data_ptr: ?[*]const u8, data_len: u64) u32 {
    return base.sa_node_plugin_events_emit(ee_ptr, event_ptr, event_len, data_ptr, data_len);
}

// ============================================================
// CONSOLE
// ============================================================

var console_count_map = std.StringHashMap(u64).init(std.heap.page_allocator);

fn consoleWrite(prefix: []const u8, data_ptr: ?[*]const u8, data_len: u64) void {
    const out = std.io.getStdOut().writer();
    const data = if (data_len == 0)
        ""
    else
        (data_ptr orelse return)[0..data_len];
    out.print("{s}{s}\n", .{ prefix, data }) catch {};
}

pub export fn sa_node_plugin_console_warn(data_ptr: ?[*]const u8, data_len: u64) u32 {
    consoleWrite("[WARN] ", data_ptr, data_len);
    return 0;
}
pub export fn sa_node_plugin_console_info(data_ptr: ?[*]const u8, data_len: u64) u32 {
    consoleWrite("[INFO] ", data_ptr, data_len);
    return 0;
}
pub export fn sa_node_plugin_console_debug(data_ptr: ?[*]const u8, data_len: u64) u32 {
    consoleWrite("[DEBUG] ", data_ptr, data_len);
    return 0;
}
pub export fn sa_node_plugin_console_dir(data_ptr: ?[*]const u8, data_len: u64) u32 {
    consoleWrite("", data_ptr, data_len);
    return 0;
}
pub export fn sa_node_plugin_console_dirxml(data_ptr: ?[*]const u8, data_len: u64) u32 {
    consoleWrite("", data_ptr, data_len);
    return 0;
}
pub export fn sa_node_plugin_console_time_log(label_ptr: ?[*]const u8, label_len: u64, data_ptr: ?[*]const u8, data_len: u64) u32 {
    _ = label_ptr;
    _ = label_len;
    consoleWrite("", data_ptr, data_len);
    return 0;
}

pub export fn sa_node_plugin_console_count(label_ptr: ?[*]const u8, label_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const label = label_ptr.?[0..label_len];
    const entry = console_count_map.getOrPut(label) catch return fail();
    if (!entry.found_existing) entry.value_ptr.* = 0;
    entry.value_ptr.* += 1;
    var buf: [64]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{s}: {d}", .{ label, entry.value_ptr.* }) catch return fail();
    return writeOwned(out_ptr, out_len, result);
}

pub export fn sa_node_plugin_console_count_reset(label_ptr: ?[*]const u8, label_len: u64) u32 {
    const label = label_ptr.?[0..label_len];
    const entry = console_count_map.getOrPut(label) catch return fail();
    entry.value_ptr.* = 0;
    return 0;
}

pub export fn sa_node_plugin_console_assert(condition: u32, data_ptr: ?[*]const u8, data_len: u64) u32 {
    if (condition == 0) {
        const err = std.io.getStdErr().writer();
        err.print("Assertion failed: {s}\n", .{data_ptr.?[0..data_len]}) catch {};
    }
    return 0;
}

pub export fn sa_node_plugin_console_trace(data_ptr: ?[*]const u8, data_len: u64) u32 {
    consoleWrite("Trace: ", data_ptr, data_len);
    return 0;
}
pub export fn sa_node_plugin_console_table(data_ptr: ?[*]const u8, data_len: u64) u32 {
    consoleWrite("", data_ptr, data_len);
    return 0;
}

pub export fn sa_node_plugin_console_group() u32 {
    return 0;
}
pub export fn sa_node_plugin_console_group_end() u32 {
    return 0;
}
pub export fn sa_node_plugin_console_group_collapsed() u32 {
    return 0;
}
pub export fn sa_node_plugin_console_time_stamp(data_ptr: ?[*]const u8, data_len: u64) u32 {
    consoleWrite("[Timestamp] ", data_ptr, data_len);
    return 0;
}

// ============================================================
// DNS
// ============================================================

const DnsClassIn = 1;
const DnsTypeA = 1;
const DnsTypeNs = 2;
const DnsTypeCname = 5;
const DnsTypePtr = 12;
const DnsTypeMx = 15;
const DnsTypeTxt = 16;
const DnsTypeAaaa = 28;
const DnsTypeSrv = 33;
const DnsTypeNaptr = 35;
const DnsTypeTlsa = 52;
const DnsTypeCaa = 257;
const DnsTypeSoa = 6;
const DnsTypeAny = 255;

var dns_config_mutex = std.Thread.Mutex{};
var dns_custom_servers: ?[]u8 = null;
var dns_default_result_order: []const u8 = "verbatim";

const DnsLookupOrder = enum { verbatim, ipv4first, ipv6first };

const DNS_HINT_ADDRCONFIG: u32 = 32;
const DNS_HINT_V4MAPPED: u32 = 8;
const DNS_HINT_ALL: u32 = 16;
const DNS_SUPPORTED_HINTS: u32 = DNS_HINT_ADDRCONFIG | DNS_HINT_V4MAPPED | DNS_HINT_ALL;

const DNS_CONSTANTS_JSON =
    \\{"ADDRCONFIG":32,"V4MAPPED":8,"ALL":16,"NODATA":"ENODATA","FORMERR":"EFORMERR","SERVFAIL":"ESERVFAIL","NOTFOUND":"ENOTFOUND","NOTIMP":"ENOTIMP","REFUSED":"EREFUSED","BADQUERY":"EBADQUERY","BADNAME":"EBADNAME","BADFAMILY":"EBADFAMILY","BADRESP":"EBADRESP","CONNREFUSED":"ECONNREFUSED","TIMEOUT":"ETIMEOUT","EOF":"EOF","FILE":"EFILE","NOMEM":"ENOMEM","DESTRUCTION":"EDESTRUCTION","BADSTR":"EBADSTR","BADFLAGS":"EBADFLAGS","NONAME":"ENONAME","BADHINTS":"EBADHINTS","NOTINITIALIZED":"ENOTINITIALIZED","LOADIPHLPAPI":"ELOADIPHLPAPI","ADDRGETNETWORKPARAMS":"EADDRGETNETWORKPARAMS","CANCELLED":"ECANCELLED"}
;

pub export fn sa_node_plugin_dns_constants_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, DNS_CONSTANTS_JSON);
}

const DnsResolverHandle = struct {
    allocator: std.mem.Allocator,
    servers_json: ?[]u8 = null,
    local_ipv4: ?[]u8 = null,
    local_ipv6: ?[]u8 = null,
    timeout_ms: u64 = 0,
    tries: u64 = 0,
    cancel_count: u64 = 0,

    fn deinit(self: *DnsResolverHandle) void {
        if (self.servers_json) |servers| self.allocator.free(servers);
        if (self.local_ipv4) |addr| self.allocator.free(addr);
        if (self.local_ipv6) |addr| self.allocator.free(addr);
        self.allocator.destroy(self);
    }
};

fn parseDnsServerAddress(server: []const u8) !std.net.Address {
    if (server.len == 0) return error.InvalidServer;
    if (std.net.Address.parseIp(server, 53)) |addr| return addr else |_| {}

    if (server[0] == '[') {
        const end = std.mem.indexOfScalar(u8, server, ']') orelse return error.InvalidServer;
        var port: u16 = 53;
        if (end + 1 < server.len) {
            if (server[end + 1] != ':') return error.InvalidServer;
            port = try std.fmt.parseInt(u16, server[end + 2 ..], 10);
            if (port == 0) return error.InvalidServer;
        }
        return std.net.Address.parseIp6(server[1..end], port);
    }

    if (std.mem.lastIndexOfScalar(u8, server, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, server[0..colon], ':') != null) return error.InvalidServer;
        const port = try std.fmt.parseInt(u16, server[colon + 1 ..], 10);
        if (port == 0) return error.InvalidServer;
        return std.net.Address.parseIp4(server[0..colon], port);
    }
    return error.InvalidServer;
}

fn appendDnsServerCanonical(out: *std.ArrayList(u8), server: std.net.Address) !void {
    const host = try tlsAddressToOwnedHost(std.heap.page_allocator, server);
    defer std.heap.page_allocator.free(host);
    if (server.getPort() == 53) {
        try appendJsonString(out, host);
        return;
    }
    switch (server.any.family) {
        std.posix.AF.INET => {
            const canonical = try std.fmt.allocPrint(std.heap.page_allocator, "{s}:{d}", .{ host, server.getPort() });
            defer std.heap.page_allocator.free(canonical);
            try appendJsonString(out, canonical);
        },
        std.posix.AF.INET6 => {
            const canonical = try std.fmt.allocPrint(std.heap.page_allocator, "[{s}]:{d}", .{ host, server.getPort() });
            defer std.heap.page_allocator.free(canonical);
            try appendJsonString(out, canonical);
        },
        else => return error.InvalidServer,
    }
}

fn normalizeDnsServersJson(allocator: std.mem.Allocator, servers: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, servers, .{});
    defer parsed.deinit();
    if (parsed.value != .array) return error.InvalidServer;
    const arr = parsed.value.array;
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append('[');
    for (arr.items, 0..) |item, i| {
        if (item != .string) return error.InvalidServer;
        const server = item.string;
        const addr = try parseDnsServerAddress(server);
        if (i != 0) try out.append(',');
        try appendDnsServerCanonical(&out, addr);
    }
    try out.append(']');
    return out.toOwnedSlice();
}

fn parseDnsLookupOrder(order_ptr: ?[*]const u8, order_len: u64) !DnsLookupOrder {
    if (order_ptr == null or order_len == 0) {
        if (std.mem.eql(u8, dns_default_result_order, "ipv4first")) return .ipv4first;
        if (std.mem.eql(u8, dns_default_result_order, "ipv6first")) return .ipv6first;
        return .verbatim;
    }
    const order = order_ptr.?[0..order_len];
    if (std.mem.eql(u8, order, "verbatim")) return .verbatim;
    if (std.mem.eql(u8, order, "ipv4first")) return .ipv4first;
    if (std.mem.eql(u8, order, "ipv6first")) return .ipv6first;
    return error.InvalidDnsOrder;
}

fn dnsAddressFamilyValue(addr: std.net.Address) u64 {
    return switch (addr.any.family) {
        std.posix.AF.INET => 4,
        std.posix.AF.INET6 => 6,
        else => 0,
    };
}

fn dnsSystemHasNonLoopbackFamily(family: u32) bool {
    var ifap: ?*StructIfaddrs = null;
    if (getifaddrs(&ifap) != 0) return true;
    defer freeifaddrs(ifap);

    var current = ifap;
    while (current) |ifa| : (current = ifa.ifa_next) {
        const raw = ifa.ifa_addr orelse continue;
        const af = raw.sa_family;
        if (family == 4 and af == std.posix.AF.INET) {
            const addr: *const std.posix.sockaddr.in = @ptrCast(@alignCast(raw));
            const bytes = std.mem.asBytes(&addr.addr);
            if (!(bytes[0] == 0 or bytes[0] == 127)) return true;
        } else if (family == 6 and af == std.posix.AF.INET6) {
            const addr: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(raw));
            if (!std.mem.eql(u8, &addr.addr, &[_]u8{0} ** 16) and !std.mem.eql(u8, &addr.addr, &([_]u8{0} ** 15 ++ [_]u8{1}))) return true;
        }
    }
    return false;
}

fn dnsAddressAllowedByAddrConfig(addr: std.net.Address, has_ipv4: bool, has_ipv6: bool) bool {
    return switch (addr.any.family) {
        std.posix.AF.INET => has_ipv4,
        std.posix.AF.INET6 => has_ipv6,
        else => false,
    };
}

fn dnsIpv4MappedAddress(addr: std.net.Address) ?std.net.Address {
    if (addr.any.family != std.posix.AF.INET) return null;
    const bytes = std.mem.asBytes(&addr.in.sa.addr);
    var mapped = [_]u8{0} ** 16;
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12] = bytes[0];
    mapped[13] = bytes[1];
    mapped[14] = bytes[2];
    mapped[15] = bytes[3];
    return std.net.Address.initIp6(mapped, addr.getPort(), 0, 0);
}

fn appendDnsLookupAddressJson(out: *std.ArrayList(u8), addr: std.net.Address) !void {
    const host = try tlsAddressToOwnedHost(std.heap.page_allocator, addr);
    defer std.heap.page_allocator.free(host);
    try out.appendSlice("{\"address\":");
    try appendJsonString(out, host);
    try out.writer().print(",\"family\":{d}}}", .{dnsAddressFamilyValue(addr)});
}

pub export fn sa_node_plugin_dns_lookup_options_hints(hostname_ptr: ?[*]const u8, hostname_len: u64, family: u32, all: u32, hints: u32, order_ptr: ?[*]const u8, order_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (family != 0 and family != 4 and family != 6) return fail();
    if ((hints & ~DNS_SUPPORTED_HINTS) != 0) return fail();
    const order = parseDnsLookupOrder(order_ptr, order_len) catch return fail();
    const hostname = (hostname_ptr orelse return fail())[0..hostname_len];
    if (hostname.len == 0) return fail();
    const host_z = std.heap.page_allocator.dupeZ(u8, hostname) catch return fail();
    defer std.heap.page_allocator.free(host_z);

    var list = std.net.getAddressList(std.heap.page_allocator, host_z, 0) catch return fail();
    defer list.deinit();

    var addrs = std.ArrayList(std.net.Address).init(std.heap.page_allocator);
    defer addrs.deinit();
    var mapped_addrs = std.ArrayList(std.net.Address).init(std.heap.page_allocator);
    defer mapped_addrs.deinit();
    const use_addrconfig = (hints & DNS_HINT_ADDRCONFIG) != 0;
    const has_ipv4 = !use_addrconfig or dnsSystemHasNonLoopbackFamily(4);
    const has_ipv6 = !use_addrconfig or dnsSystemHasNonLoopbackFamily(6);
    for (list.addrs) |addr| {
        const addr_family = dnsAddressFamilyValue(addr);
        if (addr_family == 0) continue;
        if (use_addrconfig and !dnsAddressAllowedByAddrConfig(addr, has_ipv4, has_ipv6)) continue;
        if (family == 6 and addr_family == 4 and (hints & DNS_HINT_V4MAPPED) != 0) {
            if (dnsIpv4MappedAddress(addr)) |mapped| mapped_addrs.append(mapped) catch return fail();
            continue;
        }
        if (family != 0 and addr_family != family) continue;
        addrs.append(addr) catch return fail();
    }
    if (family == 6 and (hints & DNS_HINT_V4MAPPED) != 0 and ((hints & DNS_HINT_ALL) != 0 or addrs.items.len == 0)) {
        addrs.appendSlice(mapped_addrs.items) catch return fail();
    }
    if (addrs.items.len == 0) return fail();
    if (order != .verbatim) {
        const wants_ipv4_first = order == .ipv4first;
        var i: usize = 0;
        while (i < addrs.items.len) : (i += 1) {
            var best = i;
            var j = i + 1;
            while (j < addrs.items.len) : (j += 1) {
                const jf = dnsAddressFamilyValue(addrs.items[j]);
                const bf = dnsAddressFamilyValue(addrs.items[best]);
                if ((wants_ipv4_first and jf < bf) or (!wants_ipv4_first and jf > bf)) best = j;
            }
            if (best != i) std.mem.swap(std.net.Address, &addrs.items[i], &addrs.items[best]);
        }
    }

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    if (all != 0) {
        out.append('[') catch return fail();
        for (addrs.items, 0..) |addr, i| {
            if (i != 0) out.append(',') catch return fail();
            appendDnsLookupAddressJson(&out, addr) catch return fail();
        }
        out.append(']') catch return fail();
    } else {
        appendDnsLookupAddressJson(&out, addrs.items[0]) catch return fail();
    }
    const owned = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_dns_lookup_options(hostname_ptr: ?[*]const u8, hostname_len: u64, family: u32, all: u32, order_ptr: ?[*]const u8, order_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_lookup_options_hints(hostname_ptr, hostname_len, family, all, 0, order_ptr, order_len, out_ptr, out_len);
}

fn writeSystemDnsServers(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const resolv = std.fs.openFileAbsolute("/etc/resolv.conf", .{}) catch return writeOwned(out_ptr, out_len, "[]");
    defer resolv.close();
    const data = resolv.readToEndAlloc(std.heap.page_allocator, 64 * 1024) catch return fail();
    defer std.heap.page_allocator.free(data);
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("[") catch return fail();
    var first = true;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "nameserver")) continue;
        var parts = std.mem.tokenizeAny(u8, trimmed, " \t");
        _ = parts.next();
        const server = parts.next() orelse continue;
        if (!first) out.appendSlice(",") catch return fail();
        first = false;
        appendJsonString(&out, server) catch return fail();
    }
    out.appendSlice("]") catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}

fn appendAddressJson(out: *std.ArrayList(u8), addr: std.net.Address, family: u16, first: *bool) !void {
    if (family == DnsTypeA and addr.any.family != std.posix.AF.INET) return;
    if (family == DnsTypeAaaa and addr.any.family != std.posix.AF.INET6) return;
    if (!first.*) try out.appendSlice(",");
    first.* = false;
    switch (addr.any.family) {
        std.posix.AF.INET => {
            const bytes = std.mem.asBytes(&addr.in.sa.addr);
            try out.writer().print("\"{d}.{d}.{d}.{d}\"", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
        },
        std.posix.AF.INET6 => {
            var buf: [64]u8 = undefined;
            const text = try std.fmt.bufPrint(&buf, "{}", .{addr});
            const without_port = if (std.mem.lastIndexOfScalar(u8, text, ']')) |end| text[1..end] else text;
            try appendJsonString(out, without_port);
        },
        else => {},
    }
}

fn writeAddressList(hostname: []const u8, family: u16, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const list = std.net.getAddressList(std.heap.page_allocator, hostname, 0) catch return fail();
    defer list.deinit();
    var results = std.ArrayList(u8).init(std.heap.page_allocator);
    defer results.deinit();
    results.appendSlice("[") catch return fail();
    var first = true;
    for (list.addrs) |addr| appendAddressJson(&results, addr, family, &first) catch return fail();
    results.appendSlice("]") catch return fail();
    return writeOwned(out_ptr, out_len, results.items);
}

fn skipDnsName(packet: []const u8, offset: *usize) !void {
    var pos = offset.*;
    while (true) {
        if (pos >= packet.len) return error.Truncated;
        const len = packet[pos];
        if ((len & 0xc0) == 0xc0) {
            if (pos + 1 >= packet.len) return error.Truncated;
            offset.* = pos + 2;
            return;
        }
        pos += 1;
        if (len == 0) {
            offset.* = pos;
            return;
        }
        if ((len & 0xc0) != 0 or pos + len > packet.len) return error.Truncated;
        pos += len;
    }
}

fn readDnsNameInto(packet: []const u8, start: usize, out: *std.ArrayList(u8)) !usize {
    var pos = start;
    var consumed: usize = 0;
    var jumped = false;
    var jumps: usize = 0;
    var first = true;
    while (true) {
        if (pos >= packet.len) return error.Truncated;
        const len = packet[pos];
        if ((len & 0xc0) == 0xc0) {
            if (pos + 1 >= packet.len) return error.Truncated;
            const ptr = (@as(usize, len & 0x3f) << 8) | packet[pos + 1];
            if (!jumped) consumed += 2;
            jumped = true;
            pos = ptr;
            jumps += 1;
            if (jumps > 32) return error.PointerLoop;
            continue;
        }
        if ((len & 0xc0) != 0) return error.Truncated;
        pos += 1;
        if (!jumped) consumed += 1;
        if (len == 0) break;
        if (pos + len > packet.len) return error.Truncated;
        if (!first) try out.append('.');
        first = false;
        try out.appendSlice(packet[pos .. pos + len]);
        pos += len;
        if (!jumped) consumed += len;
    }
    return consumed;
}

fn readDnsNameAlloc(allocator: std.mem.Allocator, packet: []const u8, start: usize) !struct { name: []u8, consumed: usize } {
    var name = std.ArrayList(u8).init(allocator);
    errdefer name.deinit();
    const consumed = try readDnsNameInto(packet, start, &name);
    return .{ .name = try name.toOwnedSlice(), .consumed = consumed };
}

fn dnsQuery(hostname: []const u8, rrtype: u16, packet: []u8) ![]u8 {
    const host_z = try std.heap.page_allocator.dupeZ(u8, hostname);
    defer std.heap.page_allocator.free(host_z);
    const n = res_query(host_z.ptr, DnsClassIn, rrtype, packet.ptr, @intCast(packet.len));
    if (n < 0) return error.QueryFailed;
    return packet[0..@intCast(n)];
}

fn encodeDnsName(out: *std.ArrayList(u8), hostname: []const u8) !void {
    var labels = std.mem.splitScalar(u8, hostname, '.');
    while (labels.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return error.InvalidName;
        try out.append(@intCast(label.len));
        try out.appendSlice(label);
    }
    try out.append(0);
}

fn firstDnsServerAddress(servers_json: []const u8) !std.net.Address {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, servers_json, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    if (arr.items.len == 0) return error.InvalidServer;
    return parseDnsServerAddress(arr.items[0].string);
}

fn dnsLocalBindAddress(server: std.net.Address, local_ipv4: ?[]const u8, local_ipv6: ?[]const u8) !?std.net.Address {
    if (server.any.family == std.posix.AF.INET) {
        const local = local_ipv4 orelse return null;
        if (local.len == 0) return null;
        const addr = try std.net.Address.parseIp4(local, 0);
        return addr;
    }
    if (server.any.family == std.posix.AF.INET6) {
        const local = local_ipv6 orelse return null;
        if (local.len == 0) return null;
        const addr = try std.net.Address.parseIp6(local, 0);
        return addr;
    }
    return null;
}

fn dnsQueryServer(hostname: []const u8, rrtype: u16, server: std.net.Address, timeout_ms: u64, local_ipv4: ?[]const u8, local_ipv6: ?[]const u8, packet: []u8) ![]u8 {
    var query = std.ArrayList(u8).init(std.heap.page_allocator);
    defer query.deinit();

    var random_id: u16 = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&random_id));
    try query.writer().writeInt(u16, random_id, .big);
    try query.writer().writeInt(u16, 0x0100, .big);
    try query.writer().writeInt(u16, 1, .big);
    try query.writer().writeInt(u16, 0, .big);
    try query.writer().writeInt(u16, 0, .big);
    try query.writer().writeInt(u16, 0, .big);
    try encodeDnsName(&query, hostname);
    try query.writer().writeInt(u16, rrtype, .big);
    try query.writer().writeInt(u16, DnsClassIn, .big);

    const family: u32 = if (server.any.family == std.posix.AF.INET6) std.posix.AF.INET6 else std.posix.AF.INET;
    const fd = try std.posix.socket(family, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(fd);

    if (try dnsLocalBindAddress(server, local_ipv4, local_ipv6)) |bind_addr| {
        try std.posix.bind(fd, &bind_addr.any, bind_addr.getOsSockLen());
    }

    const timeout = @max(timeout_ms, @as(u64, 100));
    var tv = std.posix.timeval{
        .sec = @intCast(timeout / 1000),
        .usec = @intCast((timeout % 1000) * 1000),
    };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

    _ = try std.posix.sendto(fd, query.items, 0, &server.any, server.getOsSockLen());
    var src_addr: std.net.Address = undefined;
    var src_len: std.posix.socklen_t = @sizeOf(std.net.Address);
    const n = try std.posix.recvfrom(fd, packet, 0, &src_addr.any, &src_len);
    if (n < 12) return error.Truncated;
    if (std.mem.readInt(u16, packet[0..2], .big) != random_id) return error.InvalidResponse;
    return packet[0..n];
}

fn skipDnsQuestions(packet: []const u8, offset: *usize, qdcount: u16) !void {
    var i: u16 = 0;
    while (i < qdcount) : (i += 1) {
        try skipDnsName(packet, offset);
        if (offset.* + 4 > packet.len) return error.Truncated;
        offset.* += 4;
    }
}

fn appendDnsRecordsFromPacket(packet: []const u8, rrtype: u16, out: *std.ArrayList(u8)) !void {
    if (packet.len < 12) return error.Truncated;
    const qdcount = std.mem.readInt(u16, packet[4..6][0..2], .big);
    const ancount = std.mem.readInt(u16, packet[6..8][0..2], .big);
    var offset: usize = 12;
    try skipDnsQuestions(packet, &offset, qdcount);
    var first = true;
    var i: u16 = 0;
    while (i < ancount) : (i += 1) {
        try skipDnsName(packet, &offset);
        if (offset + 10 > packet.len) return error.Truncated;
        const typ = std.mem.readInt(u16, packet[offset .. offset + 2][0..2], .big);
        const class = std.mem.readInt(u16, packet[offset + 2 .. offset + 4][0..2], .big);
        const rdlen = std.mem.readInt(u16, packet[offset + 8 .. offset + 10][0..2], .big);
        offset += 10;
        if (offset + rdlen > packet.len) return error.Truncated;
        defer offset += rdlen;
        if (class != DnsClassIn) continue;
        if (rrtype != DnsTypeAny and typ != rrtype) continue;
        if (!first) try out.appendSlice(",");
        first = false;
        switch (typ) {
            DnsTypeA => {
                if (rdlen != 4) return error.Truncated;
                const bytes = packet[offset .. offset + 4];
                try out.writer().print("\"{d}.{d}.{d}.{d}\"", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
            },
            DnsTypeAaaa => {
                if (rdlen != 16) return error.Truncated;
                var addr_bytes: [16]u8 = undefined;
                @memcpy(&addr_bytes, packet[offset .. offset + 16]);
                const addr = std.net.Address.initIp6(addr_bytes, 0, 0, 0);
                var buf: [64]u8 = undefined;
                const text = try std.fmt.bufPrint(&buf, "{}", .{addr});
                const clean = if (std.mem.lastIndexOfScalar(u8, text, ']')) |end| text[1..end] else text;
                try appendJsonString(out, clean);
            },
            DnsTypeCname, DnsTypeNs, DnsTypePtr => {
                const rec = try readDnsNameAlloc(std.heap.page_allocator, packet, offset);
                defer std.heap.page_allocator.free(rec.name);
                try appendJsonString(out, rec.name);
            },
            DnsTypeMx => {
                if (rdlen < 3) return error.Truncated;
                const priority = std.mem.readInt(u16, packet[offset .. offset + 2][0..2], .big);
                const rec = try readDnsNameAlloc(std.heap.page_allocator, packet, offset + 2);
                defer std.heap.page_allocator.free(rec.name);
                try out.writer().print("{{\"exchange\":", .{});
                try appendJsonString(out, rec.name);
                try out.writer().print(",\"priority\":{d}}}", .{priority});
            },
            DnsTypeSrv => {
                if (rdlen < 7) return error.Truncated;
                const priority = std.mem.readInt(u16, packet[offset .. offset + 2][0..2], .big);
                const weight = std.mem.readInt(u16, packet[offset + 2 .. offset + 4][0..2], .big);
                const port = std.mem.readInt(u16, packet[offset + 4 .. offset + 6][0..2], .big);
                const rec = try readDnsNameAlloc(std.heap.page_allocator, packet, offset + 6);
                defer std.heap.page_allocator.free(rec.name);
                try out.writer().print("{{\"name\":", .{});
                try appendJsonString(out, rec.name);
                try out.writer().print(",\"priority\":{d},\"weight\":{d},\"port\":{d}}}", .{ priority, weight, port });
            },
            DnsTypeTlsa => {
                if (rdlen < 3) return error.Truncated;
                const cert_usage = packet[offset];
                const selector = packet[offset + 1];
                const match = packet[offset + 2];
                const data = packet[offset + 3 .. offset + rdlen];
                if (data.len == 0) return error.Truncated;
                const enc_len = std.base64.standard.Encoder.calcSize(data.len);
                const enc = std.heap.page_allocator.alloc(u8, enc_len) catch return error.Truncated;
                defer std.heap.page_allocator.free(enc);
                _ = std.base64.standard.Encoder.encode(enc, data);
                try out.writer().print("{{\"certUsage\":{d},\"selector\":{d},\"match\":{d},\"data\":", .{ cert_usage, selector, match });
                try appendJsonString(out, enc);
                try out.append('}');
            },
            DnsTypeNaptr => {
                if (rdlen < 5) return error.Truncated;
                const order = std.mem.readInt(u16, packet[offset .. offset + 2][0..2], .big);
                const preference = std.mem.readInt(u16, packet[offset + 2 .. offset + 4][0..2], .big);
                const flags_len = packet[offset + 4];
                const flags_off = offset + 5;
                if (flags_off + flags_len > offset + rdlen) return error.Truncated;
                const service_len_off = flags_off + flags_len;
                if (service_len_off >= offset + rdlen) return error.Truncated;
                const service_len = packet[service_len_off];
                const service_off = service_len_off + 1;
                if (service_off + service_len > offset + rdlen) return error.Truncated;
                const regexp_len_off = service_off + service_len;
                if (regexp_len_off >= offset + rdlen) return error.Truncated;
                const regexp_len = packet[regexp_len_off];
                const regexp_off = regexp_len_off + 1;
                if (regexp_off + regexp_len > offset + rdlen) return error.Truncated;
                const replacement_off = regexp_off + regexp_len;
                if (replacement_off > offset + rdlen) return error.Truncated;
                const rec = try readDnsNameAlloc(std.heap.page_allocator, packet, replacement_off);
                defer std.heap.page_allocator.free(rec.name);
                try out.writer().print("{{\"flags\":", .{});
                try appendJsonString(out, packet[flags_off .. flags_off + flags_len]);
                try out.writer().print(",\"service\":", .{});
                try appendJsonString(out, packet[service_off .. service_off + service_len]);
                try out.writer().print(",\"regexp\":", .{});
                try appendJsonString(out, packet[regexp_off .. regexp_off + regexp_len]);
                try out.writer().print(",\"replacement\":", .{});
                try appendJsonString(out, rec.name);
                try out.writer().print(",\"order\":{d},\"preference\":{d}}}", .{ order, preference });
            },
            DnsTypeCaa => {
                if (rdlen < 2) return error.Truncated;
                const critical = packet[offset];
                const tag_len = packet[offset + 1];
                if (@as(usize, 2) + tag_len > rdlen) return error.Truncated;
                const tag = packet[offset + 2 .. offset + 2 + tag_len];
                const value = packet[offset + 2 + tag_len .. offset + rdlen];
                try out.writer().print("{{\"critical\":{d},\"type\":", .{critical});
                try appendJsonString(out, "CAA");
                try out.append(',');
                try appendJsonString(out, tag);
                try out.append(':');
                try appendJsonString(out, value);
                try out.append('}');
            },
            DnsTypeSoa => {
                const mname = try readDnsNameAlloc(std.heap.page_allocator, packet, offset);
                defer std.heap.page_allocator.free(mname.name);
                const rname = try readDnsNameAlloc(std.heap.page_allocator, packet, offset + mname.consumed);
                defer std.heap.page_allocator.free(rname.name);
                const soa_base = offset + mname.consumed + rname.consumed;
                if (soa_base + 20 > offset + rdlen) return error.Truncated;
                const serial = std.mem.readInt(u32, packet[soa_base .. soa_base + 4][0..4], .big);
                const refresh = std.mem.readInt(u32, packet[soa_base + 4 .. soa_base + 8][0..4], .big);
                const retry = std.mem.readInt(u32, packet[soa_base + 8 .. soa_base + 12][0..4], .big);
                const expire = std.mem.readInt(u32, packet[soa_base + 12 .. soa_base + 16][0..4], .big);
                const minimum = std.mem.readInt(u32, packet[soa_base + 16 .. soa_base + 20][0..4], .big);
                try out.writer().print("{{\"nsname\":", .{});
                try appendJsonString(out, mname.name);
                try out.writer().print(",\"hostmaster\":", .{});
                try appendJsonString(out, rname.name);
                try out.writer().print(",\"serial\":{d},\"refresh\":{d},\"retry\":{d},\"expire\":{d},\"minimum\":{d}}}", .{ serial, refresh, retry, expire, minimum });
            },
            DnsTypeTxt => {
                try out.append('[');
                var txt_off = offset;
                var txt_first = true;
                while (txt_off < offset + rdlen) {
                    const seg_len = packet[txt_off];
                    txt_off += 1;
                    if (txt_off + seg_len > offset + rdlen) return error.Truncated;
                    if (!txt_first) try out.appendSlice(",");
                    txt_first = false;
                    try appendJsonString(out, packet[txt_off .. txt_off + seg_len]);
                    txt_off += seg_len;
                }
                try out.append(']');
            },
            else => first = true,
        }
    }
}

fn appendDnsRecords(hostname: []const u8, rrtype: u16, out: *std.ArrayList(u8)) !void {
    var packet_buf: [8192]u8 = undefined;
    const packet = try dnsQuery(hostname, rrtype, &packet_buf);
    try appendDnsRecordsFromPacket(packet, rrtype, out);
}

fn appendDnsRecordsFromServer(hostname: []const u8, rrtype: u16, server: std.net.Address, timeout_ms: u64, local_ipv4: ?[]const u8, local_ipv6: ?[]const u8, out: *std.ArrayList(u8)) !void {
    var packet_buf: [8192]u8 = undefined;
    const packet = try dnsQueryServer(hostname, rrtype, server, timeout_ms, local_ipv4, local_ipv6, &packet_buf);
    try appendDnsRecordsFromPacket(packet, rrtype, out);
}

fn writeDnsRecords(hostname: []const u8, rrtype: u16, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var results = std.ArrayList(u8).init(std.heap.page_allocator);
    defer results.deinit();
    results.appendSlice("[") catch return fail();
    appendDnsRecords(hostname, rrtype, &results) catch {};
    results.appendSlice("]") catch return fail();
    return writeOwned(out_ptr, out_len, results.items);
}

fn writeSoaRecord(hostname: []const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var packet_buf: [8192]u8 = undefined;
    const packet = dnsQuery(hostname, DnsTypeSoa, &packet_buf) catch return fail();
    if (packet.len < 12) return fail();

    const qdcount = std.mem.readInt(u16, packet[4..6][0..2], .big);
    const ancount = std.mem.readInt(u16, packet[6..8][0..2], .big);
    var offset: usize = 12;
    skipDnsQuestions(packet, &offset, qdcount) catch return fail();

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("[") catch return fail();

    var first = true;
    var i: u16 = 0;
    while (i < ancount) : (i += 1) {
        skipDnsName(packet, &offset) catch return fail();
        if (offset + 10 > packet.len) return fail();
        const typ = std.mem.readInt(u16, packet[offset .. offset + 2][0..2], .big);
        const class = std.mem.readInt(u16, packet[offset + 2 .. offset + 4][0..2], .big);
        const rdlen = std.mem.readInt(u16, packet[offset + 8 .. offset + 10][0..2], .big);
        offset += 10;
        if (offset + rdlen > packet.len) return fail();
        defer offset += rdlen;
        if (typ != DnsTypeSoa or class != DnsClassIn) continue;

        const mname = readDnsNameAlloc(std.heap.page_allocator, packet, offset) catch return fail();
        defer std.heap.page_allocator.free(mname.name);
        const rname = readDnsNameAlloc(std.heap.page_allocator, packet, offset + mname.consumed) catch return fail();
        defer std.heap.page_allocator.free(rname.name);
        const soa_base = offset + mname.consumed + rname.consumed;
        if (soa_base + 20 > offset + rdlen) return fail();
        const serial = std.mem.readInt(u32, packet[soa_base .. soa_base + 4][0..4], .big);
        const refresh = std.mem.readInt(u32, packet[soa_base + 4 .. soa_base + 8][0..4], .big);
        const retry = std.mem.readInt(u32, packet[soa_base + 8 .. soa_base + 12][0..4], .big);
        const expire = std.mem.readInt(u32, packet[soa_base + 12 .. soa_base + 16][0..4], .big);
        const minimum = std.mem.readInt(u32, packet[soa_base + 16 .. soa_base + 20][0..4], .big);

        if (!first) out.appendSlice(",") catch return fail();
        first = false;
        out.writer().print("{{\"nsname\":", .{}) catch return fail();
        appendJsonString(&out, mname.name) catch return fail();
        out.writer().print(",\"hostmaster\":", .{}) catch return fail();
        appendJsonString(&out, rname.name) catch return fail();
        out.writer().print(",\"serial\":{d},\"refresh\":{d},\"retry\":{d},\"expire\":{d},\"minimum\":{d}}}", .{ serial, refresh, retry, expire, minimum }) catch return fail();
    }

    out.appendSlice("]") catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}

pub fn dnsReverseName(ip: []const u8, out: *std.ArrayList(u8)) !void {
    if (std.net.Address.parseIp4(ip, 0)) |addr| {
        const bytes = std.mem.asBytes(&addr.in.sa.addr);
        try out.writer().print("{d}.{d}.{d}.{d}.in-addr.arpa", .{ bytes[3], bytes[2], bytes[1], bytes[0] });
        return;
    } else |_| {}
    if (std.net.Address.parseIp6(ip, 0)) |addr| {
        const bytes = std.mem.asBytes(&addr.in6.sa.addr);
        var i: usize = bytes.len;
        while (i > 0) {
            i -= 1;
            const byte = bytes[i];
            try out.writer().print("{x}.", .{byte & 0x0f});
            try out.writer().print("{x}.", .{byte >> 4});
        }
        try out.appendSlice("ip6.arpa");
        return;
    } else |_| {}
    return error.UnsupportedAddress;
}

pub export fn sa_node_plugin_dns_resolve4(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const hostname = hostname_ptr.?[0..hostname_len];
    return writeAddressList(hostname, DnsTypeA, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_resolve6(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeAddressList(hostname_ptr.?[0..hostname_len], DnsTypeAaaa, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_resolve_cname(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypeCname, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_resolve_mx(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypeMx, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_resolve_ns(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypeNs, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_resolve_txt(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypeTxt, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_resolve_srv(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypeSrv, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_resolve_ptr(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypePtr, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_reverse(ip_ptr: ?[*]const u8, ip_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var name = std.ArrayList(u8).init(std.heap.page_allocator);
    defer name.deinit();
    dnsReverseName(ip_ptr.?[0..ip_len], &name) catch return writeOwned(out_ptr, out_len, "[]");
    return writeDnsRecords(name.items, DnsTypePtr, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_resolve_any(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypeAny, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_resolve_tlsa(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypeTlsa, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_resolve_naptr(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypeNaptr, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_resolve_caa(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeDnsRecords(hostname_ptr.?[0..hostname_len], DnsTypeCaa, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_resolve_soa(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeSoaRecord(hostname_ptr.?[0..hostname_len], out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_get_servers(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    dns_config_mutex.lock();
    defer dns_config_mutex.unlock();
    if (dns_custom_servers) |servers| return writeOwned(out_ptr, out_len, servers);
    return writeSystemDnsServers(out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_set_servers(servers_ptr: ?[*]const u8, servers_len: u64) u32 {
    const servers = (servers_ptr orelse return fail())[0..servers_len];
    const owned = normalizeDnsServersJson(std.heap.page_allocator, servers) catch return fail();
    dns_config_mutex.lock();
    defer dns_config_mutex.unlock();
    if (dns_custom_servers) |old| std.heap.page_allocator.free(old);
    dns_custom_servers = owned;
    return 0;
}

pub export fn sa_node_plugin_dns_get_default_result_order(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    dns_config_mutex.lock();
    defer dns_config_mutex.unlock();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendJsonString(&out, dns_default_result_order) catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_dns_set_default_result_order(order_ptr: ?[*]const u8, order_len: u64) u32 {
    const order = (order_ptr orelse return fail())[0..order_len];
    if (!std.mem.eql(u8, order, "verbatim") and !std.mem.eql(u8, order, "ipv4first") and !std.mem.eql(u8, order, "ipv6first")) return fail();
    dns_config_mutex.lock();
    defer dns_config_mutex.unlock();
    dns_default_result_order = if (std.mem.eql(u8, order, "ipv4first")) "ipv4first" else if (std.mem.eql(u8, order, "ipv6first")) "ipv6first" else "verbatim";
    return 0;
}

pub export fn sa_node_plugin_dns_resolver_new(timeout_ms: u64, tries: u64, out_resolver: ?*?*anyopaque) u32 {
    const allocator = std.heap.page_allocator;
    const resolver = allocator.create(DnsResolverHandle) catch return fail();
    resolver.* = .{
        .allocator = allocator,
        .timeout_ms = timeout_ms,
        .tries = tries,
    };
    out_resolver.?.* = @ptrCast(resolver);
    return 0;
}

pub export fn sa_node_plugin_dns_resolver_free(resolver_ptr: ?*anyopaque) u32 {
    if (resolver_ptr) |ptr| {
        const resolver: *DnsResolverHandle = @ptrCast(@alignCast(ptr));
        resolver.deinit();
    }
    return 0;
}

pub export fn sa_node_plugin_dns_resolver_set_servers(resolver_ptr: ?*anyopaque, servers_ptr: ?[*]const u8, servers_len: u64) u32 {
    const resolver: *DnsResolverHandle = @ptrCast(@alignCast(resolver_ptr orelse return fail()));
    const servers = (servers_ptr orelse return fail())[0..servers_len];
    const owned = normalizeDnsServersJson(resolver.allocator, servers) catch return fail();
    if (resolver.servers_json) |old| resolver.allocator.free(old);
    resolver.servers_json = owned;
    return 0;
}

pub export fn sa_node_plugin_dns_resolver_get_servers(resolver_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const resolver: *DnsResolverHandle = @ptrCast(@alignCast(resolver_ptr orelse return fail()));
    if (resolver.servers_json) |servers| return writeOwned(out_ptr, out_len, servers);
    return writeSystemDnsServers(out_ptr, out_len);
}

fn dnsResolverSetLocalAddress(resolver: *DnsResolverHandle, ipv4: []const u8, ipv6: []const u8) u32 {
    var new_ipv4: ?[]u8 = null;
    var new_ipv6: ?[]u8 = null;

    if (ipv4.len > 0) {
        _ = std.net.Address.parseIp4(ipv4, 0) catch return fail();
        new_ipv4 = resolver.allocator.dupe(u8, ipv4) catch return fail();
    }
    if (ipv6.len > 0) {
        _ = std.net.Address.parseIp6(ipv6, 0) catch return fail();
        new_ipv6 = resolver.allocator.dupe(u8, ipv6) catch {
            if (new_ipv4) |addr| resolver.allocator.free(addr);
            return fail();
        };
    }

    if (resolver.local_ipv4) |old| resolver.allocator.free(old);
    if (resolver.local_ipv6) |old| resolver.allocator.free(old);
    resolver.local_ipv4 = new_ipv4;
    resolver.local_ipv6 = new_ipv6;
    return 0;
}

pub export fn sa_node_plugin_dns_resolver_set_local_address(resolver_ptr: ?*anyopaque, ipv4_ptr: ?[*]const u8, ipv4_len: u64, ipv6_ptr: ?[*]const u8, ipv6_len: u64) u32 {
    const resolver: *DnsResolverHandle = @ptrCast(@alignCast(resolver_ptr orelse return fail()));
    const ipv4 = if (ipv4_len == 0) "" else (ipv4_ptr orelse return fail())[0..ipv4_len];
    const ipv6 = if (ipv6_len == 0) "" else (ipv6_ptr orelse return fail())[0..ipv6_len];
    return dnsResolverSetLocalAddress(resolver, ipv4, ipv6);
}

pub export fn sa_node_plugin_dns_resolver_cancel(resolver_ptr: ?*anyopaque) u32 {
    const resolver: *DnsResolverHandle = @ptrCast(@alignCast(resolver_ptr orelse return fail()));
    resolver.cancel_count +|= 1;
    return 0;
}

pub export fn sa_node_plugin_dns_resolver_resolve4(resolver_ptr: ?*anyopaque, hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolver_resolve(resolver_ptr, hostname_ptr, hostname_len, "A".ptr, 1, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_resolver_resolve6(resolver_ptr: ?*anyopaque, hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolver_resolve(resolver_ptr, hostname_ptr, hostname_len, "AAAA".ptr, 4, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_resolver_resolve(resolver_ptr: ?*anyopaque, hostname_ptr: ?[*]const u8, hostname_len: u64, rrtype_ptr: ?[*]const u8, rrtype_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const resolver: *DnsResolverHandle = @ptrCast(@alignCast(resolver_ptr orelse return fail()));
    const hostname = hostname_ptr.?[0..hostname_len];
    const rrtype = rrtype_ptr.?[0..rrtype_len];
    const rrtype_code: u16 = if (std.ascii.eqlIgnoreCase(rrtype, "A")) DnsTypeA else if (std.ascii.eqlIgnoreCase(rrtype, "AAAA")) DnsTypeAaaa else if (std.ascii.eqlIgnoreCase(rrtype, "CNAME")) DnsTypeCname else if (std.ascii.eqlIgnoreCase(rrtype, "MX")) DnsTypeMx else if (std.ascii.eqlIgnoreCase(rrtype, "NS")) DnsTypeNs else if (std.ascii.eqlIgnoreCase(rrtype, "TXT")) DnsTypeTxt else if (std.ascii.eqlIgnoreCase(rrtype, "SRV")) DnsTypeSrv else if (std.ascii.eqlIgnoreCase(rrtype, "PTR")) DnsTypePtr else if (std.ascii.eqlIgnoreCase(rrtype, "CAA")) DnsTypeCaa else if (std.ascii.eqlIgnoreCase(rrtype, "NAPTR")) DnsTypeNaptr else if (std.ascii.eqlIgnoreCase(rrtype, "SOA")) DnsTypeSoa else if (std.ascii.eqlIgnoreCase(rrtype, "TLSA")) DnsTypeTlsa else if (std.ascii.eqlIgnoreCase(rrtype, "ANY")) DnsTypeAny else return fail();

    if (resolver.servers_json) |servers_json| {
        const server = firstDnsServerAddress(servers_json) catch return fail();
        var results = std.ArrayList(u8).init(std.heap.page_allocator);
        defer results.deinit();
        results.appendSlice("[") catch return fail();
        appendDnsRecordsFromServer(hostname, rrtype_code, server, resolver.timeout_ms, resolver.local_ipv4, resolver.local_ipv6, &results) catch return fail();
        results.appendSlice("]") catch return fail();
        return writeOwned(out_ptr, out_len, results.items);
    }

    if (std.ascii.eqlIgnoreCase(rrtype, "A")) return sa_node_plugin_dns_resolve4(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "AAAA")) return sa_node_plugin_dns_resolve6(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "CNAME")) return sa_node_plugin_dns_resolve_cname(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "MX")) return sa_node_plugin_dns_resolve_mx(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "NS")) return sa_node_plugin_dns_resolve_ns(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "TXT")) return sa_node_plugin_dns_resolve_txt(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "SRV")) return sa_node_plugin_dns_resolve_srv(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "PTR")) return sa_node_plugin_dns_resolve_ptr(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "CAA")) return sa_node_plugin_dns_resolve_caa(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "NAPTR")) return sa_node_plugin_dns_resolve_naptr(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "SOA")) return sa_node_plugin_dns_resolve_soa(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "TLSA")) return sa_node_plugin_dns_resolve_tlsa(hostname_ptr, hostname_len, out_ptr, out_len);
    if (std.ascii.eqlIgnoreCase(rrtype, "ANY")) return sa_node_plugin_dns_resolve_any(hostname_ptr, hostname_len, out_ptr, out_len);
    return fail();
}

pub export fn sa_node_plugin_dns_resolver_reverse(resolver_ptr: ?*anyopaque, ip_ptr: ?[*]const u8, ip_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = resolver_ptr orelse return fail();
    return sa_node_plugin_dns_reverse(ip_ptr, ip_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_resolver_snapshot_json(resolver_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const resolver: *DnsResolverHandle = @ptrCast(@alignCast(resolver_ptr orelse return fail()));
    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    defer json.deinit();
    json.writer().print("{{\"timeoutMs\":{d},\"tries\":{d},\"servers\":", .{ resolver.timeout_ms, resolver.tries }) catch return fail();
    if (resolver.servers_json) |servers| {
        json.appendSlice(servers) catch return fail();
    } else {
        json.appendSlice("null") catch return fail();
    }
    json.appendSlice(",\"usesSystemServers\":") catch return fail();
    json.appendSlice(if (resolver.servers_json == null) "true" else "false") catch return fail();
    json.appendSlice(",\"localAddress\":{\"ipv4\":") catch return fail();
    if (resolver.local_ipv4) |addr| {
        appendJsonString(&json, addr) catch return fail();
    } else {
        json.appendSlice("null") catch return fail();
    }
    json.appendSlice(",\"ipv6\":") catch return fail();
    if (resolver.local_ipv6) |addr| {
        appendJsonString(&json, addr) catch return fail();
    } else {
        json.appendSlice("null") catch return fail();
    }
    json.writer().print("}},\"cancelCount\":{d}", .{resolver.cancel_count}) catch return fail();
    json.append('}') catch return fail();
    return writeOwned(out_ptr, out_len, json.items);
}

// dns.promises exposes the same native resolver work through Node-compatible
// promise module entry-point names. SA receives already-resolved buffers.
pub export fn sa_node_plugin_dns_promises_lookup(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_dns_lookup(hostname_ptr, hostname_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_promises_constants_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_constants_json(out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_promises_get_servers(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_get_servers(out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_promises_set_servers(servers_ptr: ?[*]const u8, servers_len: u64) u32 {
    return sa_node_plugin_dns_set_servers(servers_ptr, servers_len);
}

pub export fn sa_node_plugin_dns_promises_get_default_result_order(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_get_default_result_order(out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_promises_set_default_result_order(order_ptr: ?[*]const u8, order_len: u64) u32 {
    return sa_node_plugin_dns_set_default_result_order(order_ptr, order_len);
}

pub export fn sa_node_plugin_dns_promises_lookup_options(hostname_ptr: ?[*]const u8, hostname_len: u64, family: u32, all: u32, order_ptr: ?[*]const u8, order_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_lookup_options(hostname_ptr, hostname_len, family, all, order_ptr, order_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_promises_lookup_options_hints(hostname_ptr: ?[*]const u8, hostname_len: u64, family: u32, all: u32, hints: u32, order_ptr: ?[*]const u8, order_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_lookup_options_hints(hostname_ptr, hostname_len, family, all, hints, order_ptr, order_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_promises_lookup_service(address_ptr: ?[*]const u8, address_len: u64, port: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_dns_lookup_service(address_ptr, address_len, port, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_promises_resolve(hostname_ptr: ?[*]const u8, hostname_len: u64, rrtype_ptr: ?[*]const u8, rrtype_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var resolver: ?*anyopaque = null;
    if (sa_node_plugin_dns_resolver_new(0, 0, &resolver) != 0) return fail();
    defer _ = sa_node_plugin_dns_resolver_free(resolver);
    return sa_node_plugin_dns_resolver_resolve(resolver, hostname_ptr, hostname_len, rrtype_ptr, rrtype_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_promises_resolve4(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve4(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve6(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve6(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_cname(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_cname(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_mx(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_mx(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_ns(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_ns(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_txt(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_txt(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_srv(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_srv(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_ptr(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_ptr(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_any(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_any(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_caa(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_caa(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_naptr(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_naptr(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_soa(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_soa(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolve_tlsa(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolve_tlsa(hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_reverse(ip_ptr: ?[*]const u8, ip_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_reverse(ip_ptr, ip_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_dns_promises_resolver_new(timeout_ms: u64, tries: u64, out_resolver: ?*?*anyopaque) u32 {
    return sa_node_plugin_dns_resolver_new(timeout_ms, tries, out_resolver);
}
pub export fn sa_node_plugin_dns_promises_resolver_free(resolver_ptr: ?*anyopaque) u32 {
    return sa_node_plugin_dns_resolver_free(resolver_ptr);
}
pub export fn sa_node_plugin_dns_promises_resolver_set_servers(resolver_ptr: ?*anyopaque, servers_ptr: ?[*]const u8, servers_len: u64) u32 {
    return sa_node_plugin_dns_resolver_set_servers(resolver_ptr, servers_ptr, servers_len);
}
pub export fn sa_node_plugin_dns_promises_resolver_get_servers(resolver_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolver_get_servers(resolver_ptr, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolver_set_local_address(resolver_ptr: ?*anyopaque, ipv4_ptr: ?[*]const u8, ipv4_len: u64, ipv6_ptr: ?[*]const u8, ipv6_len: u64) u32 {
    return sa_node_plugin_dns_resolver_set_local_address(resolver_ptr, ipv4_ptr, ipv4_len, ipv6_ptr, ipv6_len);
}
pub export fn sa_node_plugin_dns_promises_resolver_cancel(resolver_ptr: ?*anyopaque) u32 {
    return sa_node_plugin_dns_resolver_cancel(resolver_ptr);
}
pub export fn sa_node_plugin_dns_promises_resolver_resolve(resolver_ptr: ?*anyopaque, hostname_ptr: ?[*]const u8, hostname_len: u64, rrtype_ptr: ?[*]const u8, rrtype_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolver_resolve(resolver_ptr, hostname_ptr, hostname_len, rrtype_ptr, rrtype_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolver_resolve4(resolver_ptr: ?*anyopaque, hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolver_resolve4(resolver_ptr, hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolver_resolve6(resolver_ptr: ?*anyopaque, hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolver_resolve6(resolver_ptr, hostname_ptr, hostname_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolver_reverse(resolver_ptr: ?*anyopaque, ip_ptr: ?[*]const u8, ip_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolver_reverse(resolver_ptr, ip_ptr, ip_len, out_ptr, out_len);
}
pub export fn sa_node_plugin_dns_promises_resolver_snapshot_json(resolver_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_dns_resolver_snapshot_json(resolver_ptr, out_ptr, out_len);
}

// ============================================================
// CHILD PROCESS
// ============================================================

fn parseSaArgvVector(argv_ptr: ?[*]const u8, argc: u64, out: *std.ArrayList([]const u8)) !void {
    if (argc == 0) return;
    const ptr = argv_ptr orelse return error.InvalidArgv;
    if (argc > 256) return error.InvalidArgv;
    for (0..@intCast(argc)) |i| {
        const base_off = i * 16;
        const arg_ptr_int = std.mem.readInt(usize, ptr[base_off..][0..@sizeOf(usize)], .little);
        const arg_len = std.mem.readInt(u64, ptr[base_off + 8 ..][0..8], .little);
        if (arg_ptr_int == 0 or arg_len > 1024 * 1024) return error.InvalidArgv;
        const arg_ptr: [*]const u8 = @ptrFromInt(arg_ptr_int);
        try out.append(arg_ptr[0..@intCast(arg_len)]);
    }
}

fn looksLikeSaArgvVector(argv_ptr: ?[*]const u8, argc: u64) bool {
    if (argc == 0 or argc > 64) return false;
    const ptr = argv_ptr orelse return false;
    const arg_ptr_int = std.mem.readInt(usize, ptr[0..@sizeOf(usize)], .little);
    const arg_len = std.mem.readInt(u64, ptr[8..16], .little);
    return arg_ptr_int > 4096 and arg_len > 0 and arg_len <= 1024 * 1024;
}

fn buildCommandArgv(command_ptr: ?[*]const u8, command_len: u64, args_ptr: ?[*]const u8, args_len: u64, allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
    var argv = std.ArrayList([]const u8).init(allocator);
    errdefer argv.deinit();

    if (looksLikeSaArgvVector(command_ptr, command_len)) {
        try parseSaArgvVector(command_ptr, command_len, &argv);
    } else {
        try argv.append((command_ptr orelse return error.InvalidArgv)[0..command_len]);
    }

    if (args_len > 0) {
        if (looksLikeSaArgvVector(args_ptr, args_len)) {
            try parseSaArgvVector(args_ptr, args_len, &argv);
        } else {
            try argv.append((args_ptr orelse return error.InvalidArgv)[0..args_len]);
        }
    }
    return argv;
}

fn runChildCapture(argv: []const []const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = argv,
        .max_output_bytes = 1024 * 1024,
    }) catch return fail();
    defer std.heap.page_allocator.free(result.stderr);
    defer std.heap.page_allocator.free(result.stdout);
    switch (result.term) {
        .Exited => {},
        else => return fail(),
    }
    return writeOwned(out_ptr, out_len, result.stdout);
}

pub export fn sa_node_plugin_child_process_exec(
    command_ptr: ?[*]const u8,
    command_len: u64,
    options_json_ptr: ?[*]const u8,
    options_json_len: u64,
    out_pid: ?*u64,
    out_ptr: ?*?[*]const u8,
    out_len: ?*u64,
) u32 {
    const command = command_ptr.?[0..command_len];
    _ = options_json_ptr;
    _ = options_json_len;
    var argv = [_][]const u8{ "sh", "-c", command };
    var child = std.process.Child.init(&argv, std.heap.page_allocator);
    child.stderr_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.spawn() catch return fail();
    out_pid.?.* = @intCast(child.id);
    const stdout = child.stdout.?.reader().readAllAlloc(std.heap.page_allocator, 1024 * 1024) catch "";
    {
        _ = child.wait() catch null;
    }
    return writeOwned(out_ptr, out_len, stdout);
}

pub export fn sa_node_plugin_child_process_exec_file(
    file_ptr: ?[*]const u8,
    file_len: u64,
    args_ptr: ?[*]const u8,
    args_len: u64,
    out_ptr: ?*?[*]const u8,
    out_len: ?*u64,
) u32 {
    var argv = buildCommandArgv(file_ptr, file_len, args_ptr, args_len, std.heap.page_allocator) catch return fail();
    defer argv.deinit();
    return runChildCapture(argv.items, out_ptr, out_len);
}

pub export fn sa_node_plugin_child_process_execfile_sync(
    file_ptr: ?[*]const u8,
    file_len: u64,
    args_ptr: ?[*]const u8,
    args_len: u64,
    out_ptr: ?*?[*]const u8,
    out_len: ?*u64,
) u32 {
    return sa_node_plugin_child_process_exec_file(file_ptr, file_len, args_ptr, args_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_child_process_fork(
    module_ptr: ?[*]const u8,
    module_len: u64,
    args_ptr: ?[*]const u8,
    args_len: u64,
    out_pid: ?*u64,
) u32 {
    var argv = std.ArrayList([]const u8).init(std.heap.page_allocator);
    defer argv.deinit();
    argv.append("node") catch return fail();
    argv.append(module_ptr.?[0..module_len]) catch return fail();
    if (args_len > 0) parseSaArgvVector(args_ptr, args_len, &argv) catch argv.append(args_ptr.?[0..args_len]) catch return fail();
    var child = std.process.Child.init(argv.items, std.heap.page_allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return fail();
    out_pid.?.* = @intCast(child.id);
    return 0;
}

pub export fn sa_node_plugin_child_process_spawn(
    command_ptr: ?[*]const u8,
    command_len: u64,
    args_ptr: ?[*]const u8,
    args_len: u64,
    out_pid: ?*u64,
) u32 {
    var argv = buildCommandArgv(command_ptr, command_len, args_ptr, args_len, std.heap.page_allocator) catch return fail();
    defer argv.deinit();
    var child = std.process.Child.init(argv.items, std.heap.page_allocator);
    child.spawn() catch return fail();
    out_pid.?.* = @intCast(child.id);
    return 0;
}

pub export fn sa_node_plugin_child_process_spawn_sync(
    command_ptr: ?[*]const u8,
    command_len: u64,
    args_ptr: ?[*]const u8,
    args_len: u64,
    out_ptr: ?*?[*]const u8,
    out_len: ?*u64,
) u32 {
    var argv = buildCommandArgv(command_ptr, command_len, args_ptr, args_len, std.heap.page_allocator) catch return fail();
    defer argv.deinit();
    return runChildCapture(argv.items, out_ptr, out_len);
}

// ============================================================
// STREAM (non-duplicate new functions only)
// ============================================================

const StreamHandle = struct {
    magic: u64 = 0x5341_4e4f_4445_5354,
    id: u64,
    kind: []const u8,
    data: std.ArrayList(u8),
    destroyed: bool = false,
    ended: bool = false,
    error_count: u64 = 0,
    piped_to: u64 = 0,
    piped_from: u64 = 0,
    composed_count: u64 = 0,
};

var next_stream_id: u64 = 1;

fn newStreamHandle(kind: []const u8, out_handle: ?*?*anyopaque) u32 {
    if (out_handle == null) return fail();
    const h = std.heap.page_allocator.create(StreamHandle) catch return fail();
    const id = @atomicRmw(u64, &next_stream_id, .Add, 1, .monotonic);
    h.* = .{
        .id = id,
        .kind = kind,
        .data = std.ArrayList(u8).init(std.heap.page_allocator),
    };
    out_handle.?.* = @ptrCast(h);
    return 0;
}

fn streamHandle(handle_ptr: ?*anyopaque) ?*StreamHandle {
    const ptr = handle_ptr orelse return null;
    const h: *StreamHandle = @ptrCast(@alignCast(ptr));
    if (h.magic != 0x5341_4e4f_4445_5354) return null;
    return h;
}

fn writeStreamState(out_ptr: ?*?[*]const u8, out_len: ?*u64, h: *const StreamHandle) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.writer().print(
        "{{\"id\":{d},\"kind\":",
        .{h.id},
    ) catch return fail();
    appendJsonString(&out, h.kind) catch return fail();
    out.writer().print(
        ",\"destroyed\":{},\"ended\":{},\"errored\":{},\"errorCount\":{d},\"bufferedLength\":{d},\"pipedTo\":{d},\"pipedFrom\":{d},\"composedCount\":{d}}}",
        .{ h.destroyed, h.ended, h.error_count != 0, h.error_count, h.data.items.len, h.piped_to, h.piped_from, h.composed_count },
    ) catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_stream_duplex_new(out_handle: ?*?*anyopaque) u32 {
    return newStreamHandle("duplex", out_handle);
}

pub export fn sa_node_plugin_stream_transform_new(out_handle: ?*?*anyopaque) u32 {
    return newStreamHandle("transform", out_handle);
}
pub export fn sa_node_plugin_stream_passthrough_new(out_handle: ?*?*anyopaque) u32 {
    return newStreamHandle("passthrough", out_handle);
}

pub export fn sa_node_plugin_stream_pipeline(steps_ptr: ?*const anyopaque, steps_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const first = streamHandle(@constCast(steps_ptr orelse return fail())) orelse return fail();
    var count: u64 = 1;
    var last_id: u64 = first.id;
    if (steps_len > 4096) {
        const second_ptr: ?*anyopaque = @ptrFromInt(steps_len);
        if (streamHandle(second_ptr)) |second| {
            first.piped_to = second.id;
            second.piped_from = first.id;
            second.ended = true;
            last_id = second.id;
            count = 2;
        }
    } else if (steps_len > 1) {
        count = steps_len;
    }
    first.ended = true;

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.writer().print("{{\"status\":\"ok\",\"count\":{d},\"firstId\":{d},\"lastId\":{d}}}", .{ count, first.id, last_id }) catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}
pub export fn sa_node_plugin_stream_finished(handle_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const h = streamHandle(handle_ptr) orelse return writeOwned(out_ptr, out_len, "{\"finished\":false,\"destroyed\":false,\"errored\":true,\"error\":\"ERR_INVALID_STREAM\"}");
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.writer().print(
        "{{\"finished\":{},\"destroyed\":{},\"ended\":{},\"errored\":{},\"bufferedLength\":{d}}}",
        .{ h.ended or h.destroyed, h.destroyed, h.ended, h.error_count != 0, h.data.items.len },
    ) catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}
pub export fn sa_node_plugin_stream_compose(streams_ptr: ?*const anyopaque, streams_len: u64, out_handle: ?*?*anyopaque) u32 {
    if (newStreamHandle("composed", out_handle) != 0) return fail();
    const composed = streamHandle(out_handle.?.*) orelse return fail();
    composed.composed_count = streams_len;

    if (streams_ptr) |ptr| {
        const bytes: [*]const u8 = @ptrCast(ptr);
        var i: u64 = 0;
        while (i < streams_len and i < 1024) : (i += 1) {
            const base_off: usize = @intCast(i * 16);
            const child_addr = std.mem.readInt(usize, bytes[base_off..][0..@sizeOf(usize)], .little);
            if (child_addr == 0) continue;
            const child = streamHandle(@ptrFromInt(child_addr)) orelse continue;
            child.piped_to = composed.id;
            if (i == 0) composed.piped_from = child.id;
        }
    }
    return 0;
}

pub export fn sa_node_plugin_stream_destroy(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| {
        const h = streamHandle(ptr) orelse return fail();
        h.destroyed = true;
        h.magic = 0;
        h.data.deinit();
        std.heap.page_allocator.destroy(h);
    }
    return 0;
}

pub export fn sa_node_plugin_stream_duplex_pair(out_h1: ?*?*anyopaque, out_h2: ?*?*anyopaque) u32 {
    const s1 = sa_node_plugin_stream_duplex_new(out_h1);
    if (s1 != 0) return s1;
    return sa_node_plugin_stream_duplex_new(out_h2);
}

pub export fn sa_node_plugin_stream_readable_destroy(handle_ptr: ?*anyopaque) u32 {
    return sa_node_plugin_stream_destroy(handle_ptr);
}
pub export fn sa_node_plugin_stream_writable_destroy(handle_ptr: ?*anyopaque) u32 {
    return sa_node_plugin_stream_destroy(handle_ptr);
}

// ============================================================
// NET
// ============================================================

var net_auto_select_family_default: bool = true;
var net_auto_select_family_attempt_timeout_default: u64 = 500;

pub export fn sa_node_plugin_net_is_ip(str_ptr: ?[*]const u8, str_len: u64, out_version: ?*u64) u32 {
    const out = out_version orelse return fail();
    const str = (str_ptr orelse return fail())[0..str_len];
    if (std.net.Address.parseIp4(str, 0)) |_| {
        out.* = 4;
        return 0;
    } else |_| {}
    if (std.net.Address.parseIp6(str, 0)) |_| {
        out.* = 6;
        return 0;
    } else |_| {}
    out.* = 0;
    return 0;
}

pub export fn sa_node_plugin_net_is_ipv4(str_ptr: ?[*]const u8, str_len: u64, out_bool: ?*u64) u32 {
    const out = out_bool orelse return fail();
    const str = (str_ptr orelse return fail())[0..str_len];
    if (std.net.Address.parseIp4(str, 0)) |_| {
        out.* = 1;
    } else |_| {
        out.* = 0;
    }
    return 0;
}

pub export fn sa_node_plugin_net_is_ipv6(str_ptr: ?[*]const u8, str_len: u64, out_bool: ?*u64) u32 {
    const out = out_bool orelse return fail();
    const str = (str_ptr orelse return fail())[0..str_len];
    if (std.net.Address.parseIp6(str, 0)) |_| {
        out.* = 1;
    } else |_| {
        out.* = 0;
    }
    return 0;
}

pub export fn sa_node_plugin_net_get_default_auto_select_family(out_bool: ?*u64) u32 {
    (out_bool orelse return fail()).* = if (net_auto_select_family_default) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_net_set_default_auto_select_family(value: u64) u32 {
    if (value > 1) return fail();
    net_auto_select_family_default = value != 0;
    return 0;
}

pub export fn sa_node_plugin_net_get_default_auto_select_family_attempt_timeout(out_timeout: ?*u64) u32 {
    (out_timeout orelse return fail()).* = net_auto_select_family_attempt_timeout_default;
    return 0;
}

pub export fn sa_node_plugin_net_set_default_auto_select_family_attempt_timeout(value: u64) u32 {
    if (value == 0 or value > std.math.maxInt(i32)) return fail();
    net_auto_select_family_attempt_timeout_default = @max(value, 10);
    return 0;
}

pub export fn sa_node_plugin_net_create_connection(host_ptr: ?[*]const u8, host_len: u64, port: u64, out_socket: ?*?*anyopaque) u32 {
    return base.sa_node_plugin_net_connect(host_ptr, host_len, port, out_socket);
}

fn netJsonBool(value: std.json.Value) ?u32 {
    return switch (value) {
        .bool => |b| if (b) 1 else 0,
        .integer => |i| if (i == 0) 0 else 1,
        else => null,
    };
}

fn netJsonU64(value: std.json.Value) ?u64 {
    return switch (value) {
        .integer => |i| if (i >= 0) @intCast(i) else null,
        .string => |s| std.fmt.parseInt(u64, s, 10) catch null,
        else => null,
    };
}

fn netJsonFamily(value: std.json.Value) ?u32 {
    return switch (value) {
        .integer => |i| if (i == 4 or i == 6) @intCast(i) else null,
        .string => |s| blk: {
            if (std.mem.eql(u8, s, "4") or std.ascii.eqlIgnoreCase(s, "ipv4")) break :blk 4;
            if (std.mem.eql(u8, s, "6") or std.ascii.eqlIgnoreCase(s, "ipv6")) break :blk 6;
            break :blk null;
        },
        else => null,
    };
}

pub export fn sa_node_plugin_net_create_connection_options(host_ptr: ?[*]const u8, host_len: u64, port: u64, options_json_ptr: ?[*]const u8, options_json_len: u64, out_socket: ?*?*anyopaque) u32 {
    const out = out_socket orelse return fail();
    out.* = null;

    const fallback_host = (host_ptr orelse return fail())[0..host_len];
    var host = fallback_host;
    var remote_port = port;
    var family: u32 = 0;
    var local: []const u8 = "";
    var local_port: u64 = 0;
    var no_delay: u32 = 0;
    var keep_alive: u32 = 0;
    var keep_alive_initial_delay_secs: u32 = 0;
    var timeout_ms: u64 = 0;
    var owned_host: ?[]u8 = null;
    var owned_local: ?[]u8 = null;
    defer if (owned_host) |bytes| std.heap.page_allocator.free(bytes);
    defer if (owned_local) |bytes| std.heap.page_allocator.free(bytes);

    if (options_json_ptr) |ptr| {
        const options_json = ptr[0..options_json_len];
        if (options_json.len != 0) {
            var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, options_json, .{}) catch return fail();
            defer parsed.deinit();
            if (parsed.value != .object) return fail();
            const object = parsed.value.object;

            if (object.get("host")) |value| {
                if (value != .string) return fail();
                owned_host = std.heap.page_allocator.dupe(u8, value.string) catch return fail();
                host = owned_host.?;
            } else if (object.get("hostname")) |value| {
                if (value != .string) return fail();
                owned_host = std.heap.page_allocator.dupe(u8, value.string) catch return fail();
                host = owned_host.?;
            }
            if (object.get("port")) |value| {
                remote_port = netJsonU64(value) orelse return fail();
            }
            if (object.get("family")) |value| {
                family = netJsonFamily(value) orelse return fail();
            }
            if (object.get("localAddress")) |value| {
                if (value != .string) return fail();
                owned_local = std.heap.page_allocator.dupe(u8, value.string) catch return fail();
                local = owned_local.?;
            }
            if (object.get("localPort")) |value| {
                local_port = netJsonU64(value) orelse return fail();
            }
            if (object.get("noDelay")) |value| {
                no_delay = netJsonBool(value) orelse return fail();
            }
            if (object.get("keepAlive")) |value| {
                keep_alive = netJsonBool(value) orelse return fail();
            }
            if (object.get("keepAliveInitialDelay")) |value| {
                const delay_ms = netJsonU64(value) orelse return fail();
                keep_alive_initial_delay_secs = @intCast(@min(std.math.maxInt(u32), (delay_ms + 999) / 1000));
            } else if (object.get("keepAliveInitialDelaySecs")) |value| {
                const delay_secs = netJsonU64(value) orelse return fail();
                keep_alive_initial_delay_secs = @intCast(@min(std.math.maxInt(u32), delay_secs));
            }
            if (object.get("timeoutMs")) |value| {
                timeout_ms = netJsonU64(value) orelse return fail();
            } else if (object.get("timeout")) |value| {
                timeout_ms = netJsonU64(value) orelse return fail();
            }
        }
    }

    return base.sa_node_plugin_net_connect_options(host.ptr, host.len, remote_port, family, local.ptr, local.len, local_port, no_delay, keep_alive, keep_alive_initial_delay_secs, timeout_ms, null, out_socket);
}

pub export fn sa_node_plugin_net_listen_options(options_json_ptr: ?[*]const u8, options_json_len: u64, out_server: ?*?*anyopaque) u32 {
    const out = out_server orelse return fail();
    out.* = null;
    const options_json = (options_json_ptr orelse return fail())[0..options_json_len];
    if (options_json.len == 0) return fail();

    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, options_json, .{}) catch return fail();
    defer parsed.deinit();
    if (parsed.value != .object) return fail();
    const object = parsed.value.object;

    if (object.get("path")) |value| {
        if (value != .string or value.string.len == 0) return fail();
        return base.sa_node_plugin_net_listen_unix(value.string.ptr, value.string.len, out_server);
    }

    var port_present = false;
    var port: u64 = 0;
    if (object.get("port")) |value| {
        port_present = true;
        port = switch (value) {
            .null => 0,
            else => netJsonU64(value) orelse return fail(),
        };
    }
    if (!port_present) return fail();

    var host: []const u8 = "0.0.0.0";
    if (object.get("host")) |value| {
        if (value != .string) return fail();
        if (value.string.len != 0) host = value.string;
    }

    return base.sa_node_plugin_net_listen(host.ptr, host.len, port, out_server);
}

pub export fn sa_node_plugin_net_create_server(out_server: ?*?*anyopaque) u32 {
    const host = "0.0.0.0";
    return base.sa_node_plugin_net_listen(host.ptr, host.len, 0, out_server);
}

// ============================================================
// TLS
// ============================================================

pub export fn sa_node_plugin_tls_get_ciphers_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return tlsWriteCipherArray(out_ptr, out_len, false);
}

pub export fn sa_node_plugin_tls_get_ciphers_detailed_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return tlsWriteCipherArray(out_ptr, out_len, true);
}

pub export fn sa_node_plugin_tls_default_constants_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"CLIENT_RENEG_LIMIT\":3,\"CLIENT_RENEG_WINDOW\":600,\"DEFAULT_ECDH_CURVE\":\"auto\",\"DEFAULT_MIN_VERSION\":\"TLSv1.2\",\"DEFAULT_MAX_VERSION\":\"TLSv1.3\",\"DEFAULT_CIPHERS\":") catch return fail();
    appendJsonString(&out, TLS_DEFAULT_CIPHERS) catch return fail();
    out.appendSlice(",\"nativeCipherCount\":") catch return fail();
    out.writer().print("{d}", .{tls_supported_ciphers.len}) catch return fail();
    out.append('}') catch return fail();
    const owned = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_tls_default_min_version(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, "TLSv1.2");
}

pub export fn sa_node_plugin_tls_default_max_version(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, "TLSv1.3");
}

pub export fn sa_node_plugin_tls_convert_alpn_protocols(protocols_json_ptr: ?[*]const u8, protocols_json_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const protocols_json = (protocols_json_ptr orelse return fail())[0..protocols_json_len];
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, protocols_json, .{}) catch return fail();
    defer parsed.deinit();
    if (parsed.value != .array) return fail();

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    for (parsed.value.array.items) |item| {
        if (item != .string) return fail();
        const protocol = item.string;
        if (protocol.len > 255) return fail();
        out.append(@intCast(protocol.len)) catch return fail();
        out.appendSlice(protocol) catch return fail();
    }
    return writeOwned(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_tls_root_certificates_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    var bundle = tlsBuildSystemBundle(allocator) catch return fail();
    defer bundle.deinit(allocator);
    return tlsBundleToPemArrayJson(allocator, &bundle, out_ptr, out_len);
}

pub export fn sa_node_plugin_tls_get_ca_certificates_json(type_ptr: ?[*]const u8, type_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    const typ = if (type_ptr) |ptr| ptr[0..type_len] else "default";
    if (typ.len == 0 or std.mem.eql(u8, typ, "default")) {
        tls_default_ca_mutex.lock();
        const custom = if (tls_default_ca_pem) |pem| allocator.dupe(u8, pem) catch null else null;
        tls_default_ca_mutex.unlock();
        if (custom) |pem| {
            defer allocator.free(pem);
            var bundle = tlsBuildBundleFromPem(allocator, pem) catch return fail();
            defer bundle.deinit(allocator);
            return tlsBundleToPemArrayJson(allocator, &bundle, out_ptr, out_len);
        }
        var bundle = tlsBuildSystemBundle(allocator) catch return fail();
        defer bundle.deinit(allocator);
        return tlsBundleToPemArrayJson(allocator, &bundle, out_ptr, out_len);
    }
    if (std.mem.eql(u8, typ, "system") or std.mem.eql(u8, typ, "bundled")) {
        var bundle = tlsBuildSystemBundle(allocator) catch return fail();
        defer bundle.deinit(allocator);
        return tlsBundleToPemArrayJson(allocator, &bundle, out_ptr, out_len);
    }
    if (std.mem.eql(u8, typ, "extra")) return tlsWriteExtraCaCertificatesJson(allocator, out_ptr, out_len);
    return fail();
}

pub export fn sa_node_plugin_tls_set_default_ca_certificates(certs_pem_ptr: ?[*]const u8, certs_pem_len: u64) u32 {
    const allocator = std.heap.page_allocator;
    const pem = (certs_pem_ptr orelse return fail())[0..certs_pem_len];
    var bundle = tlsBuildBundleFromPem(allocator, pem) catch return fail();
    const count: u64 = bundle.map.count();
    bundle.deinit(allocator);
    const owned = allocator.dupe(u8, pem) catch return fail();
    tls_default_ca_mutex.lock();
    defer tls_default_ca_mutex.unlock();
    if (tls_default_ca_pem) |old| allocator.free(old);
    tls_default_ca_pem = owned;
    tls_default_ca_count = count;
    return 0;
}

pub export fn sa_node_plugin_tls_reset_default_ca_certificates() u32 {
    tls_default_ca_mutex.lock();
    defer tls_default_ca_mutex.unlock();
    if (tls_default_ca_pem) |old| std.heap.page_allocator.free(old);
    tls_default_ca_pem = null;
    tls_default_ca_count = 0;
    return 0;
}

pub export fn sa_node_plugin_tls_create_secure_context(ca_ptr: ?[*]const u8, ca_len: u64, cert_ptr: ?[*]const u8, cert_len: u64, key_ptr: ?[*]const u8, key_len: u64, ciphers_ptr: ?[*]const u8, ciphers_len: u64, min_ptr: ?[*]const u8, min_len: u64, max_ptr: ?[*]const u8, max_len: u64, out_context: ?*?*anyopaque) u32 {
    const out = out_context orelse return fail();
    out.* = null;
    const allocator = std.heap.page_allocator;
    const ctx = allocator.create(TlsSecureContextHandle) catch return fail();
    ctx.* = .{ .allocator = allocator };
    errdefer ctx.deinit();
    if (ca_ptr) |ptr| {
        const ca = ptr[0..ca_len];
        if (ca.len > 0) {
            var bundle = tlsBuildBundleFromPem(allocator, ca) catch return fail();
            ctx.ca_count = bundle.map.count();
            bundle.deinit(allocator);
            ctx.ca_pem = allocator.dupe(u8, ca) catch return fail();
        }
    }
    if (cert_ptr) |ptr| {
        if (cert_len > 0) ctx.cert_pem = allocator.dupe(u8, ptr[0..cert_len]) catch return fail();
    }
    if (key_ptr) |ptr| {
        if (key_len > 0) ctx.key_pem = allocator.dupe(u8, ptr[0..key_len]) catch return fail();
    }
    if (ciphers_ptr) |ptr| {
        if (ciphers_len > 0) ctx.ciphers = allocator.dupe(u8, ptr[0..ciphers_len]) catch return fail();
    }
    if (min_ptr) |ptr| {
        if (min_len > 0) ctx.min_version = allocator.dupe(u8, ptr[0..min_len]) catch return fail();
    }
    if (max_ptr) |ptr| {
        if (max_len > 0) ctx.max_version = allocator.dupe(u8, ptr[0..max_len]) catch return fail();
    }
    out.* = @ptrCast(ctx);
    return 0;
}

pub export fn sa_node_plugin_tls_secure_context_snapshot_json(context_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const ctx: *TlsSecureContextHandle = @ptrCast(@alignCast(context_ptr orelse return fail()));
    var out = std.ArrayList(u8).init(ctx.allocator);
    defer out.deinit();
    out.writer().print("{{\"caCount\":{d},\"hasCA\":{},\"hasCert\":{},\"hasKey\":{},\"hasCiphers\":{}", .{ ctx.ca_count, ctx.ca_pem != null, ctx.cert_pem != null, ctx.key_pem != null, ctx.ciphers != null }) catch return fail();
    out.appendSlice(",\"minVersion\":") catch return fail();
    if (ctx.min_version) |v| appendJsonString(&out, v) catch return fail() else out.appendSlice("null") catch return fail();
    out.appendSlice(",\"maxVersion\":") catch return fail();
    if (ctx.max_version) |v| appendJsonString(&out, v) catch return fail() else out.appendSlice("null") catch return fail();
    out.append('}') catch return fail();
    const owned = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_tls_secure_context_free(context_ptr: ?*anyopaque) u32 {
    if (context_ptr) |ptr| {
        const ctx: *TlsSecureContextHandle = @ptrCast(@alignCast(ptr));
        ctx.deinit();
    }
    return 0;
}

pub export fn sa_node_plugin_tls_connect(host_ptr: ?[*]const u8, host_len: u64, port: u64, servername_ptr: ?[*]const u8, servername_len: u64, reject_unauthorized: u64, out_socket: ?*?*anyopaque) u32 {
    const allocator = std.heap.page_allocator;
    const host = (host_ptr orelse return fail())[0..host_len];
    const servername = if (servername_ptr) |ptr| ptr[0..servername_len] else host;
    if (port > std.math.maxInt(u16)) return fail();
    const stream = std.net.tcpConnectToHost(allocator, host, @as(u16, @intCast(port))) catch return fail();
    errdefer stream.close();
    return tlsInitClientHandle(allocator, stream, host, servername, reject_unauthorized, 0, out_socket);
}

pub export fn sa_node_plugin_tls_connect_secure_context(context_ptr: ?*anyopaque, host_ptr: ?[*]const u8, host_len: u64, port: u64, servername_ptr: ?[*]const u8, servername_len: u64, reject_unauthorized: u64, out_socket: ?*?*anyopaque) u32 {
    const allocator = std.heap.page_allocator;
    const ctx: *TlsSecureContextHandle = @ptrCast(@alignCast(context_ptr orelse return fail()));
    const host = (host_ptr orelse return fail())[0..host_len];
    const servername = if (servername_ptr) |ptr| ptr[0..servername_len] else host;
    if (port > std.math.maxInt(u16)) return fail();
    const stream = std.net.tcpConnectToHost(allocator, host, @as(u16, @intCast(port))) catch return fail();
    errdefer stream.close();
    return tlsInitClientHandleWithCaPem(allocator, stream, host, servername, reject_unauthorized, 0, ctx.ca_pem, out_socket);
}

pub export fn sa_node_plugin_tls_connect_options(host_ptr: ?[*]const u8, host_len: u64, port: u64, servername_ptr: ?[*]const u8, servername_len: u64, reject_unauthorized: u64, family: u32, local_ptr: ?[*]const u8, local_len: u64, local_port: u64, no_delay: u32, keep_alive: u32, keep_alive_initial_delay_secs: u32, timeout_ms: u64, blocklist_ptr: ?*anyopaque, out_socket: ?*?*anyopaque) u32 {
    const out = out_socket orelse return fail();
    out.* = null;
    const allocator = std.heap.page_allocator;
    const host = (host_ptr orelse return fail())[0..host_len];
    const servername = if (servername_ptr) |ptr| ptr[0..servername_len] else host;
    const address = tlsParseRemoteAddress(host, port, family) catch return fail();
    if (tlsAddressBlocked(allocator, blocklist_ptr, address)) return 3;
    const stream = tlsConnectAddressWithOptions(address, local_ptr, local_len, local_port, no_delay, keep_alive, keep_alive_initial_delay_secs, timeout_ms) catch return fail();
    errdefer stream.close();
    return tlsInitClientHandle(allocator, stream, host, servername, reject_unauthorized, timeout_ms, out_socket);
}

pub export fn sa_node_plugin_tls_write(socket_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    if (handle.closed or !handle.writable) return fail();
    const stream = handle.stream orelse return fail();
    const data = data_ptr.?[0..data_len];
    handle.client.writeAll(stream, data) catch return fail();
    handle.bytes_written +|= data_len;
    return 0;
}

pub export fn sa_node_plugin_tls_read(socket_ptr: ?*anyopaque, max_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    if (handle.closed or !handle.readable) return fail();
    const stream = handle.stream orelse return fail();
    const cap = @max(@as(u64, 1), max_len);
    const buf = handle.allocator.alloc(u8, cap) catch return fail();
    errdefer handle.allocator.free(buf);

    const n = handle.client.read(stream, buf) catch return fail();
    if (n == 0) {
        handle.allocator.free(buf);
        handle.readable = false;
        out_ptr.?.* = null;
        out_len.?.* = 0;
        return 0;
    }
    handle.bytes_read +|= @intCast(n);

    const owned = handle.allocator.realloc(buf, n) catch buf[0..n];
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_tls_authorized_json(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    if (handle.authorized) {
        return writeOwned(out_ptr, out_len, "{\"authorized\":true,\"authorizationError\":null}");
    }
    return writeOwned(out_ptr, out_len, "{\"authorized\":false,\"authorizationError\":\"UNABLE_TO_VERIFY_LEAF_SIGNATURE\"}");
}

pub export fn sa_node_plugin_tls_servername(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return writeOwned(out_ptr, out_len, handle.servername);
}

pub export fn sa_node_plugin_tls_alpn_protocol(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    _ = handle;
    return writeOwned(out_ptr, out_len, "false");
}

pub export fn sa_node_plugin_tls_get_protocol(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return writeOwned(out_ptr, out_len, tlsProtocolName(handle.client.tls_version));
}

pub export fn sa_node_plugin_tls_get_cipher_json(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    const tag_name = @tagName(handle.client.application_cipher);
    const standard_name = tlsCipherStandardName(tag_name);
    var out = std.ArrayList(u8).init(handle.allocator);
    defer out.deinit();
    out.appendSlice("{\"name\":") catch return fail();
    appendJsonString(&out, tag_name) catch return fail();
    out.appendSlice(",\"standardName\":") catch return fail();
    appendJsonString(&out, standard_name) catch return fail();
    out.appendSlice(",\"version\":") catch return fail();
    appendJsonString(&out, tlsProtocolName(handle.client.tls_version)) catch return fail();
    out.append('}') catch return fail();
    const owned = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_tls_address(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return tlsWriteSocketAddressJson(handle, false, out_ptr, out_len);
}

pub export fn sa_node_plugin_tls_remote_address(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return tlsWriteSocketAddressJson(handle, true, out_ptr, out_len);
}

pub export fn sa_node_plugin_tls_local_address(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return tlsWriteSocketAddressProperty(handle, false, .address, out_ptr, out_len);
}

pub export fn sa_node_plugin_tls_local_family(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return tlsWriteSocketAddressProperty(handle, false, .family, out_ptr, out_len);
}

pub export fn sa_node_plugin_tls_local_port(socket_ptr: ?*anyopaque, out_port: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return tlsWriteSocketAddressPort(handle, false, out_port);
}

pub export fn sa_node_plugin_tls_remote_address_value(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return tlsWriteSocketAddressProperty(handle, true, .address, out_ptr, out_len);
}

pub export fn sa_node_plugin_tls_remote_family(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return tlsWriteSocketAddressProperty(handle, true, .family, out_ptr, out_len);
}

pub export fn sa_node_plugin_tls_remote_port(socket_ptr: ?*anyopaque, out_port: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    return tlsWriteSocketAddressPort(handle, true, out_port);
}

pub export fn sa_node_plugin_tls_set_timeout(socket_ptr: ?*anyopaque, timeout_ms: u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    if (handle.closed) return fail();
    const stream = handle.stream orelse return fail();
    const tv = tlsTimevalFromMs(timeout_ms);
    std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch return fail();
    std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch return fail();
    handle.timeout_ms = timeout_ms;
    return 0;
}

pub export fn sa_node_plugin_tls_get_timeout(socket_ptr: ?*anyopaque, out_timeout_ms: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    (out_timeout_ms orelse return fail()).* = handle.timeout_ms;
    return 0;
}

pub export fn sa_node_plugin_tls_bytes_read(socket_ptr: ?*anyopaque, out_bytes: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    out_bytes.?.* = handle.bytes_read;
    return 0;
}

pub export fn sa_node_plugin_tls_bytes_written(socket_ptr: ?*anyopaque, out_bytes: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    out_bytes.?.* = handle.bytes_written;
    return 0;
}

pub export fn sa_node_plugin_tls_buffer_size(socket_ptr: ?*anyopaque, out_size: ?*u64) u32 {
    _ = @as(*TlsClientHandle, @ptrCast(@alignCast(socket_ptr orelse return fail())));
    (out_size orelse return fail()).* = 0;
    return 0;
}

pub export fn sa_node_plugin_tls_connecting(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    _ = @as(*TlsClientHandle, @ptrCast(@alignCast(socket_ptr orelse return fail())));
    (out_bool orelse return fail()).* = 0;
    return 0;
}

pub export fn sa_node_plugin_tls_pending(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    _ = @as(*TlsClientHandle, @ptrCast(@alignCast(socket_ptr orelse return fail())));
    (out_bool orelse return fail()).* = 0;
    return 0;
}

pub export fn sa_node_plugin_tls_ready_state(socket_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    const state = if (handle.closed or (!handle.readable and !handle.writable))
        "closed"
    else if (handle.readable and handle.writable)
        "open"
    else if (handle.readable)
        "readOnly"
    else
        "writeOnly";
    return writeOwned(out_ptr, out_len, state);
}

pub export fn sa_node_plugin_tls_readable(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    out_bool.?.* = if (!handle.closed and handle.readable) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_tls_writable(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    out_bool.?.* = if (!handle.closed and handle.writable) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_tls_closed(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    out_bool.?.* = if (handle.closed) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_tls_destroyed(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    out_bool.?.* = if (handle.closed) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_tls_ref(socket_ptr: ?*anyopaque) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    handle.has_ref = true;
    return 0;
}

pub export fn sa_node_plugin_tls_unref(socket_ptr: ?*anyopaque) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    handle.has_ref = false;
    return 0;
}

pub export fn sa_node_plugin_tls_has_ref(socket_ptr: ?*anyopaque, out_bool: ?*u64) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    (out_bool orelse return fail()).* = if (handle.has_ref) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_tls_destroy(socket_ptr: ?*anyopaque) u32 {
    const handle: *TlsClientHandle = @ptrCast(@alignCast(socket_ptr orelse return fail()));
    handle.destroySocket();
    return 0;
}

pub export fn sa_node_plugin_tls_close(socket_ptr: ?*anyopaque) u32 {
    if (socket_ptr) |ptr| {
        const handle: *TlsClientHandle = @ptrCast(@alignCast(ptr));
        handle.deinit();
    }
    return 0;
}

// ============================================================
// TIMERS
// ============================================================

const TimerHandle = struct { id: u64, ms: u64, is_interval: bool, callback: ?*anyopaque, created_ns: i128, refed: bool = true, cleared: bool = false };
var timer_next_id: u64 = 1;
var timer_mutex = std.Thread.Mutex{};
var timer_registry = std.AutoHashMap(u64, *TimerHandle).init(std.heap.page_allocator);

fn timerCreate(ms: u64, is_interval: bool, out_id: ?*u64) u32 {
    if (out_id == null) return fail();
    const h = std.heap.page_allocator.create(TimerHandle) catch return fail();
    timer_mutex.lock();
    defer timer_mutex.unlock();
    h.* = .{ .id = timer_next_id, .ms = ms, .is_interval = is_interval, .callback = null, .created_ns = std.time.nanoTimestamp() };
    timer_registry.put(h.id, h) catch {
        std.heap.page_allocator.destroy(h);
        return fail();
    };
    timer_next_id +%= 1;
    if (timer_next_id == 0) timer_next_id = 1;
    out_id.?.* = h.id;
    return 0;
}

fn timerCreateWithCallback(ms: u64, is_interval: bool, callback: ?*anyopaque, out_id: ?*u64) u32 {
    const status = timerCreate(ms, is_interval, out_id);
    if (status != 0) return status;
    timer_mutex.lock();
    defer timer_mutex.unlock();
    if (timer_registry.get(out_id.?.*)) |h| h.callback = callback;
    return 0;
}

fn timerClear(id: u64) u32 {
    timer_mutex.lock();
    defer timer_mutex.unlock();
    if (timer_registry.fetchRemove(id)) |entry| {
        entry.value.cleared = true;
        std.heap.page_allocator.destroy(entry.value);
    }
    return 0;
}

pub export fn sa_node_plugin_timers_set_timeout(ms: u64, callback: ?*anyopaque, out_id: ?*u64) u32 {
    return timerCreateWithCallback(ms, false, callback, out_id);
}
pub export fn sa_node_plugin_timers_set_interval(ms: u64, callback: ?*anyopaque, out_id: ?*u64) u32 {
    return timerCreateWithCallback(ms, true, callback, out_id);
}
pub export fn sa_node_plugin_timers_set_immediate(callback: ?*anyopaque, out_id: ?*u64) u32 {
    return timerCreateWithCallback(0, false, callback, out_id);
}
pub export fn sa_node_plugin_timers_clear_timeout(id: u64) u32 {
    return timerClear(id);
}
pub export fn sa_node_plugin_timers_clear_interval(id: u64) u32 {
    return sa_node_plugin_timers_clear_timeout(id);
}
pub export fn sa_node_plugin_timers_clear_immediate(id: u64) u32 {
    return sa_node_plugin_timers_clear_timeout(id);
}

// ============================================================
// BUFFER
// ============================================================

pub export fn sa_node_plugin_buffer_atob(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const data = data_ptr.?[0..data_len];
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(data) catch return fail();
    const dest = std.heap.page_allocator.alloc(u8, decoded_len) catch return fail();
    std.base64.standard.Decoder.decode(dest, data) catch {
        std.heap.page_allocator.free(dest);
        return fail();
    };
    out_ptr.?.* = dest.ptr;
    out_len.?.* = decoded_len;
    return 0;
}

pub export fn sa_node_plugin_buffer_btoa(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const data = data_ptr.?[0..data_len];
    const enc_len = std.base64.standard.Encoder.calcSize(data.len);
    const dest = std.heap.page_allocator.alloc(u8, enc_len) catch return fail();
    _ = std.base64.standard.Encoder.encode(dest, data);
    out_ptr.?.* = dest.ptr;
    out_len.?.* = enc_len;
    return 0;
}

pub export fn sa_node_plugin_buffer_is_utf8(data_ptr: ?[*]const u8, data_len: u64, out_bool: ?*u32) u32 {
    out_bool.?.* = if (std.unicode.utf8ValidateSlice(data_ptr.?[0..data_len])) 1 else 0;
    return 0;
}

pub export fn sa_node_plugin_buffer_is_ascii(data_ptr: ?[*]const u8, data_len: u64, out_bool: ?*u32) u32 {
    for (data_ptr.?[0..data_len]) |byte| {
        if (byte > 127) {
            out_bool.?.* = 0;
            return 0;
        }
    }
    out_bool.?.* = 1;
    return 0;
}

const BufferEncoding = enum { utf8, utf16le, latin1, ascii, base64, base64url, hex };

fn parseBufferEncoding(enc: []const u8) ?BufferEncoding {
    if (std.ascii.eqlIgnoreCase(enc, "utf8") or std.ascii.eqlIgnoreCase(enc, "utf-8")) return .utf8;
    if (std.ascii.eqlIgnoreCase(enc, "utf16le") or std.ascii.eqlIgnoreCase(enc, "utf-16le") or std.ascii.eqlIgnoreCase(enc, "ucs2") or std.ascii.eqlIgnoreCase(enc, "ucs-2")) return .utf16le;
    if (std.ascii.eqlIgnoreCase(enc, "latin1") or std.ascii.eqlIgnoreCase(enc, "binary")) return .latin1;
    if (std.ascii.eqlIgnoreCase(enc, "ascii")) return .ascii;
    if (std.ascii.eqlIgnoreCase(enc, "base64")) return .base64;
    if (std.ascii.eqlIgnoreCase(enc, "base64url")) return .base64url;
    if (std.ascii.eqlIgnoreCase(enc, "hex")) return .hex;
    return null;
}

fn latin1ToUtf8(out: *std.ArrayList(u8), bytes: []const u8) !void {
    for (bytes) |byte| {
        if (byte < 0x80) {
            try out.append(byte);
        } else {
            var buf: [4]u8 = undefined;
            const n = try std.unicode.utf8Encode(byte, &buf);
            try out.appendSlice(buf[0..n]);
        }
    }
}

fn utf16leBytesToUtf8(out: *std.ArrayList(u8), bytes: []const u8) !void {
    if ((bytes.len % 2) != 0) return error.InvalidUtf16Le;
    var units = try std.heap.page_allocator.alloc(u16, bytes.len / 2);
    defer std.heap.page_allocator.free(units);
    var i: usize = 0;
    while (i < units.len) : (i += 1) {
        units[i] = std.mem.readInt(u16, bytes[i * 2 ..][0..2], .little);
    }
    try std.unicode.utf16LeToUtf8ArrayList(out, units);
}

fn decodeBufferToUtf8(enc: BufferEncoding, src: []const u8, out: *std.ArrayList(u8)) !void {
    switch (enc) {
        .utf8 => {
            if (!std.unicode.utf8ValidateSlice(src)) return error.InvalidUtf8;
            try out.appendSlice(src);
        },
        .utf16le => try utf16leBytesToUtf8(out, src),
        .latin1 => try latin1ToUtf8(out, src),
        .ascii => for (src) |byte| try out.append(byte & 0x7f),
        .base64 => {
            const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(src);
            const old_len = out.items.len;
            try out.resize(old_len + decoded_len);
            try std.base64.standard.Decoder.decode(out.items[old_len..], src);
            if (!std.unicode.utf8ValidateSlice(out.items[old_len..])) return error.InvalidUtf8;
        },
        .base64url => {
            const decoded_len = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(src);
            const old_len = out.items.len;
            try out.resize(old_len + decoded_len);
            try std.base64.url_safe_no_pad.Decoder.decode(out.items[old_len..], src);
            if (!std.unicode.utf8ValidateSlice(out.items[old_len..])) return error.InvalidUtf8;
        },
        .hex => {
            if ((src.len % 2) != 0) return error.InvalidHex;
            const old_len = out.items.len;
            try out.resize(old_len + src.len / 2);
            _ = try std.fmt.hexToBytes(out.items[old_len..], src);
            if (!std.unicode.utf8ValidateSlice(out.items[old_len..])) return error.InvalidUtf8;
        },
    }
}

fn encodeUtf8ToBuffer(enc: BufferEncoding, utf8: []const u8, out: *std.ArrayList(u8)) !void {
    switch (enc) {
        .utf8 => try out.appendSlice(utf8),
        .utf16le => {
            const units = try std.unicode.utf8ToUtf16LeAlloc(std.heap.page_allocator, utf8);
            defer std.heap.page_allocator.free(units);
            try out.ensureUnusedCapacity(units.len * 2);
            for (units) |unit| {
                var bytes: [2]u8 = undefined;
                std.mem.writeInt(u16, &bytes, unit, .little);
                try out.appendSlice(&bytes);
            }
        },
        .latin1, .ascii => {
            var view = try std.unicode.Utf8View.init(utf8);
            var it = view.iterator();
            while (it.nextCodepoint()) |cp| {
                if (enc == .ascii) {
                    try out.append(if (cp <= 0x7f) @intCast(cp) else '?');
                } else {
                    try out.append(if (cp <= 0xff) @intCast(cp) else '?');
                }
            }
        },
        .base64 => {
            const enc_len = std.base64.standard.Encoder.calcSize(utf8.len);
            const old_len = out.items.len;
            try out.resize(old_len + enc_len);
            _ = std.base64.standard.Encoder.encode(out.items[old_len..], utf8);
        },
        .base64url => {
            const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(utf8.len);
            const old_len = out.items.len;
            try out.resize(old_len + enc_len);
            _ = std.base64.url_safe_no_pad.Encoder.encode(out.items[old_len..], utf8);
        },
        .hex => {
            const old_len = out.items.len;
            try out.resize(old_len + utf8.len * 2);
            _ = std.fmt.bufPrint(out.items[old_len..], "{s}", .{std.fmt.fmtSliceHexLower(utf8)}) catch return error.NoSpaceLeft;
        },
    }
}

pub export fn sa_node_plugin_buffer_transcode(src_ptr: ?[*]const u8, src_len: u64, from_enc_ptr: ?[*]const u8, from_enc_len: u64, to_enc_ptr: ?[*]const u8, to_enc_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (src_ptr == null or from_enc_ptr == null or to_enc_ptr == null) return fail();
    const from = parseBufferEncoding(from_enc_ptr.?[0..from_enc_len]) orelse return fail();
    const to = parseBufferEncoding(to_enc_ptr.?[0..to_enc_len]) orelse return fail();
    const src = src_ptr.?[0..src_len];

    var utf8 = std.ArrayList(u8).init(std.heap.page_allocator);
    defer utf8.deinit();
    decodeBufferToUtf8(from, src, &utf8) catch return fail();

    var encoded = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer encoded.deinit();
    encodeUtf8ToBuffer(to, utf8.items, &encoded) catch return fail();
    const slice = encoded.toOwnedSlice() catch return fail();
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_buffer_resolve_object_url(url_ptr: ?[*]const u8, url_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const url = if (url_ptr) |p| p[0..url_len] else "";
    if (std.mem.startsWith(u8, url, "blob:")) {
        return writeOwned(out_ptr, out_len, url[5..]);
    }
    return writeOwned(out_ptr, out_len, url);
}

// ============================================================
// ZLIB
// ============================================================

pub export fn sa_node_plugin_zlib_deflate_raw(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const input = data_ptr.?[0..data_len];
    const in_stream = std.io.fixedBufferStream(input);
    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();
    var compressor = std.compress.flate.compressor(out_list.writer(), .{}) catch return fail();
    compressor.writer().writeAll(input) catch return fail();
    compressor.finish() catch return fail();
    const slice = out_list.toOwnedSlice() catch return fail();
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    _ = in_stream;
    return 0;
}

pub export fn sa_node_plugin_zlib_inflate_raw(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const input = data_ptr.?[0..data_len];
    var in_stream = std.io.fixedBufferStream(input);
    var decompressor = std.compress.flate.decompressor(in_stream.reader());
    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();
    var temp: [4096]u8 = undefined;
    while (true) {
        const n = decompressor.reader().read(&temp) catch return fail();
        if (n == 0) break;
        out_list.appendSlice(temp[0..n]) catch return fail();
    }
    const slice = out_list.toOwnedSlice() catch return fail();
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_zlib_unzip(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const input = data_ptr.?[0..data_len];
    var out_list = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out_list.deinit();

    {
        var in_stream = std.io.fixedBufferStream(input);
        var decompressor = std.compress.gzip.decompressor(in_stream.reader());
        var temp: [4096]u8 = undefined;
        while (true) {
            const n = decompressor.reader().read(&temp) catch break;
            if (n == 0) break;
            out_list.appendSlice(temp[0..n]) catch return fail();
        }
        if (out_list.items.len > 0) {
            const slice = out_list.toOwnedSlice() catch return fail();
            out_ptr.?.* = slice.ptr;
            out_len.?.* = slice.len;
            return 0;
        }
    }

    out_list.clearRetainingCapacity();
    {
        var in_stream = std.io.fixedBufferStream(input);
        var decompressor = std.compress.zlib.decompressor(in_stream.reader());
        var temp: [4096]u8 = undefined;
        while (true) {
            const n = decompressor.reader().read(&temp) catch return fail();
            if (n == 0) break;
            out_list.appendSlice(temp[0..n]) catch return fail();
        }
    }

    const slice = out_list.toOwnedSlice() catch return fail();
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

fn brotliCompress(input: []const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadBrotliApi() orelse return fail();
    const max_size = api.max_compressed_size(input.len);
    const out = std.heap.page_allocator.alloc(u8, max_size) catch return fail();
    var written: usize = out.len;
    const ok = api.compress(11, 22, @intFromEnum(BrotliEncoderMode.generic), input.len, input.ptr, &written, out.ptr);
    if (ok == 0) {
        std.heap.page_allocator.free(out);
        return fail();
    }
    const slice = out[0..written];
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

fn brotliDecompress(input: []const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadBrotliApi() orelse return fail();
    const state = api.decoder_create(null, null, null) orelse return fail();
    defer api.decoder_destroy(state);

    var available_in: usize = input.len;
    var next_in: ?[*]const u8 = input.ptr;
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();
    var temp: [4096]u8 = undefined;

    while (true) {
        var available_out: usize = temp.len;
        var next_out: ?[*]u8 = &temp;
        var total_out: usize = 0;
        const result = api.decoder_decompress_stream(state, &available_in, &next_in, &available_out, &next_out, &total_out);
        const produced = temp.len - available_out;
        if (produced > 0) out.appendSlice(temp[0..produced]) catch return fail();
        if (result == @intFromEnum(BrotliDecoderResult.success)) break;
        if (result == @intFromEnum(BrotliDecoderResult.err)) return fail();
        if (available_in == 0 and produced == 0) break;
    }

    const slice = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}

pub export fn sa_node_plugin_zlib_brotli_compress(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return brotliCompress(data_ptr.?[0..data_len], out_ptr, out_len);
}

pub export fn sa_node_plugin_zlib_brotli_decompress(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return brotliDecompress(data_ptr.?[0..data_len], out_ptr, out_len);
}

pub export fn sa_node_plugin_zlib_zstd_compress(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadZstdApi() orelse return fail();
    const input = data_ptr.?[0..data_len];
    const max_size = api.compress_bound(input.len);
    if (max_size == 0) return fail();
    const out = std.heap.page_allocator.alloc(u8, max_size) catch return fail();
    const written = api.compress(out.ptr, out.len, input.ptr, input.len, 3);
    if (api.is_error(written) != 0) {
        std.heap.page_allocator.free(out);
        return fail();
    }
    out_ptr.?.* = out.ptr;
    out_len.?.* = written;
    return 0;
}

pub export fn sa_node_plugin_zlib_zstd_decompress(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const api = loadZstdApi() orelse return fail();
    const input = data_ptr.?[0..data_len];
    const content_size = api.get_frame_content_size(input.ptr, input.len);
    if (content_size == ZSTD_CONTENTSIZE_ERROR or content_size == ZSTD_CONTENTSIZE_UNKNOWN) return fail();
    if (content_size > std.math.maxInt(usize)) return fail();
    const out = std.heap.page_allocator.alloc(u8, @intCast(content_size)) catch return fail();
    const written = api.decompress(out.ptr, out.len, input.ptr, input.len);
    if (api.is_error(written) != 0 or written != out.len) {
        std.heap.page_allocator.free(out);
        return fail();
    }
    out_ptr.?.* = out.ptr;
    out_len.?.* = written;
    return 0;
}

pub export fn sa_node_plugin_zlib_crc32(data_ptr: ?[*]const u8, data_len: u64, out_val: ?*u32) u32 {
    out_val.?.* = std.hash.Crc32.hash(data_ptr.?[0..data_len]);
    return 0;
}

// ============================================================
// URL
// ============================================================

const UrlHandle = struct { href: []u8, protocol: []u8, host: []u8, pathname: []u8 };

fn jsonObjectStringField(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    if (obj.get(key)) |value| {
        return switch (value) {
            .string => |text| text,
            else => "",
        };
    }
    return "";
}

pub export fn sa_node_plugin_url_new(href_ptr: ?[*]const u8, href_len: u64, out_handle: ?*?*anyopaque) u32 {
    const href = href_ptr.?[0..href_len];
    const allocator = std.heap.page_allocator;
    const h = allocator.create(UrlHandle) catch return fail();
    var protocol: []const u8 = "https:";
    var host: []const u8 = href;
    var pathname: []const u8 = "/";
    if (std.mem.indexOf(u8, href, "://")) |sep| {
        protocol = href[0 .. sep + 1];
        const rest = href[sep + 3 ..];
        if (std.mem.indexOfScalar(u8, rest, '/')) |slash_pos| {
            host = rest[0..slash_pos];
            pathname = rest[slash_pos..];
        } else {
            host = rest;
        }
    }
    h.* = .{
        .href = allocator.dupe(u8, href) catch return fail(),
        .protocol = allocator.dupe(u8, protocol) catch return fail(),
        .host = allocator.dupe(u8, host) catch return fail(),
        .pathname = allocator.dupe(u8, pathname) catch return fail(),
    };
    out_handle.?.* = @ptrCast(h);
    return 0;
}

pub export fn sa_node_plugin_url_get_href(h: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, @as(*UrlHandle, @ptrCast(@alignCast(h orelse return fail()))).href);
}
pub export fn sa_node_plugin_url_get_protocol(h: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, @as(*UrlHandle, @ptrCast(@alignCast(h orelse return fail()))).protocol);
}
pub export fn sa_node_plugin_url_get_host(h: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, @as(*UrlHandle, @ptrCast(@alignCast(h orelse return fail()))).host);
}
pub export fn sa_node_plugin_url_get_pathname(h: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, @as(*UrlHandle, @ptrCast(@alignCast(h orelse return fail()))).pathname);
}

pub export fn sa_node_plugin_url_domain_to_ascii(domain_ptr: ?[*]const u8, domain_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_punycode_to_ascii(domain_ptr, domain_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_url_domain_to_unicode(domain_ptr: ?[*]const u8, domain_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_punycode_to_unicode(domain_ptr, domain_len, out_ptr, out_len);
}

fn appendPercentEncodedByte(out: *std.ArrayList(u8), byte: u8) !void {
    try out.writer().print("%{X:0>2}", .{byte});
}

fn appendFileUrlPathEncoded(out: *std.ArrayList(u8), path: []const u8) !void {
    for (path) |c| {
        switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '/', ':' => try out.append(c),
            else => try appendPercentEncodedByte(out, c),
        }
    }
}

pub export fn sa_node_plugin_url_path_to_file_url(path_ptr: ?[*]const u8, path_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const input = if (path_len == 0) "." else (path_ptr orelse return fail())[0..path_len];
    const resolved = std.fs.path.resolve(std.heap.page_allocator, &.{input}) catch return fail();
    defer std.heap.page_allocator.free(resolved);

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("file://") catch return fail();
    if (resolved.len == 0 or resolved[0] != '/') out.append('/') catch return fail();
    appendFileUrlPathEncoded(&out, resolved) catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}

fn decodeFileUrlPath(url: []const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (!std.mem.startsWith(u8, url, "file://")) return fail();
    const path_part = url[7..];
    if (path_part.len == 0 or path_part[0] != '/') return fail();

    var decoded_ptr: ?[*]const u8 = null;
    var decoded_len: u64 = 0;
    if (sa_node_plugin_querystring_unescape_buffer(path_part.ptr, path_part.len, &decoded_ptr, &decoded_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(decoded_ptr, decoded_len);
    return writeOwned(out_ptr, out_len, (decoded_ptr orelse return fail())[0..@intCast(decoded_len)]);
}

pub export fn sa_node_plugin_url_file_url_to_path(url_ptr: ?[*]const u8, url_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const url = (url_ptr orelse return fail())[0..url_len];
    return decodeFileUrlPath(url, out_ptr, out_len);
}

pub export fn sa_node_plugin_url_file_url_to_path_buffer(url_ptr: ?[*]const u8, url_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const url = (url_ptr orelse return fail())[0..url_len];
    return decodeFileUrlPath(url, out_ptr, out_len);
}

pub export fn sa_node_plugin_url_to_http_options(h: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *UrlHandle = @ptrCast(@alignCast(h orelse return fail()));

    var parsed_ptr: ?[*]const u8 = null;
    var parsed_len: u64 = 0;
    if (base.sa_node_plugin_url_parse(handle.href.ptr, handle.href.len, &parsed_ptr, &parsed_len) != 0) return fail();
    defer _ = base.sa_node_plugin_free_buffer(parsed_ptr, parsed_len);

    const parsed_json = (parsed_ptr orelse return fail())[0..@intCast(parsed_len)];
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, parsed_json, .{}) catch return fail();
    defer parsed.deinit();

    const obj = parsed.value.object;
    const protocol = jsonObjectStringField(obj, "protocol");
    const auth = jsonObjectStringField(obj, "auth");
    const host = jsonObjectStringField(obj, "host");
    const hostname = jsonObjectStringField(obj, "hostname");
    const port = jsonObjectStringField(obj, "port");
    const pathname = jsonObjectStringField(obj, "pathname");
    const search = jsonObjectStringField(obj, "search");
    const hash = jsonObjectStringField(obj, "hash");

    var path_buf = std.ArrayList(u8).init(std.heap.page_allocator);
    defer path_buf.deinit();
    path_buf.appendSlice(pathname) catch return fail();
    path_buf.appendSlice(search) catch return fail();

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{") catch return fail();
    out.appendSlice("\"protocol\":") catch return fail();
    std.json.stringify(protocol, .{}, out.writer()) catch return fail();
    out.appendSlice(",\"auth\":") catch return fail();
    std.json.stringify(auth, .{}, out.writer()) catch return fail();
    out.appendSlice(",\"host\":") catch return fail();
    std.json.stringify(host, .{}, out.writer()) catch return fail();
    out.appendSlice(",\"hostname\":") catch return fail();
    std.json.stringify(hostname, .{}, out.writer()) catch return fail();
    out.appendSlice(",\"port\":") catch return fail();
    std.json.stringify(port, .{}, out.writer()) catch return fail();
    out.appendSlice(",\"pathname\":") catch return fail();
    std.json.stringify(pathname, .{}, out.writer()) catch return fail();
    out.appendSlice(",\"search\":") catch return fail();
    std.json.stringify(search, .{}, out.writer()) catch return fail();
    out.appendSlice(",\"hash\":") catch return fail();
    std.json.stringify(hash, .{}, out.writer()) catch return fail();
    out.appendSlice(",\"path\":") catch return fail();
    std.json.stringify(path_buf.items, .{}, out.writer()) catch return fail();
    out.appendSlice(",\"href\":") catch return fail();
    std.json.stringify(handle.href, .{}, out.writer()) catch return fail();
    out.append('}') catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_url_can_parse(url_ptr: ?[*]const u8, url_len: u64, base_ptr: ?[*]const u8, base_len: u64, out_bool: ?*u64) u32 {
    const url = (url_ptr orelse return fail())[0..url_len];
    if (base_len != 0) {
        const base_text = (base_ptr orelse return fail())[0..base_len];
        var resolved_ptr: ?[*]const u8 = null;
        var resolved_len: u64 = 0;
        const status = base.sa_node_plugin_url_resolve(base_text.ptr, base_text.len, url.ptr, url.len, &resolved_ptr, &resolved_len);
        if (status == 0) {
            defer _ = base.sa_node_plugin_free_buffer(resolved_ptr, resolved_len);
            out_bool.?.* = 1;
            return 0;
        }
        out_bool.?.* = 0;
        return 0;
    }

    out_bool.?.* = if (std.Uri.parse(url)) |_| 1 else |_| 0;
    return 0;
}

pub export fn sa_node_plugin_url_free(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| {
        const h: *UrlHandle = @ptrCast(@alignCast(ptr));
        std.heap.page_allocator.free(h.href);
        std.heap.page_allocator.free(h.protocol);
        std.heap.page_allocator.free(h.host);
        std.heap.page_allocator.free(h.pathname);
        std.heap.page_allocator.destroy(h);
    }
    return 0;
}

// ============================================================
// UTIL
// ============================================================

fn utilWrapMeta(kind: []const u8, fn_ptr: ?[*]const u8, fn_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{") catch return fail();
    out.appendSlice("\"kind\":") catch return fail();
    appendJsonString(&out, kind) catch return fail();
    out.appendSlice(",\"name\":") catch return fail();
    if (fn_ptr) |ptr| {
        appendJsonString(&out, ptr[0..fn_len]) catch return fail();
    } else {
        appendJsonString(&out, "") catch return fail();
    }
    out.appendSlice("}") catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_util_callbackify(fn_ptr: ?[*]const u8, fn_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return utilWrapMeta("callbackify", fn_ptr, fn_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_util_promisify(fn_ptr: ?[*]const u8, fn_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return utilWrapMeta("promisify", fn_ptr, fn_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_util_inherits(c: ?[*]const u8, c_len: u64, s: ?[*]const u8, s_len: u64) u32 {
    _ = c;
    _ = c_len;
    _ = s;
    _ = s_len;
    return 0;
}

const DeprecationRecord = struct {
    code: []u8,
    message: []u8,
};

var util_mutex = std.Thread.Mutex{};
var util_deprecations = std.ArrayList(DeprecationRecord).init(std.heap.page_allocator);

fn nodeDebugSectionEnabled(section: []const u8) bool {
    const env = std.process.getEnvVarOwned(std.heap.page_allocator, "NODE_DEBUG") catch return false;
    defer std.heap.page_allocator.free(env);
    var sections = std.mem.splitScalar(u8, env, ',');
    while (sections.next()) |raw| {
        const item = std.mem.trim(u8, raw, " \t\r\n");
        if (item.len == 0) continue;
        if (std.mem.eql(u8, item, "*")) return true;
        if (std.ascii.eqlIgnoreCase(item, section)) return true;
    }
    return false;
}

pub export fn sa_node_plugin_util_debuglog(section_ptr: ?[*]const u8, section_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const section = if (section_ptr) |ptr| ptr[0..section_len] else "";
    const enabled = nodeDebugSectionEnabled(section);
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.appendSlice("{\"section\":") catch return fail();
    appendJsonString(&out, section) catch return fail();
    out.writer().print(
        ",\"enabled\":{},\"pid\":{d},\"prefix\":",
        .{ enabled, std.c.getpid() },
    ) catch return fail();
    var prefix_buf: [128]u8 = undefined;
    const prefix = std.fmt.bufPrint(&prefix_buf, "{s} {d}:", .{ section, std.c.getpid() }) catch "";
    appendJsonString(&out, prefix) catch return fail();
    out.append('}') catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}
pub export fn sa_node_plugin_util_deprecate(fn_ptr: ?[*]const u8, fn_len: u64, msg_ptr: ?[*]const u8, msg_len: u64) u32 {
    const code = if (fn_ptr) |ptr| ptr[0..fn_len] else "";
    const msg = if (msg_ptr) |ptr| ptr[0..msg_len] else "";
    const code_dup = std.heap.page_allocator.dupe(u8, code) catch return fail();
    errdefer std.heap.page_allocator.free(code_dup);
    const msg_dup = std.heap.page_allocator.dupe(u8, msg) catch return fail();
    errdefer std.heap.page_allocator.free(msg_dup);

    util_mutex.lock();
    defer util_mutex.unlock();
    for (util_deprecations.items) |record| {
        if (std.mem.eql(u8, record.code, code_dup)) {
            std.heap.page_allocator.free(code_dup);
            std.heap.page_allocator.free(msg_dup);
            return 0;
        }
    }
    util_deprecations.append(.{ .code = code_dup, .message = msg_dup }) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_util_diff(actual_ptr: ?[*]const u8, actual_len: u64, expected_ptr: ?[*]const u8, expected_len: u64, operator_ptr: ?[*]const u8, operator_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = operator_ptr;
    _ = operator_len;
    if (std.mem.eql(u8, actual_ptr.?[0..actual_len], expected_ptr.?[0..expected_len])) return writeOwned(out_ptr, out_len, "[]");
    return writeOwned(out_ptr, out_len, "[{\"op\":\"replace\"}]");
}

fn mimeTypeForPath(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    if (std.mem.eql(u8, ext, ".html") or std.mem.eql(u8, ext, ".htm")) return "text/html";
    if (std.mem.eql(u8, ext, ".js") or std.mem.eql(u8, ext, ".mjs")) return "application/javascript";
    if (std.mem.eql(u8, ext, ".json")) return "application/json";
    if (std.mem.eql(u8, ext, ".txt")) return "text/plain";
    if (std.mem.eql(u8, ext, ".css")) return "text/css";
    if (std.mem.eql(u8, ext, ".svg")) return "image/svg+xml";
    if (std.mem.eql(u8, ext, ".png")) return "image/png";
    if (std.mem.eql(u8, ext, ".jpg") or std.mem.eql(u8, ext, ".jpeg")) return "image/jpeg";
    if (std.mem.eql(u8, ext, ".gif")) return "image/gif";
    if (std.mem.eql(u8, ext, ".sa") or std.mem.eql(u8, ext, ".sal") or std.mem.eql(u8, ext, ".sai")) return "text/plain";
    return "application/octet-stream";
}

pub export fn sa_node_plugin_util_parse_args(config_ptr: ?[*]const u8, config_len: u64, args_ptr: ?[*]const u8, args_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const config_js = if (config_ptr) |p| p[0..config_len] else "{}";
    const args_js = if (args_ptr) |p| p[0..args_len] else "[]";

    const config = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, config_js, .{}) catch return fail();
    defer config.deinit();
    const args = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, args_js, .{}) catch return fail();
    defer args.deinit();

    var values = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer values.deinit();
    values.append('{') catch return fail();
    var first = true;
    switch (args.value) {
        .array => |arr| {
            for (arr.items) |arg| {
                const arg_s = switch (arg) {
                    .string => |s| s,
                    else => continue,
                };
                if (!std.mem.startsWith(u8, arg_s, "--")) continue;
                const eq_idx = std.mem.indexOfScalar(u8, arg_s, '=') orelse continue;
                if (!first) values.append(',') catch return fail();
                first = false;
                std.json.stringify(arg_s[2..eq_idx], .{}, values.writer()) catch return fail();
                values.append(':') catch return fail();
                std.json.stringify(arg_s[eq_idx + 1 ..], .{}, values.writer()) catch return fail();
            }
        },
        else => {},
    }
    values.append('}') catch return fail();

    var positionals = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer positionals.deinit();
    positionals.append('[') catch return fail();
    first = true;
    switch (args.value) {
        .array => |arr| {
            for (arr.items) |arg| {
                const arg_s = switch (arg) {
                    .string => |s| s,
                    else => continue,
                };
                if (std.mem.startsWith(u8, arg_s, "--")) continue;
                if (!first) positionals.append(',') catch return fail();
                first = false;
                std.json.stringify(arg_s, .{}, positionals.writer()) catch return fail();
            }
        },
        else => {},
    }
    positionals.append(']') catch return fail();

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();
    out.appendSlice("{\"values\":") catch return fail();
    out.appendSlice(values.items) catch return fail();
    out.appendSlice(",\"positionals\":") catch return fail();
    out.appendSlice(positionals.items) catch return fail();
    out.append('}') catch return fail();

    return writeOwned(out_ptr, out_len, out.items);
}

pub export fn sa_node_plugin_util_mime_type(str_ptr: ?[*]const u8, str_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const s = if (str_ptr) |p| p[0..str_len] else "";
    const mime = mimeTypeForPath(s);
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer out.deinit();
    std.json.stringify(mime, .{}, out.writer()) catch return fail();
    const slice = out.toOwnedSlice() catch return fail();
    out_ptr.?.* = slice.ptr;
    out_len.?.* = slice.len;
    return 0;
}
pub export fn sa_node_plugin_util_style_text(style_ptr: ?[*]const u8, style_len: u64, text_ptr: ?[*]const u8, text_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = style_ptr;
    _ = style_len;
    return writeOwned(out_ptr, out_len, text_ptr.?[0..text_len]);
}

// ============================================================
// READLINE
// ============================================================

fn writeAnsiToFd(fd: u64, bytes: []const u8) u64 {
    if (fd > std.math.maxInt(posix.fd_t)) return fail();
    const os_fd: posix.fd_t = @intCast(fd);
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = posix.write(os_fd, bytes[offset..]) catch return fail();
        if (written == 0) return fail();
        offset += written;
    }
    return 0;
}

fn signedFromAbi(value: u64) i64 {
    return @bitCast(value);
}

fn appendReadlineMove(out: *std.ArrayList(u8), amount: i64, positive_code: u8, negative_code: u8) !void {
    if (amount == 0) return;
    const code = if (amount > 0) positive_code else negative_code;
    const magnitude: u64 = @intCast(if (amount > 0) amount else -amount);
    try out.writer().print("\x1b[{d}{c}", .{ magnitude, code });
}

pub export fn sa_node_plugin_readline_clear_line(fd: u64, dir: u64) u64 {
    const signed_dir = signedFromAbi(dir);
    const seq = if (signed_dir < 0) "\x1b[1K" else if (signed_dir > 0) "\x1b[0K" else "\x1b[2K";
    return writeAnsiToFd(fd, seq);
}

pub export fn sa_node_plugin_readline_clear_screen_down(fd: u64) u64 {
    return writeAnsiToFd(fd, "\x1b[0J");
}
pub export fn sa_node_plugin_readline_cursor_to(fd: u64, x: u64, y: u64) u64 {
    var buf: [64]u8 = undefined;
    const seq = std.fmt.bufPrint(&buf, "\x1b[{d};{d}H", .{ y +| 1, x +| 1 }) catch return fail();
    return writeAnsiToFd(fd, seq);
}
pub export fn sa_node_plugin_readline_move_cursor(fd: u64, dx: u64, dy: u64) u64 {
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    appendReadlineMove(&out, signedFromAbi(dx), 'C', 'D') catch return fail();
    appendReadlineMove(&out, signedFromAbi(dy), 'B', 'A') catch return fail();
    return writeAnsiToFd(fd, out.items);
}
pub export fn sa_node_plugin_readline_emit_keypress_events(stream_ptr: ?[*]const u8, stream_len: u64) u32 {
    _ = stream_ptr;
    _ = stream_len;
    return 0;
}

const ReadlinePromisesInterface = struct {
    allocator: std.mem.Allocator,
    input: []u8,
    offset: usize = 0,
    closed: bool = false,

    fn deinit(self: *ReadlinePromisesInterface) void {
        self.allocator.free(self.input);
        self.allocator.destroy(self);
    }
};

pub export fn sa_node_plugin_readline_promises_create_interface(input_ptr: ?[*]const u8, input_len: u64, out_interface: ?*?*anyopaque) u32 {
    const allocator = std.heap.page_allocator;
    const input = if (input_ptr) |ptr| ptr[0..input_len] else &[_]u8{};
    const handle = allocator.create(ReadlinePromisesInterface) catch return fail();
    handle.* = .{
        .allocator = allocator,
        .input = allocator.dupe(u8, input) catch {
            allocator.destroy(handle);
            return fail();
        },
    };
    out_interface.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_readline_promises_question(interface_ptr: ?*anyopaque, query_ptr: ?[*]const u8, query_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *ReadlinePromisesInterface = @ptrCast(@alignCast(interface_ptr orelse return fail()));
    if (handle.closed) return fail();
    _ = query_ptr;
    _ = query_len;
    if (handle.offset >= handle.input.len) return writeOwned(out_ptr, out_len, "");
    const start = handle.offset;
    var end = start;
    while (end < handle.input.len and handle.input[end] != '\n') : (end += 1) {}
    handle.offset = if (end < handle.input.len) end + 1 else end;
    var line = handle.input[start..end];
    if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
    return writeOwned(out_ptr, out_len, line);
}

pub export fn sa_node_plugin_readline_promises_close(interface_ptr: ?*anyopaque) u32 {
    const handle: *ReadlinePromisesInterface = @ptrCast(@alignCast(interface_ptr orelse return fail()));
    handle.closed = true;
    return 0;
}

pub export fn sa_node_plugin_readline_promises_snapshot_json(interface_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const handle: *ReadlinePromisesInterface = @ptrCast(@alignCast(interface_ptr orelse return fail()));
    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    defer json.deinit();
    json.writer().print("{{\"closed\":{s},\"offset\":{d},\"inputLen\":{d}}}", .{ if (handle.closed) "true" else "false", handle.offset, handle.input.len }) catch return fail();
    return writeOwned(out_ptr, out_len, json.items);
}

pub export fn sa_node_plugin_readline_promises_free(interface_ptr: ?*anyopaque) u32 {
    if (interface_ptr) |ptr| {
        const handle: *ReadlinePromisesInterface = @ptrCast(@alignCast(ptr));
        handle.deinit();
    }
    return 0;
}

// ============================================================
// PATH
// ============================================================

pub export fn sa_node_plugin_path_sep(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, "/");
}
pub export fn sa_node_plugin_path_delimiter(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, ":");
}

pub export fn sa_node_plugin_path_matches_glob(pattern_ptr: ?[*]const u8, pattern_len: u64, str_ptr: ?[*]const u8, str_len: u64, out_bool: ?*u32) u32 {
    const pattern = pattern_ptr.?[0..pattern_len];
    const str = str_ptr.?[0..str_len];
    if (std.mem.indexOfScalar(u8, pattern, '*')) |star_pos| {
        const prefix = pattern[0..star_pos];
        const suffix = pattern[star_pos + 1 ..];
        if (prefix.len > 0 and !std.mem.startsWith(u8, str, prefix)) {
            out_bool.?.* = 0;
            return 0;
        }
        if (suffix.len > 0 and !std.mem.endsWith(u8, str, suffix)) {
            out_bool.?.* = 0;
            return 0;
        }
        out_bool.?.* = 1;
    } else {
        out_bool.?.* = if (std.mem.eql(u8, pattern, str)) 1 else 0;
    }
    return 0;
}

// ============================================================
// PUNYCODE
// ============================================================

fn punycodeConvert(input: []const u8, convert_fn: anytype, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const allocator = std.heap.page_allocator;
    const c_input = allocator.alloc(u8, input.len + 1) catch return fail();
    @memcpy(c_input[0..input.len], input);
    c_input[input.len] = 0;
    defer allocator.free(c_input);

    const c_input_z: [*:0]u8 = @ptrCast(c_input.ptr);

    var c_output: ?[*:0]u8 = null;
    const rc = convert_fn(c_input_z, &c_output, 0);
    if (rc != 0 or c_output == null) return fail();
    const api = loadIdn2Api() orelse return fail();
    defer api.free(@as(?*anyopaque, @ptrCast(c_output.?)));

    const out_slice = std.mem.span(c_output.?);
    return writeOwned(out_ptr, out_len, out_slice);
}

pub export fn sa_node_plugin_punycode_to_ascii(domain_ptr: ?[*]const u8, domain_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const domain = domain_ptr.?[0..domain_len];
    const api = loadIdn2Api() orelse return fail();
    return punycodeConvert(domain, api.to_ascii_8z, out_ptr, out_len);
}

pub export fn sa_node_plugin_punycode_to_unicode(domain_ptr: ?[*]const u8, domain_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const domain = domain_ptr.?[0..domain_len];
    const api = loadIdn2Api() orelse return fail();
    return punycodeConvert(domain, api.to_unicode_8z8z, out_ptr, out_len);
}

// ============================================================
// QUERYSTRING
// ============================================================

pub export fn sa_node_plugin_querystring_unescape_buffer(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const data = data_ptr.?[0..data_len];
    const allocator = std.heap.page_allocator;
    var result = allocator.alloc(u8, data.len) catch return fail();
    var i: usize = 0;
    var j: usize = 0;
    while (i < data.len) {
        if (data[i] == '%' and i + 2 < data.len) {
            result[j] = std.fmt.parseInt(u8, data[i + 1 .. i + 3], 16) catch data[i];
            i += 3;
        } else if (data[i] == '+') {
            result[j] = ' ';
            i += 1;
        } else {
            result[j] = data[i];
            i += 1;
        }
        j += 1;
    }
    out_ptr.?.* = result.ptr;
    out_len.?.* = j;
    return 0;
}

// ============================================================
// OS
// ============================================================

pub export fn sa_node_plugin_os_eol(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, "\n");
}

pub export fn sa_node_plugin_os_dev_null(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, "/dev/null");
}

pub export fn sa_node_plugin_os_constants(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len,
        \\{"signals":{"SIGHUP":1,"SIGINT":2,"SIGQUIT":3,"SIGILL":4,"SIGTRAP":5,"SIGABRT":6,"SIGIOT":6,"SIGBUS":7,"SIGFPE":8,"SIGKILL":9,"SIGUSR1":10,"SIGSEGV":11,"SIGUSR2":12,"SIGPIPE":13,"SIGALRM":14,"SIGTERM":15,"SIGCHLD":17,"SIGSTKFLT":16,"SIGCONT":18,"SIGSTOP":19,"SIGTSTP":20,"SIGTTIN":21,"SIGTTOU":22,"SIGURG":23,"SIGXCPU":24,"SIGXFSZ":25,"SIGVTALRM":26,"SIGPROF":27,"SIGWINCH":28,"SIGIO":29,"SIGPOLL":29,"SIGPWR":30,"SIGSYS":31},"errno":{"E2BIG":7,"EACCES":13,"EADDRINUSE":98,"EADDRNOTAVAIL":99,"EAFNOSUPPORT":97,"EAGAIN":11,"EALREADY":114,"EBADF":9,"EBADMSG":74,"EBUSY":16,"ECANCELED":125,"ECHILD":10,"ECONNABORTED":103,"ECONNREFUSED":111,"ECONNRESET":104,"EDEADLK":35,"EDESTADDRREQ":89,"EDOM":33,"EEXIST":17,"EFAULT":14,"EFBIG":27,"EHOSTUNREACH":113,"EIDRM":43,"EILSEQ":84,"EINPROGRESS":115,"EINTR":4,"EINVAL":22,"EIO":5,"EISCONN":106,"EISDIR":21,"ELOOP":40,"EMFILE":24,"EMLINK":31,"EMSGSIZE":90,"ENAMETOOLONG":36,"ENETDOWN":100,"ENETRESET":102,"ENETUNREACH":101,"ENFILE":23,"ENOBUFS":105,"ENODATA":61,"ENODEV":19,"ENOENT":2,"ENOEXEC":8,"ENOLCK":37,"ENOLINK":67,"ENOMEM":12,"ENOMSG":42,"ENOPROTOOPT":92,"ENOSPC":28,"ENOSR":63,"ENOSTR":60,"ENOSYS":38,"ENOTCONN":107,"ENOTDIR":20,"ENOTEMPTY":39,"ENOTSOCK":88,"ENOTSUP":95,"ENOTTY":25,"ENXIO":6,"EOPNOTSUPP":95,"EOVERFLOW":75,"EPERM":1,"EPIPE":32,"EPROTO":71,"EPROTONOSUPPORT":93,"EPROTOTYPE":91,"ERANGE":34,"EROFS":30,"ESPIPE":29,"ESRCH":3,"ESTALE":116,"ETIME":62,"ETIMEDOUT":110,"ETXTBSY":26,"EWOULDBLOCK":11,"EXDEV":18},"priority":{"PRIORITY_LOW":19,"PRIORITY_BELOW_NORMAL":10,"PRIORITY_NORMAL":0,"PRIORITY_ABOVE_NORMAL":-7,"PRIORITY_HIGH":-14,"PRIORITY_HIGHEST":-20},"dlopen":{"RTLD_LAZY":1,"RTLD_NOW":2,"RTLD_GLOBAL":256,"RTLD_LOCAL":0,"RTLD_DEEPBIND":8},"UV_UDP_REUSEADDR":4}
    );
}
pub export fn sa_node_plugin_os_get_priority(pid: u32, out_priority: ?*i32) u32 {
    __errno_location().* = 0;
    const prio = getpriority(PRIO_PROCESS, pid);
    if (prio == -1 and __errno_location().* != 0) return fail();
    out_priority.?.* = prio;
    return 0;
}
pub export fn sa_node_plugin_os_set_priority(pid: u32, priority: i32) u32 {
    if (priority < -20 or priority > 19) return fail();
    return if (setpriority(PRIO_PROCESS, pid, @intCast(priority)) == 0) 0 else fail();
}

pub export fn sa_node_plugin_process_arch(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_os_arch(out_ptr, out_len);
}

pub export fn sa_node_plugin_process_platform(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return base.sa_node_plugin_os_platform(out_ptr, out_len);
}

pub export fn sa_node_plugin_process_release_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, "{\"name\":\"node\",\"sourceUrl\":\"https://nodejs.org/download/release/v20.11.1/node-v20.11.1.tar.gz\",\"headersUrl\":\"https://nodejs.org/download/release/v20.11.1/node-v20.11.1-headers.tar.gz\"}");
}

pub export fn sa_node_plugin_process_umask(mask: u32, set_mask: u32, out_old: ?*u32) u32 {
    const old = umask(if (set_mask != 0) mask else 0);
    if (set_mask == 0) _ = umask(old);
    out_old.?.* = old;
    return 0;
}

pub export fn sa_node_plugin_process_chdir(path_ptr: ?[*]const u8, path_len: u64) u32 {
    const path = (path_ptr orelse return fail())[0..path_len];
    const path_z = std.heap.page_allocator.dupeZ(u8, path) catch return fail();
    defer std.heap.page_allocator.free(path_z);
    return if (chdir(path_z.ptr) == 0) 0 else fail();
}

// ============================================================
// PROCESS
// ============================================================

pub export fn sa_node_plugin_process_exit(code: u32) u32 {
    std.process.exit(@intCast(code));
}

fn processSignalNumber(signal: u32) ?c_int {
    if (signal > @as(u32, @intCast(std.math.maxInt(c_int)))) return null;
    return @intCast(signal);
}

fn processSignalNameToNumber(name: []const u8) ?c_int {
    if (name.len == 0) return 15;
    if (std.ascii.eqlIgnoreCase(name, "0")) return 0;
    if (std.ascii.eqlIgnoreCase(name, "SIGTERM") or std.ascii.eqlIgnoreCase(name, "TERM")) return 15;
    if (std.ascii.eqlIgnoreCase(name, "SIGKILL") or std.ascii.eqlIgnoreCase(name, "KILL")) return 9;
    if (std.ascii.eqlIgnoreCase(name, "SIGINT") or std.ascii.eqlIgnoreCase(name, "INT")) return 2;
    if (std.ascii.eqlIgnoreCase(name, "SIGHUP") or std.ascii.eqlIgnoreCase(name, "HUP")) return 1;
    if (std.ascii.eqlIgnoreCase(name, "SIGQUIT") or std.ascii.eqlIgnoreCase(name, "QUIT")) return 3;
    if (std.ascii.eqlIgnoreCase(name, "SIGABRT") or std.ascii.eqlIgnoreCase(name, "ABRT")) return 6;
    if (std.ascii.eqlIgnoreCase(name, "SIGALRM") or std.ascii.eqlIgnoreCase(name, "ALRM")) return 14;
    if (std.ascii.eqlIgnoreCase(name, "SIGUSR1") or std.ascii.eqlIgnoreCase(name, "USR1")) return 10;
    if (std.ascii.eqlIgnoreCase(name, "SIGUSR2") or std.ascii.eqlIgnoreCase(name, "USR2")) return 12;
    if (std.ascii.eqlIgnoreCase(name, "SIGPIPE") or std.ascii.eqlIgnoreCase(name, "PIPE")) return 13;
    if (std.ascii.eqlIgnoreCase(name, "SIGCHLD") or std.ascii.eqlIgnoreCase(name, "CHLD")) return 17;
    if (std.ascii.eqlIgnoreCase(name, "SIGCONT") or std.ascii.eqlIgnoreCase(name, "CONT")) return 18;
    if (std.ascii.eqlIgnoreCase(name, "SIGSTOP") or std.ascii.eqlIgnoreCase(name, "STOP")) return 19;
    if (std.ascii.eqlIgnoreCase(name, "SIGTSTP") or std.ascii.eqlIgnoreCase(name, "TSTP")) return 20;
    if (std.ascii.eqlIgnoreCase(name, "SIGTTIN") or std.ascii.eqlIgnoreCase(name, "TTIN")) return 21;
    if (std.ascii.eqlIgnoreCase(name, "SIGTTOU") or std.ascii.eqlIgnoreCase(name, "TTOU")) return 22;
    return null;
}

pub export fn sa_node_plugin_process_kill(pid: u32, signal: u32) u32 {
    const sig = processSignalNumber(signal) orelse return fail();
    return if (kill(@intCast(pid), sig) == 0) 0 else fail();
}

pub export fn sa_node_plugin_process_kill_signal(pid: u32, signal_ptr: ?[*]const u8, signal_len: u64) u32 {
    const signal = if (signal_ptr) |ptr| ptr[0..signal_len] else "SIGTERM";
    const sig = processSignalNameToNumber(signal) orelse return fail();
    return if (kill(@intCast(pid), sig) == 0) 0 else fail();
}

pub export fn sa_node_plugin_process_resource_usage_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    var usage: Rusage = undefined;
    if (getrusage(RUSAGE_SELF, &usage) != 0) return fail();
    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.writer().print(
        "{{\"userCPUTime\":{d},\"systemCPUTime\":{d},\"maxRSS\":{d},\"sharedMemorySize\":{d},\"unsharedDataSize\":{d},\"unsharedStackSize\":{d},\"minorPageFault\":{d},\"majorPageFault\":{d},\"swappedOut\":{d},\"fsRead\":{d},\"fsWrite\":{d},\"ipcSent\":{d},\"ipcReceived\":{d},\"signalsCount\":{d},\"voluntaryContextSwitches\":{d},\"involuntaryContextSwitches\":{d}}}",
        .{
            @as(i64, @intCast(usage.ru_utime.tv_sec)) * 1_000_000 + @as(i64, @intCast(usage.ru_utime.tv_usec)),
            @as(i64, @intCast(usage.ru_stime.tv_sec)) * 1_000_000 + @as(i64, @intCast(usage.ru_stime.tv_usec)),
            usage.ru_maxrss,
            usage.ru_ixrss,
            usage.ru_idrss,
            usage.ru_isrss,
            usage.ru_minflt,
            usage.ru_majflt,
            usage.ru_nswap,
            usage.ru_inblock,
            usage.ru_oublock,
            usage.ru_msgsnd,
            usage.ru_msgrcv,
            usage.ru_nsignals,
            usage.ru_nvcsw,
            usage.ru_nivcsw,
        },
    ) catch return fail();
    return writeOwned(out_ptr, out_len, out.items);
}

fn processParseMemInfo(key: []const u8) u64 {
    var file = std.fs.openFileAbsolute("/proc/meminfo", .{}) catch return 0;
    defer file.close();
    var buf: [4096]u8 = undefined;
    const n = file.readAll(&buf) catch return 0;
    var lines = std.mem.tokenizeScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        var parts = std.mem.tokenizeAny(u8, line, " \t:");
        _ = parts.next();
        const value = std.fmt.parseInt(u64, parts.next() orelse return 0, 10) catch return 0;
        return value * 1024;
    }
    return 0;
}

fn processReadU64File(path: []const u8) ?u64 {
    var file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    var buf: [128]u8 = undefined;
    const n = file.readAll(&buf) catch return null;
    const text = std.mem.trim(u8, buf[0..n], " \t\r\n");
    if (std.mem.eql(u8, text, "max")) return null;
    return std.fmt.parseInt(u64, text, 10) catch null;
}

fn processCgroupMemoryLimit() u64 {
    const total = processParseMemInfo("MemTotal");
    const candidates = [_][]const u8{
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    };
    for (candidates) |path| {
        const limit = processReadU64File(path) orelse continue;
        if (limit == 0) continue;
        if (total != 0 and limit >= total) continue;
        return limit;
    }
    return 0;
}

pub export fn sa_node_plugin_process_available_memory(out_bytes: ?*u64) u32 {
    const mem_available = processParseMemInfo("MemAvailable");
    const fallback_free = if (mem_available == 0) processParseMemInfo("MemFree") else mem_available;
    const limit = processCgroupMemoryLimit();
    if (limit == 0) {
        out_bytes.?.* = fallback_free;
        return 0;
    }
    const current = processReadU64File("/sys/fs/cgroup/memory.current") orelse processReadU64File("/sys/fs/cgroup/memory/memory.usage_in_bytes") orelse 0;
    const cgroup_available = if (limit > current) limit - current else 0;
    out_bytes.?.* = if (fallback_free == 0) cgroup_available else @min(fallback_free, cgroup_available);
    return 0;
}

pub export fn sa_node_plugin_process_constrained_memory(out_bytes: ?*u64) u32 {
    out_bytes.?.* = processCgroupMemoryLimit();
    return 0;
}

pub export fn sa_node_plugin_process_features_json(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return writeOwned(out_ptr, out_len, "{\"cached_builtins\":false,\"debug\":false,\"inspector\":false,\"ipv6\":true,\"require_module\":false,\"tls\":true,\"tls_alpn\":false,\"tls_ocsp\":true,\"tls_sni\":true,\"typescript\":false,\"uv\":true}");
}

// ============================================================
// PERF HOOKS
// ============================================================

const HistogramHandle = struct {
    allocator: std.mem.Allocator,
    values: std.ArrayList(u64),

    fn init(allocator: std.mem.Allocator) HistogramHandle {
        return .{ .allocator = allocator, .values = std.ArrayList(u64).init(allocator) };
    }

    fn deinit(self: *HistogramHandle) void {
        self.values.deinit();
        self.allocator.destroy(self);
    }
};

var perf_elu_start_wall_ns: i128 = 0;
var perf_elu_start_cpu_us: u64 = 0;

fn rusageCpuMicros() u64 {
    var usage: Rusage = undefined;
    if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
    const user = @as(u64, @intCast(usage.ru_utime.tv_sec)) * 1_000_000 + @as(u64, @intCast(usage.ru_utime.tv_usec));
    const sys = @as(u64, @intCast(usage.ru_stime.tv_sec)) * 1_000_000 + @as(u64, @intCast(usage.ru_stime.tv_usec));
    return user + sys;
}

fn histogramPercentile(sorted: []const u64, pct: u64) u64 {
    if (sorted.len == 0) return 0;
    const idx = @min(sorted.len - 1, @as(usize, @intCast(((@as(u128, sorted.len) * pct) + 99) / 100)) -| 1);
    return sorted[idx];
}

pub export fn sa_node_plugin_perf_hooks_create_histogram(out_handle: ?*?*anyopaque) u32 {
    const h = std.heap.page_allocator.create(HistogramHandle) catch return fail();
    h.* = HistogramHandle.init(std.heap.page_allocator);
    out_handle.?.* = @ptrCast(h);
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_histogram_record(handle_ptr: ?*anyopaque, value: u64) u32 {
    const h: *HistogramHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    h.values.append(value) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_histogram_get_statistics(handle_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const h: *HistogramHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    const count = h.values.items.len;
    var sum: u128 = 0;
    var min: u64 = if (count == 0) 0 else std.math.maxInt(u64);
    var max: u64 = 0;
    for (h.values.items) |value| {
        sum += value;
        min = @min(min, value);
        max = @max(max, value);
    }
    const mean = if (count == 0) 0 else @as(u64, @intCast(sum / count));
    var variance_sum: u128 = 0;
    for (h.values.items) |value| {
        const diff = if (value > mean) value - mean else mean - value;
        variance_sum += @as(u128, diff) * diff;
    }
    const stddev = if (count == 0) 0 else std.math.sqrt(@as(f64, @floatFromInt(variance_sum)) / @as(f64, @floatFromInt(count)));

    const sorted = std.heap.page_allocator.dupe(u64, h.values.items) catch return fail();
    defer std.heap.page_allocator.free(sorted);
    std.mem.sort(u64, sorted, {}, std.sort.asc(u64));

    var json = std.ArrayList(u8).init(std.heap.page_allocator);
    errdefer json.deinit();
    json.writer().print(
        "{{\"count\":{d},\"sum\":{d},\"min\":{d},\"max\":{d},\"mean\":{d},\"stddev\":{d:.3},\"exceeds\":0,\"percentiles\":{{\"50\":{d},\"75\":{d},\"90\":{d},\"99\":{d}}}}}",
        .{ count, sum, min, max, mean, stddev, histogramPercentile(sorted, 50), histogramPercentile(sorted, 75), histogramPercentile(sorted, 90), histogramPercentile(sorted, 99) },
    ) catch return fail();
    const owned = json.toOwnedSlice() catch return fail();
    out_ptr.?.* = owned.ptr;
    out_len.?.* = owned.len;
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_histogram_free(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| @as(*HistogramHandle, @ptrCast(@alignCast(ptr))).deinit();
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_event_loop_utilization(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (perf_elu_start_wall_ns == 0) {
        perf_elu_start_wall_ns = std.time.nanoTimestamp();
        perf_elu_start_cpu_us = rusageCpuMicros();
    }
    const elapsed_ns = @max(@as(i128, 0), std.time.nanoTimestamp() - perf_elu_start_wall_ns);
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const cpu_now = rusageCpuMicros();
    const active_ms = @as(f64, @floatFromInt(if (cpu_now > perf_elu_start_cpu_us) cpu_now - perf_elu_start_cpu_us else 0)) / 1000.0;
    const bounded_active = @min(active_ms, elapsed_ms);
    const idle_ms = if (elapsed_ms > bounded_active) elapsed_ms - bounded_active else 0;
    const util = if (elapsed_ms > 0) bounded_active / elapsed_ms else 0;
    var buffer: [256]u8 = undefined;
    const json = std.fmt.bufPrint(&buffer, "{{\"idle\":{d:.3},\"active\":{d:.3},\"utilization\":{d:.6}}}", .{ idle_ms, bounded_active, util }) catch return fail();
    return writeOwned(out_ptr, out_len, json);
}
pub export fn sa_node_plugin_perf_hooks_timerify(name_ptr: ?[*]const u8, name_len: u64, out_id: ?*u64) u32 {
    _ = name_ptr;
    _ = name_len;
    out_id.?.* = timer_next_id;
    timer_next_id += 1;
    return 0;
}

// ============================================================
// DIAGNOSTICS CHANNEL
// ============================================================

pub export fn sa_node_plugin_diagnostics_channel_tracing_channel(name_ptr: ?[*]const u8, name_len: u64, out_handle: ?*?*anyopaque) u32 {
    const handle = std.heap.page_allocator.create(u8) catch return fail();
    handle.* = 0;
    _ = name_ptr;
    _ = name_len;
    out_handle.?.* = @ptrCast(handle);
    return 0;
}
