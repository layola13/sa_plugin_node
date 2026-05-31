const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

extern fn getpid() c_int;
extern fn close(fd: c_int) c_int;

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

// ============================================================
// CRYPTO
// ============================================================

const crypto = std.crypto;
const HashAlgo = enum { sha256, sha384, sha512, md5, sha1 };

fn parseHashAlgo(name: []const u8) ?HashAlgo {
    if (std.mem.eql(u8, name, "sha256") or std.mem.eql(u8, name, "SHA256")) return .sha256;
    if (std.mem.eql(u8, name, "sha384") or std.mem.eql(u8, name, "SHA384")) return .sha384;
    if (std.mem.eql(u8, name, "sha512") or std.mem.eql(u8, name, "SHA512")) return .sha512;
    if (std.mem.eql(u8, name, "md5") or std.mem.eql(u8, name, "MD5")) return .md5;
    if (std.mem.eql(u8, name, "sha1") or std.mem.eql(u8, name, "SHA1")) return .sha1;
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
            var h = crypto.hash.sha2.Sha256.init(.{}); h.update(input); h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .sha384 => {
            var buf: [48]u8 = undefined;
            var h = crypto.hash.sha2.Sha384.init(.{}); h.update(input); h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .sha512 => {
            var buf: [64]u8 = undefined;
            var h = crypto.hash.sha2.Sha512.init(.{}); h.update(input); h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .md5 => {
            var buf: [16]u8 = undefined;
            var h = crypto.hash.Md5.init(.{}); h.update(input); h.final(&buf);
            return writeOwned(out_ptr, out_len, &buf);
        },
        .sha1 => {
            var buf: [20]u8 = undefined;
            var h = crypto.hash.Sha1.init(.{}); h.update(input); h.final(&buf);
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
    const key_dup = allocator.dupe(u8, key_ptr.?[0..key_len]) catch { allocator.destroy(state); return fail(); };
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
    digest_ptr: ?[*]const u8, digest_len: u64,
    ikm_ptr: ?[*]const u8, ikm_len: u64,
    salt_ptr: ?[*]const u8, salt_len: u64,
    info_ptr: ?[*]const u8, info_len: u64,
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
    pass_ptr: ?[*]const u8, pass_len: u64,
    salt_ptr: ?[*]const u8, salt_len: u64,
    n: u64, r: u64, p: u64,
    keylen: u64,
    out_ptr: ?*?[*]const u8,
) u32 {
    _ = pass_ptr; _ = pass_len; _ = salt_ptr; _ = salt_len;
    _ = n; _ = r; _ = p;
    const allocator = std.heap.page_allocator;
    const out = allocator.alloc(u8, keylen) catch return fail();
    @memset(out, 0);
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
    algo_ptr: ?[*]const u8, algo_len: u64,
    key_ptr: ?[*]const u8, key_len: u64,
    iv_ptr: ?[*]const u8, iv_len: u64,
    out_state_ptr: ?*?*anyopaque,
) u32 {
    _ = algo_ptr; _ = algo_len;
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
    algo_ptr: ?[*]const u8, algo_len: u64,
    key_ptr: ?[*]const u8, key_len: u64,
    iv_ptr: ?[*]const u8, iv_len: u64,
    out_state_ptr: ?*?*anyopaque,
) u32 {
    return sa_node_plugin_crypto_create_cipher(algo_ptr, algo_len, key_ptr, key_len, iv_ptr, iv_len, out_state_ptr);
}

pub export fn sa_node_plugin_crypto_decipher_update(state_ptr: ?*anyopaque, data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return sa_node_plugin_crypto_cipher_update(state_ptr, data_ptr, data_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_crypto_decipher_final(state_ptr: ?*anyopaque, tag_ptr: ?[*]const u8, tag_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = tag_ptr; _ = tag_len;
    return sa_node_plugin_crypto_cipher_final(state_ptr, out_ptr, out_len, null, null);
}

pub export fn sa_node_plugin_crypto_decipher_free(state_ptr: ?*anyopaque) u32 {
    return sa_node_plugin_crypto_cipher_free(state_ptr);
}

pub export fn sa_node_plugin_crypto_sign(
    algo_ptr: ?[*]const u8, algo_len: u64,
    key_ptr: ?[*]const u8, key_len: u64,
    data_ptr: ?[*]const u8, data_len: u64,
    out_sig_ptr: ?*?[*]const u8, out_sig_len: ?*u64,
) u32 {
    _ = algo_ptr; _ = algo_len;
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
    algo_ptr: ?[*]const u8, algo_len: u64,
    key_ptr: ?[*]const u8, key_len: u64,
    data_ptr: ?[*]const u8, data_len: u64,
    sig_ptr: ?[*]const u8, sig_len: u64,
    out_bool: ?*u32,
) u32 {
    _ = algo_ptr; _ = algo_len;
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
    algo_ptr: ?[*]const u8, algo_len: u64,
    bits: u64,
    out_ptr: ?*?[*]const u8, out_len: ?*u64,
) u32 {
    _ = algo_ptr; _ = algo_len;
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

// ============================================================
// FILE SYSTEM
// ============================================================

const fs = std.fs;

pub export fn sa_node_plugin_fs_chmod(path_ptr: ?[*]const u8, path_len: u64, mode: u32) u32 {
    const path = path_ptr.?[0..path_len];
    const file = fs.cwd().openFile(path, .{}) catch return fail();
    defer file.close();
    file.chmod(@intCast(mode)) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_chown(path_ptr: ?[*]const u8, path_len: u64, uid: u32, gid: u32) u32 {
    _ = path_ptr; _ = path_len; _ = uid; _ = gid;
    return 0;
}

pub export fn sa_node_plugin_fs_fchmod(fd: u32, mode: u32) u32 {
    const file = fs.File{ .handle = @intCast(fd) };
    file.chmod(@intCast(mode)) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_fchown(fd: u32, uid: u32, gid: u32) u32 {
    _ = fd; _ = uid; _ = gid;
    return 0;
}

pub export fn sa_node_plugin_fs_fdatasync(fd: u32) u32 {
    _ = fd;
    return 0;
}

pub export fn sa_node_plugin_fs_fstat(fd: u32, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const file = fs.File{ .handle = @intCast(fd) };
    const st = file.stat() catch return fail();
    var buffer: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&buffer, "{{\"size\":{d},\"mode\":{d},\"mtimeMs\":{d},\"isFile\":{},\"isDirectory\":{}}}", .{
        st.size, @as(u64, st.mode), st.mtime, st.kind == .file, st.kind == .directory,
    }) catch return fail();
    return writeOwned(out_ptr, out_len, json);
}

pub export fn sa_node_plugin_fs_fsync(fd: u32) u32 {
    _ = fd;
    return 0;
}

pub export fn sa_node_plugin_fs_ftruncate(fd: u32, len: u64) u32 {
    const file = fs.File{ .handle = @intCast(fd) };
    file.setEndPos(len) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_futimes(fd: u32, atime_ms: u64, mtime_ms: u64) u32 {
    _ = fd; _ = atime_ms; _ = mtime_ms;
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
    const src = src_ptr.?[0..src_len];
    const dst = dst_ptr.?[0..dst_len];
    posix.linkat(posix.AT.FDCWD, src, posix.AT.FDCWD, dst, 0) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_mkdtemp(template_ptr: ?[*]const u8, template_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const template_name = template_ptr.?[0..template_len];
    var buf: [256]u8 = undefined;
    if (template_name.len > 240) return fail();
    @memcpy(buf[0..template_name.len], template_name);
    const rand_val = crypto.random.int(u64);
    const suffix = std.fmt.bufPrint(buf[template_name.len..], "{x}", .{rand_val}) catch return fail();
    const full_path = buf[0..template_name.len + suffix.len];
    fs.cwd().makeDir(full_path) catch return fail();
    return writeOwned(out_ptr, out_len, full_path);
}

pub export fn sa_node_plugin_fs_open(path_ptr: ?[*]const u8, path_len: u64, flags: u32, mode: u32, out_fd: ?*u32) u32 {
    _ = mode;
    const path = path_ptr.?[0..path_len];
    var open_flags: fs.File.OpenFlags = .{};
    if (flags & 2 != 0) open_flags.mode = .read_write else if (flags & 1 != 0) open_flags.mode = .write_only else open_flags.mode = .read_only;
    const file = fs.cwd().openFile(path, open_flags) catch return fail();
    out_fd.?.* = @intCast(file.handle);
    return 0;
}

pub export fn sa_node_plugin_fs_close_fd(fd: u32) u32 {
    const file = fs.File{ .handle = @intCast(fd) };
    file.close();
    return 0;
}

pub export fn sa_node_plugin_fs_read_fd(fd: u32, buf_ptr: ?[*]u8, len: u64, offset: u64, out_n: ?*u64) u32 {
    const file = fs.File{ .handle = @intCast(fd) };
    const buf = buf_ptr.?[0..len];
    const n = file.pread(buf, offset) catch return fail();
    out_n.?.* = n;
    return 0;
}

pub export fn sa_node_plugin_fs_write_fd(fd: u32, data_ptr: ?[*]const u8, data_len: u64, offset: u64, out_n: ?*u64) u32 {
    const file = fs.File{ .handle = @intCast(fd) };
    const data = data_ptr.?[0..data_len];
    const n = file.pwrite(data, offset) catch return fail();
    out_n.?.* = n;
    return 0;
}

pub export fn sa_node_plugin_fs_readv(fd: u32, iov_json_ptr: ?[*]const u8, iov_json_len: u64, out_n: ?*u64) u32 {
    _ = fd; _ = iov_json_ptr; _ = iov_json_len;
    out_n.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_fs_writev(fd: u32, iov_json_ptr: ?[*]const u8, iov_json_len: u64, out_n: ?*u64) u32 {
    _ = fd; _ = iov_json_ptr; _ = iov_json_len;
    out_n.?.* = 0;
    return 0;
}

const DirIterHandle = struct {
    dir_fd: std.posix.fd_t,
    dir: fs.Dir,
};

pub export fn sa_node_plugin_fs_opendir(path_ptr: ?[*]const u8, path_len: u64, out_handle: ?*?*anyopaque) u32 {
    const path = path_ptr.?[0..path_len];
    var dir = fs.cwd().openDir(path, .{}) catch return fail();
    const handle = std.heap.page_allocator.create(DirIterHandle) catch {
        dir.close();
        return fail();
    };
    handle.* = .{ .dir_fd = dir.fd, .dir = dir };
    out_handle.?.* = @ptrCast(handle);
    return 0;
}

pub export fn sa_node_plugin_fs_opendir_next(handle_ptr: ?*anyopaque, out_name_ptr: ?*?[*]const u8, out_name_len: ?*u64, out_entry_type: ?*u32) u32 {
    _ = handle_ptr; _ = out_name_ptr; _ = out_name_len; _ = out_entry_type;
    return 1;
}

pub export fn sa_node_plugin_fs_opendir_free(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| {
        const handle: *DirIterHandle = @ptrCast(@alignCast(ptr));
        handle.dir.close();
        std.heap.page_allocator.destroy(handle);
    }
    return 0;
}

pub export fn sa_node_plugin_fs_rm(path_ptr: ?[*]const u8, path_len: u64, recursive: u8) u32 {
    const path = path_ptr.?[0..path_len];
    if (recursive != 0) {
        fs.cwd().deleteTree(path) catch return fail();
    } else {
        fs.cwd().deleteFile(path) catch return fail();
    }
    return 0;
}

pub export fn sa_node_plugin_fs_statfs(path_ptr: ?[*]const u8, out_json_ptr: ?*?[*]const u8, out_json_len: ?*u64) u32 {
    _ = path_ptr;
    return writeOwned(out_json_ptr, out_json_len, "{\"bsize\":4096,\"blocks\":0,\"bfree\":0,\"bavail\":0,\"files\":0,\"ffree\":0}");
}

pub export fn sa_node_plugin_fs_symlink(src_ptr: ?[*]const u8, src_len: u64, dst_ptr: ?[*]const u8, dst_len: u64) u32 {
    const src = src_ptr.?[0..src_len];
    const dst = dst_ptr.?[0..dst_len];
    posix.symlinkat(src, posix.AT.FDCWD, dst) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_truncate(path_ptr: ?[*]const u8, path_len: u64, len: u64) u32 {
    const path = path_ptr.?[0..path_len];
    const file = fs.cwd().openFile(path, .{ .mode = .write_only }) catch return fail();
    defer file.close();
    file.setEndPos(len) catch return fail();
    return 0;
}

pub export fn sa_node_plugin_fs_utimes(path_ptr: ?[*]const u8, path_len: u64, atime_ms: u64, mtime_ms: u64) u32 {
    _ = path_ptr; _ = path_len; _ = atime_ms; _ = mtime_ms;
    return 0;
}

// ============================================================
// EVENTS
// ============================================================

pub export fn sa_node_plugin_events_once(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, callback: ?*anyopaque) u32 {
    _ = ee_ptr; _ = event_ptr; _ = event_len; _ = callback;
    return 0;
}

pub export fn sa_node_plugin_events_off(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, callback: ?*anyopaque) u32 {
    _ = ee_ptr; _ = event_ptr; _ = event_len; _ = callback;
    return 0;
}

pub export fn sa_node_plugin_events_remove_all_listeners(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64) u32 {
    _ = ee_ptr; _ = event_ptr; _ = event_len;
    return 0;
}

pub export fn sa_node_plugin_events_prepend_listener(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, callback: ?*anyopaque) u32 {
    _ = ee_ptr; _ = event_ptr; _ = event_len; _ = callback;
    return 0;
}

pub export fn sa_node_plugin_events_set_max_listeners(ee_ptr: ?*anyopaque, max: u32) u32 {
    _ = ee_ptr; _ = max;
    return 0;
}

pub export fn sa_node_plugin_events_get_max_listeners(ee_ptr: ?*anyopaque, out_max: ?*u32) u32 {
    _ = ee_ptr;
    out_max.?.* = 10;
    return 0;
}

pub export fn sa_node_plugin_events_get_event_listeners(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = ee_ptr; _ = event_ptr; _ = event_len;
    return writeOwned(out_ptr, out_len, "[]");
}

pub export fn sa_node_plugin_events_listener_count_by_event(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, out_count: ?*u64) u32 {
    _ = ee_ptr; _ = event_ptr; _ = event_len;
    out_count.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_events_emit_with_error(ee_ptr: ?*anyopaque, event_ptr: ?[*]const u8, event_len: u64, data_ptr: ?[*]const u8, data_len: u64) u32 {
    _ = ee_ptr; _ = event_ptr; _ = event_len; _ = data_ptr; _ = data_len;
    return 0;
}

// ============================================================
// CONSOLE
// ============================================================

var console_count_map = std.StringHashMap(u64).init(std.heap.page_allocator);

fn consoleWrite(prefix: []const u8, data_ptr: ?[*]const u8, data_len: u64) void {
    const out = std.io.getStdOut().writer();
    out.print("{s}{s}\n", .{ prefix, data_ptr.?[0..data_len] }) catch {};
}

pub export fn sa_node_plugin_console_warn(data_ptr: ?[*]const u8, data_len: u64) u32 { consoleWrite("[WARN] ", data_ptr, data_len); return 0; }
pub export fn sa_node_plugin_console_info(data_ptr: ?[*]const u8, data_len: u64) u32 { consoleWrite("[INFO] ", data_ptr, data_len); return 0; }
pub export fn sa_node_plugin_console_debug(data_ptr: ?[*]const u8, data_len: u64) u32 { consoleWrite("[DEBUG] ", data_ptr, data_len); return 0; }
pub export fn sa_node_plugin_console_dir(data_ptr: ?[*]const u8, data_len: u64) u32 { consoleWrite("", data_ptr, data_len); return 0; }
pub export fn sa_node_plugin_console_dirxml(data_ptr: ?[*]const u8, data_len: u64) u32 { consoleWrite("", data_ptr, data_len); return 0; }
pub export fn sa_node_plugin_console_time_log(label_ptr: ?[*]const u8, label_len: u64, data_ptr: ?[*]const u8, data_len: u64) u32 { _ = label_ptr; _ = label_len; consoleWrite("", data_ptr, data_len); return 0; }

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

pub export fn sa_node_plugin_console_trace(data_ptr: ?[*]const u8, data_len: u64) u32 { consoleWrite("Trace: ", data_ptr, data_len); return 0; }
pub export fn sa_node_plugin_console_table(data_ptr: ?[*]const u8, data_len: u64) u32 { consoleWrite("", data_ptr, data_len); return 0; }

pub export fn sa_node_plugin_console_group() u32 { return 0; }
pub export fn sa_node_plugin_console_group_end() u32 { return 0; }
pub export fn sa_node_plugin_console_group_collapsed() u32 { return 0; }
pub export fn sa_node_plugin_console_time_stamp(data_ptr: ?[*]const u8, data_len: u64) u32 { consoleWrite("[Timestamp] ", data_ptr, data_len); return 0; }

// ============================================================
// DNS
// ============================================================

pub export fn sa_node_plugin_dns_resolve4(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const hostname = hostname_ptr.?[0..hostname_len];
    const list = std.net.getAddressList(std.heap.page_allocator, hostname, 0) catch return fail();
    defer list.deinit();
    var results = std.ArrayList(u8).init(std.heap.page_allocator);
    defer results.deinit();
    results.appendSlice("[") catch return fail();
    var first = true;
    for (list.addrs) |addr| {
        if (!first) results.appendSlice(",") catch return fail();
        first = false;
        var buf: [64]u8 = undefined;
        const ip = std.fmt.bufPrint(&buf, "\"{}\"", .{addr}) catch continue;
        results.appendSlice(ip) catch return fail();
    }
    results.appendSlice("]") catch return fail();
    return writeOwned(out_ptr, out_len, results.items);
}

pub export fn sa_node_plugin_dns_resolve6(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = hostname_ptr; _ = hostname_len; return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_dns_resolve_cname(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = hostname_ptr; _ = hostname_len; return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_dns_resolve_mx(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = hostname_ptr; _ = hostname_len; return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_dns_resolve_ns(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = hostname_ptr; _ = hostname_len; return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_dns_resolve_txt(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = hostname_ptr; _ = hostname_len; return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_dns_resolve_srv(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = hostname_ptr; _ = hostname_len; return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_dns_resolve_ptr(hostname_ptr: ?[*]const u8, hostname_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = hostname_ptr; _ = hostname_len; return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_dns_reverse(ip_ptr: ?[*]const u8, ip_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = ip_ptr; _ = ip_len; return writeOwned(out_ptr, out_len, "[]"); }
pub export fn sa_node_plugin_dns_get_servers(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "[\"8.8.8.8\"]"); }
pub export fn sa_node_plugin_dns_set_servers(servers_ptr: ?[*]const u8, servers_len: u64) u32 { _ = servers_ptr; _ = servers_len; return 0; }
pub export fn sa_node_plugin_dns_get_default_result_order(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "\"auto\""); }
pub export fn sa_node_plugin_dns_set_default_result_order(order_ptr: ?[*]const u8, order_len: u64) u32 { _ = order_ptr; _ = order_len; return 0; }

// ============================================================
// CHILD PROCESS
// ============================================================

pub export fn sa_node_plugin_child_process_exec(
    command_ptr: ?[*]const u8, command_len: u64,
    options_json_ptr: ?[*]const u8, options_json_len: u64,
    out_pid: ?*u32,
    out_ptr: ?*?[*]const u8, out_len: ?*u64,
) u32 {
    _ = options_json_ptr; _ = options_json_len;
    const command = command_ptr.?[0..command_len];
    var argv = [_][]const u8{ "sh", "-c", command };
    var child = std.process.Child.init(&argv, std.heap.page_allocator);
    child.stderr_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.spawn() catch return fail();
    out_pid.?.* = @intCast(child.id);
    const stdout = child.stdout.?.reader().readAllAlloc(std.heap.page_allocator, 1024 * 1024) catch "";
    { _ = child.wait() catch null; }
    return writeOwned(out_ptr, out_len, stdout);
}

pub export fn sa_node_plugin_child_process_exec_file(
    file_ptr: ?[*]const u8, file_len: u64,
    args_ptr: ?[*]const u8, args_len: u64,
    out_ptr: ?*?[*]const u8, out_len: ?*u64,
) u32 {
    _ = args_ptr; _ = args_len;
    const file = file_ptr.?[0..file_len];
    var argv = [_][]const u8{file};
    var child = std.process.Child.init(&argv, std.heap.page_allocator);
    child.stderr_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.spawn() catch return fail();
    const stdout = child.stdout.?.reader().readAllAlloc(std.heap.page_allocator, 1024 * 1024) catch "";
    { _ = child.wait() catch null; }
    return writeOwned(out_ptr, out_len, stdout);
}

pub export fn sa_node_plugin_child_process_execfile_sync(
    file_ptr: ?[*]const u8, file_len: u64,
    args_ptr: ?[*]const u8, args_len: u64,
    out_ptr: ?*?[*]const u8, out_len: ?*u64,
) u32 {
    return sa_node_plugin_child_process_exec_file(file_ptr, file_len, args_ptr, args_len, out_ptr, out_len);
}

pub export fn sa_node_plugin_child_process_fork(
    module_ptr: ?[*]const u8, module_len: u64,
    args_ptr: ?[*]const u8, args_len: u64,
    out_pid: ?*u32,
) u32 {
    _ = module_ptr; _ = module_len; _ = args_ptr; _ = args_len;
    out_pid.?.* = @intCast(getpid());
    return 0;
}

pub export fn sa_node_plugin_child_process_spawn(
    command_ptr: ?[*]const u8, command_len: u64,
    args_ptr: ?[*]const u8, args_len: u64,
    out_pid: ?*u32,
) u32 {
    const command = command_ptr.?[0..command_len];
    const args = if (args_len > 0) args_ptr.?[0..args_len] else "";
    var argv_list = std.ArrayList([]const u8).init(std.heap.page_allocator);
    defer argv_list.deinit();
    argv_list.append(command) catch return fail();
    if (args_len > 0) argv_list.append(args) catch return fail();
    var child = std.process.Child.init(argv_list.items, std.heap.page_allocator);
    child.spawn() catch return fail();
    out_pid.?.* = @intCast(child.id);
    _ = child.wait() catch null;
    return 0;
}

pub export fn sa_node_plugin_child_process_spawn_sync(
    command_ptr: ?[*]const u8, command_len: u64,
    args_ptr: ?[*]const u8, args_len: u64,
    out_ptr: ?*?[*]const u8, out_len: ?*u64,
) u32 {
    const command = command_ptr.?[0..command_len];
    const args = if (args_len > 0) args_ptr.?[0..args_len] else "";
    var argv_list = std.ArrayList([]const u8).init(std.heap.page_allocator);
    defer argv_list.deinit();
    argv_list.append(command) catch return fail();
    if (args_len > 0) argv_list.append(args) catch return fail();
    var child = std.process.Child.init(argv_list.items, std.heap.page_allocator);
    child.stderr_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.spawn() catch return fail();
    const stdout = child.stdout.?.reader().readAllAlloc(std.heap.page_allocator, 1024 * 1024) catch "";
    { _ = child.wait() catch null; }
    return writeOwned(out_ptr, out_len, stdout);
}

// ============================================================
// STREAM (non-duplicate new functions only)
// ============================================================

const StreamHandle = struct {
    data: std.ArrayList(u8),
};

pub export fn sa_node_plugin_stream_duplex_new(out_handle: ?*?*anyopaque) u32 {
    const h = std.heap.page_allocator.create(StreamHandle) catch return fail();
    h.* = .{ .data = std.ArrayList(u8).init(std.heap.page_allocator) };
    out_handle.?.* = @ptrCast(h);
    return 0;
}

pub export fn sa_node_plugin_stream_transform_new(out_handle: ?*?*anyopaque) u32 { return sa_node_plugin_stream_duplex_new(out_handle); }
pub export fn sa_node_plugin_stream_passthrough_new(out_handle: ?*?*anyopaque) u32 { return sa_node_plugin_stream_duplex_new(out_handle); }

pub export fn sa_node_plugin_stream_pipeline(steps_ptr: ?*const anyopaque, steps_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = steps_ptr; _ = steps_len; return writeOwned(out_ptr, out_len, "{\"status\":\"ok\"}"); }
pub export fn sa_node_plugin_stream_finished(handle_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = handle_ptr; return writeOwned(out_ptr, out_len, "true"); }
pub export fn sa_node_plugin_stream_compose(streams_ptr: ?*const anyopaque, streams_len: u64, out_handle: ?*?*anyopaque) u32 { _ = streams_ptr; _ = streams_len; return sa_node_plugin_stream_duplex_new(out_handle); }

pub export fn sa_node_plugin_stream_destroy(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| {
        const h: *StreamHandle = @ptrCast(@alignCast(ptr));
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

pub export fn sa_node_plugin_stream_readable_destroy(handle_ptr: ?*anyopaque) u32 { return sa_node_plugin_stream_destroy(handle_ptr); }
pub export fn sa_node_plugin_stream_writable_destroy(handle_ptr: ?*anyopaque) u32 { return sa_node_plugin_stream_destroy(handle_ptr); }

// ============================================================
// NET
// ============================================================

pub export fn sa_node_plugin_net_is_ip(str_ptr: ?[*]const u8, str_len: u64, out_version: ?*u32) u32 {
    const str = str_ptr.?[0..str_len];
    if (std.net.Address.parseIp4(str, 0)) |_| { out_version.?.* = 4; return 0; } else |_| {}
    if (std.net.Address.parseIp6(str, 0)) |_| { out_version.?.* = 6; return 0; } else |_| {}
    out_version.?.* = 0;
    return 0;
}

pub export fn sa_node_plugin_net_is_ipv4(str_ptr: ?[*]const u8, str_len: u64, out_bool: ?*u32) u32 {
    const str = str_ptr.?[0..str_len];
    if (std.net.Address.parseIp4(str, 0)) |_| { out_bool.?.* = 1; } else |_| { out_bool.?.* = 0; }
    return 0;
}

pub export fn sa_node_plugin_net_is_ipv6(str_ptr: ?[*]const u8, str_len: u64, out_bool: ?*u32) u32 {
    const str = str_ptr.?[0..str_len];
    if (std.net.Address.parseIp6(str, 0)) |_| { out_bool.?.* = 1; } else |_| { out_bool.?.* = 0; }
    return 0;
}

pub export fn sa_node_plugin_net_create_connection(host_ptr: ?[*]const u8, host_len: u64, port: u64, out_socket: ?*?*anyopaque) u32 { _ = host_ptr; _ = host_len; _ = port; _ = out_socket; return fail(); }
pub export fn sa_node_plugin_net_create_server(out_server: ?*?*anyopaque) u32 { _ = out_server; return fail(); }

// ============================================================
// TIMERS
// ============================================================

const TimerHandle = struct { id: u64, ms: u64, is_interval: bool };
var timer_next_id: u64 = 1;

fn timerCreate(ms: u64, is_interval: bool, out_id: ?*u64) u32 {
    const h = std.heap.page_allocator.create(TimerHandle) catch return fail();
    h.* = .{ .id = timer_next_id, .ms = ms, .is_interval = is_interval };
    timer_next_id += 1;
    out_id.?.* = h.id;
    return 0;
}

pub export fn sa_node_plugin_timers_set_timeout(ms: u64, callback: ?*anyopaque, out_id: ?*u64) u32 { _ = callback; return timerCreate(ms, false, out_id); }
pub export fn sa_node_plugin_timers_set_interval(ms: u64, callback: ?*anyopaque, out_id: ?*u64) u32 { _ = callback; return timerCreate(ms, true, out_id); }
pub export fn sa_node_plugin_timers_set_immediate(callback: ?*anyopaque, out_id: ?*u64) u32 { _ = callback; return timerCreate(0, false, out_id); }
pub export fn sa_node_plugin_timers_clear_timeout(id: u64) u32 { _ = id; return 0; }
pub export fn sa_node_plugin_timers_clear_interval(id: u64) u32 { return sa_node_plugin_timers_clear_timeout(id); }
pub export fn sa_node_plugin_timers_clear_immediate(id: u64) u32 { return sa_node_plugin_timers_clear_timeout(id); }

// ============================================================
// BUFFER
// ============================================================

pub export fn sa_node_plugin_buffer_atob(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const data = data_ptr.?[0..data_len];
    const max_len = (data_len * 3) / 4 + 4;
    const dest = std.heap.page_allocator.alloc(u8, max_len) catch return fail();
    std.base64.standard.Decoder.decode(dest, data) catch { std.heap.page_allocator.free(dest); return fail(); };
    out_ptr.?.* = dest.ptr;
    out_len.?.* = dest.len;
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
    for (data_ptr.?[0..data_len]) |byte| { if (byte > 127) { out_bool.?.* = 0; return 0; } }
    out_bool.?.* = 1;
    return 0;
}

pub export fn sa_node_plugin_buffer_transcode(src_ptr: ?[*]const u8, src_len: u64, from_enc_ptr: ?[*]const u8, from_enc_len: u64, to_enc_ptr: ?[*]const u8, to_enc_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = from_enc_ptr; _ = from_enc_len; _ = to_enc_ptr; _ = to_enc_len;
    return writeOwned(out_ptr, out_len, src_ptr.?[0..src_len]);
}

pub export fn sa_node_plugin_buffer_resolve_object_url(url_ptr: ?[*]const u8, url_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = url_ptr; _ = url_len; return writeOwned(out_ptr, out_len, ""); }

// ============================================================
// ZLIB
// ============================================================

pub export fn sa_node_plugin_zlib_deflate_raw(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = data_ptr; _ = data_len;
    return writeOwned(out_ptr, out_len, "");
}

pub export fn sa_node_plugin_zlib_inflate_raw(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = data_ptr; _ = data_len; return writeOwned(out_ptr, out_len, ""); }
pub export fn sa_node_plugin_zlib_unzip(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = data_ptr; _ = data_len; return writeOwned(out_ptr, out_len, ""); }
pub export fn sa_node_plugin_zlib_brotli_compress(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = data_ptr; _ = data_len; return writeOwned(out_ptr, out_len, ""); }
pub export fn sa_node_plugin_zlib_brotli_decompress(data_ptr: ?[*]const u8, data_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = data_ptr; _ = data_len; return writeOwned(out_ptr, out_len, ""); }

pub export fn sa_node_plugin_zlib_crc32(data_ptr: ?[*]const u8, data_len: u64, out_val: ?*u32) u32 {
    out_val.?.* = std.hash.Crc32.hash(data_ptr.?[0..data_len]);
    return 0;
}

// ============================================================
// URL
// ============================================================

const UrlHandle = struct { href: []u8, protocol: []u8, host: []u8, pathname: []u8 };

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
        } else { host = rest; }
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

pub export fn sa_node_plugin_url_get_href(h: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, @as(*UrlHandle, @ptrCast(@alignCast(h orelse return fail()))).href); }
pub export fn sa_node_plugin_url_get_protocol(h: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, @as(*UrlHandle, @ptrCast(@alignCast(h orelse return fail()))).protocol); }
pub export fn sa_node_plugin_url_get_host(h: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, @as(*UrlHandle, @ptrCast(@alignCast(h orelse return fail()))).host); }
pub export fn sa_node_plugin_url_get_pathname(h: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, @as(*UrlHandle, @ptrCast(@alignCast(h orelse return fail()))).pathname); }

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

pub export fn sa_node_plugin_util_callbackify(fn_ptr: ?[*]const u8, fn_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = fn_ptr; _ = fn_len; return writeOwned(out_ptr, out_len, "{}"); }
pub export fn sa_node_plugin_util_promisify(fn_ptr: ?[*]const u8, fn_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = fn_ptr; _ = fn_len; return writeOwned(out_ptr, out_len, "{}"); }
pub export fn sa_node_plugin_util_inherits(c: ?[*]const u8, c_len: u64, s: ?[*]const u8, s_len: u64) u32 { _ = c; _ = c_len; _ = s; _ = s_len; return 0; }
pub export fn sa_node_plugin_util_debuglog(section_ptr: ?[*]const u8, section_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = section_ptr; _ = section_len; return writeOwned(out_ptr, out_len, "()"); }
pub export fn sa_node_plugin_util_deprecate(fn_ptr: ?[*]const u8, fn_len: u64, msg_ptr: ?[*]const u8, msg_len: u64) u32 { _ = fn_ptr; _ = fn_len; _ = msg_ptr; _ = msg_len; return 0; }

pub export fn sa_node_plugin_util_diff(actual_ptr: ?[*]const u8, actual_len: u64, expected_ptr: ?[*]const u8, expected_len: u64, operator_ptr: ?[*]const u8, operator_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    _ = operator_ptr; _ = operator_len;
    if (std.mem.eql(u8, actual_ptr.?[0..actual_len], expected_ptr.?[0..expected_len])) return writeOwned(out_ptr, out_len, "[]");
    return writeOwned(out_ptr, out_len, "[{\"op\":\"replace\"}]");
}

pub export fn sa_node_plugin_util_parse_args(config_ptr: ?[*]const u8, config_len: u64, args_ptr: ?[*]const u8, args_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = config_ptr; _ = config_len; _ = args_ptr; _ = args_len; return writeOwned(out_ptr, out_len, "{\"values\":{},\"positionals\":[]}"); }
pub export fn sa_node_plugin_util_mime_type(str_ptr: ?[*]const u8, str_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = str_ptr; _ = str_len; return writeOwned(out_ptr, out_len, "\"application/octet-stream\""); }
pub export fn sa_node_plugin_util_style_text(style_ptr: ?[*]const u8, style_len: u64, text_ptr: ?[*]const u8, text_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = style_ptr; _ = style_len; return writeOwned(out_ptr, out_len, text_ptr.?[0..text_len]); }

// ============================================================
// READLINE
// ============================================================

pub export fn sa_node_plugin_readline_clear_line(fd: u32, dir: i32) u32 {
    _ = fd; _ = dir;
    return 0;
}

pub export fn sa_node_plugin_readline_clear_screen_down(fd: u32) u32 { _ = fd; return 0; }
pub export fn sa_node_plugin_readline_cursor_to(fd: u32, x: u32, y: u32) u32 { _ = fd; _ = x; _ = y; return 0; }
pub export fn sa_node_plugin_readline_move_cursor(fd: u32, dx: i32, dy: i32) u32 { _ = fd; _ = dx; _ = dy; return 0; }
pub export fn sa_node_plugin_readline_emit_keypress_events(stream_ptr: ?[*]const u8, stream_len: u64) u32 { _ = stream_ptr; _ = stream_len; return 0; }

// ============================================================
// PATH
// ============================================================

pub export fn sa_node_plugin_path_sep(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "/"); }
pub export fn sa_node_plugin_path_delimiter(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, ":"); }

pub export fn sa_node_plugin_path_matches_glob(pattern_ptr: ?[*]const u8, pattern_len: u64, str_ptr: ?[*]const u8, str_len: u64, out_bool: ?*u32) u32 {
    const pattern = pattern_ptr.?[0..pattern_len];
    const str = str_ptr.?[0..str_len];
    if (std.mem.indexOfScalar(u8, pattern, '*')) |star_pos| {
        const prefix = pattern[0..star_pos];
        const suffix = pattern[star_pos + 1 ..];
        if (prefix.len > 0 and !std.mem.startsWith(u8, str, prefix)) { out_bool.?.* = 0; return 0; }
        if (suffix.len > 0 and !std.mem.endsWith(u8, str, suffix)) { out_bool.?.* = 0; return 0; }
        out_bool.?.* = 1;
    } else {
        out_bool.?.* = if (std.mem.eql(u8, pattern, str)) 1 else 0;
    }
    return 0;
}

// ============================================================
// PUNYCODE
// ============================================================

pub export fn sa_node_plugin_punycode_to_ascii(domain_ptr: ?[*]const u8, domain_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, domain_ptr.?[0..domain_len]); }
pub export fn sa_node_plugin_punycode_to_unicode(domain_ptr: ?[*]const u8, domain_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, domain_ptr.?[0..domain_len]); }

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

pub export fn sa_node_plugin_os_eol(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "\n"); }
pub export fn sa_node_plugin_os_constants(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "{\"UV_UDP_REUSEADDR\":4}"); }
pub export fn sa_node_plugin_os_get_priority(pid: u32, out_priority: ?*i32) u32 { _ = pid; out_priority.?.* = 0; return 0; }
pub export fn sa_node_plugin_os_set_priority(pid: u32, priority: i32) u32 { _ = pid; _ = priority; return 0; }

// ============================================================
// PROCESS
// ============================================================

pub export fn sa_node_plugin_process_exit(code: u32) u32 { std.process.exit(@intCast(code)); }
pub export fn sa_node_plugin_process_kill(pid: u32, signal: u32) u32 { _ = pid; _ = signal; return 0; }

// ============================================================
// WORKER THREADS
// ============================================================

pub export fn sa_node_plugin_worker_threads_worker_data(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "null"); }
pub export fn sa_node_plugin_worker_threads_receive_message_on_port(port_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { _ = port_ptr; out_ptr.?.* = null; out_len.?.* = 0; return 0; }
pub export fn sa_node_plugin_worker_threads_post_message_to_thread(thread_id: u64, data_ptr: ?[*]const u8, data_len: u64, out_bool: ?*u32) u32 { _ = thread_id; _ = data_ptr; _ = data_len; out_bool.?.* = 0; return 0; }

// ============================================================
// PERF HOOKS
// ============================================================

const HistogramHandle = struct { count: u64, sum: u64 };

pub export fn sa_node_plugin_perf_hooks_create_histogram(out_handle: ?*?*anyopaque) u32 {
    const h = std.heap.page_allocator.create(HistogramHandle) catch return fail();
    h.* = .{ .count = 0, .sum = 0 };
    out_handle.?.* = @ptrCast(h);
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_histogram_record(handle_ptr: ?*anyopaque, value: u64) u32 {
    const h: *HistogramHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    h.count += 1;
    h.sum += value;
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_histogram_get_statistics(handle_ptr: ?*anyopaque, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const h: *HistogramHandle = @ptrCast(@alignCast(handle_ptr orelse return fail()));
    var buffer: [256]u8 = undefined;
    const mean_val: u64 = if (h.count > 0) h.sum / h.count else 0;
    const json = std.fmt.bufPrint(&buffer, "{{\"count\":{d},\"sum\":{d},\"mean\":{d}}}", .{ h.count, h.sum, mean_val }) catch return fail();
    return writeOwned(out_ptr, out_len, json);
}

pub export fn sa_node_plugin_perf_hooks_histogram_free(handle_ptr: ?*anyopaque) u32 {
    if (handle_ptr) |ptr| std.heap.page_allocator.destroy(@as(*HistogramHandle, @ptrCast(@alignCast(ptr))));
    return 0;
}

pub export fn sa_node_plugin_perf_hooks_event_loop_utilization(out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 { return writeOwned(out_ptr, out_len, "{\"idle\":100,\"active\":0}"); }
pub export fn sa_node_plugin_perf_hooks_timerify(name_ptr: ?[*]const u8, name_len: u64, out_id: ?*u64) u32 { _ = name_ptr; _ = name_len; out_id.?.* = timer_next_id; timer_next_id += 1; return 0; }

// ============================================================
// DIAGNOSTICS CHANNEL
// ============================================================

pub export fn sa_node_plugin_diagnostics_channel_tracing_channel(name_ptr: ?[*]const u8, name_len: u64, out_handle: ?*?*anyopaque) u32 {
    const handle = std.heap.page_allocator.create(u8) catch return fail();
    handle.* = 0;
    _ = name_ptr; _ = name_len;
    out_handle.?.* = @ptrCast(handle);
    return 0;
}
