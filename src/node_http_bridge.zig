const std = @import("std");
const http_client = @import("http_client");
const http_server = @import("http_server");

fn appendJsonString(out: *std.ArrayList(u8), bytes: []const u8) !void {
    try out.append('"');
    for (bytes) |c| switch (c) {
        '"' => try out.appendSlice("\\\""),
        '\\' => try out.appendSlice("\\\\"),
        '\n' => try out.appendSlice("\\n"),
        '\r' => try out.appendSlice("\\r"),
        '\t' => try out.appendSlice("\\t"),
        else => try out.append(c),
    };
    try out.append('"');
}

fn writeOwned(out_ptr: ?*?[*]const u8, out_len: ?*u64, bytes: []const u8) u32 {
    const ptr_slot = out_ptr orelse return 2;
    const len_slot = out_len orelse return 2;
    const owned = std.heap.page_allocator.dupe(u8, bytes) catch return 2;
    ptr_slot.* = owned.ptr;
    len_slot.* = owned.len;
    return 0;
}

fn httpMethodCode(method: []const u8) ?u8 {
    if (std.ascii.eqlIgnoreCase(method, "GET")) return 1;
    if (std.ascii.eqlIgnoreCase(method, "POST")) return 2;
    if (std.ascii.eqlIgnoreCase(method, "PUT")) return 3;
    if (std.ascii.eqlIgnoreCase(method, "DELETE")) return 4;
    return null;
}

fn httpOneShotJson(method: []const u8, url: []const u8, body: ?[]const u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    const method_code = httpMethodCode(method) orelse return 2;
    const use_tls: u8 = if (std.mem.startsWith(u8, url, "https://")) 1 else 0;

    var client: ?*anyopaque = null;
    if (sa_node_plugin_http_client_new(use_tls, &client) != 0) return 2;
    defer _ = sa_node_plugin_http_client_free(client);

    var req: ?*anyopaque = null;
    if (sa_node_plugin_http_client_req_new(client, method_code, url.ptr, url.len, &req) != 0) return 2;
    defer _ = sa_node_plugin_http_client_req_free(req);

    if (body) |payload| {
        if (sa_node_plugin_http_client_req_set_body(req, payload.ptr, payload.len) != 0) return 2;
    }

    var resp: ?*anyopaque = null;
    if (sa_node_plugin_http_client_req_send(req, &resp) != 0) return 2;
    defer _ = sa_node_plugin_http_client_resp_free(resp);

    var body_ptr: ?[*]const u8 = null;
    var body_len: u64 = 0;
    if (sa_node_plugin_http_client_resp_body_slice(resp, &body_ptr, &body_len) != 0) return 2;

    var content_type_ptr: ?[*]const u8 = null;
    var content_type_len: u64 = 0;
    const has_content_type = sa_node_plugin_http_client_resp_get_header(resp, "content-type", 12, &content_type_ptr, &content_type_len) == 0;

    var out = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out.deinit();
    out.writer().print("{{\"statusCode\":{d},\"body\":", .{sa_node_plugin_http_client_resp_status(resp)}) catch return 2;
    appendJsonString(&out, (body_ptr orelse return 2)[0..body_len]) catch return 2;
    out.appendSlice(",\"contentType\":") catch return 2;
    if (has_content_type) {
        appendJsonString(&out, content_type_ptr.?[0..content_type_len]) catch return 2;
    } else {
        out.appendSlice("null") catch return 2;
    }
    out.append('}') catch return 2;
    return writeOwned(out_ptr, out_len, out.items);
}

// --- HTTP Client ---
pub export fn sa_node_plugin_http_client_new(use_tls: u8, out_client: ?*?*anyopaque) u32 {
    return http_client.sa_http_client_new(use_tls, out_client);
}

pub export fn sa_node_plugin_http_client_req_new(client: ?*anyopaque, method: u8, url_ptr: ?[*]const u8, url_len: u64, out_req: ?*?*anyopaque) u32 {
    return http_client.sa_http_client_req_new(client, method, url_ptr, url_len, out_req);
}

pub export fn sa_node_plugin_http_client_req_add_header(req: ?*anyopaque, key_ptr: ?[*]const u8, key_len: u64, val_ptr: ?[*]const u8, val_len: u64) u32 {
    return http_client.sa_http_client_req_add_header(req, key_ptr, key_len, val_ptr, val_len);
}

pub export fn sa_node_plugin_http_client_req_set_body(req: ?*anyopaque, body_ptr: ?[*]const u8, body_len: u64) u32 {
    return http_client.sa_http_client_req_set_body(req, body_ptr, body_len);
}

pub export fn sa_node_plugin_http_client_req_send(req: ?*anyopaque, out_resp: ?*?*anyopaque) u32 {
    return http_client.sa_http_client_req_send(req, out_resp);
}

pub export fn sa_node_plugin_http_client_req_send_async(req: ?*anyopaque, out_op: ?*?*anyopaque) u32 {
    return http_client.sa_http_client_req_send_async(req, out_op);
}

pub export fn sa_node_plugin_http_client_async_poll(op: ?*anyopaque, out_ready: ?*u64) u32 {
    const slot = out_ready orelse return 2;
    var ready: u8 = 0;
    const status = http_client.sa_http_client_async_poll(op, &ready);
    if (status != 0) return status;
    slot.* = ready;
    return 0;
}

pub export fn sa_node_plugin_http_client_async_take_response(op: ?*anyopaque, out_resp: ?*?*anyopaque) u32 {
    return http_client.sa_http_client_async_take_response(op, out_resp);
}

pub export fn sa_node_plugin_http_client_async_free(op: ?*anyopaque) u32 {
    return http_client.sa_http_client_async_free(op);
}

pub export fn sa_node_plugin_http_client_resp_status(resp: ?*anyopaque) u16 {
    return http_client.sa_http_client_resp_status(resp);
}

pub export fn sa_node_plugin_http_client_resp_get_header(resp: ?*anyopaque, key_ptr: ?[*]const u8, key_len: u64, out_val_ptr: ?*?[*]const u8, out_val_len: ?*u64) u32 {
    return http_client.sa_http_client_resp_get_header(resp, key_ptr, key_len, out_val_ptr, out_val_len);
}

pub export fn sa_node_plugin_http_client_resp_body_slice(resp: ?*anyopaque, out_body_ptr: ?*?[*]const u8, out_body_len: ?*u64) u32 {
    return http_client.sa_http_client_resp_body_slice(resp, out_body_ptr, out_body_len);
}

pub export fn sa_node_plugin_http_client_resp_body_reader(resp: ?*anyopaque, out_reader: ?*?*anyopaque) u32 {
    return http_client.sa_http_client_resp_body_reader(resp, out_reader);
}

pub export fn sa_node_plugin_http_client_resp_read_chunk(reader: ?*anyopaque, buf_ptr: ?[*]u8, cap: u64, out_len: ?*u64) u32 {
    return http_client.sa_http_client_resp_read_chunk(reader, buf_ptr, cap, out_len);
}

pub export fn sa_node_plugin_http_client_resp_free(resp: ?*anyopaque) u32 {
    return http_client.sa_http_client_resp_free(resp);
}

pub export fn sa_node_plugin_http_client_body_reader_free(reader: ?*anyopaque) u32 {
    return http_client.sa_http_client_body_reader_free(reader);
}

pub export fn sa_node_plugin_http_client_free(client: ?*anyopaque) u32 {
    return http_client.sa_http_client_free(client);
}

pub export fn sa_node_plugin_http_client_req_free(req: ?*anyopaque) u32 {
    return http_client.sa_http_client_req_free(req);
}

pub export fn sa_node_plugin_http_request_json(method_ptr: ?[*]const u8, method_len: u64, url_ptr: ?[*]const u8, url_len: u64, body_ptr: ?[*]const u8, body_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (out_ptr) |slot| slot.* = null;
    if (out_len) |slot| slot.* = 0;
    const method = (method_ptr orelse return 2)[0..method_len];
    const url = (url_ptr orelse return 2)[0..url_len];
    const body = if (body_ptr) |ptr| ptr[0..body_len] else if (body_len == 0) null else return 2;
    return httpOneShotJson(method, url, body, out_ptr, out_len);
}

pub export fn sa_node_plugin_http_get_json(url_ptr: ?[*]const u8, url_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (out_ptr) |slot| slot.* = null;
    if (out_len) |slot| slot.* = 0;
    const url = (url_ptr orelse return 2)[0..url_len];
    return httpOneShotJson("GET", url, null, out_ptr, out_len);
}

pub export fn sa_node_plugin_https_request_json(method_ptr: ?[*]const u8, method_len: u64, url_ptr: ?[*]const u8, url_len: u64, body_ptr: ?[*]const u8, body_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (out_ptr) |slot| slot.* = null;
    if (out_len) |slot| slot.* = 0;
    const method = (method_ptr orelse return 2)[0..method_len];
    const url = (url_ptr orelse return 2)[0..url_len];
    if (!std.mem.startsWith(u8, url, "https://")) return 2;
    const body = if (body_ptr) |ptr| ptr[0..body_len] else if (body_len == 0) null else return 2;
    return httpOneShotJson(method, url, body, out_ptr, out_len);
}

pub export fn sa_node_plugin_https_get_json(url_ptr: ?[*]const u8, url_len: u64, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    if (out_ptr) |slot| slot.* = null;
    if (out_len) |slot| slot.* = 0;
    const url = (url_ptr orelse return 2)[0..url_len];
    if (!std.mem.startsWith(u8, url, "https://")) return 2;
    return httpOneShotJson("GET", url, null, out_ptr, out_len);
}

// --- HTTP Client WebSocket ---
pub export fn sa_node_plugin_http_websocket_connect(client: ?*anyopaque, url_ptr: ?[*]const u8, url_len: u64, out_ws: ?*?*anyopaque) u32 {
    return http_client.sa_http_client_websocket_connect(client, url_ptr, url_len, out_ws);
}

pub export fn sa_node_plugin_http_websocket_read(ws: ?*anyopaque, max_len: u64, out_opcode: ?*u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return http_client.sa_http_websocket_read(ws, max_len, out_opcode, out_ptr, out_len);
}

pub export fn sa_node_plugin_http_websocket_write(ws: ?*anyopaque, opcode: u8, data_ptr: ?[*]const u8, data_len: u64) u32 {
    return http_client.sa_http_websocket_write(ws, opcode, data_ptr, data_len);
}

pub export fn sa_node_plugin_http_websocket_free(ws: ?*anyopaque) u32 {
    return http_client.sa_http_websocket_free(ws);
}

// --- HTTP Server ---
pub export fn sa_node_plugin_http_server_new(out_server: ?*?*anyopaque) u32 {
    return http_server.sa_http_server_new(out_server);
}

pub export fn sa_node_plugin_http_server_start(server: ?*anyopaque, host_ptr: ?[*]const u8, host_len: u64, port: u16) u32 {
    return http_server.sa_http_server_start(server, host_ptr, host_len, port);
}

pub export fn sa_node_plugin_http_server_accept(server: ?*anyopaque, out_req: ?*?*anyopaque) u32 {
    return http_server.sa_http_server_accept(server, out_req);
}

pub export fn sa_node_plugin_http_server_req_get_method(req: ?*anyopaque, out_method_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return http_server.sa_http_server_req_get_method(req, out_method_ptr, out_len);
}

pub export fn sa_node_plugin_http_server_req_get_path(req: ?*anyopaque, out_path_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return http_server.sa_http_server_req_get_path(req, out_path_ptr, out_len);
}

pub export fn sa_node_plugin_http_server_req_get_header(req: ?*anyopaque, key_ptr: ?[*]const u8, key_len: u64, out_val_ptr: ?*?[*]const u8, out_val_len: ?*u64) u32 {
    return http_server.sa_http_server_req_get_header(req, key_ptr, key_len, out_val_ptr, out_val_len);
}

pub export fn sa_node_plugin_http_server_req_get_body(req: ?*anyopaque, out_body_ptr: ?*?[*]const u8, out_body_len: ?*u64) u32 {
    return http_server.sa_http_server_req_get_body(req, out_body_ptr, out_body_len);
}

pub export fn sa_node_plugin_http_server_req_free(req: ?*anyopaque) u32 {
    return http_server.sa_http_server_req_free(req);
}

pub export fn sa_node_plugin_http_server_resp_new(req: ?*anyopaque, status: u16, out_resp: ?*?*anyopaque) u32 {
    return http_server.sa_http_server_resp_new(req, status, out_resp);
}

pub export fn sa_node_plugin_http_server_resp_send(resp: ?*anyopaque, body_ptr: ?[*]const u8, body_len: u64) u32 {
    return http_server.sa_http_server_resp_send(resp, body_ptr, body_len);
}

pub export fn sa_node_plugin_http_server_resp_set_content_type(resp: ?*anyopaque, content_type_ptr: ?[*]const u8, content_type_len: u64) u32 {
    return http_server.sa_http_server_resp_set_content_type(resp, content_type_ptr, content_type_len);
}

pub export fn sa_node_plugin_http_server_resp_free(resp: ?*anyopaque) u32 {
    return http_server.sa_http_server_resp_free(resp);
}

// --- HTTP Server Streaming (SSE / chunked) ---
pub export fn sa_node_plugin_http_server_resp_stream_new(req: ?*anyopaque, status: u16, out_resp: ?*?*anyopaque) u32 {
    return http_server.sa_http_server_resp_stream_new(req, status, out_resp);
}

pub export fn sa_node_plugin_http_server_resp_stream_write(resp: ?*anyopaque, body_ptr: ?[*]const u8, body_len: u64) u32 {
    return http_server.sa_http_server_resp_stream_write(resp, body_ptr, body_len);
}

pub export fn sa_node_plugin_http_server_resp_stream_flush(resp: ?*anyopaque) u32 {
    return http_server.sa_http_server_resp_stream_flush(resp);
}

pub export fn sa_node_plugin_http_server_resp_stream_end(resp: ?*anyopaque) u32 {
    return http_server.sa_http_server_resp_stream_end(resp);
}

pub export fn sa_node_plugin_http_server_resp_stream_free(resp: ?*anyopaque) u32 {
    return http_server.sa_http_server_resp_stream_free(resp);
}

pub export fn sa_node_plugin_http_server_free(server: ?*anyopaque) u32 {
    return http_server.sa_http_server_free(server);
}

// --- HTTP Server WebSocket ---
pub export fn sa_node_plugin_http_server_websocket_upgrade(req: ?*anyopaque, out_ws: ?*?*anyopaque) u32 {
    return http_server.sa_http_server_websocket_upgrade(req, out_ws);
}

pub export fn sa_node_plugin_http_server_websocket_read(ws: ?*anyopaque, max_len: u64, out_opcode: ?*u8, out_ptr: ?*?[*]const u8, out_len: ?*u64) u32 {
    return http_server.sa_http_server_websocket_read(ws, max_len, out_opcode, out_ptr, out_len);
}

pub export fn sa_node_plugin_http_server_websocket_write(ws: ?*anyopaque, opcode: u8, data_ptr: ?[*]const u8, data_len: u64) u32 {
    return http_server.sa_http_server_websocket_write(ws, opcode, data_ptr, data_len);
}

pub export fn sa_node_plugin_http_server_websocket_free(ws: ?*anyopaque) u32 {
    return http_server.sa_http_server_websocket_free(ws);
}
