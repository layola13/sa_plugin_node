const http_client = @import("http_client");
const http_server = @import("http_server");

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
