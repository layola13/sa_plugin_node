nodejs api list
---------------------------
Asynchronous context tracking
Async hooks
Buffer
Child processes
Cluster
Command-line options
Console
Crypto
Debugger
Deprecated APIs
Diagnostics Channel
DNS
Domain
Environment Variables
Errors
Events
File system
FFI
Globals
HTTP
HTTP/2
HTTPS
Inspector
Internationalization
Iterable Streams API
Modules: CommonJS modules
Modules: ECMAScript modules
Modules: node:module API
Modules: Packages
Modules: TypeScript
Net
OS
Path
Performance hooks
Permissions
Process
Punycode
Query strings
Readline
REPL
Report
Single executable applications
SQLite
Stream
String decoder
Test runner
Timers
TLS/SSL
Trace events
TTY
UDP/datagram
URL
Utilities
V8
VM
WASI
Web Crypto API
Web Streams API
Worker threads
Zlib
---

## Network Protocol Capability Matrix (verified 2026-07-03, code-static)

本表为联合 `sci` + `sa_plugin_http_client` + `sa_plugin_http_server` + `sa_plugin_deno` + `sa_plugin_node` 源码静态核验得出的真实完成度,不基于自陈宣称。每行注明真后端与 ABI/壳分层。"真支持"= 端到端可跑;"壳"= 仅 ABI + capability gate,无真协议机。

| 协议层 | 真后端 / 实现实体 | 完成度 | 真实证据路径 |
|---|---|---|---|
| TCP socket | sci `net.sa` syscall 包装(64+ 宏) | ✅ 真完整 | `sci/sa_std/net.sa`; `sci/src/runtime/sa_pthread_host.c` |
| UDP socket | sci `net.sa`(send_to/recv_from/v4/v6/multicast/broadcast) | ✅ 真完整 | 同上 |
| IPv4/IPv6 addr | sci `net.sa`(ip_new/family/format/scope_id/free) | ✅ 真完整 | 同上 |
| DNS | node plugin `sa_node_plugin_dns_*`(servers/promises/resolver) | ✅ ABI(基础解析) | `node_extra.sai` 127-175 |
| HTTP/1.0、HTTP/1.1 客户端 | Zig std `std.http.Client`(Version={HTTP/1.0,HTTP/1.1}) | ✅ 真完整 | `sa_plugin_http_client/src/http_saasm_api.zig`; Zig std `lib/std/http.zig` |
| HTTP/1.1 服务器 | Zig std `std.http.Server` + node `sa_node_plugin_net_*` | ✅ 真支持(无 TLS server) | `sa_plugin_http_server/src/vite_api.zig:65` |
| HTTPS(HTTP/1.1 over TLS) | `std.crypto.tls.Client` 真握手经 http_client `use_tls` / node `tls_connect` | ✅ 真支持 | `node_saasm_api_ext.zig:529 std.crypto.tls.Client.init` |
| TLS 1.2/1.3 客户端 | Zig std `std.crypto.tls.Client`(X25519/AES-GCM/ChaCha20,真记录层握手/close_notify,ALPN helper/SNI/custom CA bundle) | ✅ 真支持 | `node_saasm_api_ext.zig:114/529`; Zig std `lib/std/crypto/tls/Client.zig` |
| TLS 服务端 | (无) | ❌ 未实现 | `http_server` 无 TLS;node 无 `tls_server` ABI |
| WebSocket(RFC6455) | http_client/server 自实现 frame(SHA1 sec-key/mask/opcode,两端) | ✅ 真支持 | `http_saasm_api.zig` `WebSocketHandle`/`maskInPlace` |
| HTTP/2(h2c 客户端 + server handshake) | node plugin dlopen **`libnghttp2.so`**(14+ nghttp2 真函数 lookup:callbacks/session_client_new/submit_request/submit_settings/mem_send/mem_recv/want) | ✅ 真支持(h2c 客户端子集 + server 握手) | `node_saasm_extra.zig:5563` "HTTP/2 h2c client subset backed by libnghttp2"; `Nghttp2Api` |
| HTTP/2 server 完整(响应帧 submit_response 等) | (无) | ❌ 仅前置握手,无完整 server response | 无 `nghttp2_session_server_new`/`submit_response` |
| HTTP/2 over TLS(ALPN "h2") | `tls_convert_alpn_protocols`/`tls_alpn_protocol` helper 齐,但无端到端一键路径 | ⚠️ 半接通(需用户拼装) | `node_saasm_api_ext.zig:3829/4044` |
| HTTP/3 | node plugin `http3_session_send/recv_datagram` ABI;实现就是 QUIC endpoint 的 `dgram_send/recv`(裸 UDP),无 `nghttp3_conn/submit` 真帧 | ❌ 仅 ABI 壳(capability gate only) | `node_saasm_extra.zig:6286` `http3_session_send_datagram` == `dgram_send_connected` |
| QUIC | `quic_create_endpoint/connect/listen` = UDP socket + ALPN/cc/idle_timeout 元数据手柄;cap detection 查 ngtcp2+nghttp3+openssl 装齐判 supported,但代码无 `ngtcp2_conn*` 真连接状态机 | ❌ 仅 endpoint 元数据(无真协议机) | `node_saasm_extra.zig:6002 QuicEndpointHandle`; `5940 quicNgTcp2Available` 仅 dynLib 检测 |
| DTLS | ABI 有 connect/listen/send/recv/close;**plugin 自陈 `"handshake":false","record-layer encryption not modeled"`,send/recv 是裸 UDP** | ❌ 仅门面(无真实协议) | `node_saasm_extra.zig dtls_status_json` 自白 |
| async 网络(sci runtime) | sci `libsa_async.sa` 状态机模板 + `sa_net_uring.zig`(2485 行真 io_uring reactor:accept/recv/send/timeout/ticket queue/worker)| ⚠️ sci 内部有,但 sa_std 未导出 io_uring SA ABI;sla_plugin_sla 未接通 executor | `sci/sa_std/libsa_async.sa`; `sci/src/runtime/sa_net_uring.zig` |
| I/O 多路复用 | sci 有 epoll(`sa_term_epoll_*`)+ io_uring reactor(Zig std 无 quic/kqueue),无对外 io_uring ABI | ⚠️ runtime 内部可用,DSL 接入缺 | `sci/src/sa_std.zig:6014 sa_term_epoll_create` |
| Deno plugin 复用层 | `DENO_HTTP_CLIENT_NEW` 直接 call `sa_http_client_new`(走 Zig std HTTP/1.1) | ✅ REST 复用 http_client;Deno namespace 网络句柄在 planned_native | `sa_plugin_deno/deno.sal:441` |

### 一句话答复"是否完整支持 HTTP 1/2/3 等所有协议"

- HTTP/1.0、HTTP/1.1(+HTTPS、WebSocket):✅ 完整
- HTTP/2(h2c 客户端 + server 握手):✅;完整 server response ❌;H2-over-TLS(ALPN)半
- HTTP/3:❌(仅 ABI 壳,send/recv 是裸 UDP 非 H3/QPACK 帧)
- QUIC:❌(仅 endpoint 元数据,无 ngtcp2 真连接)
- TLS 客户端 ✅,TLS 服务端 ❌,DTLS ❌
- TCP/UDP ✅,DNS ✅

### 结论

真端到端可用层:**TCP/UDP、HTTP/1+HTTPS、WebSocket、H2 h2c 客户端、TLS 客户端、DNS**。
真协议机未接通层:**HTTP/3、QUIC、DTLS、TLS 服务端、H2 完整 server、H2-over-TLS 一键**。
工程上已铺路:`Nghttp2Api` 模式(dlopen 真库 + lookup 真函数 + 装 handle)是补 H3/QUIC 的明确路径;`QuicEndpointHandle`/`http3_session_*` ABI 与 capability gate 已就位,接 `ngtcp2`+`nghttp3`+`openssl` 真函数即可由壳转实,无架构阻塞。sci 内部 io_uring reactor 完整但需扩到 sa_std 导出 SA ABI 才能让 DSL 用户使用,这是 sci 端的明确下一步。
