# sa_plugin_node 0.17 迁移 TODO

> 分支: `0.17` (ahead origin/0.17 x2, 2026-10-18)
> 工具链: `zig 0.17.0` + `sci#main` + `LLVM 20.1.2` (`/usr/lib/llvm-20/bin`)
> 上游进度: `04652c3 wip(0.17): S4 node migration checkpoint - extra done, api/ext mechanical fixes, deep socket pending`
> 当前卡点: `zig build test -Dsci-root=/content/sa_all/sci` → **128 compilation errors**
> 未提交改动: `build.zig` (+ test_module sio import), `tests/plugin_test.zig` (+ sio import) — 仅脚手架, 源码修复未开始

## 1. 错误总览 (128 个, 2026-10-18 实测)

| # | 错误信息 | 数量 | 涉及文件 |
|---|----------|------|----------|
| 1 | `struct 'std' has no member named 'net'` | 30 | api.zig x15, ext.zig x12, test x3 |
| 2 | `no field 'lock' in 'atomic.Mutex'` | 12 | ext.zig x12 (596,633,691,3019,3036,3047,3897,3935,4281,4297,4304,4941) |
| 3 | `expected type 'usize', found 'void'` | 9 | api.zig x7 (143,220,299,312,432,463,505), ext.zig x2 (5406,5422) — `sio.File.readAll(&buf)` 新 ABI 返回 `void` 不是 `usize` |
| 4 | `struct 'fs' has no member 'File'/'cwd'/'Dir'` | ~20 | ext.zig x16 + test x1 (7092) — 需全量切 `sio.File/sio.cwd()/sio.Dir` |
| 5 | `struct 'posix' has no member 'socket/close/getcwd/clock_gettime/pipe/write/symlinkat/linkat/futimens/fsync/fchown'` | ~13 | api+ext+test — 0.17 `std.posix` 大瘦身, 切 `std.c.*` / `sio.*` / `std.os.linux.*` |
| 6 | `struct 'fmt' has no member 'fmtSliceHexLower'` | 5 | api.zig x3 (714,1808,1868), ext.zig x1 (4483), test x1 (939) — 手写 hex (对标 bun `hex_digits` 循环) |
| 7 | `struct 'crypto' has no member 'random'` / `'utils'` | 6 | ext.zig (1057,1063,1219,1334,1624 + 1399) — 切 `sio.io().random()` / `std.crypto.timing_safe.eql` |
| 8 | `expected type 'T', found '*const T'` | 5 | api.zig x1 (112), ext.zig x4 (807,2726,4726,5082) — `sio.managedWriter(&out)` 误传 `**Managed`, 应为 `sio.managedWriter(out)` |
| 9 | `expected type 'type', found 'comptime_int'` | 4 | api.zig x2 (2331,4013), test x2 (907,966) — `.{0}**16` / `[_]u8{0x42}**32` / `.{.family=...}` 旧字面量写法 |
| 10 | `struct 'array_list.Aligned' has no member 'init'` | 2 | test x2 (830,6399) — `std.ArrayList(u8).init` → `std.array_list.Managed(u8).init` |
| 11 | `no field 'realpathAlloc'/'makePath' in 'Io.Dir'` | 4 | test x4 (1195,3685,5831) — 切 `sio.*` (`realpathAlloc/makePath/deleteTree` 等) |
| 12 | `member function expected 1/2 arg(s)` | 4 | api.zig x1 (2104 `writer().writeAll`), ext.zig x2 (2148,2202 `writer()` 需传 buf), test x1 (3977 `writeFile` 需 `io`) |
| 13 | `missing struct field: map` (Certificate.Bundle) | 2 | ext.zig (290,319) — `Bundle = .{}` → `Bundle.empty` / `.{.map=.empty,.bytes=.empty}`; 另 `rescan/deinit/parseCert` 签名变 (`io, now`) |
| 14 | `process.Child.Term has no member 'Exited'` + `no field 'id' in sa_io.Child` + `Child.run` | 5 | ext.zig (3375,3398,3447,3462) + test (7425) — `.Exited`→`.exited`, `child.id`→`inner.id`?, `std.process.Child.run`→`sio.Child.run` |
| 15 | `fs 'readLinkAbsolute/makeDirAbsolute/delete*/renameAbsolute/copyFileAbsolute'` | 6 | api.zig (4396,4499,4513,4526,4543,4560) — 切 `std.Io.Dir.*Absolute(sio.io(),…)` / `sio.*Absolute` |
| 16 | `time has no member 'sleep'` | 2 | api.zig (4668) + test (2304) — 切 `sioSleep(ns)` / `std.Io.sleep(sio.io(),…)` (已有 `sioSleep` helper, bun 对标 `sio.io().sleep`) |
| 17 | `fmt has no member 'allocPrintZ'` | 1 | test (4820) — 切 `dupeSentinel + allocPrint` |
| 18 | `incompatible types: 'void' and 'u64'` + 其他 | 2 | api.zig (4459 `file.readAll` 语义变, 需重写为 `readToEndAlloc`/loop) |

详细行号清单见 `/tmp/node_err.txt` (`zig build test 2>&1 | grep error:` 生成, 129 行含汇总行).

## 2. 对标修法 (已迁移插件)

- `sa_plugin_bun@be2ddbe`: `sio.cwd/openFileAbsolute/createFileAbsolute/access`, `dupeSentinel`, `sio.io().random`, 手写 hex, `flate.Compress/Decompress`, `sio.Child.run` + `.exited`, `gzip→flate`
- `sa_plugin_http_client@150fb99/ba6a67e`: `std.net→std.Io.net` (`IpAddress.parse/listen(sio.io())/accept(sio.io())/deinit(sio.io())`, `socket.address.getPort()`, `HostName.connect` 代 `tcpConnectToHost`), `TcpConn.writer/read`, `sleepNs`, `sio.cwd/Child`
- `sa_plugin_http_server@b01f5c5/90ad889`: `Io.net serve`, `std.c.accept4/read`, `setNonBlocking`, `Mutex: tryLock spin`
- `sci/src/sa_io.zig` (737 行, 权威 shim): `sio.io/cwd/Dir/File/openFileAbsolute/openDirAbsolute/createFileAbsolute/renameAbsolute/copyFileAbsolute/readFileAbsoluteAlloc/getCwdAlloc/nanoTimestamp/random/Child(argsAlloc/spawn/wait/run/.exited)/managedWriter/managedPrint/getStdOut/getStdErr`

## 3. 分批修复计划

> 进展 2026-10-18: **S5-a 已完成并推送** (`05aa7fb` + random/hex 待提交)。
> 错误数 128 → **105** (Mutex 12 / managedWriter真指针 10 / random 5 / timing 1 / hex 5+test1 / `**`空格 全消)。
> 新浮现 (被早期错误掩盖): `tls.Client read/writeAll` x2, `Ip6Address.scope_id`, `Io.net.Stream.handle`, `expected error union found usize` x1。

- [x] **S5-a 机械批**: `Mutex.lock→spinLock` (12), `managedWriter(&out→out)` 真指针点 (10, 按函数作用域+阴影判断),
> `crypto.random→sio.io().random` (5), `timingSafeEql→timing_safe.eql` (1), `fmtSliceHexLower→手写hex` (api 3 + ext 1),
> `**` 空格 (`}.{0}**16`, `[_]u8{...}**32`) — 已推送 `05aa7fb`, 本批剩余 random/hex 待提交
- [ ] **S5-b fs/posix 批 (约 35 个)**: `fs.cwd/File/Dir→sio` (20), `*Absolute→Io.Dir.*Absolute(sio.io())` (6), `posix socket/close/bind/connect/recvfrom/sendto/getsockname/getpeername/setsockopt→std.c/os.linux/Io.net` (deep socket, 与 S4 checkpoint 描述一致), `pipe→std.c.pipe`, `write→std.c.write`, `linkat/symlinkat/futimens/fsync/fchown→std.c.*`, `readAll(void)调用点重写` (9, 切 `readToEndAlloc` 或 streaming read loop), `writeFile/makePath/realpathAlloc` (4)
- [ ] **S5-c net/TLS/DNS 大批 (约 35 个)**: `std.net.Address/Stream/Server/tcpConnectToHost/getAddressList/connectUnixSocket→std.Io.net` (30, 对标 http_client `dialHost`: `IpAddress.parse else HostName.connect`), `SaNetObject/TlsClientHandle stream 字段类型`, `Bundle map/rescan/parseCert` (2+ 周边 `tlsBuildBundle*`), `dgram raw fd 路径` (api.zig 3823-4240, 需 `std.c.socket` + `Io.net.Socket` 决策 — 最大风险点)
- [ ] **S5-d tests 批 (19 个)**: `socket/pipe/net/Server/cwd/realpathAlloc/writeFile/sleep` 全量对标 http_client `150fb99` (TcpConn helper + `server.socket.address.getPort()` + `sleepNs`)
- [ ] **验证**: `zig build test --summary all -Dsci-root=/content/sa_all/sci` 全绿 → `sa .sa 测试` (node_test_*.sa) → `zig fmt` → commit → `GIT_TOKEN` push `0.17`
- [ ] **推送**: `git push origin 0.17` (用 `GIT_TOKEN` 全局变量, 不要落盘), 确认 `ahead 0`

## 4. 风险提示

- `SaDgramSocket` raw-posix 整段 (socket/connect/recvfrom/sendto/blocklist) 在 0.17 无 `std.posix.socket` 直路, 需 `std.c.socket + std.os.linux` 手工封装, 或迁 `std.Io.net.Socket/bind/connect` — 改动面大, 先做 S5-a/b 留出编译, 再集中攻坚
- `Certificate.Bundle` API 变化 (`rescan(gpa,io,now)`, `bytes: ArrayList` 非 Managed) 会连带 `tlsBuildBundleFromPem/System` 重写
- `sio.File.readAll(&buf)` 返回 `void` (非 `usize`), 所有 `if (file.readAll(&buf)) |n|` 模式必须重写, 不能简单 sed

## 5. 下一步 (紧接着做)

1. S5-a: `spinLock` + hex + random + managedWriter + comptime_int + Child/sleep (先把错误数从 128 压到 ~85)
2. 每批 `zig build test` 抽 `grep error:` 计数, 更新本文件
