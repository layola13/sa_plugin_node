# sa_plugin_node Progress

## Tracking Basis

- Scope: public non-VM/V8 Node top-level facade compatibility modules
- Progress rule: update this file after each completed module feature
- Current status: `43 / 43` modules completed (`100.0%`)

## Completed Modules

- `async_hooks`
- `assert`
- `buffer`
- `child_process`
- `cluster`
- `console`
- `constants`
- `crypto`
- `diagnostics_channel`
- `dgram`
- `dns`
- `domain`
- `events`
- `fs`
- `http`
- `http2`
- `https`
- `inspector`
- `module`
- `net`
- `os`
- `path`
- `punycode`
- `perf_hooks`
- `process`
- `querystring`
- `readline`
- `repl`
- `report`
- `sea`
- `stream`
- `string_decoder`
- `sys`
- `test`
- `timers`
- `trace_events`
- `tls`
- `tty`
- `url`
- `util`
- `wasi`
- `worker_threads`
- `zlib`

## Remaining Modules In Current Sweep

- None in the current non-VM/V8 public top-level facade sweep.

## Notes

- This file tracks the current public non-VM/V8 top-level facade sweep.
- The current denominator is the set of public Node modules in `lib/` that are not VM/V8-exclusive and do not live only as internal path variants such as `path/posix`, `path/win32`, `assert/strict`, `dns/promises`, `fs/promises`, `stream/promises`, `timers/promises`, or `util/types`.

## Current Helper Tranche

- Scope: network DNS RRtype dispatch alignment for direct `node.sai` ABI `sa_node_plugin_dns_resolve`
- Current status: `1 / 1` helper features completed (`100.0%`)
- Planned helpers:
  - Direct `sa_node_plugin_dns_resolve` C-ABI calls reuse the existing native resolver surface for A, AAAA, CNAME, MX, NS, TXT, SRV, PTR, CAA, NAPTR, SOA, TLSA, and ANY instead of only the base A-record helper

## Recent Completed Helper Features

- network DNS direct ABI RRtype dispatch alignment completed:
  - Direct `node.sai` callers of `sa_node_plugin_dns_resolve` now reuse the same existing native resolver dispatch path as `dns.promises.resolve`
  - `tests/node_test_dns_resolve.sa` now validates non-A RRtype dispatch through both the public `node.sal` macro and direct `node.sai` ABI call

- network DNS RRtype dispatch alignment completed:
  - Top-level `NODE_DNS_RESOLVE` now reuses the existing native resolver implementation exposed through `node_extra.sai`, keeping the public `node.sal` facade aligned with the broader resolver and `dns.promises.resolve` behavior
  - `tests/node_test_dns_resolve.sa` now validates non-A RRtype dispatch through `node.sal`

- installed main `node.sal` vfs helper macro tranche completed:
  - VFS status, lifecycle, file read/write/open handle, directory iteration, metadata, mutation, symlink, watcher, cwd, realpath, and snapshot helpers available through `node.sal`
  - `tests/node_test_vfs.sa` validates common VFS operations through `node.sal` only

- installed main `node.sal` sqlite helper macro tranche completed:
  - SQLite status/version, open/close, exec/query, prepared statement, bind/reset/clear/finalize, changes/rowid, backup, session/changeset, apply_changeset, and SQLTagStore helpers available through `node.sal`
  - `tests/node_test_sqlite.sa` validates common sqlite operations through `node.sal` only

- installed main `node.sal` ffi helper macro tranche completed:
  - FFI status, `open`, `close`, `hasSymbol`, `call_i64_0/1/2`, `call_strlen`, `call_string_i64`, and `call_ptr_string` helpers available through `node.sal`
  - `tests/node_test_ffi.sa` validates through `node.sal` only

- installed main `node.sal` web_crypto/web_streams helper macro tranche completed:
  - `web_crypto` random values, UUID, digest, raw key import/generation/export, sign/verify, encrypt/decrypt, and key-free helpers available through `node.sal`
  - `web_streams` readable/writable/transform construction, enqueue/write/read, snapshot, close, and free helpers available through `node.sal`
  - `tests/node_test_web_crypto_streams.sa` validates through `node.sal` only

- installed main `node.sal` punycode/tty compatibility helper tranche completed:
  - `punycode.toASCII` and legacy `tty` status macros available through `node.sal`
  - `tests/node_test_punycode_tty_misc.sa` validates through `node.sal` only

- installed main `node.sal` timers.promises helper macro tranche completed:
  - `timers.promises` setTimeout, setImmediate, scheduler.wait, scheduler.yield, setInterval, interval next/return/snapshot/free helpers available through `node.sal`
  - `tests/node_test_timers_promises.sa` validates through `node.sal` only

- installed main `node.sal` fs/fs.promises helper macro tranche completed:
  - `fs` descriptor open/close/read/write, fstat/fchmod/fchown/fsync/fdatasync/ftruncate/futimes, chmod/chown, glob, link/symlink/readlink, mkdtemp, opendir, rm, statfs, truncate, utimes, vector-IO, top-level metadata, and `fs.promises` helpers available through `node.sal`
  - `tests/node_test_fs_top.sa`, `node_test_fs_extra.sa`, `node_test_fs_extra1.sa`, `node_test_fs_extra2.sa`, `node_test_fs_extra3.sa`, `node_test_fs_extra4.sa`, `node_test_fs_extra5.sa`, and `node_test_fs_extra6.sa` validate through `node.sal` only

- installed main `node.sal` crypto helper macro tranche completed:
  - `crypto` incremental hash/HMAC, HKDF, scrypt, randomInt, randomFill, cipher/decipher lifecycle, sign/verify, key-generation, hash-list, top-level metadata, and secure-heap helpers available through `node.sal`
  - `tests/node_test_crypto_top.sa`, `node_test_crypto_extra.sa`, `node_test_crypto_cipher.sa`, and `node_test_crypto_verify.sa` now validate through `node.sal` only

- installed main `node.sal` perf_hooks helper macro tranche completed:
  - `perf_hooks` status, exports, supported-entry-types, constants, performance, feature-support, `now`, `timeOrigin`, `mark`, `measure`, entries, clear helpers, histogram helpers, event-loop utilization, and `timerify` helpers available through `node.sal`
  - `tests/node_test_perf_hooks_top.sa`, `node_test_perf_extra.sa`, `node_test_perf_entries.sa`, and `node_test_perf_tty.sa` now validate through `node.sal` only

- installed main `node.sal` web_crypto/web_streams status helper tranche completed:
  - `web_crypto` and `web_streams` status helpers available through `node.sal`
  - `tests/node_test_status_json10.sa`, `node_test_status_json11.sa`, and `node_test_status_json12.sa` now validate through `node.sal` only, reusing existing `repl`, `test_runner`, and `https` status support already present in `node.sal`

- installed main `node.sal` cluster helper macro tranche completed:
  - `cluster` status, exports, primary-config, feature-support, primary setup, scheduling-policy, primary snapshot, fork, and worker lifecycle/message helpers available through `node.sal`
  - `tests/node_test_cluster.sa`, `node_test_cluster_top.sa`, and `node_test_status_json2.sa` now validate through `node.sal` only

- installed main `node.sal` diagnostics_channel status helper tranche completed:
  - `diagnostics_channel` status helper available through `node.sal`
  - `tests/node_test_status_json5.sa` now validates through `node.sal` only, reusing existing `wasi` status support already present in `node.sal`

- installed main `node.sal` child_process helper macro tranche completed:
  - `child_process` status, exports, config, feature-support, `exec`, `execFile`, `execFileSync`, `execSync`, `spawn`, `spawnSync`, and `fork` helpers available through `node.sal`
  - `tests/node_test_child_process.sa`, `node_test_child_process_top.sa`, `node_test_child_exec.sa`, `node_test_child_execfile.sa`, `node_test_child_spawn.sa`, `node_test_child_fork.sa`, and `node_test_child_fork2.sa` now validate through `node.sal` only

- installed main `node.sal` debugger helper macro tranche completed:
  - `debugger` status helper available through `node.sal`
  - `tests/node_test_status_json6.sa` now validates through `node.sal` only

- installed main `node.sal` permissions/iterable_streams helper macro tranche completed:
  - `permissions` status, enabled/audit-mode flags, available/declared manifests, and scope-check helpers available through `node.sal`
  - `iterable_streams` status, stream-types, capabilities, bridge, stream-type check, and capability check helpers available through `node.sal`
  - `tests/node_test_permissions.sa`, `node_test_iterable_streams.sa`, and `node_test_status_json9.sa` now validate through `node.sal` only

- installed main `node.sal` errors/internationalization helper macro tranche completed:
  - `errors` status, code tables, system error name/message/json, `invalidArgType`, `invalidArgValue`, and `outOfRange` helpers available through `node.sal`
  - `internationalization` status, config, effective-locale, supported-encodings, encoding check, and ICU-config helpers available through `node.sal`
  - `tests/node_test_errors.sa`, `node_test_internationalization.sa`, and `node_test_status_json8.sa` now validate through `node.sal` only

- installed main `node.sal` deprecated helper macro tranche completed:
  - `deprecated` status, flags, `record`, snapshot, `clear`, and `has` helpers available through `node.sal`
  - `tests/node_test_deprecated.sa` and `node_test_status_json7.sa` now validate through `node.sal` only

- installed main `node.sal` command_line_options helper macro tranche completed:
  - `command_line_options` status, argv, `NODE_OPTIONS` token parsing, env-file enumeration, and `hasFlag` helpers available through `node.sal`
  - `tests/node_test_command_line_options.sa` now validates through `node.sal` only

- installed main `node.sal` sea helper macro tranche completed:
  - `sea` status, top-level status/exports/config/feature-support, `isSea`, asset-keys, `getAsset`, `getRawAsset`, and `getAssetAsBlob` helpers available through `node.sal`
  - `tests/node_test_sea.sa`, `node_test_sea_top.sa`, `node_test_sea_extra.sa`, `node_test_sea_get_asset.sa`, `node_test_sea_raw.sa`, and `node_test_sea_blob.sa` now validate through `node.sal` only

- installed main `node.sal` report helper macro tranche completed:
  - `report` status, `getReport`, `writeReport`, exports, config, and feature-support helpers available through `node.sal`
  - `tests/node_test_report.sa`, `node_test_report_top.sa`, and `node_test_report_write.sa` now validate through `node.sal` only

- installed main `node.sal` environment_variables helper macro tranche completed:
  - `environment_variables` status, snapshot, `has`, `get`, `parseEnv`, and `loadEnvFile` helpers available through `node.sal`
  - `tests/node_test_environment_variables.sa` now validates through `node.sal` only

- installed main `node.sal` os/process helper macro tranche completed:
  - `os` top-level status, exports, config, feature-support, constants, priority, `EOL`, and `devNull` helpers available through `node.sal`
  - `process` top-level status, exports, config, feature-support, exec-path, argv0, exec-argv, allowed-flags, emit-warning, kill, resource-usage, memory/features, arch/platform/release, `umask`, `chdir`, and argv-json helpers available through `node.sal`
  - dependent `path.sep` and `path.delimiter` helpers used by `tests/node_test_os_process.sa` available through `node.sal`
  - `tests/node_test_os_top.sa`, `node_test_process_top.sa`, `node_test_process_extra.sa`, `node_test_os_extra.sa`, and `node_test_os_process.sa` now validate through `node.sal` only

- installed main `node.sal` events helper macro tranche completed:
  - `events` top-level status, exports, config, and feature-support helpers available through `node.sal`
  - `events.once`, `off`, `removeAllListeners`, `prependListener`, `setMaxListeners`, `getMaxListeners`, `getEventListeners`, `listenerCount` by event, and `emitWithError` helpers available through `node.sal`
  - `tests/node_test_events_top.sa` and `node_test_events_extra.sa` now validate through `node.sal` only

- installed main `node.sal` async_hooks helper macro tranche completed:
  - `async_hooks` top-level status, exports, config, feature-support, snapshot, execution/trigger async-id, and async-resource create/free/snapshot helpers available through `node.sal`
  - `async_context_tracking` status, snapshot, enter, exit, depth, reset, and execution/trigger async-id helpers available through `node.sal`
  - `tests/node_test_async_hooks_top.sa`, `node_test_async_hooks.sa`, `node_test_async_extra.sa`, and `node_test_async_context_tracking.sa` now validate through `node.sal` only

- installed main `node.sal` worker_threads helper macro tranche completed:
  - `worker_threads` top-level status, exports, `SHARE_ENV`, parent-port, and feature-support helpers available through `node.sal`
  - `worker_threads` thread-id, main/internal-thread flags, thread-name, worker-data, resource-limits, environment-data, message-channel, message-port, `receiveMessageOnPort`, and `postMessageToThread` helpers available through `node.sal`
  - `tests/node_test_worker_threads_top.sa`, `node_test_worker_threads.sa`, `node_test_worker_extra.sa`, `node_test_worker_extra2.sa`, `node_test_worker_env.sa`, `node_test_worker_edata.sa`, `node_test_worker_recvport.sa`, `node_test_worker_msgport.sa`, `node_test_worker_msgport2.sa`, and `node_test_worker_ptt.sa` now validate through `node.sal` only

- installed main `node.sal` test helper macro tranche completed:
  - `test` top-level status, exports, config, reporters, assert-support, property-support, and feature-support helpers available through `node.sal`
  - `test_runner` status, builtin-reporters, config, and `hasBuiltinReporter` helpers available through `node.sal`
  - `tests/node_test_test_top.sa`, `node_test_test_module.sa`, and `node_test_test_runner.sa` now validate through `node.sal` only

- installed main `node.sal` inspector helper macro tranche completed:
  - `inspector` top-level status, exports, enabled, allowed, config, url, and feature-support helpers available through `node.sal`
  - `tests/node_test_inspector_top.sa` now validates through `node.sal` only

- installed main `node.sal` repl helper macro tranche completed:
  - `repl` top-level status, exports, default-config, and feature-support helpers available through `node.sal`
  - `repl` createSession, setPrompt, defineCommand, evalLine, history, snapshot, close, and free helpers available through `node.sal`
  - `tests/node_test_repl_top.sa` and `node_test_repl.sa` now validate through `node.sal` only

- installed main `node.sal` module helper macro tranche completed:
  - `module` top-level status, exports, config, builtin-modules, constants, global-paths, and feature-support helpers available through `node.sal`
  - `module.isBuiltin`, `findPackageJSON`, compile-cache helpers, source-map support helpers, and `findSourceMap` available through `node.sal`
  - `tests/node_test_module_top.sa` and `node_test_module.sa` now validate through `node.sal` only

- installed main `node.sal` domain helper macro tranche completed:
  - `domain` top-level status, exports, active, and feature-support helpers available through `node.sal`
  - `domain` create, add, remove, enter, exit, dispose, getActive, memberCount, snapshot, and free helpers available through `node.sal`
  - `tests/node_test_domain_top.sa` and `node_test_domain.sa` now validate through `node.sal` only

- installed main `node.sal` diagnostics_channel helper macro tranche completed:
  - `diagnostics_channel` top-level status, exports, factories, and feature-support helpers available through `node.sal`
  - `diagnostics_channel` create, subscribe, unsubscribe, publish, hasSubscribers, free, snapshot, and tracingChannel helpers available through `node.sal`
  - `tests/node_test_diagnostics_channel_top.sa`, `node_test_diag_channel.sa`, and `node_test_diag_snapshot.sa` now validate through `node.sal` only

- installed main `node.sal` assert/constants helper macro tranche completed:
  - `assert` top-level status, exports, config, feature-support, `ok`, `equal`, `deepStrictEqual`, `fail`, and strict-config helpers available through `node.sal`
  - `constants` top-level status, exports, config, feature-support, and constants JSON helpers available through `node.sal`
  - `tests/node_test_assert_top.sa`, `node_test_constants_top.sa`, and `node_test_assert_constants_sys.sa` now validate through `node.sal` only

- installed main `node.sal` sys helper macro tranche completed:
  - `sys` top-level status, exports, config, feature-support, and deprecation helpers available through `node.sal`
  - `sys.format`, `sys.inspect`, `sys.debuglog`, and `sys.inherits` available through `node.sal`
  - `tests/node_test_sys_top.sa` now validates through `node.sal` only

- installed main `node.sal` trace_events helper macro tranche completed:
  - `trace_events` top-level status, exports, config, and feature-support helpers available through `node.sal`
  - `trace_events.createTracing`, `enable`, `disable`, `getEnabledCategories`, and `free` helpers available through `node.sal`
  - `tests/node_test_trace_events_top.sa`, `node_test_trace_events.sa`, and `node_test_trace_extra.sa` now validate through `node.sal` only

- installed main `node.sal` wasi helper macro tranche completed:
  - `wasi` top-level status, exports, config, supported-versions, import-modules, allow-state, and feature-support helpers available through `node.sal`
  - `tests/node_test_wasi_top.sa` now validates through `node.sal` only

- installed main `node.sal` tty helper macro tranche completed:
  - `tty` top-level metadata helpers available through `node.sal`
  - `tty.isatty`, `tty.ReadStream`, `tty.WriteStream`, raw-mode, window-size, color-depth, has-colors, and free helpers available through `node.sal`
  - `tests/node_test_tty_top.sa` and `node_test_tty_extra.sa` now validate through `node.sal` only

- installed main `node.sal` zlib helper macro tranche completed:
  - `zlib` top-level metadata, constants, and codes helpers available through `node.sal`
  - `zlib.deflateRaw`, `zlib.inflateRaw`, `zlib.unzip`, `zlib.brotliCompress`, `zlib.brotliDecompress`, `zlib.zstdCompress`, `zlib.zstdDecompress`, and `zlib.crc32` available through `node.sal`
  - `tests/node_test_zlib_top.sa`, `node_test_zlib_extra.sa`, `node_test_zlib_inflate_raw.sa`, and `node_test_zlib_buffer_url.sa` now validate through `node.sal` only

- installed main `node.sal` util helper macro tranche completed:
  - `util` top-level metadata helpers available through `node.sal`
  - `tests/node_test_util_top.sa` now validates through `node.sal` only

- installed main `node.sal` querystring/punycode/readline.promises helper macro tranche completed:
  - `querystring` top-level metadata helpers and `querystring.unescapeBuffer` available through `node.sal`
  - `punycode` top-level metadata helpers, `punycode.version`, and `punycode.toUnicode` available through `node.sal`
  - `readline.promises` create/question/close/snapshot/free helpers available through `node.sal`
  - `tests/node_test_querystring_top.sa`, `node_test_punycode_top.sa`, and `node_test_buffer_timers.sa` now validate through `node.sal` only

- installed main `node.sal` buffer/timers/string_decoder helper macro tranche completed:
  - `buffer` top-level metadata, constants, base64, encoding-check, transcode, and object-url helper macros available through `node.sal`
  - `timers` top-level metadata and basic `setTimeout` / `setInterval` / `setImmediate` clear helper macros available through `node.sal`
  - `string_decoder` top-level metadata helpers available through `node.sal`
  - `tests/node_test_buffer_top.sa`, `node_test_timers_top.sa`, and `node_test_string_decoder_top.sa` now validate through `node.sal` only

- installed main `node.sal` readline helper macro tranche completed:
  - `readline` top-level metadata helpers available through `node.sal`
  - `readline.clearLine`, `readline.clearScreenDown`, `readline.cursorTo`, `readline.moveCursor`, `readline.emitKeypressEvents`, and `readline.createInterface` available through `node.sal`
  - `tests/node_test_readline_top.sa` and `node_test_readline_q.sa` now validate through `node.sal` only

- installed main `node.sal` path helper macro tranche completed:
  - `path` top-level metadata helpers available through `node.sal`
  - `path.matchesGlob` available through `node.sal`
  - `tests/node_test_path_top.sa` and `node_test_path_extra.sa` now validate through `node.sal` only

- installed main `node.sal` console helper macro tranche completed:
  - `console` top-level metadata helpers available through `node.sal`
  - `console.warn`, `console.info`, `console.debug`, `console.dir`, `console.dirxml`, `console.trace`, `console.table`, `console.assert`, `console.count`, `console.countReset`, `console.group`, `console.groupCollapsed`, `console.groupEnd`, `console.timeLog`, and `console.timeStamp` available through `node.sal`
  - `tests/node_test_console_top.sa` and `node_test_console_extra.sa` now validate through `node.sal` only

- installed main `node.sal` quic/http3/dtls helper macro tranche completed:
  - `quic` endpoint helpers available through `node.sal`
  - `http3` metadata and session helpers available through `node.sal`
  - `dtls` metadata and endpoint helpers available through `node.sal`
  - `tests/node_test_quic_http3_extra.sa` and `node_test_quic_dtls.sa` now validate through `node.sal` only

- installed main `node.sal` http2 helper macro tranche completed:
  - `http2` settings / constants / handshake macros available through `node.sal`
  - `tests/node_test_http2_extra.sa` now validates through `node.sal` only

- installed main `node.sal` net helper macro tranche completed:
  - `net` create / socket-address / blocklist / lifecycle macros available through `node.sal`
  - `tests/node_test_net_extra.sa`, `node_test_net_create.sa`, and `node_test_net_full.sa` now validate through `node.sal` only

- installed main `node.sal` stream helper macro tranche completed:
  - `stream` top-level / constructor / pipeline / destroy macros available through `node.sal`
  - `tests/node_test_stream_top.sa`, `node_test_streams_extra.sa`, `node_test_stream_pipeline.sa`, `node_test_stream_finished.sa`, `node_test_stream_destroy.sa`, and `node_test_stream_compose.sa` now validate through `node.sal` only
- installed main `node.sal` url/util helper macro tranche completed:
  - `url` metadata / handle / helper macros available through `node.sal`
  - dependent `util` helper macros used by `tests/node_test_url_util_extra.sa` available through `node.sal`
  - `tests/node_test_url_top.sa`, `node_test_url_helper_tranche.sa`, and `node_test_url_util_extra.sa` now validate through `node.sal` only
- installed main `node.sal` tls helper macro tranche completed:
  - `tls` cipher / CA / secure-context / socket macros available through `node.sal`
  - `tests/node_test_tls_extra.sa` now validates through `node.sal` only
  - `tests/node_test_tls_main.sa` compile-checks the wider `tls` connect and socket helper surface through `node.sal`
- installed main `node.sal` http/https macro tranche completed:
  - `http` metadata / request / client / server / websocket macros available through `node.sal`
  - `https` metadata / request helper macros available through `node.sal`
  - `tests/node_test_http_top.sa`, `node_test_https_top.sa`, and `node_test_http_extra.sa` now validate through `node.sal` only
  - `tests/node_test_http_main.sa` compile-checks the wider `http` client/server/websocket surface through `node.sal`
- installed main `node.sal` dns.promises macro tranche completed:
  - `dns.promises` lookup / resolve / resolver macros available through `node.sal`
  - `tests/node_test_dns_extra.sa` now validates the promise helpers through `node.sal` only
  - `tests/node_test_dns_promises_main.sa` compile-checks the full `dns.promises` surface through `node.sal`
- installed main `node.sal` dns/net/dgram macro tranche completed:
  - `dns` top-level and resolver macros available through `node.sal`
  - `net` top-level factory/status macros available through `node.sal`
  - `dgram` top-level macros available through `node.sal`
- installed main `node.sal` network top-level macro tranche completed:
  - `http2` top-level macros available through `node.sal`
  - `quic` top-level macros available through `node.sal`
  - `http3` top-level macros available through `node.sal`
  - `dtls` top-level macros available through `node.sal`
  - `tls` top-level macros available through `node.sal`
- installed SA public facade aggregation tranche completed:
  - installed `node.sal` imports `node_extra.sai`
  - published plugin interface metadata includes `node_extra` companions
- `dtls` top-level metadata tranche completed:
  - `dtls.exports`
  - `dtls.config`
  - `dtls.featureSupport`
  - `dtls` top-level status alignment
- `quic` top-level metadata tranche completed:
  - `quic.exports`
  - `quic.config`
  - `quic.featureSupport`
  - `quic` top-level status alignment
- `http3` top-level metadata tranche completed:
  - `http3.exports`
  - `http3.config`
  - `http3.featureSupport`
  - `http3` top-level status alignment
- `process` cpu usage helper tranche completed:
  - `process.cpuUsage`
- `process` credential helper tranche completed:
  - `process.geteuid`
  - `process.getegid`
  - `process.getgroups`
- `process` warning-surface alignment tranche completed:
  - `process.emitWarning` top-level status
- `readline` interface helper tranche completed:
  - `readline.createInterface`
- `module` source-map helper tranche completed:
  - `module.findSourceMap`
- `process` warning helper tranche completed:
  - `process.emitWarning`
- `sys` helper tranche completed:
  - `sys.inherits`
- `process` command-line flag helper tranche completed:
  - `process.allowedNodeEnvironmentFlags`
- `fs` path-mutation helper tranche completed:
  - `fs.symlink`
  - `fs.truncate`
  - `fs.utimes`
  - `fs.promises.symlink`
  - `fs.promises.truncate`
  - `fs.promises.utimes`
- `util` string normalization helper tranche completed:
  - `util.toUSVString`
- `util` text codec helper tranche completed:
  - `util.TextEncoder`
  - `util.TextDecoder`
- `process` command-line helper tranche completed:
  - `process.execPath`
  - `process.argv0`
  - `process.execArgv`
- `crypto` helper tranche completed:
  - `crypto.secureHeapUsed`
- `util` helper tranche completed:
  - `util.formatWithOptions`
- `path` helper tranche completed:
  - `path.toNamespacedPath`
- `net` helper tranche completed:
  - `net.BlockList.isBlockList`
  - `net.SocketAddress.isSocketAddress`
- `tls` helper tranche completed:
  - `tls.checkServerIdentity`
- `http2` helper tranche completed:
  - `http2.performServerHandshake`
- `fs` helper tranche completed:
  - `fs.cp`
  - `fs.promises.cp`
- `zlib` helper tranche completed:
  - `zlib.constants`
  - `zlib.codes`
- `punycode` helper tranche completed:
  - `punycode.version`
- `buffer` helper tranche completed:
  - `buffer.constants` / `buffer.kMaxLength` / `buffer.kStringMaxLength`
- `string_decoder` helper tranche completed:
  - `StringDecoder.end`
- `process` helper tranche completed:
  - `process.release`
  - `process.umask`
  - `process.chdir`
- `url` helper tranche completed:
  - `url.urlToHttpOptions`
- `console` helper tranche completed:
  - `console.time`
  - `console.timeEnd`
  - `console.clear`
- `process`/`os` helper tranche completed:
  - `process.arch`
  - `process.platform`
  - `process.version`
  - `os.devNull`
  - `os.EOL`
- `util` helper tranche completed:
  - `parseEnv`
  - `getSystemErrorName`
  - `getSystemErrorMessage`
  - `getSystemErrorMap`
- `url` helper tranche completed:
  - `domainToASCII`
  - `domainToUnicode`
  - `pathToFileURL`
  - `fileURLToPath`
  - `fileURLToPathBuffer`
  - `canParse`
