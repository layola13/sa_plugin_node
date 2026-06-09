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

- Scope: installed main `node.sal` public macro coverage for `zlib`
- Current status: `1 / 1` helper features completed (`100.0%`)
- Planned helpers:
  - `zlib` top-level metadata, raw/brotli/zstd helpers, and codes/constants macros available through `node.sal`

## Recent Completed Helper Features

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
