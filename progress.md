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

- Scope: public non-VM/V8 `net` helper parity by exposing native static handle-type checks
- Current status: `2 / 2` helper features completed (`100.0%`)
- Planned helpers:
  - `net.BlockList.isBlockList`
  - `net.SocketAddress.isSocketAddress`

## Recent Completed Helper Features

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
