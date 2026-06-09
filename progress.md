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

- Scope: explicit `http3` top-level facade metadata over the existing native session/datagram subset
- Current status: `4 / 4` helper features completed (`100.0%`)
- Planned helpers:
  - `http3.exports`
  - `http3.config`
  - `http3.featureSupport`
  - `http3` top-level status alignment

## Recent Completed Helper Features

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
