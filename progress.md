# sa_plugin_node Progress

## Tracking Basis

- Scope: public non-VM/V8 Node top-level facade compatibility modules
- Progress rule: update this file after each completed module feature
- Current status: `35 / 43` modules completed (`81.4%`)

## Completed Modules

- `assert`
- `async_hooks`
- `buffer`
- `child_process`
- `cluster`
- `console`
- `crypto`
- `constants`
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
- `perf_hooks`
- `readline`
- `repl`
- `report`
- `sea`
- `stream`
- `sys`
- `test`
- `timers`
- `trace_events`
- `tls`
- `tty`
- `util`
- `wasi`
- `worker_threads`

## Remaining Modules In Current Sweep

- `os`
- `path`
- `process`
- `punycode`
- `querystring`
- `string_decoder`
- `url`
- `zlib`

## Notes

- This file tracks the current public non-VM/V8 top-level facade sweep.
- The current denominator is the set of public Node modules in `lib/` that are not VM/V8-exclusive and do not live only as internal path variants such as `path/posix`, `path/win32`, `assert/strict`, `dns/promises`, `fs/promises`, `stream/promises`, `timers/promises`, or `util/types`.
