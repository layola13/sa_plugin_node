# sa_plugin_node Progress

## Tracking Basis

- Scope: public non-VM/V8 Node top-level facade compatibility modules
- Progress rule: update this file after each completed module feature
- Current status: `39 / 43` modules completed (`90.7%`)

## Completed Modules

- `async_hooks`
- `assert`
- `buffer`
- `child_process`
- `cluster`
- `console`
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

- `constants`
- `module`
- `sys`
- `test`

## Notes

- This file tracks the current public non-VM/V8 top-level facade sweep.
- The current denominator is the set of public Node modules in `lib/` that are not VM/V8-exclusive and do not live only as internal path variants such as `path/posix`, `path/win32`, `assert/strict`, `dns/promises`, `fs/promises`, `stream/promises`, `timers/promises`, or `util/types`.
