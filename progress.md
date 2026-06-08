# sa_plugin_node Progress

## Tracking Basis

- Scope: common non-VM/V8 Node top-level facade compatibility modules
- Progress rule: update this file after each completed module feature
- Current status: `29 / 31` modules completed (`93.5%`)

## Completed Modules

- `assert`
- `async_hooks`
- `child_process`
- `cluster`
- `console`
- `constants`
- `diagnostics_channel`
- `dgram`
- `dns`
- `domain`
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
- `tls`
- `tty`
- `wasi`
- `worker_threads`

## Remaining Modules In Current Sweep

- `events`
- `trace_events`

## Notes

- This file tracks the current top-level facade completion sweep only.
- If the audit finds another non-VM/V8 common module that should be in this sweep, increase the denominator before updating the percentage.
