# @kernelforge/ntsim-analyzer

Run-any-`.sys` harness: map → `DriverEntry` → deferred drains → scripted IOCTLs → report.
Pair with `@kernelforge/linux-analyzer` (`analyzeKo`) for `.ko` files. Same code runs in
Node tests and in the browser (no `fs`, no `Buffer`).

```js
import { analyzeDriver } from "@kernelforge/ntsim-analyzer";
const report = await analyzeDriver(bytes, { backendName: "js" });
```

## CLI mode (`kf-analyze`)

The repo ships a small unified CLI for `.sys` and `.ko` (Linux support via
`@kernelforge/linux-analyzer`). No build step, Node `>=20`.

### Install

```bash
# from a checkout of kernelforge-analyzer (or the Kasm monorepo)
npm install

# or global from npm (also pulls @kernelforge/ntsim + struct tables)
npm install -g @kernelforge/ntsim-analyzer @kernelforge/linux-analyzer
```

`z3-solver` is only needed for concolic / find-bugs flows, not for plain CLI runs.
`--backend=qemu` additionally needs `qemu-system-x86_64` on `PATH`
(or `QEMU_PATH=/path/to/qemu-system-x86_64`).

### Use

```bash
# Windows driver, deterministic JS backend, full JSON report to stdout
kf-analyze driver.sys --backend=js

# auto-drive harvested IOCTLs, save report to a file
kf-analyze driver.sys --auto-irp --max-codes 16 --json report.json

# scripted IOCTLs (repeat --ioctl), hex input, custom output length
kf-analyze driver.sys --ioctl 0x222003 --ioctl 0x222007 --input deadbeef --output-len 128

# invoke DriverUnload at the end
kf-analyze driver.sys --ioctl 0x222003 --run-unload

# Linux LKM (unlocked_ioctl is the default file_op)
kf-analyze mod.ko --auto-ops --json report.json
kf-analyze mod.ko --op unlocked_ioctl --ioctl 0x1234 --input 00ff

# from a repo checkout without a global install
node packages/ntsim-analyzer/bin/kf-analyze.mjs driver.sys --auto-irp
node tools/kf-analyze.mjs driver.sys --help     # same CLI, shortcut path
npm run analyze -- driver.sys --auto-irp        # monorepo script alias
```

Useful flags: `--backend=js|hybrid|unicorn|qemu`, `--tables=<dir>` (Vergilius
struct tables, `.sys` only), `--quiet` (JSON only, no progress on stderr),
`--help` for the full list.

### Report surfaces

`analyzeDriver` returns, alongside `load`/`entry`/`ioctls`/`trace`:

- `arch` + `archEvents` — CPUID/MSR/TSC/port-I/O counters and the hot leaves
  and MSRs the driver touched. Virtualization is on by default; disable with
  `arch: false` or tune with `{ intel: true, hypervisor: true, timing: false }`
  (CLI: `--no-arch`, `--intel`, `--hv`).
- `detections` — probe classifier: PE-header scans, KUSD/hypervisor-page reads,
  system-module and kernel-struct probes, driver self-reads (header/IAT),
  SEH accept/reject telemetry, stuck-`STATUS_ACCESS_DENIED` runs, plus a
  timeline of the last events. Disable with `diag: false` (CLI: `--no-diag`).
- `callbacks` — simulated process/thread/image notify events, Ob pre/post
  handle operations (pre-op access stripping is surfaced as
  `accessStripped`), and Cm registry callbacks with blocking status. Disable
  with `simulateEvents: false` (CLI: `--no-events`).
- `bugcheck` + `bugcheckText` — named stop code, decoded parameters,
  double/triple-fault status and a register/stack/RBP-chain post-mortem.
- `registryActivity` — real driver registry mutations (writes/creates/deletes)
  classified into self service key / security policy / boot config / other
  services / user / BCD, plus emulator auto-created key count. Replaces reading
  `registryWrites` (the full registry dump) as evidence.
- `apiResolutions` — what `MmGetSystemRoutineAddress` resolved, provisioned or
  failed to resolve.
- `integrity` — verified negatives: process-list consistency (DKOM),
  SSDT entries vs pristine thunks, and foreign MajorFunction slots.
- IRP results include `method` (BUFFERED/IN_DIRECT/OUT_DIRECT/NEITHER),
  `buffers` and invoked `completions`; pending IRPs drain DPC/timer work.

BCD hive virtualization (`bcd: false`, CLI `--no-bcd`) seeds
`\Registry\Machine\BCD` and synthesizes typed zeros for queried elements.
