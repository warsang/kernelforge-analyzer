# kernelforge-analyzer

Analysis harnesses — map a real PE/ELF, resolve imports, run the entry (or any
DLL export), drive IOCTLs/file_ops, and get a behavior report. Everything runs
client-side in the KernelForge analyzers; these packages are the Node library.

- `@kernelforge/compiler-worker` - COFF parser + x64 linker (clang .obj -> .sys) - MIT
- `@kernelforge/ntsim-analyzer` - Windows kernel harness: analyzeDriver, fuzz, concolic (Z3), find-bugs - MIT
- `@kernelforge/linux-analyzer` - Linux harness: analyzeKo - MIT
- `@kernelforge/pe-runner` - Userland PE harness: EXE entry + DLL rundll32-style export runner - MIT
- `@kernelforge/elf-runner` - Userland ELF64 harness: PT_LOAD mapping, syscall model - MIT
- `@kernelforge/shellcode-runner` - Raw x64 shellcode harness (Windows PEB/EAT + Linux syscalls) - MIT
- `@kernelforge/triage` - Static triage primitives: PE/ELF facts, entropy, strings, imphash, YARA - MIT
- `tools/` - fetch-sogen-wasm, build-ghidra-wasm, build-wine-root, gen-elf-fixtures

```bash
npm install @kernelforge/ntsim-analyzer
import { analyzeDriver } from "@kernelforge/ntsim-analyzer";
const report = await analyzeDriver(bytes, { backendName: "js" });
```

Z3 solver required for concolic/find-bugs.

## Userland harnesses

```bash
npm install @kernelforge/pe-runner @kernelforge/elf-runner @kernelforge/shellcode-runner
```

```js
import { runUserlandPe, listPeExports } from "@kernelforge/pe-runner";

// EXE: run the entry point
const exe = await runUserlandPe(bytes, { name: "sample.exe" });

// DLL: rundll32-style — DllMain(attach), then the picked export
const exports = listPeExports(dllBytes).entries;
const dll = await runUserlandPe(dllBytes, {
  name: "sample.dll",
  dllMode: "export",              // "export" | "attach" | "all"
  export: "DllRegisterServer",    // name, "#ordinal" or bare ordinal
  exportArgs: "/i",               // passed as arg3 (wide), like rundll32
});
// dllMode:"all" sweeps every non-forwarder export in a fresh world -> report.runs[]
```

```js
import { runElf } from "@kernelforge/elf-runner";
import { runShellcode } from "@kernelforge/shellcode-runner";
```

## CLI mode (`kf-analyze`)

Small unified CLI for `.sys` (via `@kernelforge/ntsim-analyzer`) and `.ko`
(via `@kernelforge/linux-analyzer`). No build step, Node `>=20`.

### Install

```bash
git clone https://github.com/warsang/kernelforge-analyzer.git
cd kernelforge-analyzer
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
node tools/kf-analyze.mjs driver.sys --auto-irp
npm run analyze -- driver.sys --auto-irp
kf-analyze driver.sys --help     # full flag list
```

Useful flags: `--backend=js|hybrid|unicorn|qemu`, `--tables=<dir>` (Vergilius
struct tables, `.sys` only), `--quiet` (JSON only, no progress on stderr).

## Development

```bash
npm install
npm test        # node --test packages/*/test/*.test.mjs
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the monorepo/split workflow.
