# Contributing

Thanks for looking! This repo hosts KernelForge's analysis harnesses:

| package | what it does |
|---|---|
| `@kernelforge/compiler-worker` | COFF parser + x64 linker (clang `.obj` -> `.sys`) |
| `@kernelforge/ntsim-analyzer` | Windows kernel harness: `analyzeDriver`, auto-IRP, fuzz, concolic (Z3), find-bugs |
| `@kernelforge/linux-analyzer` | Linux LKM harness: `analyzeKo`, auto-ops, find-bugs |
| `@kernelforge/pe-runner` | Userland PE harness: EXE entry + **DLL rundll32-style export runner** |
| `@kernelforge/elf-runner` | Userland ELF64 harness: PT_LOAD mapping, syscall model |
| `@kernelforge/shellcode-runner` | Raw x64 shellcode harness (Windows PEB/EAT + Linux syscalls) |
| `@kernelforge/triage` | Static triage primitives: PE/ELF facts, entropy, strings, imphash, YARA |

## Dev setup

Node `>= 20`. Clang is needed for tests that compile fixtures (compiler-worker,
linux-analyzer):

```bash
npm install
npm test                 # node --test packages/*/test/*.test.mjs (~2 min)
```

Per-package runs, e.g.:

```bash
node --test packages/pe-runner/test/*.test.mjs
node --test packages/elf-runner/test/*.test.mjs
```

## How changes flow (important)

These packages are developed in a private monorepo and **split** into this
repository. The split is regenerated, so:

- Issues and PRs are welcome here. A maintainer ports accepted changes back
  upstream, then the next split carries them.
- Large refactors are best discussed in an issue first so the port-back is clean.
- Keep changes scoped to `packages/<name>/{src,test}`; root files
  (`package.json`, CI, this file) are maintained by the split job.

## Adding behavior models

- Win32 API model: add a handler in `packages/pe-runner/src/win32.mjs`
  (name the API, record intent into `artifacts`, return a plausible value).
- DLL export parsing: `packages/pe-runner/src/pe-exports.mjs`.
- Linux syscalls: `packages/elf-runner/src/linux.mjs`.
- Static rules: `packages/triage/src/rules/` (+ tests).

## License

MIT unless the package declares otherwise (see each `package.json` and
`LEGAL.md`). No CLA required.
