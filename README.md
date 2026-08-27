# kernelforge-analyzer
Analysis harnesses: run-any-.sys / .ko -> map -> DriverEntry -> IOCTLs -> report

- `@kernelforge/compiler-worker` - COFF parser + x64 linker (clang .obj -> .sys) - MIT
- `@kernelforge/ntsim-analyzer` - Windows harness: analyzeDriver, fuzz, concolic (Z3), find-bugs - MIT
- `@kernelforge/linux-analyzer` - Linux harness: analyzeKo - MIT
- `tools/` - fetch-sogen-wasm, build-ghidra-wasm, build-wine-root, gen-elf-fixtures

```bash
npm install @kernelforge/ntsim-analyzer
import { analyzeDriver } from "@kernelforge/ntsim-analyzer";
const report = await analyzeDriver(bytes, { backendName: "js" });
```

Z3 solver required for concolic/find-bugs.
