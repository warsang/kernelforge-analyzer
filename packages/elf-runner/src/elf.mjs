/**
 * elf.mjs — re-export of the shared ELF reader in @kernelforge/triage.
 * Kept as a module path for backwards compatibility.
 */
export { parseElf64, parseElfStatic, R_X86_64, PT, DT } from "@kernelforge/triage";
