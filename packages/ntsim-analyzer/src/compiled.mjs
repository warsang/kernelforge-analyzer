/**
 * loadCompiledDriver — link COFF object(s) into the emulated kernel.
 *
 * Shared path for labs that compile real C (module compiler labs):
 * linkDriver bakes ABSOLUTE relocations against `base`, mapPe drops the
 * image in, a real DRIVER_OBJECT receives DriverUnload writes, and the
 * driver becomes visible to lm (loadedModules + loadedDrivers).
 *
 * Extern resolution policy:
 *   - known kernel API name    -> existing thunk VA (host-side impl runs)
 *   - "PsInitialSystemProcess" -> qword slot containing System's EPROCESS
 *                                 (data export semantics: guest dereferences)
 *   - anything else            -> provisioned traced stub (STATUS_SUCCESS)
 */

import {
  mapPe,
  createDriverObject,
  initDriverObjectName,
} from "@kernelforge/ntsim/src/index.mjs";
import { linkDriver } from "@kernelforge/compiler-worker";

/** Deterministic per-lab driver name: kf_m1_l2_lab1.sys etc. */
export function driverNameForLab(labId) {
  return `kf_${String(labId).replace(/\./g, "_").replace(/[^a-z0-9_]/gi, "")}.sys`;
}

const DEFAULT_LOAD_BASE_OFFSET = 0x40000000n; // 1GB above thunk region

/**
 * @param {object} kernel booted NtKernel (bootstrap() done)
 * @param {Uint8Array|Uint8Array[]} objBytes COFF object(s) from clang
 * @param {{base?: bigint, name?: string, labId?: string}} opts
 */
export function loadCompiledDriver(kernel, objBytes, opts = {}) {
  const objs = Array.isArray(objBytes) ? objBytes : [objBytes];
  // Default: 1GB above this session's API-thunk region — every link-time
  // external (thunks, data slots) then sits inside REL32's +-2GB window,
  // mirroring how real loaders keep drivers close to ntoskrnl.
  const base = opts.base ?? (kernel.bases?.thunk ?? 0xfffff80100000000n)
    + DEFAULT_LOAD_BASE_OFFSET;
  const name = opts.name ?? driverNameForLab(opts.labId ?? "driver");

  // Modeled data exports must live within +-2GB of the image: clang accesses
  // them via RIP-relative disp32, which physically cannot reach far regions
  // (real kernels satisfy this by keeping globals in ntoskrnl's .data).
  // Carve a tiny arena just below the load base.
  let nextDataSlot = base - 0x100000n;

  /** symbol -> qword slot VA holding a pointer (modeled data exports) */
  const dataSlots = new Map();

  const resolveExternal = (symName) => {
    // 1. plain API thunk (DbgPrint, ExAllocatePoolWithTag, ...)
    const known = kernel.apiThunks.get(symName);
    if (known) return known;

    // 2. data exports modeled as pointer slots
    if (symName === "PsInitialSystemProcess") {
      if (!dataSlots.has(symName)) {
        const slot = nextDataSlot;
        nextDataSlot += 16n;
        const systemEproc = kernel.processesByName?.get("System")
          ?? kernel.findEprocessByPid(4n);
        if (!systemEproc) throw new Error("System EPROCESS not present — bootstrap first");
        kernel.mem.w64(slot, systemEproc);
        dataSlots.set(symName, slot);
      }
      return dataSlots.get(symName);
    }

    // 3. everything else: traced stub so unknown imports never abort the load
    return kernel.resolveImportProvisioned(symName);
  };

  const linked = linkDriver(objs, resolveExternal, base);
  const mapped = mapPe(linked.image, kernel.mem, base, () => null); // relocs already absolute

  const expectedEntry = base + BigInt(linked.entryRva);
  if (mapped.entry !== expectedEntry) {
    throw new Error(`linker/mapPe entry mismatch: ${linked.entryRva} vs ${mapped.entry - base}`);
  }

  const drvRec = createDriverObject(kernel, name);
  initDriverObjectName(kernel, drvRec, name, mapped.base, mapped.imageSize);
  drvRec.image = { base: mapped.base, bytes: linked.image };

  // lm visibility: register like module-3's mmpayload pattern
  kernel.loadedModules = kernel.loadedModules ?? [];
  kernel.loadedDrivers = kernel.loadedDrivers ?? [];
  if (!kernel.loadedModules.some((m) => m.name === name)) {
    kernel.loadedModules.push({
      base: mapped.base,
      sizeOfImage: mapped.imageSize,
      name,
      full: `\\SystemRoot\\system32\\drivers\\${name}`,
    });
    // back the whole image extent (headers included) so !dh / s -a / u work
    // across it, and pre-map it in the emulator address space (unicorn)
    kernel.materializeModuleRange?.(mapped.base, mapped.imageSize);
  }
  if (!kernel.loadedDrivers.some((d) => d.name === name)) {
    kernel.loadedDrivers.push({ name, base: mapped.base, imageSize: mapped.imageSize });
  }

  return {
    base: mapped.base,
    entry: mapped.entry,
    drvRec,
    image: drvRec.image,
    entryRva: linked.entryRva,
    name,
  };
}
