/**
 * kernel-driver.mjs — curated pure-JS rule pack for Windows kernel drivers.
 *
 * These rules encode the deterministic, high-signal indicators that show up
 * as strings/symbol references in .sys images. They complement (not replace)
 * the emulator: a hit is a lead, not a verdict. Severity is the potential
 * impact if the referenced behavior is actually implemented.
 */

/** @type {Array<{id:string, meta:object, strings:Array, condition:string}>} */
export const KERNEL_DRIVER_RULES = [
  {
    id: "kf_kernel_debug_flags",
    meta: {
      severity: "medium",
      tags: ["anti-analysis"],
      description: "References KdDebuggerEnabled/KdDebuggerNotPresent — kernel debugger detection.",
    },
    strings: [
      { id: "$a", type: "text", value: "KdDebuggerEnabled" },
      { id: "$b", type: "text", value: "KdDebuggerNotPresent" },
      { id: "$c", type: "text", value: "KdDebuggerEnabled" },
    ],
    condition: "$a or $b or $c",
  },
  {
    id: "kf_loaded_module_walk",
    meta: {
      severity: "high",
      tags: ["rootkit", "hidden-module"],
      description: "Walks PsLoadedModuleList / InLoadOrderLinks — module enumeration or unlinking.",
    },
    strings: [
      { id: "$a", type: "text", value: "PsLoadedModuleList" },
      { id: "$b", type: "text", value: "InLoadOrderLinks" },
    ],
    condition: "$a and $b",
  },
  {
    id: "kf_ssdt_symbols",
    meta: {
      severity: "high",
      tags: ["rootkit", "hook"],
      description: "References KeServiceDescriptorTable — SSDT inspection or hooking.",
    },
    strings: [{ id: "$a", type: "text", value: "KeServiceDescriptorTable" }],
    condition: "$a",
  },
  {
    id: "kf_dynamic_api_resolution",
    meta: {
      severity: "medium",
      tags: ["anti-analysis", "evasion"],
      description: "Resolves APIs at runtime via MmGetSystemRoutineAddress (string-built names).",
    },
    strings: [
      { id: "$a", type: "text", value: "MmGetSystemRoutineAddress" },
      { id: "$b", type: "text", value: "ZwTerminateProcess" },
      { id: "$c", type: "text", value: "ZwOpenProcess" },
      { id: "$d", type: "text", value: "MmCopyVirtualMemory" },
    ],
    condition: "$a and ($b or $c or $d)",
  },
  {
    id: "kf_hypervisor_artifacts",
    meta: {
      severity: "medium",
      tags: ["anti-analysis", "anti-vm"],
      description: "Hypervisor/VM artifact strings (VMware/VBox/QEMU/Hyper-V).",
    },
    strings: [
      { id: "$a", type: "regex", value: "VMware|VirtualBox|VBOX|QEMU|Hyper-V|vboxguest|vmmouse", nocase: true },
      { id: "$b", type: "text", value: "hypervisor", nocase: true },
    ],
    condition: "$a or $b",
  },
  {
    id: "kf_defender_tamper",
    meta: {
      severity: "high",
      tags: ["security-tamper"],
      description: "Defender/security policy tamper strings (DisableAntiSpyware, TamperProtection).",
    },
    strings: [
      { id: "$a", type: "text", value: "DisableAntiSpyware", nocase: true },
      { id: "$b", type: "text", value: "DisableRealtimeMonitoring", nocase: true },
      { id: "$c", type: "text", value: "TamperProtection", nocase: true },
      { id: "$d", type: "text", value: "DisableAntiVirus", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "kf_process_termination",
    meta: {
      severity: "high",
      tags: ["process-control"],
      description: "Process termination path (ZwTerminateProcess + process lookup).",
    },
    strings: [
      { id: "$a", type: "text", value: "ZwTerminateProcess" },
      { id: "$b", type: "text", value: "PsLookupProcessByProcessId" },
      { id: "$c", type: "text", value: "NtTerminateProcess" },
    ],
    condition: "($a or $c) and $b",
  },
  {
    id: "kf_remote_memory_access",
    meta: {
      severity: "high",
      tags: ["memory-access"],
      description: "Cross-process memory access primitives (MmCopyVirtualMemory / ZwWriteVirtualMemory).",
    },
    strings: [
      { id: "$a", type: "text", value: "MmCopyVirtualMemory" },
      { id: "$b", type: "text", value: "ZwWriteVirtualMemory" },
      { id: "$c", type: "text", value: "ZwReadVirtualMemory" },
      { id: "$d", type: "text", value: "MmMapIoSpace" },
    ],
    condition: "any of them",
  },
  {
    id: "kf_kernel_apc_injection",
    meta: {
      severity: "high",
      tags: ["injection"],
      description: "Kernel APC injection primitives (KeInitializeApc/KeInsertQueueApc).",
    },
    strings: [
      { id: "$a", type: "text", value: "KeInitializeApc" },
      { id: "$b", type: "text", value: "KeInsertQueueApc" },
    ],
    condition: "$a and $b",
  },
  {
    id: "kf_thread_hijack",
    meta: {
      severity: "high",
      tags: ["injection"],
      description: "Thread context manipulation (ZwGetContextThread/SetContextThread/KeStackAttachProcess).",
    },
    strings: [
      { id: "$a", type: "text", value: "ZwGetContextThread" },
      { id: "$b", type: "text", value: "ZwSetContextThread" },
      { id: "$c", type: "text", value: "KeStackAttachProcess" },
      { id: "$d", type: "text", value: "KeForceResumeThread" },
    ],
    condition: "($a and $b) or $c or $d",
  },
  {
    id: "kf_dkom_links",
    meta: {
      severity: "high",
      tags: ["rootkit"],
      description: "Direct EPROCESS/ETHREAD link manipulation (ActiveProcessLinks/ActiveThreadList).",
    },
    strings: [
      { id: "$a", type: "text", value: "ActiveProcessLinks" },
      { id: "$b", type: "text", value: "ActiveThreadList" },
      { id: "$c", type: "text", value: "ThreadListHead" },
    ],
    condition: "any of them",
  },
  {
    id: "kf_etw_tamper",
    meta: {
      severity: "high",
      tags: ["security-tamper"],
      description: "ETW provider tamper (EtwThreatIntProvRegHandle / Etwp / EtwRegister).",
    },
    strings: [
      { id: "$a", type: "text", value: "EtwThreatIntProvRegHandle" },
      { id: "$b", type: "text", value: "Etwp" },
      { id: "$c", type: "text", value: "EtwWrite" },
    ],
    condition: "$a or ($b and $c)",
  },
  {
    id: "kf_ci_bypass",
    meta: {
      severity: "high",
      tags: ["code-signing", "evasion"],
      description: "Code-integrity bypass symbols (g_CiOptions / CiValidateImageHeader).",
    },
    strings: [
      { id: "$a", type: "text", value: "g_CiOptions" },
      { id: "$b", type: "text", value: "CiValidateImageHeader" },
      { id: "$c", type: "text", value: "SeValidateImageHeader" },
    ],
    condition: "any of them",
  },
  {
    id: "kf_registry_policy",
    meta: {
      severity: "medium",
      tags: ["persistence", "security-tamper"],
      description: "Security policy registry paths under Policies\\System.",
    },
    strings: [
      { id: "$a", type: "text", value: "CurrentVersion\\Policies\\System", nocase: true },
      { id: "$b", type: "text", value: "CurrentVersion\\Policies\\Explorer", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "kf_known_tool_drivers",
    meta: {
      severity: "high",
      tags: ["known-tool", "byovd"],
      description: "References known BYOVD tool driver names (mhyprot, kdmapper, iqvw64e, winio).",
    },
    strings: [
      { id: "$a", type: "text", value: "mhyprot", nocase: true },
      { id: "$b", type: "text", value: "kdmapper", nocase: true },
      { id: "$c", type: "text", value: "iqvw64e", nocase: true },
      { id: "$d", type: "text", value: "winio", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "kf_packer_artifacts",
    meta: {
      severity: "medium",
      tags: ["packer"],
      description: "Packer/protector artifacts in the image (UPX!, Themida, VMProtect, Enigma).",
    },
    strings: [
      { id: "$a", type: "text", value: "UPX!" },
      { id: "$b", type: "text", value: "Themida", nocase: true },
      { id: "$c", type: "text", value: "VMProtect", nocase: true },
      { id: "$d", type: "text", value: "Enigma protector", nocase: true },
      { id: "$e", type: "text", value: ".vmp0" },
    ],
    condition: "any of them",
  },
  {
    id: "kf_msr_hypercall",
    meta: {
      severity: "medium",
      tags: ["low-level"],
      description: "MSR/hypercall access symbols (__readmsr/__writemsr, hypercall page).",
    },
    strings: [
      { id: "$a", type: "text", value: "__writemsr" },
      { id: "$b", type: "text", value: "__readmsr" },
      { id: "$c", type: "text", value: "Hypercall" },
      { id: "$d", type: "text", value: "0x40000000" },
    ],
    condition: "$a or $b or $c",
  },
  {
    id: "kf_kernel_heap_spray",
    meta: {
      severity: "medium",
      tags: ["exploit-primitive"],
      description: "Pool spray / big allocation patterns (ExAllocatePool + nonpaged + large size).",
    },
    strings: [
      { id: "$a", type: "text", value: "ExAllocatePool" },
      { id: "$b", type: "text", value: "NonPagedPool" },
      { id: "$c", type: "text", value: "MmAllocateContiguousMemory" },
    ],
    condition: "$a and ($b or $c)",
  },
  {
    id: "kf_timing_rdtsc",
    meta: {
      severity: "low",
      tags: ["anti-analysis"],
      description: "RDTSC instruction present (0F 31) — timing checks possible.",
    },
    strings: [{ id: "$a", type: "hex", value: "0F 31" }],
    condition: "$a",
  },
];

export default KERNEL_DRIVER_RULES;
