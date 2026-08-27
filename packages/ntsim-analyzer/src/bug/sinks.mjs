/**
 * sinks.mjs — vulnerability sink catalogue for Find Bugs
 * Ordered by severity/exploitability as per spec.
 */

export const SEVERITY = {
  CRITICAL: 10,
  HIGH: 8,
  MEDIUM: 5,
  LOW: 3,
  INFO: 1,
};

export const SINK_CATALOG = [
  // Arbitrary read/write primitives
  {
    id: "ARBITRARY_WRITE_DEREF",
    title: "Write-what-where via tainted pointer dereference",
    severity: SEVERITY.CRITICAL,
    type: "mem",
    access: "write",
    check: "addr_tainted",
    description: "*(PVOID)tainted = data — full arbitrary write",
  },
  {
    id: "ARBITRARY_READ_DEREF",
    title: "Arbitrary read via tainted pointer",
    severity: SEVERITY.CRITICAL,
    type: "mem",
    access: "read",
    check: "addr_tainted",
  },
  {
    id: "RTLCOPYMEM_TAINTED_DST_OR_LEN",
    title: "RtlCopyMemory/memcpy with tainted dst or len",
    severity: SEVERITY.CRITICAL,
    type: "api",
    apis: ["RtlCopyMemory","RtlCopyBytes","memcpy","memmove","RtlMoveMemory"],
    params: [{ idx: 0, role: "dstAddr" }, { idx: 2, role: "length" }],
  },
  {
    id: "MM_MAP_IOSPACE_TAINTED",
    title: "MmMapIoSpace with tainted physical address",
    severity: SEVERITY.CRITICAL,
    type: "api",
    apis: ["MmMapIoSpace","ZwMapViewOfSection"],
    params: [{ idx: 0, role: "physAddr" }],
  },
  {
    id: "ARBITRARY_INC_DEC",
    title: "Arbitrary increment/decrement *(int*)tainted += val",
    severity: SEVERITY.CRITICAL,
    type: "mem",
    access: "rmw",
    check: "addr_tainted_incdec",
  },

  // Control-register / privileged state
  {
    id: "WRMSR_TAINTED",
    title: "WRMSR/RDMSR with tainted MSR index or value (LSTAR hijack)",
    severity: SEVERITY.HIGH,
    type: "msr",
  },
  {
    id: "MOV_CR_TAINTED",
    title: "MOV CR0/CR4 with tainted bits (WP/SMEP clear)",
    severity: SEVERITY.HIGH,
    type: "cr",
    check: "cr_tainted",
  },
  {
    id: "PORT_IO_TAINTED",
    title: "IN/OUT with tainted port number",
    severity: SEVERITY.MEDIUM,
    type: "port",
  },
  {
    id: "IDT_GDT_TAINTED",
    title: "IDT/GDT manipulation (LIDT/SIDT or direct write)",
    severity: SEVERITY.HIGH,
    type: "mem",
    check: "idt_write",
  },

  // Object/handle-manager sinks (BYOVD)
  {
    id: "OBJ_OPEN_TAINTED_PID",
    title: "ObOpenObjectByPointer/PsLookupProcessByProcessId with tainted PID + PROCESS_ALL_ACCESS",
    severity: SEVERITY.CRITICAL,
    type: "api",
    apis: ["ObOpenObjectByPointer","PsLookupProcessByProcessId","ZwOpenProcess"],
    params: [{ idx: 0, role: "pid" }],
    needsAccessCheck: true,
  },
  {
    id: "ZW_FILE_TAINTED_PATH",
    title: "ZwOpenFile/ZwDeleteFile/ZwCreateFile with tainted path",
    severity: SEVERITY.HIGH,
    type: "api",
    apis: ["ZwOpenFile","ZwCreateFile","ZwDeleteFile","ZwOpenKey"],
    params: [{ idx: 2, role: "path" }],
  },
  {
    id: "TOKEN_SWAP",
    title: "EPROCESS Token copy via tainted PID",
    severity: SEVERITY.CRITICAL,
    type: "mem",
    check: "token_swap",
  },

  // Structural / memory safety
  {
    id: "STACK_OVERFLOW_TAINTED_LEN",
    title: "Fixed-size stack buffer written with tainted length",
    severity: SEVERITY.HIGH,
    type: "mem",
    check: "stack_overflow",
  },
  {
    id: "POOL_OVERFLOW_TAINTED_SIZE",
    title: "ExAllocatePoolWithTag with tainted size (integer overflow)",
    severity: SEVERITY.HIGH,
    type: "api",
    apis: ["ExAllocatePoolWithTag","ExAllocatePool","ExAllocatePool2"],
    params: [{ idx: 1, role: "size" }],
  },
  {
    id: "MISSING_PROBE",
    title: "Direct dereference of tainted user pointer without ProbeForRead/Write",
    severity: SEVERITY.MEDIUM,
    type: "mem",
    check: "missing_probe",
  },
  {
    id: "DOUBLE_FETCH",
    title: "Double-fetch / TOCTOU on tainted memory",
    severity: SEVERITY.MEDIUM,
    type: "mem",
    check: "double_fetch",
  },
  {
    id: "UAF_CROSS_IRP",
    title: "Use-after-free across IOCTLs (handle lifetime)",
    severity: SEVERITY.HIGH,
    type: "lifetime",
    check: "uaf",
  },

  // Lower severity
  {
    id: "INFO_LEAK_UNINIT",
    title: "Uninitialized stack/pool returned to userspace",
    severity: SEVERITY.LOW,
    type: "infoleak",
  },
  {
    id: "NULL_DEREF",
    title: "NULL dereference / unhandled exception in dispatch",
    severity: SEVERITY.INFO,
    type: "crash",
  },
];

export function sinksForApi(apiName) {
  return SINK_CATALOG.filter(s => s.type==="api" && s.apis?.includes(apiName));
}
