/**
 * syscalls.mjs — Windows x64 native-syscall surface for shellcode.
 *
 * A fixed, self-consistent SSN table (the synthetic ntdll stubs built by
 * loader.mjs embed these same numbers, so Hell's-Gate style SSN scraping
 * works) maps system-service numbers to Nt* names. The dispatcher feeds them
 * to the pe-runner Win32 model (`model.dispatch("NtXxx", …)`), which already
 * models NtAllocateVirtualMemory / NtDelayExecution / NtQuery / NtClose and
 * records everything else as a traced unmodeled call. Args arrive in the
 * native-syscall order rcx/rdx/r8/r9 (+5th/6th on the caller's stack).
 */

export const NT_SSNS = {
  NtSetInformationThread: 0x0d,
  NtClose: 0x0f,
  NtReadFile: 0x06,
  NtWriteFile: 0x08,
  NtWaitForSingleObject: 0x04,
  NtAllocateVirtualMemory: 0x18,
  NtFreeVirtualMemory: 0x1e,
  NtProtectVirtualMemory: 0x50,
  NtReadVirtualMemory: 0x3f,
  NtWriteVirtualMemory: 0x3a,
  NtDelayExecution: 0x34,
  NtQueryInformationProcess: 0x19,
  NtSetInformationProcess: 0x1c,
  NtQueryInformationThread: 0x25,
  NtQuerySystemInformation: 0x36,
  NtQuerySystemTime: 0x27,
  NtQueryPerformanceCounter: 0x31,
  NtQueryVirtualMemory: 0x23,
  NtCreateFile: 0x55,
  NtOpenProcess: 0x26,
  NtOpenThread: 0x125,
  NtCreateThreadEx: 0xc1,
  NtCreateSection: 0x4a,
  NtMapViewOfSection: 0x28,
  NtUnmapViewOfSection: 0x2a,
  NtResumeThread: 0x52,
  NtTerminateProcess: 0x2c,
  NtQueueApcThread: 0x45,
  NtCreateMutant: 0x4e,
  NtWaitForMultipleObjects: 0x3b,
};

/** SSN -> Nt name */
export const SSN_TO_NAME = Object.fromEntries(
  Object.entries(NT_SSNS).map(([name, ssn]) => [ssn, name]),
);

/** Zw* aliases share the Nt* SSN (same stub bytes, separate exports). */
export function zwAlias(name) {
  return name.replace(/^Nt/, "Zw");
}

const u64 = (v) => BigInt.asUintN(64, BigInt(v ?? 0n));

/** Native-syscall argument registers + 5th/6th stack slots. */
export function readNtArgs(cpu, mem) {
  const a = [u64(cpu.regs.rcx), u64(cpu.regs.rdx), u64(cpu.regs.r8), u64(cpu.regs.r9)];
  const rsp = u64(cpu.regs.rsp);
  for (const off of [0x28n, 0x30n]) {
    try { a.push(mem.u64(rsp + off)); } catch { a.push(0n); }
  }
  return a;
}

/**
 * @param {{mem:object, cpu:object, model:object}} env
 * @returns {(ssn: bigint|number, args?: bigint[]) => bigint} NTSTATUS
 */
export function createWindowsSyscallHandler({ mem, cpu, model }) {
  return function winSyscall(ssnRaw, args = null) {
    const ssn = Number(u64(ssnRaw) & 0xffffffffn);
    const name = SSN_TO_NAME[ssn];
    const a = args ?? readNtArgs(cpu, mem);
    if (!name) {
      model.unmodeled.add(`Nt#${ssn}`);
      model.events.push({ name: `Nt#${ssn}`, args: a.slice(0, 4), ret: 0xc0000001n });
      return 0xc0000001n; // STATUS_UNSUCCESSFUL
    }
    const ret = model.dispatch(name, a);
    return ret === undefined ? 0n : u64(ret);
  };
}
