/**
 * apihash.mjs — API-name hash detection.
 *
 * Shellcode and hardened loaders avoid plaintext API names by storing
 * 4-byte hashes and resolving them at runtime (ROR13 + add, djb2, CRC32,
 * Murmur3). This module precomputes hashes for a dictionary of common APIs
 * and scans a buffer for those constants (little-endian).
 */

/** Common Windows API/export names worth resolving dynamically. */
export const API_DICTIONARY = [
  // memory / process
  "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "VirtualFree",
  "VirtualQuery", "ReadProcessMemory", "WriteProcessMemory", "OpenProcess", "CreateProcessA",
  "CreateProcessW", "TerminateProcess", "CreateRemoteThread", "CreateRemoteThreadEx",
  "OpenThread", "SuspendThread", "ResumeThread", "GetThreadContext", "SetThreadContext",
  "QueueUserAPC", "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
  "Thread32First", "Thread32Next", "Module32First", "Module32Next", "OpenProcessToken",
  "LookupPrivilegeValueA", "AdjustTokenPrivileges", "GetCurrentProcess", "GetCurrentProcessId",
  // modules
  "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress",
  "GetModuleHandleA", "GetModuleHandleW", "GetModuleFileNameA", "GetModuleFileNameW",
  "FreeLibrary", "GetModuleHandleExA", "LdrLoadDll", "LdrGetProcedureAddress", "LdrUnloadDll",
  // files
  "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "DeleteFileA",
  "DeleteFileW", "CopyFileA", "MoveFileA", "SetFilePointer", "GetFileSize", "FindFirstFileA",
  "FindNextFileA", "CreateDirectoryA", "GetTempPathA", "GetTempFileNameA",
  // registry
  "RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegSetValueExA", "RegQueryValueExA",
  "RegDeleteValueA", "RegCloseKey", "RegEnumKeyExA",
  // network
  "WSAStartup", "WSASocketA", "socket", "connect", "send", "recv", "bind", "listen",
  "accept", "closesocket", "gethostbyname", "inet_addr", "InternetOpenA", "InternetConnectA",
  "HttpOpenRequestA", "HttpSendRequestA", "InternetReadFile", "URLDownloadToFileA",
  "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "WinHttpReceiveResponse",
  "WinHttpReadData",
  // execution / injection
  "WinExec", "ShellExecuteA", "ShellExecuteExA", "CreateThread", "WaitForSingleObject",
  "ExitProcess", "GetCommandLineA", "GetCommandLineW", "NtAllocateVirtualMemory",
  "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtReadVirtualMemory", "NtCreateThreadEx",
  "NtOpenProcess", "NtQuerySystemInformation", "NtQueryInformationProcess", "NtMapViewOfSection",
  "NtUnmapViewOfSection", "NtCreateSection", "NtQueueApcThread", "ZwAllocateVirtualMemory",
  "RtlMoveMemory", "RtlCopyMemory", "RtlZeroMemory",
  // anti-analysis
  "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "GetTickCount",
  "GetTickCount64", "QueryPerformanceCounter", "Sleep", "GetSystemTime", "GetSystemInfo",
  "GetComputerNameA", "GetUserNameA", "GetVolumeInformationA", "GetSystemFirmwareTable",
  "EnumDeviceDrivers", "GetDeviceDriverBaseNameA",
  // crypto / encoding
  "CryptAcquireContextA", "CryptGenRandom", "CryptEncrypt", "CryptDecrypt", "CryptHashData",
  "BCryptOpenAlgorithmProvider", "BCryptGenRandom", "BCryptEncrypt",
  // kernel driver symbols (for driver binaries)
  "MmGetSystemRoutineAddress", "PsLookupProcessByProcessId", "PsGetProcessImageFileName",
  "KeStackAttachProcess", "ObRegisterCallbacks", "PsSetCreateProcessNotifyRoutine",
  "PsSetLoadImageNotifyRoutine", "IoCreateDevice", "IoCreateSymbolicLink", "ZwOpenProcess",
  "ZwTerminateProcess", "ZwProtectVirtualMemory", "MmCopyVirtualMemory", "KeBugCheckEx",
  "ExAllocatePool", "ExAllocatePool2", "SeAccessCheck", "CmRegisterCallback",
];

const u32 = (v) => v >>> 0;

/** ROR13 + add (the classic shellcode/loader hash, a.k.a. "ROR13"). */
export function ror13(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) {
    h = u32(((h >>> 13) | (h << 19)) + name.charCodeAt(i));
  }
  return u32(h);
}

/** DJB2 (with the 5381 seed). */
export function djb2(name) {
  let h = 5381;
  for (let i = 0; i < name.length; i++) h = u32(h * 33 + name.charCodeAt(i));
  return u32(h);
}

/** CRC32 (IEEE) over the name bytes. */
export function crc32(name) {
  let crc = 0xffffffff;
  for (let i = 0; i < name.length; i++) {
    crc ^= name.charCodeAt(i);
    for (let k = 0; k < 8; k++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return u32(crc ^ 0xffffffff);
}

/** Murmur3 x86 32-bit, seed 0. */
export function murmur3(name) {
  const data = new TextEncoder().encode(name);
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  let h = 0;
  const nblocks = data.length >> 2;
  for (let i = 0; i < nblocks; i++) {
    let k = (data[i * 4] | (data[i * 4 + 1] << 8) | (data[i * 4 + 2] << 16) | (data[i * 4 + 3] << 24)) >>> 0;
    k = Math.imul(k, c1) >>> 0;
    k = ((k << 15) | (k >>> 17)) >>> 0;
    k = Math.imul(k, c2) >>> 0;
    h ^= k;
    h = ((h << 13) | (h >>> 19)) >>> 0;
    h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  }
  let k = 0;
  const tail = nblocks * 4;
  switch (data.length & 3) {
    case 3: k ^= data[tail + 2] << 16; // fallthrough
    case 2: k ^= data[tail + 1] << 8; // fallthrough
    case 1:
      k ^= data[tail];
      k = Math.imul(k, c1) >>> 0;
      k = ((k << 15) | (k >>> 17)) >>> 0;
      k = Math.imul(k, c2) >>> 0;
      h ^= k;
  }
  h ^= data.length;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return u32(h);
}

export const HASH_ALGOS = { ror13, djb2, crc32, murmur3 };

/** Build hash -> name maps per algorithm. */
export function buildApiHashTable(dictionary = API_DICTIONARY) {
  const table = {};
  for (const algo of Object.keys(HASH_ALGOS)) {
    const map = new Map();
    for (const name of dictionary) {
      const h = HASH_ALGOS[algo](name);
      if (!map.has(h)) map.set(h, name);
    }
    table[algo] = map;
  }
  return table;
}

const DEFAULT_TABLE = buildApiHashTable();

/**
 * Scan a buffer for little-endian 32-bit API-hash constants.
 * @param {Uint8Array} bytes
 * @param {{algos?:string[], table?:object, maxHits?:number, dictionary?:string[]}} [opts]
 * @returns {{hits:Array<{algo:string, hash:number, offset:number, name:string}>, scanned:number}}
 */
export function detectApiHashes(bytes, opts = {}) {
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  const table = opts.table ?? (opts.dictionary ? buildApiHashTable(opts.dictionary) : DEFAULT_TABLE);
  const algos = opts.algos ?? Object.keys(table);
  const maxHits = opts.maxHits ?? 256;
  const hits = [];
  for (let i = 0; i + 4 <= b.length && hits.length < maxHits; i++) {
    const v = (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
    if (v === 0) continue;
    for (const algo of algos) {
      const name = table[algo]?.get(v);
      if (name) {
        hits.push({ algo, hash: v, offset: i, name });
        break;
      }
    }
  }
  return { hits, scanned: b.length };
}
