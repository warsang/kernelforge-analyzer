/**
 * shellcode.mjs — pure-JS rule pack for raw x64 shellcode (Windows + Linux).
 *
 * Shellcode has no file format to inspect, so the high-signal indicators are
 * code patterns: PIC get-PC sequences, PEB/Ldr walks, EAT-hashing loops,
 * syscall stubs, anti-debug tricks and embedded second stages.
 */

/** @type {Array<{id:string, meta:object, strings:Array, condition:string}>} */
export const SHELLCODE_RULES = [
  {
    id: "sc_pic_getpc",
    meta: { severity: "medium", tags: ["shellcode", "pic"], description: "Position-independent get-PC sequences (call $+5 / fnstenv)." },
    strings: [
      { id: "$call5", type: "hex", value: "E8 00 00 00 00" },
      { id: "$fnstenv", type: "hex", value: "D9 74 24 F4" },
      { id: "$fnstenv2", type: "hex", value: "9B D9 74 24 F4" },
    ],
    condition: "$fnstenv or $fnstenv2 or $call5",
  },
  {
    id: "sc_peb_walk",
    meta: { severity: "high", tags: ["shellcode", "anti-analysis"], description: "PEB/TEB access via gs: — module-list walking to resolve APIs at runtime." },
    strings: [
      { id: "$gs60", type: "hex", value: "65 48 8B ?? 25 60 00 00 00" },
      { id: "$gs30", type: "hex", value: "65 48 8B ?? 25 30 00 00 00" },
      { id: "$gs60b", type: "hex", value: "65 48 8B ?? ?? 60 00 00 00" },
      { id: "$gs64", type: "hex", value: "65 48 8B ?? 25 64 00 00 00" },
    ],
    condition: "any of them",
  },
  {
    id: "sc_eat_hash_loop",
    meta: { severity: "high", tags: ["shellcode", "evasion"], description: "EAT-walk hashing loop (ror/rol + add sequences) — API resolution by hash." },
    strings: [
      { id: "$ror13", type: "hex", value: "C1 ?? 0D" },
      { id: "$ror7", type: "hex", value: "C1 ?? 07" },
    ],
    condition: "$ror13 and $ror7",
  },
  {
    id: "sc_api_hash_constants",
    meta: { severity: "high", tags: ["shellcode", "evasion"], description: "ROR13 API-hash constants (VirtualAlloc/WinExec/LoadLibraryA/GetProcAddress/...)." },
    strings: [
      { id: "$virtualalloc", type: "hex", value: "54 CA AF 91" },
      { id: "$winexec", type: "hex", value: "98 FE 8A 0E" },
      { id: "$loadlibrarya", type: "hex", value: "8E 4E 0E EC" },
      { id: "$getprocaddress", type: "hex", value: "AA FC 0D 7C" },
      { id: "$urldownloadtofilea", type: "hex", value: "36 1A 2F 70" },
      { id: "$isdebuggerpresent", type: "hex", value: "76 C6 6D A3" },
    ],
    condition: "2 of them",
  },
  {
    id: "sc_syscall_stubs",
    meta: { severity: "medium", tags: ["shellcode"], description: "Direct syscalls (syscall / sysenter / int 2e) — bypassing hooked ntdll." },
    strings: [
      { id: "$syscall", type: "hex", value: "0F 05" },
      { id: "$int2e", type: "hex", value: "CD 2E" },
      { id: "$sysenter", type: "hex", value: "0F 34" },
    ],
    condition: "$int2e or $sysenter or $syscall",
  },
  {
    id: "sc_anti_debug_int2d",
    meta: { severity: "medium", tags: ["shellcode", "anti-analysis"], description: "int 2d (anti-debug) / icebp tricks." },
    strings: [
      { id: "$int2d", type: "hex", value: "CD 2D" },
    ],
    condition: "$int2d",
  },
  {
    id: "sc_embedded_pe",
    meta: { severity: "high", tags: ["shellcode", "loader"], description: "Embedded second-stage PE (MZ + PE header present in the buffer)." },
    strings: [
      { id: "$mz", type: "hex", value: "4D 5A" },
      { id: "$pe", type: "hex", value: "50 45 00 00" },
    ],
    condition: "$mz and $pe",
  },
  {
    id: "sc_stage_strings",
    meta: { severity: "medium", tags: ["shellcode", "network"], description: "Stage/download strings (URLs, interpreters, persistence helpers)." },
    strings: [
      { id: "$url", type: "regex", value: "https?://\\S+" },
      { id: "$cmd", type: "text", value: "cmd.exe", nocase: true },
      { id: "$ps", type: "text", value: "powershell", nocase: true },
      { id: "$schtasks", type: "text", value: "schtasks", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "sc_linux_privesc_strings",
    meta: { severity: "medium", tags: ["shellcode", "linux"], description: "Linux shellcode strings (shells, credential files, preload rootkit, /dev/tcp)." },
    strings: [
      { id: "$sh", type: "text", value: "/bin/sh" },
      { id: "$shadow", type: "text", value: "/etc/shadow" },
      { id: "$preload", type: "text", value: "ld.so.preload" },
      { id: "$devtcp", type: "text", value: "/dev/tcp/" },
    ],
    condition: "any of them",
  },
];

export default SHELLCODE_RULES;
