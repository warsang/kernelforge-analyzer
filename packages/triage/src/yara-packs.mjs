/**
 * yara-packs.mjs — built-in YARA-X rule sources per target format.
 *
 * These run through the real YARA-X engine (wasm) when available and are
 * complementary to the pure-JS packs in ./rules/*.mjs (which are the
 * always-available baseline). Keep rules small and high-signal; long rule
 * sets belong in user-supplied sources.
 */

export const KERNEL_DRIVER_YARA = `
rule kf_loaded_module_walk {
  meta:
    severity = "high"
    description = "Walks PsLoadedModuleList (module enumeration/unlinking)"
  strings:
    $a = "PsLoadedModuleList" ascii wide
    $b = "InLoadOrderLinks" ascii wide
  condition:
    $a and $b
}

rule kf_ssdt_symbols {
  meta:
    severity = "high"
    description = "References KeServiceDescriptorTable (SSDT hooking)"
  strings:
    $a = "KeServiceDescriptorTable" ascii wide
  condition:
    $a
}

rule kf_dkom_links {
  meta:
    severity = "high"
    description = "EPROCESS/ETHREAD link manipulation"
  strings:
    $a = "ActiveProcessLinks" ascii wide
    $b = "ActiveThreadList" ascii wide
  condition:
    any of them
}

rule kf_known_tool_drivers {
  meta:
    severity = "high"
    description = "Known BYOVD/tool driver names"
  strings:
    $a = "mhyprot" nocase
    $b = "kdmapper" nocase
    $c = "iqvw64e" nocase
    $d = "winio" nocase
  condition:
    any of them
}

rule kf_ci_bypass {
  meta:
    severity = "high"
    description = "Code integrity bypass symbols"
  strings:
    $a = "g_CiOptions" ascii wide
    $b = "CiValidateImageHeader" ascii wide
  condition:
    any of them
}

rule kf_packer_artifacts {
  meta:
    severity = "medium"
    description = "Packer/protector artifacts"
  strings:
    $a = "UPX!" ascii
    $b = "Themida" nocase
    $c = "VMProtect" nocase
  condition:
    any of them
}

rule kf_kernel_debug_flags {
  meta:
    severity = "medium"
    description = "Kernel debugger detection"
  strings:
    $a = "KdDebuggerEnabled" ascii wide
    $b = "KdDebuggerNotPresent" ascii wide
  condition:
    any of them
}
`;

export const PE_USERLAND_YARA = `
rule pe_injection_chain {
  meta:
    severity = "high"
    description = "Cross-process injection API chain"
  strings:
    $open = "OpenProcess" ascii
    $wpm = "WriteProcessMemory" ascii
    $vaex = "VirtualAllocEx" ascii
    $crt = "CreateRemoteThread" ascii
    $ntw = "NtWriteVirtualMemory" ascii
    $ntc = "NtCreateThreadEx" ascii
  condition:
    ($open and ($wpm or $ntw) and ($crt or $ntc)) or ($vaex and ($wpm or $ntw))
}

rule pe_lsass_credential_access {
  meta:
    severity = "high"
    description = "LSASS / credential dumping"
  strings:
    $lsass = "lsass" nocase
    $dump = "MiniDumpWriteDump" ascii
    $comsvcs = "comsvcs" nocase
    $sam = "SAM\\\\SAM" nocase
  condition:
    any of them
}

rule pe_defender_tamper {
  meta:
    severity = "high"
    description = "Defender/AMSI tampering"
  strings:
    $a = "Set-MpPreference" nocase
    $b = "Add-MpPreference" nocase
    $c = "AmsiScanBuffer" nocase
    $d = "DisableRealtimeMonitoring" nocase
    $e = "ExclusionPath" nocase
  condition:
    any of them
}

rule pe_ransomware_destructive {
  meta:
    severity = "high"
    description = "Shadow copy / backup destruction"
  strings:
    $a = "vssadmin" nocase
    $b = "delete shadows" nocase
    $c = "wbadmin delete" nocase
    $d = "wevtutil cl" nocase
  condition:
    ($a and $b) or $c or $d
}

rule pe_download_execute {
  meta:
    severity = "high"
    description = "Download and execute"
  strings:
    $dl = "URLDownloadToFile" ascii
    $inet = "InternetOpenUrl" ascii
    $wh = "WinHttpReadData" ascii
    $exec1 = "ShellExecute" ascii
    $exec2 = "WinExec" ascii
    $exec3 = "CreateProcess" ascii
  condition:
    ($dl or $inet or $wh) and ($exec1 or $exec2 or $exec3)
}

rule pe_script_abuse {
  meta:
    severity = "medium"
    description = "Encoded PowerShell / LOLBin execution"
  strings:
    $a = /powershell(\\.exe)?\\s+(-|\\/)(enc|encodedcommand|nop|w hidden)/ nocase
    $b = "mshta" nocase
    $c = "scrobj.dll" nocase
    $d = "FromBase64String" nocase
  condition:
    any of them
}

rule pe_packer_strings {
  meta:
    severity = "medium"
    description = "Packer/protector strings"
  strings:
    $a = "UPX!" ascii
    $b = "Themida" nocase
    $c = "VMProtect" nocase
    $d = "MPRESS" nocase
  condition:
    any of them
}
`;

export const ELF_USERLAND_YARA = `
rule elf_reverse_shell {
  meta:
    severity = "high"
    description = "Reverse shell primitives"
  strings:
    $a = "/dev/tcp/" ascii
    $b = /(bash|sh)\\s+-i/ nocase
    $c = /nc\\s+(-e|--exec)/ nocase
    $d = "pty.spawn" nocase
  condition:
    any of them
}

rule elf_ld_preload_rootkit {
  meta:
    severity = "high"
    description = "ld.so.preload / LD_PRELOAD userland rootkit"
  strings:
    $a = "/etc/ld.so.preload" ascii
    $b = "LD_PRELOAD" ascii
    $c = "RTLD_DEEPBIND" ascii
  condition:
    any of them
}

rule elf_crypto_miner {
  meta:
    severity = "high"
    description = "Mining pool / miner strings"
  strings:
    $a = /stratum\\+(tcp|ssl)/ nocase
    $b = "xmrig" nocase
    $c = "randomx" nocase
    $d = "cryptonight" nocase
    $e = "nicehash" nocase
  condition:
    any of them
}

rule elf_memfd_fileless {
  meta:
    severity = "high"
    description = "Fileless execution via memfd"
  strings:
    $a = "memfd_create" ascii
    $b = "fexecve" ascii
    $c = "/proc/self/fd/" ascii
  condition:
    $a or ($b and $c)
}

rule elf_container_escape {
  meta:
    severity = "high"
    description = "Container escape primitives"
  strings:
    $a = "/var/run/docker.sock" ascii
    $b = "nsenter" nocase
    $c = "CAP_SYS_ADMIN" ascii
    $d = "cgroup_release_agent" nocase
  condition:
    any of them
}

rule elf_credential_files {
  meta:
    severity = "high"
    description = "Credential/secret file access"
  strings:
    $a = "/etc/shadow" ascii
    $b = "id_rsa" ascii
    $c = ".aws/credentials" nocase
    $d = ".docker/config.json" nocase
  condition:
    any of them
}

rule elf_anti_debug {
  meta:
    severity = "medium"
    description = "ptrace anti-debug / VM detection"
  strings:
    $a = "PTRACE_TRACEME" ascii
    $b = "TracerPid" ascii
    $c = /hypervisor|vmware|virtualbox|qemu/ nocase
  condition:
    any of them
}

rule elf_download_pipe_shell {
  meta:
    severity = "high"
    description = "curl/wget piped to shell"
  strings:
    $a = /(curl|wget)\\s+[^\\n]{0,80}\\|\\s*(ba)?sh/ nocase
    $b = "chmod +x" nocase
  condition:
    $a or $b
}
`;

export const LKM_YARA = `
rule lkm_kallsyms_lookup {
  meta:
    severity = "high"
    description = "Runtime kernel symbol resolution"
  strings:
    $a = "kallsyms_lookup_name" ascii
    $b = "kallsyms_on_each_symbol" ascii
    $c = "/proc/kallsyms" ascii
  condition:
    any of them
}

rule lkm_syscall_table {
  meta:
    severity = "high"
    description = "Syscall table hooking"
  strings:
    $a = "sys_call_table" ascii
    $b = "ia32_sys_call_table" ascii
    $c = "native_write_cr0" ascii
  condition:
    ($a or $b) and $c
}

rule lkm_priv_escalation {
  meta:
    severity = "high"
    description = "Kernel credential manipulation"
  strings:
    $a = "commit_creds" ascii
    $b = "prepare_kernel_cred" ascii
    $c = "init_cred" ascii
  condition:
    $a and ($b or $c)
}

rule lkm_module_hiding {
  meta:
    severity = "high"
    description = "Module list manipulation / hiding"
  strings:
    $a = "list_del" ascii
    $b = "THIS_MODULE" ascii
    $c = "module_list" ascii
  condition:
    $a and ($b or $c)
}

rule lkm_kprobe_ftrace {
  meta:
    severity = "medium"
    description = "kprobe/ftrace instrumentation"
  strings:
    $a = "register_kprobe" ascii
    $b = "register_ftrace_function" ascii
    $c = "register_kretprobe" ascii
  condition:
    any of them
}

rule lkm_keylogger {
  meta:
    severity = "high"
    description = "Kernel input/keyboard hooking"
  strings:
    $a = "input_register_handler" ascii
    $b = "keyboard_notifier" ascii
    $c = "input_event" ascii
  condition:
    ($a or $b) and $c
}

rule lkm_miner_strings {
  meta:
    severity = "medium"
    description = "Mining pool strings in kernel module"
  strings:
    $a = /stratum\\+(tcp|ssl)/ nocase
    $b = "xmrig" nocase
    $c = "randomx" nocase
  condition:
    any of them
}
`;

export const SHELLCODE_YARA = `
rule sc_pic_getpc {
  meta:
    severity = "medium"
    description = "PIC get-PC sequences (call $+5 / fnstenv)"
  strings:
    $call5 = { E8 00 00 00 00 }
    $fnstenv = { D9 74 24 F4 }
    $fnstenv2 = { 9B D9 74 24 F4 }
  condition:
    $fnstenv or $fnstenv2 or $call5
}

rule sc_peb_walk {
  meta:
    severity = "high"
    description = "PEB/TEB walk via gs: for runtime API resolution"
  strings:
    $gs60 = { 65 48 8B ?? 25 60 00 00 00 }
    $gs30 = { 65 48 8B ?? 25 30 00 00 00 }
    $gs60b = { 65 48 8B ?? ?? 60 00 00 00 }
  condition:
    any of them
}

rule sc_eat_hash_loop {
  meta:
    severity = "high"
    description = "EAT-walk hashing loop (ror r32,13 + ror r32,7)"
  strings:
    $ror13 = { C1 ?? 0D }
    $ror7 = { C1 ?? 07 }
  condition:
    $ror13 and $ror7
}

rule sc_api_hash_constants {
  meta:
    severity = "high"
    description = "ROR13 API-hash constants (VirtualAlloc/WinExec/LoadLibraryA/GetProcAddress/URLDownloadToFileA/IsDebuggerPresent)"
  strings:
    $virtualalloc = { 54 CA AF 91 }
    $winexec = { 98 FE 8A 0E }
    $loadlibrarya = { 8E 4E 0E EC }
    $getprocaddress = { AA FC 0D 7C }
    $urldownloadtofilea = { 36 1A 2F 70 }
    $isdebuggerpresent = { 76 C6 6D A3 }
  condition:
    2 of them
}

rule sc_syscall_stubs {
  meta:
    severity = "medium"
    description = "Direct syscalls (syscall / sysenter / int 2e)"
  strings:
    $syscall = { 0F 05 }
    $int2e = { CD 2E }
    $sysenter = { 0F 34 }
  condition:
    $int2e or $sysenter or $syscall
}

rule sc_anti_debug_int2d {
  meta:
    severity = "medium"
    description = "int 2d anti-debug trick"
  strings:
    $int2d = { CD 2D }
  condition:
    $int2d
}

rule sc_embedded_pe {
  meta:
    severity = "high"
    description = "Embedded second-stage PE (MZ + PE header)"
  strings:
    $mz = { 4D 5A }
    $pe = { 50 45 00 00 }
  condition:
    $mz and $pe
}

rule sc_stage_strings {
  meta:
    severity = "medium"
    description = "Stage/download strings (URLs, interpreters, persistence helpers)"
  strings:
    $url = /https?:\\/\\/[^ ]+/
    $cmd = "cmd.exe" nocase
    $ps = "powershell" nocase
    $schtasks = "schtasks" nocase
  condition:
    any of them
}

rule sc_linux_privesc_strings {
  meta:
    severity = "medium"
    description = "Linux shellcode strings (shells, credential files, preload rootkit, /dev/tcp)"
  strings:
    $sh = "/bin/sh"
    $shadow = "/etc/shadow"
    $preload = "ld.so.preload"
    $devtcp = "/dev/tcp/"
  condition:
    any of them
}
`;

export const YARA_PACKS = {
  driver: KERNEL_DRIVER_YARA,
  pe: PE_USERLAND_YARA,
  elf: ELF_USERLAND_YARA,
  lkm: LKM_YARA,
  shellcode: SHELLCODE_YARA,
};
