/**
 * userland.mjs — pure-JS rule packs for userland PE / ELF / Linux LKM triage.
 *
 * Same engine as the kernel-driver pack (./rules.mjs). These rules are
 * intent/behavior indicators read from static content; a hit is a lead, not a
 * verdict. Severity reflects potential impact if the referenced behavior is
 * implemented.
 */

/** @type {Array<{id:string, meta:object, strings:Array, condition:string}>} */
export const PE_USERLAND_RULES = [
  {
    id: "pe_process_injection",
    meta: { severity: "high", tags: ["injection"], description: "Classic cross-process injection chain (OpenProcess + WriteProcessMemory + CreateRemoteThread)." },
    strings: [
      { id: "$a", type: "text", value: "OpenProcess" },
      { id: "$b", type: "text", value: "WriteProcessMemory" },
      { id: "$c", type: "text", value: "CreateRemoteThread" },
      { id: "$d", type: "text", value: "VirtualAllocEx" },
      { id: "$e", type: "text", value: "NtWriteVirtualMemory" },
      { id: "$f", type: "text", value: "NtCreateThreadEx" },
      { id: "$g", type: "text", value: "QueueUserAPC" },
    ],
    condition: "($a and ($b or $e) and ($c or $f or $g)) or ($d and ($b or $e))",
  },
  {
    id: "pe_apc_injection",
    meta: { severity: "high", tags: ["injection"], description: "APC injection primitives." },
    strings: [
      { id: "$a", type: "text", value: "QueueUserAPC" },
      { id: "$b", type: "text", value: "OpenThread" },
      { id: "$c", type: "text", value: "SetThreadContext" },
      { id: "$d", type: "text", value: "GetThreadContext" },
      { id: "$e", type: "text", value: "NtQueueApcThread" },
    ],
    condition: "($a and $b) or ($c and $d) or $e",
  },
  {
    id: "pe_process_hollowing",
    meta: { severity: "high", tags: ["injection", "evasion"], description: "Process hollowing (CreateProcess suspended + NtUnmapViewOfSection + SetThreadContext + ResumeThread)." },
    strings: [
      { id: "$a", type: "text", value: "NtUnmapViewOfSection" },
      { id: "$b", type: "text", value: "SetThreadContext" },
      { id: "$c", type: "text", value: "ResumeThread" },
      { id: "$d", type: "text", value: "ZwUnmapViewOfSection" },
    ],
    condition: "($a or $d) and $b and $c",
  },
  {
    id: "pe_credential_access",
    meta: { severity: "high", tags: ["credential-access"], description: "LSASS / credential dumping indicators." },
    strings: [
      { id: "$a", type: "text", value: "lsass.exe", nocase: true },
      { id: "$b", type: "text", value: "MiniDumpWriteDump" },
      { id: "$c", type: "text", value: "comsvcs", nocase: true },
      { id: "$d", type: "text", value: "secretsdump", nocase: true },
      { id: "$e", type: "text", value: "SAM\\SAM", nocase: true },
      { id: "$f", type: "text", value: "lsadump", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "pe_persistence_runkey",
    meta: { severity: "medium", tags: ["persistence"], description: "Run/RunOnce registry persistence strings." },
    strings: [
      { id: "$a", type: "text", value: "CurrentVersion\\Run", nocase: true },
      { id: "$b", type: "text", value: "CurrentVersion\\RunOnce", nocase: true },
      { id: "$c", type: "text", value: "Winlogon", nocase: true },
      { id: "$d", type: "text", value: "Userinit", nocase: true },
      { id: "$e", type: "text", value: "AppInit_DLLs", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "pe_persistence_scheduled",
    meta: { severity: "medium", tags: ["persistence"], description: "Scheduled task / service persistence." },
    strings: [
      { id: "$a", type: "text", value: "schtasks", nocase: true },
      { id: "$b", type: "text", value: "/create", nocase: true },
      { id: "$c", type: "text", value: "CreateServiceA" },
      { id: "$d", type: "text", value: "ChangeServiceConfigA" },
      { id: "$e", type: "text", value: "sc create", nocase: true },
      { id: "$f", type: "text", value: "StartupApproved", nocase: true },
    ],
    condition: "($a and $b) or ($c or $d) or $e or $f",
  },
  {
    id: "pe_defense_evasion_security",
    meta: { severity: "high", tags: ["security-tamper"], description: "Security product tampering (Defender exclusions, AMSI/ETW patching)." },
    strings: [
      { id: "$a", type: "text", value: "Set-MpPreference", nocase: true },
      { id: "$b", type: "text", value: "DisableRealtimeMonitoring", nocase: true },
      { id: "$c", type: "text", value: "ExclusionPath", nocase: true },
      { id: "$d", type: "text", value: "amsi.dll", nocase: true },
      { id: "$e", type: "text", value: "AmsiScanBuffer", nocase: true },
      { id: "$f", type: "text", value: "EtwEventWrite", nocase: true },
      { id: "$g", type: "text", value: "Add-MpPreference", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "pe_ransomware_behavior",
    meta: { severity: "high", tags: ["ransomware", "destructive"], description: "Shadow-copy/log destruction and ransom-note strings." },
    strings: [
      { id: "$a", type: "text", value: "vssadmin", nocase: true },
      { id: "$b", type: "text", value: "delete shadows", nocase: true },
      { id: "$c", type: "text", value: "bcdedit", nocase: true },
      { id: "$d", type: "text", value: "wevtutil cl", nocase: true },
      { id: "$e", type: "text", value: "wbadmin delete", nocase: true },
      { id: "$f", type: "regex", value: "your files (?:have been|are) encrypted|readme.*decrypt|recover.*files", nocase: true },
      { id: "$g", type: "text", value: "CryptoAPI", nocase: true },
    ],
    condition: "($a and ($b or $e)) or $c or $d or $f",
  },
  {
    id: "pe_downloader",
    meta: { severity: "high", tags: ["downloader", "network"], description: "Download-and-execute primitives." },
    strings: [
      { id: "$a", type: "text", value: "URLDownloadToFile" },
      { id: "$b", type: "text", value: "InternetOpenUrl" },
      { id: "$c", type: "text", value: "WinHttpReadData" },
      { id: "$d", type: "text", value: "ShellExecute" },
      { id: "$e", type: "text", value: "WinExec" },
      { id: "$f", type: "text", value: "CreateProcess" },
      { id: "$g", type: "text", value: "URLDownloadToCacheFile" },
    ],
    condition: "($a or $b or $c or $g) and ($d or $e or $f)",
  },
  {
    id: "pe_script_abuse",
    meta: { severity: "medium", tags: ["execution"], description: "Living-off-the-land script execution (encoded PowerShell, mshta, regsvr32 scrobj)." },
    strings: [
      { id: "$a", type: "regex", value: "powershell(?:\\.exe)?\\s+(?:-|/)(?:enc|encodedcommand|nop|w hidden)", nocase: true },
      { id: "$b", type: "text", value: "mshta", nocase: true },
      { id: "$c", type: "text", value: "scrobj.dll", nocase: true },
      { id: "$d", type: "text", value: "FromBase64String", nocase: true },
      { id: "$e", type: "text", value: "certutil -urlcache", nocase: true },
      { id: "$f", type: "text", value: "bitsadmin /transfer", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "pe_anti_debug",
    meta: { severity: "medium", tags: ["anti-analysis"], description: "Anti-debug / anti-VM APIs." },
    strings: [
      { id: "$a", type: "text", value: "IsDebuggerPresent" },
      { id: "$b", type: "text", value: "CheckRemoteDebuggerPresent" },
      { id: "$c", type: "text", value: "NtQueryInformationProcess" },
      { id: "$d", type: "text", value: "OutputDebugString" },
      { id: "$e", type: "text", value: "GetTickCount" },
      { id: "$f", type: "text", value: "QueryPerformanceCounter" },
      { id: "$g", type: "regex", value: "VBox|VMware|VirtualBox|qemu|SbieDll|dbghelp", nocase: true },
    ],
    condition: "($a and ($b or $c)) or ($d and $e and $f) or $g",
  },
  {
    id: "pe_keylogging",
    meta: { severity: "high", tags: ["spyware"], description: "Keylogging primitives." },
    strings: [
      { id: "$a", type: "text", value: "SetWindowsHookEx" },
      { id: "$b", type: "text", value: "GetAsyncKeyState" },
      { id: "$c", type: "text", value: "GetForegroundWindow" },
      { id: "$d", type: "text", value: "GetKeyboardState" },
    ],
    condition: "($a or $d) and ($b or $c)",
  },
  {
    id: "pe_screen_capture",
    meta: { severity: "medium", tags: ["spyware"], description: "Screen/webcam capture." },
    strings: [
      { id: "$a", type: "text", value: "BitBlt" },
      { id: "$b", type: "text", value: "GetDC" },
      { id: "$c", type: "text", value: "capCreateCaptureWindow" },
      { id: "$d", type: "text", value: "avicap32" },
    ],
    condition: "($a and $b) or ($c or $d)",
  },
  {
    id: "pe_packer_artifacts",
    meta: { severity: "medium", tags: ["packer"], description: "Packer/protector artifacts." },
    strings: [
      { id: "$a", type: "text", value: "UPX!" },
      { id: "$b", type: "text", value: "Themida", nocase: true },
      { id: "$c", type: "text", value: "VMProtect", nocase: true },
      { id: "$d", type: "text", value: "Enigma protector", nocase: true },
      { id: "$e", type: "text", value: ".vmp0" },
      { id: "$f", type: "text", value: "MPRESS", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "pe_com_abuse",
    meta: { severity: "medium", tags: ["execution"], description: "COM/WMI script execution (T1047/T1218)." },
    strings: [
      { id: "$a", type: "text", value: "winmgmts:", nocase: true },
      { id: "$b", type: "text", value: "WbemScripting.SWbemLocator", nocase: true },
      { id: "$c", type: "text", value: "win32_process", nocase: true },
      { id: "$d", type: "text", value: "Shell.Application", nocase: true },
      { id: "$e", type: "text", value: "WScript.Shell", nocase: true },
    ],
    condition: "any of them",
  },
];

/** @type {Array<{id:string, meta:object, strings:Array, condition:string}>} */
export const ELF_USERLAND_RULES = [
  {
    id: "elf_reverse_shell",
    meta: { severity: "high", tags: ["shell", "network"], description: "Reverse shell one-liners and primitives." },
    strings: [
      { id: "$a", type: "text", value: "/dev/tcp/" },
      { id: "$b", type: "regex", value: "(?:bash|sh)\\s+-i|nc\\s+(?:-e|--exec)|ncat\\s+-e|socat\\s+exec", nocase: true },
      { id: "$c", type: "text", value: "python -c", nocase: true },
      { id: "$d", type: "text", value: "socket.SOCK_STREAM", nocase: true },
      { id: "$e", type: "text", value: "pty.spawn", nocase: true },
      { id: "$f", type: "text", value: "/bin/sh" },
    ],
    condition: "$a or $b or ($c and $d) or ($e and $f)",
  },
  {
    id: "elf_ld_preload_persistence",
    meta: { severity: "high", tags: ["persistence", "rootkit"], description: "Userland rootkit via ld.so.preload / LD_PRELOAD." },
    strings: [
      { id: "$a", type: "text", value: "/etc/ld.so.preload" },
      { id: "$b", type: "text", value: "LD_PRELOAD" },
      { id: "$c", type: "text", value: "ld.so.preload" },
      { id: "$d", type: "text", value: "RTLD_DEEPBIND" },
    ],
    condition: "any of them",
  },
  {
    id: "elf_miner",
    meta: { severity: "high", tags: ["miner"], description: "Cryptomining pools / miner artifacts." },
    strings: [
      { id: "$a", type: "regex", value: "stratum\\+tcp|stratum\\+ssl|nicehash|xmrig|minerd|cpuminer", nocase: true },
      { id: "$b", type: "regex", value: "monero|randomx|cryptonight", nocase: true },
      { id: "$c", type: "regex", value: "pool\\.(?:minexmr|supportxmr|nanopool)", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "elf_persistence_cron_systemd",
    meta: { severity: "medium", tags: ["persistence"], description: "Cron/systemd/authorized_keys persistence." },
    strings: [
      { id: "$a", type: "text", value: "/etc/cron", nocase: true },
      { id: "$b", type: "text", value: "/etc/systemd/system", nocase: true },
      { id: "$c", type: "text", value: ".ssh/authorized_keys", nocase: true },
      { id: "$d", type: "text", value: "/etc/rc.local" },
      { id: "$e", type: "text", value: "/etc/profile.d", nocase: true },
      { id: "$f", type: "text", value: ".bashrc", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "elf_credential_files",
    meta: { severity: "high", tags: ["credential-access"], description: "Credential/secret file access." },
    strings: [
      { id: "$a", type: "text", value: "/etc/shadow" },
      { id: "$b", type: "text", value: "id_rsa" },
      { id: "$c", type: "text", value: ".aws/credentials", nocase: true },
      { id: "$d", type: "text", value: ".ssh/" },
      { id: "$e", type: "text", value: "kube/config", nocase: true },
      { id: "$f", type: "text", value: ".docker/config.json", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "elf_container_escape",
    meta: { severity: "high", tags: ["container-escape"], description: "Container escape primitives." },
    strings: [
      { id: "$a", type: "text", value: "/var/run/docker.sock" },
      { id: "$b", type: "text", value: "nsenter", nocase: true },
      { id: "$c", type: "text", value: "unshare", nocase: true },
      { id: "$d", type: "text", value: "CAP_SYS_ADMIN" },
      { id: "$e", type: "text", value: "/proc/1/root" },
      { id: "$f", type: "text", value: "cgroup_release_agent", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "elf_memfd_execution",
    meta: { severity: "high", tags: ["evasion", "execution"], description: "Fileless execution via memfd_create." },
    strings: [
      { id: "$a", type: "text", value: "memfd_create" },
      { id: "$b", type: "text", value: "fexecve" },
      { id: "$c", type: "text", value: "/proc/self/fd/" },
    ],
    condition: "$a or ($b and $c)",
  },
  {
    id: "elf_anti_analysis",
    meta: { severity: "medium", tags: ["anti-analysis"], description: "ptrace anti-debug / VM detection." },
    strings: [
      { id: "$a", type: "text", value: "ptrace" },
      { id: "$b", type: "text", value: "PTRACE_TRACEME" },
      { id: "$c", type: "regex", value: "/proc/self/status|TracerPid", nocase: true },
      { id: "$d", type: "regex", value: "hypervisor|vmware|qemu|virtualbox", nocase: true },
      { id: "$e", type: "text", value: "LD_PRELOAD" },
    ],
    condition: "($a and $b) or $c or $d",
  },
  {
    id: "elf_log_tampering",
    meta: { severity: "medium", tags: ["defense-evasion"], description: "Log/history destruction." },
    strings: [
      { id: "$a", type: "text", value: "/var/log/", nocase: true },
      { id: "$b", type: "text", value: "history -c", nocase: true },
      { id: "$c", type: "text", value: "shred", nocase: true },
      { id: "$d", type: "text", value: "wtmp", nocase: true },
      { id: "$e", type: "text", value: "utmp", nocase: true },
    ],
    condition: "($a and ($c or $b)) or ($d and $e)",
  },
  {
    id: "elf_download_execute",
    meta: { severity: "high", tags: ["downloader"], description: "curl/wget piped to a shell." },
    strings: [
      { id: "$a", type: "regex", value: "(?:curl|wget)\\s+[^\\n]{0,80}\\|\\s*(?:ba)?sh", nocase: true },
      { id: "$b", type: "text", value: "curl -fsSL", nocase: true },
      { id: "$c", type: "text", value: "wget -qO-", nocase: true },
      { id: "$d", type: "text", value: "chmod +x", nocase: true },
    ],
    condition: "$a or (($b or $c) and $d)",
  },
  {
    id: "elf_kernel_module_tamper",
    meta: { severity: "high", tags: ["rootkit"], description: "Userspace manipulation of kernel modules / syscalls." },
    strings: [
      { id: "$a", type: "text", value: "insmod", nocase: true },
      { id: "$b", type: "text", value: "sys_call_table" },
      { id: "$c", type: "text", value: "kallsyms" },
      { id: "$d", type: "text", value: "/dev/kmem" },
      { id: "$e", type: "text", value: "init_module" },
      { id: "$f", type: "text", value: "delete_module" },
    ],
    condition: "$b or $d or (($a or $e or $f) and $c)",
  },
];

/** @type {Array<{id:string, meta:object, strings:Array, condition:string}>} */
export const LKM_RULES = [
  {
    id: "lkm_kallsyms_resolution",
    meta: { severity: "high", tags: ["rootkit", "evasion"], description: "Resolves kernel symbols at runtime via kallsyms_lookup_name (no exported symbols needed)." },
    strings: [
      { id: "$a", type: "text", value: "kallsyms_lookup_name" },
      { id: "$b", type: "text", value: "kallsyms_on_each_symbol" },
      { id: "$c", type: "text", value: "/proc/kallsyms" },
    ],
    condition: "any of them",
  },
  {
    id: "lkm_syscall_hooking",
    meta: { severity: "high", tags: ["rootkit", "hook"], description: "Syscall table hooking." },
    strings: [
      { id: "$a", type: "text", value: "sys_call_table" },
      { id: "$b", type: "text", value: "ia32_sys_call_table" },
      { id: "$c", type: "text", value: "close_cr0" },
      { id: "$d", type: "text", value: "native_write_cr0" },
      { id: "$e", type: "text", value: "__x64_sys_" },
    ],
    condition: "($a or $b) and ($c or $d or $e)",
  },
  {
    id: "lkm_cred_escalation",
    meta: { severity: "high", tags: ["privilege-escalation"], description: "commit_creds/prepare_kernel_cred privilege escalation." },
    strings: [
      { id: "$a", type: "text", value: "commit_creds" },
      { id: "$b", type: "text", value: "prepare_kernel_cred" },
      { id: "$c", type: "text", value: "init_cred" },
      { id: "$d", type: "text", value: "override_creds" },
    ],
    condition: "($a or $d) and ($b or $c)",
  },
  {
    id: "lkm_module_hiding",
    meta: { severity: "high", tags: ["rootkit", "stealth"], description: "Module list unlinking / hiding." },
    strings: [
      { id: "$a", type: "text", value: "list_del" },
      { id: "$b", type: "text", value: "THIS_MODULE" },
      { id: "$c", type: "text", value: "modules" },
      { id: "$d", type: "text", value: "kobject_del" },
      { id: "$e", type: "text", value: "module_list" },
    ],
    condition: "($a and ($b or $e)) or ($c and $d and $a)",
  },
  {
    id: "lkm_ftrace_kprobe",
    meta: { severity: "medium", tags: ["hook", "instrumentation"], description: "ftrace/kprobe hooking of kernel functions." },
    strings: [
      { id: "$a", type: "text", value: "register_kprobe" },
      { id: "$b", type: "text", value: "ftrace_set_filter" },
      { id: "$c", type: "text", value: "register_ftrace_function" },
      { id: "$d", type: "text", value: "kprobe" },
      { id: "$e", type: "text", value: "kretprobe" },
      { id: "$f", type: "text", value: "register_kretprobe" },
    ],
    condition: "$a or $b or $c or $f or ($d and $e)",
  },
  {
    id: "lkm_keylogger",
    meta: { severity: "high", tags: ["spyware"], description: "Keyboard/input hooking (rootkit keylogger)." },
    strings: [
      { id: "$a", type: "text", value: "input_register_handler" },
      { id: "$b", type: "text", value: "input_register_handle" },
      { id: "$c", type: "text", value: "keyboard_notifier" },
      { id: "$d", type: "text", value: "kbd_event" },
      { id: "$e", type: "text", value: "notifier_call" },
      { id: "$f", type: "text", value: "input_event" },
    ],
    condition: "($a or $b or $c) or ($e and $f)",
  },
  {
    id: "lkm_hide_files_processes",
    meta: { severity: "high", tags: ["rootkit", "stealth"], description: "Hides files/processes by hooking VFS or task lists." },
    strings: [
      { id: "$a", type: "text", value: "iterate_dir" },
      { id: "$b", type: "text", value: "filldir" },
      { id: "$c", type: "text", value: "task_struct" },
      { id: "$d", type: "text", value: "tasklist_lock" },
      { id: "$e", type: "text", value: "for_each_process" },
      { id: "$f", type: "text", value: "getdents" },
    ],
    condition: "(($a or $f) and ($b or $e)) or ($c and $d)",
  },
  {
    id: "lkm_network_hook",
    meta: { severity: "medium", tags: ["network", "rootkit"], description: "Netfilter/socket hooking." },
    strings: [
      { id: "$a", type: "text", value: "nf_register_hook" },
      { id: "$b", type: "text", value: "nf_register_net_hook" },
      { id: "$c", type: "text", value: "sock_create" },
      { id: "$d", type: "text", value: "tcp_sendmsg" },
      { id: "$e", type: "text", value: "udp_sendmsg" },
      { id: "$f", type: "text", value: "nf_hook_ops" },
    ],
    condition: "$a or $b or $f or ($c and ($d or $e))",
  },
  {
    id: "lkm_crypto_miner_ioctl",
    meta: { severity: "medium", tags: ["miner"], description: "Mining-related kernel helpers / stratum constants." },
    strings: [
      { id: "$a", type: "regex", value: "stratum\\+tcp|xmrig|monero", nocase: true },
      { id: "$b", type: "text", value: "randomx", nocase: true },
      { id: "$c", type: "text", value: "cryptonight", nocase: true },
    ],
    condition: "any of them",
  },
  {
    id: "lkm_debug_interface",
    meta: { severity: "low", tags: ["instrumentation"], description: "Debug/proc interface (common in both tools and malware)." },
    strings: [
      { id: "$a", type: "text", value: "proc_create" },
      { id: "$b", type: "text", value: "debugfs_create" },
      { id: "$c", type: "text", value: "seq_printf" },
      { id: "$d", type: "text", value: "copy_from_user" },
    ],
    condition: "($a or $b) and ($c or $d)",
  },
];

export const USERLAND_RULE_PACKS = {
  pe: PE_USERLAND_RULES,
  elf: ELF_USERLAND_RULES,
  lkm: LKM_RULES,
};
