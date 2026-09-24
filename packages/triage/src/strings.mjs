/**
 * strings.mjs — ASCII / UTF-16LE string extraction with interest tagging.
 *
 * Deterministic, bounded, browser-safe. Used by static triage and by the
 * kernel state text (driver output/strings are already partially filtered
 * there; this is the generic extractor).
 */

export const STRING_KINDS = {
  // Substring kinds: matched anywhere inside an extracted string.
  url: /https?:\/\/[^\s"'<>|]+/i,
  ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/,
  registry: /(?:HKEY_[A-Z_]+|HKLM|HKCU|\\Registry\\|SOFTWARE\\|SYSTEM\\)[^\s"']*/i,
  path: /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/,
  command: /(?:cmd(?:\.exe)?\s+\/c\s+\S+|powershell(?:\.exe)?\s+-\S+|rundll32(?:\.exe)?\s+\S+|regsvr32(?:\.exe)?\s+\S+|schtasks(?:\.exe)?\s+\S+|sc(?:\.exe)?\s+(?:create|start)\s+\S+|wmic\s+\S+)/i,
  // Exact kinds: import-name style tokens.
  domain: /^(?!\d+\.)(?![a-z0-9-]+\.(?:exe|dll|sys|drv|ocx|txt|log|dat|bin|tmp)$)[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i,
  injectionApi: /^(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|QueueUserAPC|SetThreadContext|NtUnmapViewOfSection|LoadLibraryA?|GetProcAddress|CreateProcess[AW]?)$/,
  antiDebugApi: /^(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugStringA?|GetTickCount(?:64)?|QueryPerformanceCounter|NtSetInformationThread)$/,
  cryptoApi: /^(?:CryptEncrypt|CryptDecrypt|BCryptEncrypt|BCryptDecrypt|CryptGenKey|CryptAcquireContext[AW]?)$/,
  persistenceApi: /^(?:RegSetValueEx[AW]?|RegCreateKeyEx[AW]?|CreateService[AW]?|ChangeServiceConfig[AW]?|SHSetValue[AW]?|CreateFile[AW]?)$/,
};

const INTEREST_ORDER = [
  "url", "ipv4", "domain", "registry", "path", "command",
  "injectionApi", "antiDebugApi", "cryptoApi", "persistenceApi",
];

/**
 * Extract printable strings.
 * @param {Uint8Array} bytes
 * @param {{minLength?:number, maxStrings?:number, utf16?:boolean}} [opts]
 * @returns {{ascii:Array<{value:string,offset:number}>, utf16:Array<{value:string,offset:number}>,
 *   interesting:Array<{value:string,kind:string,offset:number}>, total:number}}
 */
export function extractStrings(bytes, { minLength = 5, maxStrings = 2048, utf16 = true } = {}) {
  const ascii = [];
  const wide = [];
  const push = (arr, value, offset) => {
    if (arr.length < maxStrings) arr.push({ value, offset });
  };

  // ASCII
  let run = "";
  let runStart = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b <= 0x7e) {
      if (!run) runStart = i;
      run += String.fromCharCode(b);
    } else {
      if (run.length >= minLength) push(ascii, run, runStart);
      run = "";
    }
  }
  if (run.length >= minLength) push(ascii, run, runStart);

  // UTF-16LE (printable ASCII chars interleaved with NUL). Check every byte
  // offset, not just even ones — wide strings are not alignment-guaranteed.
  if (utf16) {
    let i = 0;
    while (i + 1 < bytes.length) {
      if (bytes[i] >= 0x20 && bytes[i] <= 0x7e && bytes[i + 1] === 0) {
        let w = "";
        const start = i;
        while (i + 1 < bytes.length && bytes[i] >= 0x20 && bytes[i] <= 0x7e && bytes[i + 1] === 0) {
          w += String.fromCharCode(bytes[i]);
          i += 2;
        }
        if (w.length >= minLength) push(wide, w, start);
      } else {
        i++;
      }
    }
  }

  const interesting = [];
  const seen = new Set();
  for (const { value, offset } of [...ascii, ...wide]) {
    for (const kind of INTEREST_ORDER) {
      const m = value.match(STRING_KINDS[kind]);
      if (m) {
        const hit = m[0];
        const key = `${kind}:${hit}`;
        if (!seen.has(key) && interesting.length < 256) {
          seen.add(key);
          interesting.push({ value: hit, kind, offset });
        }
      }
    }
  }

  return { ascii, utf16: wide, interesting, total: ascii.length + wide.length };
}
