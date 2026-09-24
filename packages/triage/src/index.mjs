/**
 * @kernelforge/triage — static malware-triage primitives.
 *
 * Format-agnostic evidence extraction (PE/ELF facts, entropy, strings,
 * hashes, fuzzy hashing, pure-JS rules) with no I/O and no emulation, so the
 * same code runs in Node, browser workers and the analyzer UI.
 */

export { md5, sha256 } from "./md5.mjs";
export { shannonEntropy, entropyAt, printableRatio } from "./entropy.mjs";
export { extractStrings, STRING_KINDS } from "./strings.mjs";
export { parsePeStatic } from "./pe.mjs";
export { ssdeep, ssdeepCompare } from "./fuzzy/ssdeep.mjs";
export { compileRule, parseCondition, scanRules, matchRuleIds } from "./rules.mjs";
export { KERNEL_DRIVER_RULES } from "./rules/kernel-driver.mjs";
export { PE_USERLAND_RULES, ELF_USERLAND_RULES, LKM_RULES, USERLAND_RULE_PACKS } from "./rules/userland.mjs";
export { parseElf64, parseElfStatic } from "./elf.mjs";
export { stateTextFromUserland } from "./state-text-userland.mjs";
export { shellcodeFacts } from "./shellcode.mjs";
export { SHELLCODE_RULES } from "./rules/shellcode.mjs";
export { extractStackStrings } from "./stackstrings.mjs";
export { detectApiHashes, buildApiHashTable, HASH_ALGOS, API_DICTIONARY, ror13, djb2, crc32, murmur3 } from "./apihash.mjs";
export {
  initYaraX, compileYara, scanWithYaraX, normalizeYaraMatches, describeYaraRule,
  defaultYaraGlobals, isYaraWasmBroken, resetYaraWasm,
} from "./yara.mjs";
export {
  KERNEL_DRIVER_YARA, PE_USERLAND_YARA, ELF_USERLAND_YARA, LKM_YARA, SHELLCODE_YARA,
  YARA_PACKS,
} from "./yara-packs.mjs";
export {
  RULESETS, RULESET_IDS, DEFAULT_COMMUNITY_RULESETS, OPTIONAL_RULESETS, ALL_RULESETS,
  HEAVY_RULESETS, STAGED_RULESET_BASE,
  loadRulesetSource, extractZipText, extractTarGzText, mergeRulesetMatches,
  splitYaraSource, scanYaraSourceInChunks,
} from "./yara-rulesets.mjs";
