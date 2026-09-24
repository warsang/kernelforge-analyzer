/**
 * rules.mjs — pure-JS YARA-subset matching engine.
 *
 * Scope (deliberately small, deterministic, browser-safe):
 *   - string kinds: text (ASCII), wide (UTF-16LE), hex with ?? wildcards,
 *     and regex
 *   - modifiers: nocase, wide, fullword (text only)
 *   - conditions: `any/all/N of them`, `$id`, `not`, `and`, `or`,
 *     parentheses, `filesize` comparisons (`>`, `<`, `>=`, `<=`, `==`)
 *   - bounded matching: caps per string, no backtracking blowups
 *
 * A full YARA engine is available later via yara-x wasm (Phase 5); this
 * engine is the always-available baseline and the fallback in the browser.
 */

const MAX_MATCHES_PER_STRING = 64;

/* --------------------------------------------------------------- strings */

function hexPatternToBytes(text) {
  const tokens = String(text).trim().split(/\s+/).filter(Boolean);
  const bytes = [];
  const masks = [];
  for (const t of tokens) {
    if (t === "??" || t === "?") {
      bytes.push(0);
      masks.push(0);
    } else if (/^[0-9a-fA-F]{2}$/.test(t)) {
      bytes.push(parseInt(t, 16));
      masks.push(0xff);
    } else if (/^[0-9a-fA-F?]{2}$/.test(t)) {
      const hi = t[0] === "?" ? 0 : parseInt(t[0], 16);
      const lo = t[1] === "?" ? 0 : parseInt(t[1], 16);
      bytes.push((hi << 4) | lo);
      masks.push((t[0] === "?" ? 0 : 0xf0) | (t[1] === "?" ? 0 : 0x0f));
    } else {
      throw new Error(`bad hex token "${t}"`);
    }
  }
  return { bytes: Uint8Array.from(bytes), masks: Uint8Array.from(masks) };
}

function utf16le(value) {
  const out = new Uint8Array(value.length * 2);
  for (let i = 0; i < value.length; i++) {
    out[i * 2] = value.charCodeAt(i) & 0xff;
    out[i * 2 + 1] = (value.charCodeAt(i) >> 8) & 0xff;
  }
  return out;
}

function findBytes(haystack, needle, masks) {
  const hits = [];
  const n = needle.length;
  if (!n || n > haystack.length) return hits;
  outer:
  for (let i = 0; i + n <= haystack.length; i++) {
    for (let j = 0; j < n; j++) {
      if ((haystack[i + j] & masks[j]) !== (needle[j] & masks[j])) continue outer;
    }
    hits.push(i);
    if (hits.length >= MAX_MATCHES_PER_STRING) break;
  }
  return hits;
}

const toLower = (b) => (b >= 0x41 && b <= 0x5a ? b + 0x20 : b);

function findText(haystack, value, { nocase = false, fullword = false } = {}) {
  const hits = [];
  const n = value.length;
  if (!n || n > haystack.length) return hits;
  outer:
  for (let i = 0; i + n <= haystack.length; i++) {
    for (let j = 0; j < n; j++) {
      const a = haystack[i + j];
      const b = value.charCodeAt(j) & 0xff;
      if ((nocase ? toLower(a) : a) !== (nocase ? toLower(b) : b)) continue outer;
    }
    if (!fullword || isFullword(haystack, i, n)) hits.push(i);
    if (hits.length >= MAX_MATCHES_PER_STRING) break;
  }
  return hits;
}

const WORD = /[A-Za-z0-9_]/;
function isFullword(bytes, offset, length) {
  const before = offset > 0 ? String.fromCharCode(bytes[offset - 1]) : "";
  const after = offset + length < bytes.length ? String.fromCharCode(bytes[offset + length]) : "";
  return !WORD.test(before) && !WORD.test(after);
}

/** Compile a rule's strings into matchers. Throws on malformed patterns. */
export function compileRule(rule) {
  const matchers = (rule.strings ?? []).map((s) => {
    const id = s.id ?? s.name;
    if (!id) throw new Error(`rule ${rule.id}: string without id`);
    const base = { id, kind: s.type ?? "text", value: s.value };
    if (base.kind === "hex") {
      const { bytes, masks } = hexPatternToBytes(s.value);
      return { ...base, search: (ctx) => findBytes(ctx.bytes, bytes, masks) };
    }
    if (base.kind === "regex") {
      let re;
      try {
        re = new RegExp(s.value, s.nocase ? "gi" : "g");
      } catch (e) {
        throw new Error(`rule ${rule.id}: bad regex ${s.value}: ${e.message}`);
      }
      return {
        ...base,
        needsText: true,
        search: (ctx) => {
          const hits = [];
          for (const m of ctx.text().matchAll(re)) {
            hits.push(m.index);
            if (hits.length >= MAX_MATCHES_PER_STRING) break;
          }
          return hits;
        },
      };
    }
    const opts = { nocase: !!s.nocase, fullword: !!s.fullword };
    const variants = [];
    if (s.wide !== false) variants.push(utf16le(s.value));
    if (s.wide !== true) variants.push(new TextEncoder().encode(s.value));
    return {
      ...base,
      search: (ctx) => {
        const hits = [];
        for (const v of variants) {
          let needle = "";
          for (let i = 0; i < v.length; i++) needle += String.fromCharCode(v[i]);
          for (const off of findText(ctx.bytes, needle, opts)) {
            hits.push(off);
            if (hits.length >= MAX_MATCHES_PER_STRING) break;
          }
        }
        return hits.sort((a, b) => a - b).slice(0, MAX_MATCHES_PER_STRING);
      },
    };
  });
  const condition = parseCondition(rule.condition ?? "any of them");
  return { ...rule, matchers, conditionAst: condition };
}

/* ------------------------------------------------------------ conditions */

/**
 * Recursive-descent parser for the condition subset.
 * AST: {t:"or"|"and"|"not"|"str"|"count"|"filesize", ...}
 */
export function parseCondition(text) {
  const tokens = tokenizeCondition(text);
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];
  const expect = (kind) => {
    const t = next();
    if (!t || t.kind !== kind) throw new Error(`condition: expected ${kind}, got ${t?.kind ?? "end"}`);
    return t;
  };

  function parseOr() {
    let left = parseAnd();
    while (peek()?.kind === "or") {
      next();
      left = { t: "or", left, right: parseAnd() };
    }
    return left;
  }
  function parseAnd() {
    let left = parseNot();
    while (peek()?.kind === "and") {
      next();
      left = { t: "and", left, right: parseNot() };
    }
    return left;
  }
  function parseNot() {
    if (peek()?.kind === "not") {
      next();
      return { t: "not", child: parseNot() };
    }
    return parsePrimary();
  }
  function parsePrimary() {
    const t = peek();
    if (!t) throw new Error("condition: unexpected end");
    if (t.kind === "(") {
      next();
      const e = parseOr();
      expect(")");
      return e;
    }
    if (t.kind === "str") {
      next();
      return { t: "str", id: t.value };
    }
    if (t.kind === "count") {
      next();
      return { t: "count", n: t.value };
    }
    if (t.kind === "any") {
      next();
      return { t: "count", n: 1 };
    }
    if (t.kind === "all") {
      next();
      return { t: "all" };
    }
    if (t.kind === "filesize") {
      next();
      const op = next();
      if (!op || op.kind !== "op") throw new Error("condition: expected operator after filesize");
      const num = next();
      if (!num || num.kind !== "num") throw new Error("condition: expected number after filesize operator");
      return { t: "filesize", op: op.value, value: num.value };
    }
    throw new Error(`condition: unexpected token ${t.kind}`);
  }

  const ast = parseOr();
  if (pos !== tokens.length) throw new Error(`condition: trailing tokens at ${pos}`);
  return ast;
}

function tokenizeCondition(text) {
  const src = String(text);
  const tokens = [];
  const re = /\s*(?:(\d+)\s+of\s+them|(any)\s+of\s+them|(all)\s+of\s+them|(\$[A-Za-z_][A-Za-z0-9_]*)|(filesize)|(>=|<=|==|>|<)|(\d+)|(\()|(\))|(and|or|not))/y;
  let pos = 0;
  while (pos < src.length) {
    re.lastIndex = pos;
    const m = re.exec(src);
    if (!m) {
      if (/^\s*$/.test(src.slice(pos))) break;
      throw new Error(`condition: cannot tokenize at "${src.slice(pos, pos + 20)}"`);
    }
    pos = re.lastIndex;
    if (m[1] !== undefined) tokens.push({ kind: "count", value: Number(m[1]) });
    else if (m[2]) tokens.push({ kind: "any" });
    else if (m[3]) tokens.push({ kind: "all" });
    else if (m[4]) tokens.push({ kind: "str", value: m[4] });
    else if (m[5]) tokens.push({ kind: "filesize" });
    else if (m[6]) tokens.push({ kind: "op", value: m[6] });
    else if (m[7]) tokens.push({ kind: "num", value: Number(m[7]) });
    else if (m[8]) tokens.push({ kind: "(" });
    else if (m[9]) tokens.push({ kind: ")" });
    else tokens.push({ kind: m[10] });
  }
  return tokens;
}

function evalCondition(ast, matched, size) {
  switch (ast.t) {
    case "or": return evalCondition(ast.left, matched, size) || evalCondition(ast.right, matched, size);
    case "and": return evalCondition(ast.left, matched, size) && evalCondition(ast.right, matched, size);
    case "not": return !evalCondition(ast.child, matched, size);
    case "str": return matched.has(ast.id);
    case "all": return matched.total > 0 && matched.size === matched.total;
    case "count": return matched.size >= Math.min(ast.n, matched.total);
    case "filesize": {
      const v = size;
      switch (ast.op) {
        case ">": return v > ast.value;
        case "<": return v < ast.value;
        case ">=": return v >= ast.value;
        case "<=": return v <= ast.value;
        case "==": return v === ast.value;
        default: return false;
      }
    }
    default: return false;
  }
}

/* --------------------------------------------------------------- scanning */

/**
 * @param {Uint8Array} bytes
 * @param {Array} rules compiled or raw rules
 * @returns {{matches:Array<{id:string, meta:object, tags:string[], strings:Array<{id:string,offset:number}>, count:number}>, scanned:number}}
 */
export function scanRules(bytes, rules, { maxMatchesPerRule = 16 } = {}) {
  const buf = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  const matches = [];
  let cachedText = null;
  const ctx = {
    bytes: buf,
    text() {
      if (cachedText !== null) return cachedText;
      let out = "";
      const CHUNK = 0x8000;
      for (let i = 0; i < buf.length; i += CHUNK) {
        out += String.fromCharCode.apply(null, buf.subarray(i, Math.min(buf.length, i + CHUNK)));
      }
      cachedText = out;
      return out;
    },
  };
  for (const raw of rules ?? []) {
    const rule = raw.matchers ? raw : compileRule(raw);
    const stringHits = [];
    const matchedIds = new Set();
    for (const m of rule.matchers) {
      let hits;
      try {
        hits = m.search(ctx);
      } catch {
        hits = [];
      }
      if (hits.length) {
        matchedIds.add(m.id);
        stringHits.push({ id: m.id, offsets: hits.slice(0, maxMatchesPerRule) });
      }
    }
    matchedIds.total = rule.matchers.length;
    const hit = evalCondition(rule.conditionAst, matchedIds, buf.length);
    if (!hit) continue;
    matches.push({
      id: rule.id,
      meta: rule.meta ?? {},
      tags: rule.meta?.tags ?? [],
      severity: rule.meta?.severity ?? "medium",
      description: rule.meta?.description ?? "",
      strings: stringHits,
      count: stringHits.length,
    });
  }
  return { matches, scanned: buf.length };
}

/** Convenience: ids only. */
export function matchRuleIds(bytes, rules) {
  return scanRules(bytes, rules).matches.map((m) => m.id);
}
