/**
 * expr.mjs — symbolic expression AST for concolic execution.
 *
 * Node kinds:
 *  sym   {kind:"sym", id:number, bits:number, concrete:bigint}
 *  const {kind:"const", bits:number, value:bigint}
 *  binop {kind:"add"|"sub"|"and"|"or"|"xor"|"shl"|"shr"|"sar"|"mul", bits, left, right, concrete}
 *  unop  {kind:"not", bits, arg, concrete}
 *  cmp   {kind:"eq"|"ne"|"ult"|"ugt"|"ule"|"uge"|"slt"|"sgt", bits:boolean, left, right, concrete:boolean}
 *  extract {kind:"extract", bits, arg, high, low, concrete}
 *  concat  {kind:"concat", bits, args:[], concrete}
 *
 *  concrete always present so interpreter can execute concretely.
 */

export function mkSym(id, concrete, bits=8) {
  return { kind:"sym", id, bits, concrete: BigInt(concrete) & ((1n<<BigInt(bits))-1n) };
}
export function mkConst(value, bits=32) {
  const mask = bits >= 64 ? 0xffffffffffffffffn : (1n<<BigInt(bits))-1n;
  return { kind:"const", bits, value: BigInt(value) & mask, concrete: BigInt(value) & mask };
}
export function mkBinop(kind, left, right, bits, concrete) {
  const mask = bits >= 64 ? 0xffffffffffffffffn : (1n<<BigInt(bits))-1n;
  return { kind, bits, left, right, concrete: BigInt(concrete) & mask };
}
export function mkCmp(kind, left, right, concrete) {
  return { kind, left, right, concrete: !!concrete, bits: 1 };
}
export function mkNot(arg, bits, concrete) {
  const mask = bits >= 64 ? 0xffffffffffffffffn : (1n<<BigInt(bits))-1n;
  return { kind:"not", bits, arg, concrete: BigInt(concrete) & mask };
}
export function mkExtract(arg, high, low, concrete) {
  const bits = high - low + 1;
  return { kind:"extract", bits, arg, high, low, concrete: BigInt(concrete) & ((1n<<BigInt(bits))-1n) };
}
export function mkConcat(args, bits, concrete) {
  return { kind:"concat", bits, args, concrete: BigInt(concrete) & ((1n<<BigInt(bits))-1n) };
}

export function isSymbolic(node) {
  return !!node && node.kind !== "const";
}

export function collectSymIds(expr, out = new Set()) {
  if (!expr) return out;
  if (expr.kind === "sym") out.add(expr.id);
  else if (expr.left) collectSymIds(expr.left, out);
  if (expr.right) collectSymIds(expr.right, out);
  if (expr.arg) collectSymIds(expr.arg, out);
  if (expr.args) for (const a of expr.args) collectSymIds(a, out);
  return out;
}

// Pretty for debugging
export function exprToString(e) {
  if (!e) return "null";
  switch(e.kind) {
    case "sym": return `sym${e.id}:${e.bits}=0x${e.concrete.toString(16)}`;
    case "const": return `0x${e.value.toString(16)}:${e.bits}`;
    case "not": return `(not ${exprToString(e.arg)})`;
    case "extract": return `(extract ${e.high}:${e.low} ${exprToString(e.arg)})`;
    case "concat": return `(concat ${e.args.map(exprToString).join(" ")})`;
    default:
      if (e.left || e.right) return `(${e.kind} ${exprToString(e.left)} ${exprToString(e.right)})`;
      return e.kind;
  }
}

// Convert to SMT-LIB2 string (QF_BV)
export function toSMTLib(expr) {
  if (!expr) return "";
  switch(expr.kind) {
    case "sym": return `sym${expr.id}`;
    case "const": {
      const hex = expr.value.toString(16).padStart(Math.ceil(expr.bits/4),"0");
      return `#x${hex}`;
    }
    case "add": return `(bvadd ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "sub": return `(bvsub ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "and": return `(bvand ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "or": return `(bvor ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "xor": return `(bvxor ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "shl": return `(bvshl ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "shr": return `(bvlshr ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "sar": return `(bvashr ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "mul": return `(bvmul ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "not": return `(bvnot ${toSMTLib(expr.arg)})`;
    case "eq": return `(= ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "ne": return `(not (= ${toSMTLib(expr.left)} ${toSMTLib(expr.right)}))`;
    case "ult": return `(bvult ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "ugt": return `(bvugt ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "ule": return `(bvule ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "uge": return `(bvuge ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "slt": return `(bvslt ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "sgt": return `(bvsgt ${toSMTLib(expr.left)} ${toSMTLib(expr.right)})`;
    case "extract": return `((_ extract ${expr.high} ${expr.low}) ${toSMTLib(expr.arg)})`;
    case "concat": return `(concat ${expr.args.map(toSMTLib).join(" ")})`;
    default: return `; unknown ${expr.kind}`;
  }
}

export function constraintsToSMTLib(constraints, symCount) {
  // constraints: Array<{pred, taken:boolean}>
  const lines = [];
  lines.push("(set-logic QF_BV)");
  for (let i=0;i<symCount;i++) lines.push(`(declare-const sym${i} (_ BitVec 8))`);
  for (const c of constraints) {
    const smt = toSMTLib(c.pred);
    if (c.taken) lines.push(`(assert ${smt})`);
    else lines.push(`(assert (not ${smt}))`);
  }
  lines.push("(check-sat)\n(get-model)");
  return lines.join("\n");
}
