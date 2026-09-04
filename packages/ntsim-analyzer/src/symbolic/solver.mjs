/**
 * solver.mjs — Z3 wrapper for concolic path constraints.
 *
 * Tries to load `z3-solver` (WASM) lazily. Falls back to simple heuristic
 * solver for equality constraints when Z3 unavailable or times out.
 * Exports SMT-LIB2 string for debugging / cvc5 swap.
 */

import { toSMTLib, constraintsToSMTLib } from "./expr.mjs";

let z3Cache = null;
let z3InitPromise = null;

async function getZ3() {
  if (z3Cache) return z3Cache;
  if (z3InitPromise) return z3InitPromise;
  z3InitPromise = (async () => {
    try {
      const mod = await import("z3-solver");
      const { init } = mod.default ?? mod;
      if (typeof init === "function") {
        const { Context } = await init();
        const ctx = new Context("main");
        z3Cache = { ctx, api: mod };
        return z3Cache;
      }
      // alternative: mod.init returns context factory
      if (mod.Context) {
        // some builds export Context directly
        const ctx = new mod.Context("main");
        z3Cache = { ctx, api: mod };
        return z3Cache;
      }
      // try dynamic import with named export
      throw new Error("z3 Context not found");
    } catch (e) {
      // z3 unavailable — will fallback
      console.warn("[solver] z3 not available", e?.message ?? e);
      z3Cache = null;
      return null;
    }
  })();
  return z3InitPromise;
}

// Build Z3 expression from our AST
function exprToZ3Node(expr, ctx, symVars) {
  if (!expr) return null;
  const bv = (v,bits) => ctx.BitVec.val(v,bits);
  switch(expr.kind) {
    case "sym": {
      if (!symVars[expr.id]) {
        symVars[expr.id] = ctx.BitVec.const(`sym${expr.id}`, expr.bits);
      }
      return symVars[expr.id];
    }
    case "const": return ctx.BitVec.val(Number(expr.value & ((1n<<BigInt(expr.bits))-1n)), expr.bits);
    case "add": return exprToZ3Node(expr.left, ctx, symVars).add(exprToZ3Node(expr.right, ctx, symVars));
    case "sub": return exprToZ3Node(expr.left, ctx, symVars).sub(exprToZ3Node(expr.right, ctx, symVars));
    case "and": return exprToZ3Node(expr.left, ctx, symVars).and(exprToZ3Node(expr.right, ctx, symVars));
    case "or": return exprToZ3Node(expr.left, ctx, symVars).or(exprToZ3Node(expr.right, ctx, symVars));
    case "xor": return exprToZ3Node(expr.left, ctx, symVars).xor(exprToZ3Node(expr.right, ctx, symVars));
    case "shl": return exprToZ3Node(expr.left, ctx, symVars).shl(exprToZ3Node(expr.right, ctx, symVars));
    case "shr": return exprToZ3Node(expr.left, ctx, symVars).lshr(exprToZ3Node(expr.right, ctx, symVars));
    case "sar": return exprToZ3Node(expr.left, ctx, symVars).ashr(exprToZ3Node(expr.right, ctx, symVars));
    case "mul": return exprToZ3Node(expr.left, ctx, symVars).mul(exprToZ3Node(expr.right, ctx, symVars));
    case "not": return exprToZ3Node(expr.arg, ctx, symVars).not();
    case "eq": return exprToZ3Node(expr.left, ctx, symVars).eq(exprToZ3Node(expr.right, ctx, symVars));
    case "ne": return exprToZ3Node(expr.left, ctx, symVars).eq(exprToZ3Node(expr.right, ctx, symVars)).not();
    case "ult": return exprToZ3Node(expr.left, ctx, symVars).ult(exprToZ3Node(expr.right, ctx, symVars));
    case "ugt": return exprToZ3Node(expr.left, ctx, symVars).ugt(exprToZ3Node(expr.right, ctx, symVars));
    case "ule": return exprToZ3Node(expr.left, ctx, symVars).ule(exprToZ3Node(expr.right, ctx, symVars));
    case "uge": return exprToZ3Node(expr.left, ctx, symVars).uge(exprToZ3Node(expr.right, ctx, symVars));
    case "slt": return exprToZ3Node(expr.left, ctx, symVars).slt(exprToZ3Node(expr.right, ctx, symVars));
    case "sgt": return exprToZ3Node(expr.left, ctx, symVars).sgt(exprToZ3Node(expr.right, ctx, symVars));
    case "extract": {
      // z3 BitVec.extract(high, low)
      const base = exprToZ3Node(expr.arg, ctx, symVars);
      if (typeof base.extract === "function") return base.extract(expr.high, expr.low);
      // fallback: shift and mask
      const shifted = base.lshr(ctx.BitVec.val(expr.low, expr.arg.bits));
      return shifted.extract ? shifted.extract(expr.bits-1,0) : shifted;
    }
    case "concat": {
      let cur = exprToZ3Node(expr.args[0], ctx, symVars);
      for (let i=1;i<expr.args.length;i++) {
        const nxt = exprToZ3Node(expr.args[i], ctx, symVars);
        cur = ctx.Concat(cur, nxt);
      }
      return cur;
    }
    default: return null;
  }
}

// Simple heuristic solver for eq constraints: just assign required values
function heuristicSolve(constraints, symCount) {
  // constraints: [{pred, taken}]
  // Only handle eq/ne where one side is sym* and other is const
  const model = new Array(symCount).fill(null);
  for (const c of constraints) {
    const pred = c.pred;
    if (!pred) continue;
    // we need pred to be true if taken, false if not
    // For now handle pred.kind == "eq" and taken true => sym == const
    // and pred.kind == "eq" taken false => sym != const (choose not-equal arbitrary)
    if ((pred.kind==="eq" || pred.kind==="ne") && c.taken) {
      const wantEq = pred.kind==="eq";
      // try to solve left sym vs right const
      let symId=null, constVal=null;
      if (pred.left?.kind==="sym" && pred.right?.kind==="const") { symId=pred.left.id; constVal=pred.right.value; }
      else if (pred.right?.kind==="sym" && pred.left?.kind==="const") { symId=pred.right.id; constVal=pred.left.value; }
      // also handle concat(sym bytes) == const32? For simplicity treat as individual bytes later
      if (symId!==null && constVal!==null) {
        if (wantEq) {
          model[symId]= Number(constVal & 0xffn);
        } else {
          // != constraint: pick different value than const (increment)
          const v = Number(constVal & 0xffn);
          model[symId]= (v+1) & 0xff;
        }
      }
    }
  }
  // fill gaps with original concrete or 0
  for (let i=0;i<symCount;i++) if (model[i]===null) model[i]=0;
  return model;
}

/**
 * Solve constraints with Z3 or fallback.
 * @param {Array<{pred:object,taken:boolean}>} constraints
 * @param {number} symCount
 * @param {object} opts {timeoutMs}
 * @returns {Promise<{sat:boolean, model: number[]|null, smt2:string, fallback:boolean}>}
 */
export async function solveConstraints(constraints, symCount, opts={}) {
  const timeoutMs = opts.timeoutMs ?? 500;
  const smt2 = constraintsToSMTLib(constraints, symCount);

  // try Z3
  const z3 = await getZ3();
  if (z3?.ctx) {
    const ctx = z3.ctx;
    try {
      const solver = new ctx.Solver();
      // set timeout param if supported
      try { solver.set("timeout", timeoutMs); } catch {}
      const symVars = [];
      for (const c of constraints) {
        const node = exprToZ3Node(c.pred, ctx, symVars);
        if (!node) continue;
        if (c.taken) solver.add(node);
        else {
          // need to negate: for Bool predicates, node is Bool
          // For BV predicates like eq ne etc, node already Bool
          // For BV pred that is equality, node is Bool -> negate via not()
          try { solver.add(node.not()); } catch { solver.add(ctx.Not(node)); }
        }
      }
      // timeout via race
      const checkPromise = solver.check();
      const timeoutPromise = new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs));
      let sat;
      try {
        sat = await Promise.race([checkPromise, timeoutPromise]);
      } catch (e) {
        return { sat: false, model: null, smt2, timeout: true, fallback: false };
      }
      if (String(sat) === "sat" || sat === true) {
        const model = solver.model();
        const out = new Array(symCount);
        for (let i=0;i<symCount;i++) {
          const v = symVars[i];
          if (!v) { out[i]=0; continue; }
          try {
            const evaluated = model.eval(v, true);
            // evaluated may be Z3 BitVecNum; try to extract value
            let num;
            if (typeof evaluated.value === "function") num = Number(evaluated.value());
            else if (typeof evaluated.asNumber === "function") num = evaluated.asNumber();
            else if (typeof evaluated.toString === "function") {
              const s = evaluated.toString();
              // s may be "#x.."
              if (s.startsWith("#x")) num = parseInt(s.slice(2),16);
              else num = Number(s);
            } else num=0;
            out[i]= num & 0xff;
          } catch { out[i]=0; }
        }
        return { sat: true, model: out, smt2, fallback: false };
      } else {
        return { sat: false, model: null, smt2, fallback: false };
      }
    } catch (e) {
      // Z3 path failed (e.g. previous cur.concat bug) — surface for debugging, then fallback to explicit unsat
      console.warn("[solver] z3 error", e?.message ?? e);
    }
  }

  // No-WASM / fallback path: Z3 unavailable or threw. Previously returned sat:true with all-zero model,
  // which masked the multi-byte concat bug (every 4-byte magic gate collapsed to zeros). Per review decision,
  // fallback is intentionally narrow (only matters where WASM is blocked) and must not claim sat — Z3 handles
  // concat/sub/extract natively where available.
  // Keep heuristicSolve for reference but treat its result as unsat so callers do not trust a false witness.
  heuristicSolve(constraints, symCount);
  return { sat: false, model: null, smt2, fallback: true };
}

export function getSMTLibForConstraints(constraints, symCount) {
  return constraintsToSMTLib(constraints, symCount);
}
