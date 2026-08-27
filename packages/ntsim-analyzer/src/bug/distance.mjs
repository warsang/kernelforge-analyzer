/**
 * distance.mjs — BFS distance from entry to sink blocks (AFLGo-style)
 * Computes min distance from each node to nearest sink via reverse BFS.
 */

export function computeDistances(cfg, sinkRips) {
  // sinkRips: Set<string> hex like "0x401000"
  // cfg: DynamicCFG
  // Returns Map<ripHex, distance>
  const dist = new Map();
  const queue = [];
  for (const s of sinkRips) {
    // sink rips are inside driver image; ensure they exist in cfg
    dist.set(s, 0);
    queue.push(s);
  }
  // build reverse adjacency
  const rev = new Map();
  for (const [src, succs] of cfg.adj) {
    for (const dst of succs) {
      if (!rev.has(dst)) rev.set(dst, new Set());
      rev.get(dst).add(src);
    }
  }
  while (queue.length) {
    const cur = queue.shift();
    const d = dist.get(cur);
    const preds = rev.get(cur) || [];
    for (const p of preds) {
      if (!dist.has(p)) {
        dist.set(p, d+1);
        queue.push(p);
      }
    }
  }
  // nodes not reachable -> Infinity (stored as not in map)
  return dist;
}

export function distanceForTrace(traceBlocks, distMap) {
  // traceBlocks: Set<string>
  // return min distance among blocks in trace to sink, or Infinity
  let best = Infinity;
  for (const b of traceBlocks) {
    const d = distMap.get(b);
    if (d !== undefined && d < best) best = d;
  }
  return best;
}
