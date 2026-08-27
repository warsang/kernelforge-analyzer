/**
 * cfg.mjs — control-flow graph builder for directed fuzzing
 * Lightweight: built dynamically from observed edges, not full static disasm.
 */

export class DynamicCFG {
  constructor(entryRip) {
    this.entry = BigInt(entryRip);
    this.adj = new Map(); // ripHex -> Set<succHex>
    this.nodes = new Set();
  }

  addEdge(prevRip, curRip) {
    const p = "0x"+BigInt(prevRip).toString(16);
    const c = "0x"+BigInt(curRip).toString(16);
    this.nodes.add(p); this.nodes.add(c);
    if (!this.adj.has(p)) this.adj.set(p, new Set());
    this.adj.get(p).add(c);
    if (!this.adj.has(c)) this.adj.set(c, new Set());
  }

  addTrace(edges) {
    // edges is Set<"prev->cur"> as from CoverageTracker
    for (const e of edges) {
      const [prev, cur] = e.split("->");
      if (!this.adj.has(prev)) this.adj.set(prev, new Set());
      this.adj.get(prev).add(cur);
      this.nodes.add(prev); this.nodes.add(cur);
    }
  }

  // also build from blocks set as linear fallthrough assumption if no edge info
  addBlocks(blocks) {
    // blocks is Set<"0x..."> in execution order is not preserved; we can't infer edges
    // so we just ensure nodes exist
    for (const b of blocks) this.nodes.add(b);
  }

  size() { return this.nodes.size; }
}
