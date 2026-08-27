/**
 * Main-thread client for the in-browser compiler worker.
 *
 * compileSource(source) -> Uint8Array (x64 COFF .obj) | throws with stderr
 * Same shape the /api/compile bridge returns, so callers can switch freely.
 *
 * The worker spawns lazily and is guarded for non-browser contexts (Vite SSR
 * dependency scan, Node tests): `window`/`Worker` absent means "unavailable",
 * never a thrown ReferenceError.
 */

export class BrowserCompiler {
  constructor() {
    this.worker = null;
    this.failed = false;
    this.nextId = 1;
    this.pending = new Map();
  }

  /** True only in a real browser main thread. */
  static get supported() {
    return (
      typeof window !== "undefined" &&
      typeof Worker !== "undefined" &&
      typeof import.meta.url === "string"
    );
  }

  _ensureWorker() {
    if (!BrowserCompiler.supported) {
      throw new Error("browser compiler unavailable outside a browser main thread");
    }
    if (this.failed) throw new Error("browser compiler worker failed earlier this session");
    if (this.worker) return this.worker;
    try {
      this.worker = new Worker(
        new URL("./browser.worker.mjs", import.meta.url),
        { type: "module" }
      );
    } catch (e) {
      this.failed = true;
      throw new Error(`worker spawn failed: ${e?.message ?? e}`);
    }
    this.worker.onmessage = (ev) => {
      const { id, ok, objBytes, error } = ev.data ?? {};
      const pending = this.pending.get(id);
      if (!pending) return;
      this.pending.delete(id);
      ok ? pending.resolve(objBytes) : pending.reject(new Error(error));
    };
    this.worker.onerror = (e) => {
      // module-load failure inside the worker (missing dist, bad import):
      // mark broken so callers fall back to the server bridge immediately.
      this.failed = true;
      const err = new Error(e.message ?? "worker error");
      for (const p of this.pending.values()) p.reject(err);
      this.pending.clear();
    };
    return this.worker;
  }

  _call(op, payload) {
    const worker = this._ensureWorker(); // throws when unsupported/broken
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      worker.postMessage({ id, op, payload });
    });
  }

  /** Preload clang/lld WASM (~40MB). Resolves false when unavailable. */
  async warmup() {
    try {
      await this._call("warmup", {});
      return true;
    } catch {
      return false;
    }
  }

  /**
   * @param {string} source C source
   * @param {string} [target] "windows" | "linux"
   * @returns {Promise<Uint8Array>} object bytes
   */
  async compileSource(source, target="windows") {
    const bytes = await this._call("compile", { source, target });
    return bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  }
}
