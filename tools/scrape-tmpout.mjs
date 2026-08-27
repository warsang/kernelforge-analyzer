#!/usr/bin/env node
/**
 * Scrapes tmp.0ut (https://tmpout.sh) zine articles into a local gitignored cache.
 *
 * Usage:
 *   node tools/scrape-tmpout.mjs [--volumes 1,2,3,4,5] [--force] [--out dir]
 *
 * Volume 1 ships plain-text mirrors under /txt/<name>.txt; volumes 2-5 are HTML
 * only, so we extract the <div class="txtdiv"> body and strip tags. Raw source
 * files (.asm/.c/.pl) are fetched verbatim. Directory-style links (image
 * galleries) are recorded as skipped in the manifest.
 *
 * Output: <out>/v<vol>/<NN>-<slug>.txt  +  <out>/v<vol>/manifest.json
 */

import { mkdir, writeFile, access } from "node:fs/promises";
import path from "node:path";

const BASE = "https://tmpout.sh";

function args() {
  const a = process.argv.slice(2);
  const get = (k) => {
    const i = a.indexOf(k);
    return i >= 0 ? a[i + 1] : undefined;
  };
  return {
    volumes:
      get("--volumes")?.split(",").map((s) => parseInt(s, 10)) ?? [1, 2, 3, 4, 5],
    force: a.includes("--force"),
    out: get("--out") ?? new URL("../.cache/tmpout/", import.meta.url).pathname,
  };
}

async function fetchText(url) {
  const res = await fetch(url, { headers: { "user-agent": "kernelforge-research" } });
  if (!res.ok) throw Object.assign(new Error(`${res.status} ${url}`), { status: res.status });
  return res.text();
}

async function exists(p) {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

const ENTITIES = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
  "&#x27;": "'",
  "&nbsp;": " ",
};

function decodeEntities(s) {
  return s.replace(/&(?:amp|lt|gt|quot|#39|#x27|nbsp);/g, (m) => ENTITIES[m] ?? m);
}

/** Extract readable text from an article HTML page. */
function htmlToText(html) {
  const m = html.match(/<div class="txtdiv">([\s\S]*)<\/div>/);
  let s = m ? m[1] : html;
  s = s.replace(/<script[\s\S]*?<\/script>/g, "");
  s = s.replace(/<style[\s\S]*?<\/style>/g, "");
  // nav footer like: [ PREV | HOME | NEXT ]
  s = s.replace(/--\[\s*<a[\s\S]*?<\/a>\s*\]--/g, "");
  s = s.replace(/<pre><code[^>]*>/g, "\n```\n");
  s = s.replace(/<\/code><\/pre>/g, "\n```\n");
  s = s.replace(/<br\s*\/?>/gi, "\n");
  s = s.replace(/<[^>]+>/g, "");
  s = decodeEntities(s);
  return s.replace(/\n{5,}/g, "\n\n\n").trim() + "\n";
}

/** Pull article links (+ titles/authors where present) out of a volume index page. */
function parseIndex(html) {
  const links = [];
  const re = /href=['"]([^'"]+)['"][^>]*>([\s\S]*?)<\/a>/g;
  for (const match of html.matchAll(re)) {
    let href = match[1].replace(/^\.\//, "");
    const title = decodeEntities(match[2].replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
    if (/^(style\.css|index\.html?)$/i.test(href)) continue;
    if (/^https?:/i.test(href)) continue;
    if (/^[a-z]{2}\/?$/i.test(href)) continue; // translations
    const last = href.split("/").pop();
    if (!/\.(html?|asm|c|pl|h|py|rs|txt)$/i.test(last) && !href.endsWith("/")) continue;
    // multi-line titles repeat the same href — merge fragments
    const prev = links.find((l) => l.href === href);
    if (prev) {
      if (title && !prev.title.includes(title)) prev.title = `${prev.title} ${title}`.trim();
    } else {
      links.push({ href, title });
    }
  }
  return links;
}

function slugify(s) {
  return (
    s
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 48) || "untitled"
  );
}

async function scrapeVolume(vol, outDir, force) {
  const vdir = path.join(outDir, `v${vol}`);
  await mkdir(vdir, { recursive: true });
  const manifestPath = path.join(vdir, "manifest.json");
  if (!force && (await exists(manifestPath))) {
    console.log(`v${vol}: already scraped (use --force to redo)`);
    return JSON.parse(await import("node:fs/promises").then((fs) => fs.readFile(manifestPath, "utf8")));
  }

  const indexUrl = `${BASE}/${vol}/`;
  const indexHtml = await fetchText(indexUrl);
  const links = parseIndex(indexHtml);
  console.log(`v${vol}: ${links.length} links`);

  const manifest = { volume: vol, url: indexUrl, articles: [], skipped: [] };
  let seq = 0;

  for (const link of links) {
    const { href, title } = link;
    try {
      if (href.endsWith("/")) {
        // directory-style link (e.g. image gallery) — probe for an index page with text
        const subIndex = await fetchText(`${BASE}/${vol}/${href}`);
        const subLinks = parseIndex(subIndex).filter(
          (l) => /\.(html|txt)$/.test(l.href) || !/\.(png|gif|jpg|jpeg|svg)$/i.test(l.href),
        );
        if (subLinks.some((l) => l.href.endsWith(".html") || l.href.endsWith(".txt"))) {
          for (const sub of subLinks) {
            await scrapeArticle(vol, sub.href, sub.title || title, vdir, manifest, () => ++seq);
          }
        } else {
          manifest.skipped.push({ href, reason: "image gallery" });
          console.log(`  skip ${href} (images only)`);
        }
        continue;
      }
      await scrapeArticle(vol, href, title, vdir, manifest, () => ++seq);
    } catch (err) {
      console.warn(`  WARN ${href}: ${err.message}`);
      manifest.skipped.push({ href, reason: err.message });
    }
  }

  await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
  console.log(`v${vol}: saved ${manifest.articles.length}, skipped ${manifest.skipped.length}`);
  return manifest;
}

async function scrapeArticle(vol, href, title, vdir, manifest, nextSeq) {
  const isPage = /\.html?$/i.test(href);
  const base = href.replace(/\/index\.html?$/i, "").replace(/\.html?$/i, "");
  let text;
  let sourceUrl;

  if (vol === 1 && isPage) {
    // volume 1 has plain-text mirrors
    const txtUrl = `${BASE}/1/txt/${base}.txt`;
    sourceUrl = txtUrl;
    try {
      text = await fetchText(txtUrl);
      if (!text.includes("tmp.0ut") && text.length < 200) throw new Error("suspiciously small txt");
    } catch {
      text = htmlToText(await fetchText(`${BASE}/1/${href}`));
      sourceUrl = `${BASE}/1/${href}`;
    }
  } else if (isPage) {
    sourceUrl = `${BASE}/${vol}/${href}`;
    text = htmlToText(await fetchText(sourceUrl));
  } else {
    // raw source file (.asm/.c/.pl)
    sourceUrl = `${BASE}/${vol}/${encodeURI(href)}`;
    text = await fetchText(sourceUrl);
  }

  const n = String(nextSeq()).padStart(2, "0");
  const fname = `${n}-${slugify(title || base)}.txt`;
  await writeFile(path.join(vdir, fname), text);
  manifest.articles.push({ file: fname, title: title || base, href, url: sourceUrl });
  console.log(`  saved ${fname}`);
}

async function main() {
  const { volumes, force, out } = args();
  await mkdir(out, { recursive: true });
  for (const vol of volumes) {
    await scrapeVolume(vol, out, force);
  }
  console.log(`done -> ${out}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
