/**
 * linux-headers.mjs — 6.6.18 teaching headers for browser LKM builds.
 * Mirrors wdk-headers.mjs but for linux.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const INCLUDE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "../include");

export const LINUX_HEADERS = [
  "linux/module.h",
  "linux/types.h",
  "linux/fs.h",
  "linux/uaccess.h",
  "linux/slab.h",
  "linux/cdev.h",
  "linux/miscdevice.h",
  "linux/proc_fs.h",
  "linux/netlink.h",
  "linux/cred.h",
  "linux/device.h",
  "asm/unistd.h",
];

export function linuxIncludeDir(){ return INCLUDE_DIR; }

export async function linuxFileMap(){
  const out={};
  for(const h of LINUX_HEADERS){
    const bytes=await readFile(path.join(INCLUDE_DIR, h));
    out[`linux/include/${h}`]=new Uint8Array(bytes);
    // also expose as /linux/include/${h} for -isystem
  }
  return out;
}
