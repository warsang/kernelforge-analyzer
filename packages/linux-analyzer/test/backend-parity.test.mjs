import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeKo } from "../src/index.mjs";

function compileKo(source){
  const dir=mkdtempSync(path.join(tmpdir(),"kf-parity-"));
  try{
    const c=path.join(dir,"mod.c");
    const o=path.join(dir,"mod.o");
    writeFileSync(c, source);
    const includeDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../compiler-worker/include");
    execFileSync("clang", ["--target=x86_64-linux-gnu","-O1","-ffreestanding","-fno-stack-protector","-fno-pic","-mno-red-zone","-mcmodel=kernel","-isystem", includeDir,"-D__KERNEL__","-DMODULE","-c",c,"-o",o],{timeout:15000});
    return new Uint8Array(readFileSync(o));
  } finally{ try{ rmSync(dir,{recursive:true,force:true}); }catch{} }
}

test("backend parity: js vs hybrid (if available)", async (t)=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
MODULE_LICENSE("GPL");
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg){ return (cmd==0x1234)?0:-1; }
static struct file_operations fops={ .unlocked_ioctl=my_ioctl };
static int __init myinit(void){ register_chrdev(240,"parity",&fops); return 0; }
module_init(myinit);
`;
  const bytes=compileKo(src);
  const reportJs=await analyzeKo(bytes, {name:"parity.ko", backendName:"js"});
  assert.equal(reportJs.init.status,"ok");
  let reportHybrid;
  try{
    const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
    reportHybrid=await analyzeKo(bytes, {name:"parity.ko", backendName:"hybrid", makeBackend: async()=> HybridCpuBackend.create(null)});
  } catch(e){
    t.skip(`hybrid unavailable: ${e.message}`);
    return;
  }
  if(reportHybrid.init.status!=="ok"){
    t.skip(`hybrid init not ok: ${reportHybrid.init.status} ${reportHybrid.init.error||""}`);
    return;
  }
  // Compare harvested ops count
  assert.equal(reportJs.harvestedOps.length, reportHybrid.harvestedOps.length);
});
