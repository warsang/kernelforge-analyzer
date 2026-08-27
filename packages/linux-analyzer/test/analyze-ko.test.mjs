import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeKo } from "../src/index.mjs";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

function compileKo(source){
  const dir=mkdtempSync(path.join(tmpdir(),"kf-ako-"));
  try{
    const c=path.join(dir,"mod.c");
    const o=path.join(dir,"mod.o");
    writeFileSync(c, source);
    const includeDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../compiler-worker/include");
    execFileSync("clang", ["--target=x86_64-linux-gnu","-O1","-ffreestanding","-fno-stack-protector","-fno-pic","-mno-red-zone","-mcmodel=kernel","-isystem", includeDir,"-D__KERNEL__","-DMODULE","-c",c,"-o",o],{timeout:15000});
    return new Uint8Array(readFileSync(o));
  } finally{ try{ rmSync(dir,{recursive:true,force:true}); }catch{} }
}

test("analyzeKo: basic load + init + harvest", async ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
MODULE_LICENSE("GPL");
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg){ return 0; }
static struct file_operations fops={ .unlocked_ioctl=my_ioctl };
static int __init myinit(void){ register_chrdev(240,"simple",&fops); return 0; }
module_init(myinit);
`;
  const bytes=compileKo(src);
  const report=await analyzeKo(bytes, {name:"simple.ko", backendName:"js"});
  assert.ok(report.load.base);
  assert.equal(report.init.status,"ok");
  assert.ok(report.harvestedOps.length>=1);
  assert.equal(report.harvestedOps[0].op,"unlocked_ioctl");
  assert.ok(report.__session);
});

test("analyzeKo: autoOps with fuzz", async ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
MODULE_LICENSE("GPL");
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg){ return (cmd==0xdead)?0:-1; }
static struct file_operations fops={ .unlocked_ioctl=my_ioctl };
static int __init myinit(void){ register_chrdev(240,"fuzzdev",&fops); return 0; }
module_init(myinit);
`;
  const bytes=compileKo(src);
  const report=await analyzeKo(bytes, {name:"fuzz.ko", backendName:"js", autoOps:{ fuzz:{iterations:16, corpusCap:4}}});
  assert.ok(report.autoOps);
  assert.ok(report.autoOps.length>0);
  // should have at least one fuzz result
  const ioctlOps=report.autoOps.filter(r=>r.majorName==="UNLOCKED_IOCTL");
  assert.ok(ioctlOps.length>0);
});
