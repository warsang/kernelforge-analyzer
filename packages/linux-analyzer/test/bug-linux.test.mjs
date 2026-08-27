import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeKo } from "../src/index.mjs";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { findLinuxBugsCampaign } from "../src/bug/linux-engine.mjs";
import { parseElfKo, mapModule } from "@kernelforge/linux-sim/src/module-loader.mjs";
import { LinuxKernel } from "@kernelforge/linux-sim/src/linux-kernel.mjs";
import { sendFileOp } from "@kernelforge/linux-sim/src/file-ops.mjs";

function compileKo(source){
  const dir=mkdtempSync(path.join(tmpdir(),"kf-bug-"));
  try{
    const c=path.join(dir,"mod.c");
    const o=path.join(dir,"mod.o");
    writeFileSync(c, source);
    const includeDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../compiler-worker/include");
    execFileSync("clang", ["--target=x86_64-linux-gnu","-O1","-ffreestanding","-fno-stack-protector","-fno-pic","-mno-red-zone","-mcmodel=kernel","-isystem", includeDir,"-D__KERNEL__","-DMODULE","-c",c,"-o",o],{timeout:15000});
    return new Uint8Array(readFileSync(o));
  } finally{ try{ rmSync(dir,{recursive:true,force:true}); }catch{} }
}

test("bug: arbitrary write via tainted copy_to_user", async ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
MODULE_LICENSE("GPL");
struct arg{ unsigned long *ptr; };
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg){
  if(cmd==0xdeadbeef){
    struct arg k;
    if(copy_from_user(&k, (void*)arg, sizeof(k))) return -1;
    unsigned long v=0x4141;
    copy_to_user(k.ptr, &v, 8);
    return 0;
  }
  return -1;
}
static struct file_operations fops={ .unlocked_ioctl=my_ioctl };
static int __init myinit(void){ register_chrdev(240,"bug",&fops); return 0; }
module_init(myinit);
`;
  const bytes=compileKo(src);
  const parsed=parseElfKo(bytes);
  const k=new LinuxKernel({});
  const m=mapModule(k, parsed, 0xffffffffc0000000n, (n)=>k.resolveImportProvisioned(n));
  k.callFunctionSeh(m.init,[],{});
  const dev=k.deviceRegistry[0];
  const res=await findLinuxBugsCampaign(k, dev, "unlocked_ioctl", {
    sendFileOp, imageBase:m.base, imageSize:m.imageSize, iterations:24, corpusCap:4, cmd:0xdeadbeef, inputLen:16, outputLen:16, driverHash:"test"
  });
  const bugs=res.bugDB.all();
  assert.ok(bugs.some(b=>b.sinkType==="COPY_TO_USER_TAINTED_PTR_OR_LEN"), `expected copy_to_user bug, got ${JSON.stringify(bugs.map(b=>b.sinkType))}`);
});

test("bug: cred escalation via commit_creds", async ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cred.h>
MODULE_LICENSE("GPL");
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg){
  if(cmd==0xcafebabe){ struct cred *c=prepare_kernel_cred(0); commit_creds(c); return 0; }
  return -1;
}
static struct file_operations fops={ .unlocked_ioctl=my_ioctl };
static int __init myinit(void){ register_chrdev(240,"credbug",&fops); return 0; }
module_init(myinit);
`;
  const bytes=compileKo(src);
  const parsed=parseElfKo(bytes);
  const k=new LinuxKernel({});
  const m=mapModule(k, parsed, 0xffffffffc0000000n, (n)=>k.resolveImportProvisioned(n));
  k.callFunctionSeh(m.init,[],{});
  const dev=k.deviceRegistry[0];
  const res=await findLinuxBugsCampaign(k, dev, "unlocked_ioctl", {
    sendFileOp, imageBase:m.base, imageSize:m.imageSize, iterations:16, corpusCap:4, cmd:0xcafebabe, inputLen:8
  });
  const bugs=res.bugDB.all();
  assert.ok(bugs.some(b=>b.sinkType==="COMMIT_CREDS_TAINTED"), `expected cred bug, got ${JSON.stringify(bugs)}`);
});

test("bug: analyzeKo findBugs via autoOps path", async ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
MODULE_LICENSE("GPL");
struct arg{ unsigned long *ptr; };
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg){
  struct arg k; if(copy_from_user(&k,(void*)arg,sizeof(k))) return -1;
  unsigned long v=0; copy_to_user(k.ptr,&v,8); return 0;
}
static struct file_operations fops={ .unlocked_ioctl=my_ioctl };
static int __init myinit(void){ register_chrdev(240,"autobug",&fops); return 0; }
module_init(myinit);
`;
  const bytes=compileKo(src);
  const report=await analyzeKo(bytes, {name:"autobug.ko", backendName:"js", autoOps:{ fuzz:{iterations:16, corpusCap:4}}});
  assert.ok(report.harvestedOps.length>=1);
  // Then run findLinuxBugsCampaign separately to ensure bugs found
  const k=report.__session.kernel;
  const dev=report.__session.device;
  const mapped=report.__session.mapped;
  const res=await findLinuxBugsCampaign(k, dev, "unlocked_ioctl", {
    sendFileOp, imageBase:mapped.base, imageSize:mapped.imageSize, iterations:16, corpusCap:4, cmd:0, inputLen:16
  });
  assert.ok(res.bugDB.all().length>0);
});
