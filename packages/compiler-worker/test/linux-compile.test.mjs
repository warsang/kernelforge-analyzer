import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { linuxIncludeDir } from "../src/linux-headers.mjs";

test("linux headers: compile minimal LKM", ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
MODULE_LICENSE("GPL");
static int __init myinit(void){ return 0; }
module_init(myinit);
`;
  const dir=mkdtempSync(path.join(tmpdir(),"kf-lx-"));
  try{
    const c=path.join(dir,"mod.c");
    const o=path.join(dir,"mod.o");
    writeFileSync(c, src);
    execFileSync("clang", ["--target=x86_64-linux-gnu","-O1","-ffreestanding","-fno-stack-protector","-fno-pic","-mno-red-zone","-mcmodel=kernel","-isystem", linuxIncludeDir(),"-D__KERNEL__","-DMODULE","-c",c,"-o",o],{timeout:15000});
    const data=readFileSync(o);
    assert.ok(data.length>100);
    // check ELF magic
    assert.equal(data[0],0x7f);
    assert.equal(data[1],0x45);
  } finally{ try{ rmSync(dir,{recursive:true,force:true}); }catch{} }
});
