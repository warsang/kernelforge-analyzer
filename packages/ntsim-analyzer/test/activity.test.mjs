/**
 * activity.mjs — registry key classification and evidence summaries.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  classifyRegistryKey,
  summarizeRegistryActivity,
  summarizeApiResolutions,
} from "../src/activity.mjs";

test("classifyRegistryKey separates self / security / boot / services / user / bcd", () => {
  const self = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TBMKD";
  assert.equal(classifyRegistryKey(self, { driverStem: "tbmkd" }), "self");
  assert.equal(classifyRegistryKey(self + "\\Parameters", { driverStem: "tbmkd" }), "self");
  assert.equal(classifyRegistryKey(self, { driverStem: "other" }), "services");

  assert.equal(classifyRegistryKey("\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender"), "security");
  assert.equal(classifyRegistryKey("\\Registry\\Machine\\SOFTWARE\\Policies\\System"), "security");
  assert.equal(classifyRegistryKey("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"), "boot");
  assert.equal(classifyRegistryKey("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\WdFilter"), "services");
  assert.equal(classifyRegistryKey("\\Registry\\User\\S-1-5-18\\Software"), "user");
  assert.equal(classifyRegistryKey("\\Registry\\Machine\\BCD\\00000000"), "bcd");
  assert.equal(classifyRegistryKey("\\Registry\\Machine\\SOFTWARE\\SomethingElse"), "other");
});

test("summarizeRegistryActivity counts ops, flags and top keys", () => {
  const kernel = {
    registryWriteLog: [
      { op: "set", key: "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\tbmkd", value: "Start", type: 4, size: 4 },
      { op: "create", key: "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions" },
      { op: "set", key: "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\other", value: "Start", type: 4, size: 4 },
      { op: "delete-value", key: "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager", value: "X" },
    ],
    registryAutoCreated: ["\\Registry\\Machine\\SOFTWARE\\Auto"],
  };
  const out = summarizeRegistryActivity(kernel, {
    driverName: "TBMKD.sys",
    regPath: "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TBMKD",
  });
  assert.equal(out.writes, 2);
  assert.equal(out.creates, 1);
  assert.equal(out.deletes, 1);
  assert.equal(out.categories.self, 1);
  assert.equal(out.categories.security, 1);
  assert.equal(out.categories.services, 1);
  assert.equal(out.categories.boot, 1);
  assert.equal(out.autoCreatedKeys, 1);
  assert.deepEqual(out.flags, {
    selfServiceKey: true,
    securityPolicy: true,
    bootConfig: true,
    otherServices: true,
    userHive: false,
    bcd: false,
  });
  assert.equal(out.modifiedKeys[0].category, "self");
  assert.ok(out.modifiedKeys.length <= 16);
});

test("summarizeApiResolutions groups resolved/provisioned/unresolved", () => {
  const kernel = {
    apiResolutions: new Map([
      ["ZwQueryInformationProcess", { name: "ZwQueryInformationProcess", result: "provisioned", target: 0x1000n, count: 2 }],
      ["IoCreateDevice", { name: "IoCreateDevice", result: "modeled", target: 0x2000n, count: 1 }],
      ["PsInitialSystemProcess", { name: "PsInitialSystemProcess", result: "data", target: 0x3000n, count: 1 }],
      ["PsGetProcessSectionBaseAddress", { name: "PsGetProcessSectionBaseAddress", result: "unresolved", target: 0n, count: 1 }],
    ]),
  };
  const out = summarizeApiResolutions(kernel);
  assert.deepEqual(out.resolved.map((x) => x.name), ["IoCreateDevice", "PsInitialSystemProcess"]);
  assert.equal(out.resolved[0].kind, "modeled");
  assert.equal(out.resolved[0].target, "0x2000");
  assert.deepEqual(out.provisioned.map((x) => x.name), ["ZwQueryInformationProcess"]);
  assert.deepEqual(out.unresolved.map((x) => x.name), ["PsGetProcessSectionBaseAddress"]);
  assert.deepEqual(out.counts, { resolved: 2, provisioned: 1, unresolved: 1 });
});

test("summaries tolerate a kernel with no evidence", () => {
  const reg = summarizeRegistryActivity({}, {});
  assert.equal(reg.total, 0);
  assert.equal(reg.flags.selfServiceKey, false);
  const res = summarizeApiResolutions({});
  assert.deepEqual(res.counts, { resolved: 0, provisioned: 0, unresolved: 0 });
});
