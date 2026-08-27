/**
 * linux-sinks.mjs — Linux-specific sink catalogue
 */
export const SEVERITY = { CRITICAL:10, HIGH:8, MEDIUM:5, LOW:3, INFO:1 };

export const LINUX_SINK_CATALOG = [
  {
    id: "ARBITRARY_WRITE_DEREF",
    title: "Write-what-where via tainted pointer deref (copy_*_user bypass)",
    severity: SEVERITY.CRITICAL,
    type: "mem",
    access: "write",
    check: "addr_tainted",
  },
  {
    id: "ARBITRARY_READ_DEREF",
    title: "Arbitrary read via tainted pointer",
    severity: SEVERITY.CRITICAL,
    type: "mem",
    access: "read",
    check: "addr_tainted",
  },
  {
    id: "COPY_TO_USER_TAINTED_PTR_OR_LEN",
    title: "copy_to_user with tainted pointer or length",
    severity: SEVERITY.CRITICAL,
    type: "api",
    apis: ["copy_to_user","_copy_to_user","__copy_to_user","copy_to_user","_copy_from_user","copy_from_user","__copy_from_user"],
    params: [{idx:0, role:"dst"}, {idx:2, role:"len"}],
  },
  {
    id: "COPY_FROM_USER_TAINTED_DST",
    title: "copy_from_user with tainted destination",
    severity: SEVERITY.CRITICAL,
    type: "api",
    apis: ["copy_from_user","_copy_from_user","__copy_from_user"],
    params: [{idx:0, role:"dst"}, {idx:2, role:"len"}],
  },
  {
    id: "KMALLOC_TAINTED_SIZE",
    title: "kmalloc/kzalloc with tainted size (integer overflow to undersized alloc)",
    severity: SEVERITY.HIGH,
    type: "api",
    apis: ["kmalloc","kzalloc","__kmalloc","kmem_cache_alloc","vmalloc"],
    params: [{idx:0, role:"size"}],
  },
  {
    id: "COMMIT_CREDS_TAINTED",
    title: "commit_creds with tainted cred (privilege escalation)",
    severity: 10,
    type: "api",
    apis: ["commit_creds"],
    params: [{idx:0, role:"cred"}],
  },
  {
    id: "PREPARE_KERNEL_CRED_NULL",
    title: "prepare_kernel_cred(0) reachable -> commit_creds escalation",
    severity: SEVERITY.CRITICAL,
    type: "api",
    apis: ["prepare_kernel_cred"],
    params: [{idx:0, role:"daemon"}],
  },
  {
    id: "WRMSR_TAINTED",
    title: "WRMSR with tainted MSR or value (LSTAR hijack)",
    severity: SEVERITY.HIGH,
    type: "msr",
  },
  {
    id: "WRITE_CR_TAINTED",
    title: "write_cr0/cr4 with tainted bits (WP/SMEP clear)",
    severity: SEVERITY.HIGH,
    type: "cr",
  },
  {
    id: "MISSING_ACCESS_OK",
    title: "Direct dereference of __user pointer without access_ok/copy_from_user",
    severity: SEVERITY.MEDIUM,
    type: "mem",
    check: "missing_access_ok",
  },
  {
    id: "DOUBLE_FETCH",
    title: "Double-fetch TOCTOU on __user memory",
    severity: SEVERITY.MEDIUM,
    type: "mem",
    check: "double_fetch",
  },
  {
    id: "REFCOUNT_UAF",
    title: "kref/put_page imbalance -> UAF",
    severity: SEVERITY.HIGH,
    type: "lifetime",
  },
  {
    id: "PROC_SEQ_OVERFLOW",
    title: "proc seq_file overflow via tainted len",
    severity: SEVERITY.MEDIUM,
    type: "api",
    apis: ["seq_read","seq_write"],
  },
  {
    id: "NETLINK_TAINTED_CB",
    title: "netlink input callback with tainted skb",
    severity: SEVERITY.MEDIUM,
    type: "api",
    apis: ["netlink_kernel_create"],
  },
  {
    id: "NULL_DEREF",
    title: "NULL dereference in file_op",
    severity: SEVERITY.INFO,
    type: "crash",
  },
];

export function sinksForApi(apiName){
  return LINUX_SINK_CATALOG.filter(s=>s.type==="api" && s.apis?.includes(apiName));
}
