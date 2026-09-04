#!/usr/bin/env node
// Repo-checkout shortcut for `kf-analyze` (canonical impl lives in
// packages/ntsim-analyzer/bin/kf-analyze.mjs so npm `bin` picks it up).
// Usage: node tools/kf-analyze.mjs <driver.sys|module.ko> [options]
import "../packages/ntsim-analyzer/bin/kf-analyze.mjs";
