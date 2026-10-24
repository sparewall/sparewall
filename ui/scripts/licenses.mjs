// The licenses of the packages the bundle ships (dependencies, not
// devDependencies), against the ones a GPL-3.0 image may carry; the
// counterpart of `cargo deny check licenses` for the Rust crates.
//
//   node scripts/licenses.mjs

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ALLOWED = new Set([
  '0BSD',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC',
  'MIT',
  'OFL-1.1',
]);

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));

let bad = 0;
for (const [path, pkg] of Object.entries(lock.packages)) {
  if (!path || pkg.dev || pkg.devOptional) continue;
  const license = pkg.license ?? '(none)';
  // An SPDX expression such as "(MIT OR Apache-2.0)": one allowed choice is enough.
  const choices = license.replace(/[()]/g, '').split(/\s+OR\s+/);
  if (!choices.some((c) => ALLOWED.has(c.trim()))) {
    console.error(`${path.replace(/^.*node_modules\//, '')}: ${license}`);
    bad++;
  }
}
if (bad) {
  console.error(`${bad} shipped packages have licenses not on the list in scripts/licenses.mjs`);
  process.exit(1);
}
console.log('shipped packages: licenses ok');
