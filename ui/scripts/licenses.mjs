// The licenses of the packages the bundle ships (dependencies, not
// devDependencies), against the ones a GPL-3.0 image may carry; the
// counterpart of `cargo deny check licenses` for the Rust crates.
//
//   node scripts/licenses.mjs                 check them
//   node scripts/licenses.mjs --notices FILE  also write each one's license text
//
// The notices are what the image ships for the UI. Angular's own
// 3rdpartylicenses.txt covers only the code it bundles, not the fonts the
// stylesheet references (Roboto, OFL-1.1, and Material Symbols,
// Apache-2.0), whose licenses ask for their text to go with every copy.

import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
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
const at = process.argv.indexOf('--notices');
const notices = at > 0 ? process.argv[at + 1] : undefined;

let bad = 0;
let text = 'Third-party software in the Sparewall web UI, and its licenses.\n';
for (const [path, pkg] of Object.entries(lock.packages)) {
  if (!path || pkg.dev || pkg.devOptional) continue;
  const name = path.replace(/^.*node_modules\//, '');
  const license = pkg.license ?? '(none)';
  // An SPDX expression such as "(MIT OR Apache-2.0)": one allowed choice is enough.
  const choices = license.replace(/[()]/g, '').split(/\s+OR\s+/);
  if (!choices.some((c) => ALLOWED.has(c.trim()))) {
    console.error(`${name}: ${license}`);
    bad++;
  }
  const files = readdirSync(join(root, path)).filter((f) =>
    /^(licen[cs]e|copying|notice)/i.test(f),
  );
  if (!files.length) {
    console.error(`${name}: no license file to ship`);
    bad++;
  }
  text += `\n${'='.repeat(72)}\n${name} ${pkg.version} (${license})\n${'='.repeat(72)}\n`;
  for (const f of files) text += `\n${readFileSync(join(root, path, f), 'utf8').trim()}\n`;
}
if (bad) {
  console.error(`${bad} problems with the licenses of shipped packages (scripts/licenses.mjs)`);
  process.exit(1);
}
if (notices) writeFileSync(notices, text);
console.log('shipped packages: licenses ok');
