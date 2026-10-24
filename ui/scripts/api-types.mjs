// TypeScript types for the HTTP API, from docs/api/openapi.json.
//
//   node scripts/api-types.mjs          write src/app/api/api.model.ts
//   node scripts/api-types.mjs --check  fail if it is out of date
//
// The description is generated from the Varlink interfaces and uses a
// small part of JSON Schema (types, properties, required,
// additionalProperties, $ref, anyOf, oneOf, items, const, enum), which
// is all this handles.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = join(here, '../../docs/api/openapi.json');
const target = join(here, '../src/app/api/api.model.ts');

const doc = JSON.parse(readFileSync(source, 'utf8'));

const quote = (s) => JSON.stringify(s);
const pad = (depth) => '  '.repeat(depth);

function comment(text, depth) {
  if (!text) return '';
  const lines = text.replace(/\*\//g, '*\\/').split('\n');
  return `${pad(depth)}/** ${lines.join(`\n${pad(depth)} * `)} */\n`;
}

function type(s, depth = 0) {
  if (s === true || s === undefined) return 'unknown';
  if (s === false) return 'never';
  if (s.$ref) {
    const name = s.$ref.replace('#/components/schemas/', '');
    return `Schemas[${quote(name)}]`;
  }
  if ('const' in s) return quote(s.const);
  if (s.enum) return s.enum.map(quote).join(' | ');
  const alts = s.anyOf ?? s.oneOf;
  if (alts) return alts.map((a) => type(a, depth)).join(' | ');
  if (Array.isArray(s.type)) {
    return s.type.map((t) => type({ ...s, type: t }, depth)).join(' | ');
  }
  switch (s.type) {
    case 'string':
      return 'string';
    case 'integer':
    case 'number':
      return 'number';
    case 'boolean':
      return 'boolean';
    case 'null':
      return 'null';
    case 'array':
      return `Array<${type(s.items, depth)}>`;
    case 'object':
    case undefined:
      return object(s, depth);
    default:
      throw new Error(`unknown type ${s.type}`);
  }
}

function object(s, depth) {
  const props = Object.entries(s.properties ?? {});
  const required = new Set(s.required ?? []);
  const extra = s.additionalProperties;
  if (props.length === 0) {
    if (extra === false) return 'Record<string, never>';
    return `Record<string, ${typeof extra === 'object' ? type(extra, depth) : 'unknown'}>`;
  }
  let out = '{\n';
  for (const [name, p] of props) {
    out += comment(p.description, depth + 1);
    out += `${pad(depth + 1)}${quote(name)}${required.has(name) ? '' : '?'}: ${type(p, depth + 1)};\n`;
  }
  // Named properties with more besides: TypeScript wants the index
  // signature to cover the named ones too, so it says only `unknown`.
  if (extra && extra !== false) out += `${pad(depth + 1)}[key: string]: unknown;\n`;
  return `${out}${pad(depth)}}`;
}

let out = `// Generated from docs/api/openapi.json by scripts/api-types.mjs; do not edit.
// Regenerate with \`npm run api\`.

/** The description's named types. */
export interface Schemas {
`;
for (const [name, s] of Object.entries(doc.components.schemas)) {
  out += comment(s.description, 1);
  out += `  ${quote(name)}: ${type(s, 1)};\n`;
}
out += `}

/** An error reply: its name, its parameters and a message in words. */
export type ApiError = Schemas['Error'];

/** Each call: its parameters, its reply, the role it needs, and whether it streams. */
export interface Calls {
`;
const json = (c) => c?.content?.['application/json']?.schema;
for (const [path, item] of Object.entries(doc.paths)) {
  const op = item.post;
  if (!path.startsWith('/call/') || !op) continue;
  const streams = (op.parameters ?? []).some((p) => p.name === 'more');
  out += comment(op.description ?? op.summary, 1);
  out += `  ${quote(path.slice('/call/'.length))}: {\n`;
  out += `    parameters: ${type(json(op.requestBody) ?? { type: 'object', additionalProperties: false }, 2)};\n`;
  out += `    reply: ${type(json(op.responses['200']), 2)};\n`;
  out += `    role: ${quote(op['x-sparewall-role'] ?? 'none')};\n`;
  out += `    streams: ${streams};\n`;
  out += '  };\n';
}
out += `}

export type Method = keyof Calls;
export type Parameters<M extends Method> = Calls[M]['parameters'];
export type Reply<M extends Method> = Calls[M]['reply'];
export type StreamingMethod = {[M in Method]: Calls[M]['streams'] extends true ? M : never}[Method];
`;

if (process.argv.includes('--check')) {
  let current = '';
  try {
    current = readFileSync(target, 'utf8');
  } catch {}
  if (current !== out) {
    console.error('src/app/api/api.model.ts is out of date: run `npm run api`');
    process.exit(1);
  }
} else {
  writeFileSync(target, out);
}
