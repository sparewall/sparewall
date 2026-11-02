// The HTTP API, as the node's /openapi.json describes it (#161): its calls
// grouped by interface, each with the role it needs and a curl example.

import { Role } from '../core/session';

/** A JSON Schema, as far as this page reads one. */
export interface Schema {
  type?: string | string[];
  description?: string;
  properties?: Record<string, Schema>;
  required?: string[];
  items?: Schema;
  $ref?: string;
  anyOf?: Schema[];
  oneOf?: Schema[];
  enum?: unknown[];
}

export interface Field {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

export interface Call {
  /** `org.sparewall.Firewall.Status`. */
  method: string;
  interface: string;
  summary: string;
  description: string;
  /** `none` (no credentials needed), or the least role that may call it. */
  role: Role | 'none';
  /** Replies as a JSON text sequence with `?more=true`. */
  streams: boolean;
  parameters: Field[];
  reply: Field[];
}

export interface Interface {
  name: string;
  calls: Call[];
}

interface Operation {
  summary?: string;
  description?: string;
  tags?: string[];
  parameters?: { name: string; in: string }[];
  requestBody?: { content?: Record<string, { schema?: Schema }> };
  responses?: Record<string, { content?: Record<string, { schema?: Schema }> }>;
  'x-sparewall-role'?: string;
}

export interface OpenApi {
  paths: Record<string, { post?: Operation }>;
  components?: { schemas?: Record<string, Schema> };
}

const PREFIX = '/call/';

/** Every call in the document, grouped by interface, in name order. */
export function apiReference(doc: OpenApi): Interface[] {
  const schemas = doc.components?.schemas ?? {};
  const byIface = new Map<string, Call[]>();
  for (const [path, item] of Object.entries(doc.paths)) {
    const op = item.post;
    if (!op || !path.startsWith(PREFIX)) continue;
    const method = path.slice(PREFIX.length);
    const iface = method.slice(0, method.lastIndexOf('.'));
    const reply = op.responses?.['200']?.content?.['application/json']?.schema;
    const call: Call = {
      method,
      interface: iface,
      summary: op.summary ?? '',
      description: op.description ?? '',
      role: (op['x-sparewall-role'] ?? 'admin') as Call['role'],
      streams: (op.parameters ?? []).some((p) => p.in === 'query' && p.name === 'more'),
      parameters: fields(op.requestBody?.content?.['application/json']?.schema, schemas),
      reply: fields(reply, schemas),
    };
    byIface.set(iface, [...(byIface.get(iface) ?? []), call]);
  }
  return [...byIface.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, calls]) => ({
      name,
      calls: calls.sort((a, b) => a.method.localeCompare(b.method)),
    }));
}

function fields(schema: Schema | undefined, schemas: Record<string, Schema>): Field[] {
  const s = resolve(schema, schemas);
  const required = new Set(s?.required ?? []);
  return Object.entries(s?.properties ?? {})
    .map(([name, p]) => ({
      name,
      type: typeName(p, schemas),
      required: required.has(name),
      description: resolve(p, schemas)?.description ?? p.description,
    }))
    .sort((a, b) => Number(b.required) - Number(a.required) || a.name.localeCompare(b.name));
}

function resolve(s: Schema | undefined, schemas: Record<string, Schema>): Schema | undefined {
  if (!s?.$ref) return s;
  return schemas[s.$ref.split('/').pop() ?? ''] ?? s;
}

/** A field's type in a few words: `string`, `string[]`, `HealthCheck`, `integer or null`. */
export function typeName(s: Schema, schemas: Record<string, Schema> = {}): string {
  if (s.$ref) return s.$ref.split('/').pop() ?? 'object';
  const alts = s.anyOf ?? s.oneOf;
  if (alts) return alts.map((a) => typeName(a, schemas)).join(' or ');
  if (s.enum) return s.enum.map((e) => JSON.stringify(e)).join(' | ');
  const t = Array.isArray(s.type) ? s.type.join(' or ') : (s.type ?? 'any');
  if (t === 'array') return `${s.items ? typeName(s.items, schemas) : 'any'}[]`;
  return t;
}

/** Whether a user with `can` may make the call. */
export function allowed(call: Call, can: (role: Role) => boolean): boolean {
  return call.role === 'none' || can(call.role);
}

/** A placeholder for a required parameter in an example. */
function example(f: Field): unknown {
  if (f.type.endsWith('[]')) return [];
  switch (f.type.split(' ')[0]) {
    case 'integer':
    case 'number':
      return 0;
    case 'boolean':
      return false;
    case 'object':
      return {};
    default:
      return `<${f.name}>`;
  }
}

/**
 * A curl command for the call, with a token from $SPAREWALL_TOKEN and the
 * node's own URL: required parameters as placeholders, and a streaming
 * call left open (`-N`, `?more=true`).
 */
export function curlExample(call: Call, origin: string): string {
  const body: Record<string, unknown> = {};
  for (const f of call.parameters.filter((p) => p.required)) body[f.name] = example(f);
  const url = `${origin}${PREFIX}${call.method}${call.streams ? '?more=true' : ''}`;
  const auth = call.role === 'none' ? '' : ' -H "Authorization: Bearer $SPAREWALL_TOKEN"';
  const json = JSON.stringify(body).replace(/'/g, "'\\''");
  return `curl -s${call.streams ? 'N' : ''}${auth} --json '${json}' \\\n    ${url}`;
}
