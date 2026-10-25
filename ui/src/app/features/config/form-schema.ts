import { JsonSchema7 } from '@jsonforms/core';

type Schema = Record<string, unknown>;

/**
 * Marks a field the schema allows to be null: left out, the node uses its
 * default. JSON Forms ignores keywords it does not know.
 */
export const OPTIONAL = 'x-sparewall-optional';

/**
 * The document's JSON Schema, from the node's OpenAPI description, in the
 * shape JSON Forms renders: references inlined, and the generator's way of
 * marking a field optional (`anyOf: [X, {type: null}]`, `type: [T,
 * "null"]`) reduced to X and T, since an absent field already means null.
 * Integer formats (`int64`, `uint32`) are dropped: they are not formats
 * JSON Forms' validator knows.
 */
export function documentSchema(openapi: {
  components: { schemas: Record<string, Schema> };
}): JsonSchema7 {
  const defs = openapi.components.schemas;
  const seen: string[] = [];

  const walk = (s: unknown): unknown => {
    if (Array.isArray(s)) return s.map(walk);
    if (typeof s !== 'object' || s === null) return s;
    const o = s as Schema;
    if (typeof o['$ref'] === 'string') {
      const name = o['$ref'].replace('#/components/schemas/', '');
      if (seen.includes(name)) throw new Error(`recursive schema ${name}`);
      seen.push(name);
      const { $ref: _, ...rest } = o;
      const inlined = { ...(walk(defs[name]) as Schema), ...(walk(rest) as Schema) };
      seen.pop();
      return inlined;
    }
    const alts = (o['anyOf'] ?? o['oneOf']) as Schema[] | undefined;
    if (alts) {
      const nonNull = alts.filter((a) => a['type'] !== 'null');
      if (nonNull.length === 1 && nonNull.length < alts.length) {
        const { anyOf: _a, oneOf: _o, ...rest } = o;
        return { ...(walk(nonNull[0]) as Schema), ...(walk(rest) as Schema), [OPTIONAL]: true };
      }
    }
    const out: Schema = {};
    for (const [k, v] of Object.entries(o)) {
      if (k === 'type' && Array.isArray(v)) {
        const types = v.filter((t) => t !== 'null');
        out[k] = types.length === 1 ? types[0] : types;
        if (types.length < v.length) out[OPTIONAL] = true;
      } else if (
        k === 'format' &&
        (o['type'] === 'integer' || String(o['type']).includes('integer'))
      ) {
        continue;
      } else if (k === 'properties' || k === 'patternProperties') {
        out[k] = Object.fromEntries(Object.entries(v as Schema).map(([p, ps]) => [p, walk(ps)]));
      } else {
        out[k] = walk(v);
      }
    }
    return out;
  };

  return walk({ $ref: '#/components/schemas/Document' }) as JsonSchema7;
}

/**
 * On a map drawn for an object that also has fields of its own (`dhcp`:
 * its settings, then one entry per network): those fields' names, which
 * are not entries.
 */
export const FIXED = 'x-sparewall-fixed';

/** Whether a schema is a map of named things: an object of one schema per key. */
export function isMap(s: JsonSchema7 | undefined): boolean {
  return (
    !!s &&
    s.type === 'object' &&
    !s.properties &&
    typeof s.additionalProperties === 'object' &&
    s.additionalProperties !== null
  );
}
