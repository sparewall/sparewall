/**
 * Where a document references a secret (`secret:<name>`), as dotted
 * paths (`backup.credentials`), so deleting one in use isn't a surprise.
 */
export function references(doc: unknown, name: string): string[] {
  const want = `secret:${name}`;
  const out: string[] = [];
  const walk = (v: unknown, path: string[]): void => {
    if (typeof v === 'string') {
      if (v === want) out.push(path.join('.'));
    } else if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, [...path.slice(0, -1), `${path.at(-1) ?? ''}[${i}]`]));
    } else if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) {
        walk(x, [...path, /[.\s>-]/.test(k) ? `'${k}'` : k]);
      }
    }
  };
  walk(doc, []);
  return out;
}

/** The node's rule for a secret's name (`secrets::name_ok`). */
export function secretNameOk(name: string): boolean {
  return name.length > 0 && name.length <= 64 && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name);
}
