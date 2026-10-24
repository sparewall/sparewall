// Text forms of the schema's unions, which JSON Forms cannot pick a branch
// for without a validator (and Ajv may not run here: see no-eval-ajv.ts).
// Each value's own type decides how it is shown, and the text how it is
// read back, so an untouched value is never rewritten.

type MatchItem = number | string;
export type Match = MatchItem | MatchItem[];

const item = (t: string): MatchItem => (/^\d+$/.test(t) ? Number(t) : t);

/** A match (a port, an address, `low-high`, `@object`, or a list of them) as text. */
export function formatMatch(v: unknown): string {
  if (v === undefined || v === null) return '';
  return Array.isArray(v) ? v.join(', ') : String(v);
}

/**
 * Text as a match: whole numbers as numbers, anything else as a string,
 * and a comma-separated list as a list. Empty text leaves it out.
 */
export function parseMatch(text: string): Match | undefined {
  const items = text
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t !== '');
  if (items.length === 0) return undefined;
  return items.length === 1 ? item(items[0]) : items.map(item);
}

/** A value of another union (a policy's `nat`, a raw statement's `at`) as text. */
export function formatUnion(v: unknown): string {
  if (v === undefined || v === null) return '';
  return typeof v === 'string' ? v : JSON.stringify(v);
}

/**
 * Text as such a value: JSON for an object, a list, a number or a quoted
 * string, and plain text as a string (`masquerade`). Empty text leaves
 * it out.
 */
export function parseUnion(text: string): { value: unknown } | { error: string } {
  const t = text.trim();
  if (t === '') return { value: undefined };
  if (/^[[{"\d-]/.test(t) || t === 'true' || t === 'false') {
    try {
      return { value: JSON.parse(t) };
    } catch {
      return { error: 'Not valid JSON.' };
    }
  }
  return { value: t };
}
