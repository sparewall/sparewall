import { Schemas } from '../../api/api.model';

type Document = Schemas['Document'];
type Policy = Schemas['Document.Policy'];

export const SELF = 'self';

/** One cell: a policy, or the default when there is none. */
export interface Cell {
  from: string;
  to: string;
  /** `users->wan` */
  key: string;
  policy?: Policy;
  /** What applies with no policy for the pair. */
  fallback: 'accept' | 'drop';
  /** `self->self` is not a pair. */
  none: boolean;
}

/** The zones, in the document's order, and `self` last. */
export function zones(doc: Document): string[] {
  return [...Object.keys(doc.zones ?? {}).filter((z) => z !== SELF), SELF];
}

/**
 * Every pair of zones. A pair without a policy is dropped (the input and
 * forward chains' policy), except what the firewall itself sends
 * (`self->`), which is accepted (the output chain's).
 */
export function matrix(doc: Document): Cell[][] {
  const zs = zones(doc);
  return zs.map((from) =>
    zs.map((to) => {
      const key = `${from}->${to}`;
      return {
        from,
        to,
        key,
        policy: doc.policy?.[key],
        fallback: from === SELF ? 'accept' : 'drop',
        none: from === SELF && to === SELF,
      };
    }),
  );
}

/** The document with the pair's policy set, or removed when `policy` is undefined. */
export function withPolicy(doc: Document, key: string, policy: Policy | undefined): Document {
  const next = structuredClone(doc);
  const all = { ...(next.policy ?? {}) };
  if (policy) all[key] = policy;
  else delete all[key];
  next.policy = all;
  return next;
}

/** A policy's NAT in words. */
export function natLabel(nat: Policy['nat']): string | undefined {
  if (!nat) return undefined;
  return typeof nat === 'string' ? nat : `SNAT ${nat.snat}`;
}
