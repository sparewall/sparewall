import { JsonSchema7 } from '@jsonforms/core';

import { fieldLabel } from './layout';

/** The document's top-level sections, grouped as a site is usually set up. */
const GROUPS: { label: string; keys: string[] }[] = [
  { label: 'Network', keys: ['ports', 'networks', 'zones', 'objects'] },
  { label: 'Firewall', keys: ['policy', 'forwards', 'nat', 'raw'] },
  { label: 'Services', keys: ['dhcp', 'dns', 'ntp'] },
  { label: 'VPN', keys: ['vpn'] },
  {
    label: 'System',
    keys: ['cluster', 'management', 'tls', 'logging', 'metrics', 'backup', 'updates'],
  },
];
/** Where sections no group names go (added to the schema after this list). */
const OTHER = 'Other';

const LABELS: Record<string, string> = {
  dhcp: 'DHCP',
  dns: 'DNS',
  ntp: 'NTP',
  nat: 'NAT',
  tls: 'Certificates',
  vpn: 'Remote access',
  raw: 'Raw nftables',
  provider_options: 'Provider options',
};

export interface Section {
  key: string;
  label: string;
  description?: string;
}

export interface SectionGroup {
  label: string;
  sections: Section[];
}

export function sectionLabel(key: string): string {
  return LABELS[key] ?? fieldLabel(key);
}

/** The schema's top-level sections in their groups, the known ones first. */
export function sectionGroups(schema: JsonSchema7): SectionGroup[] {
  const props = (schema.properties ?? {}) as Record<string, JsonSchema7>;
  const section = (key: string): Section => ({
    key,
    label: sectionLabel(key),
    description: props[key].description,
  });
  const present = new Set(Object.keys(props).filter((k) => k !== 'schema'));
  const groups = GROUPS.map((g) => ({
    label: g.label,
    sections: g.keys.filter((k) => present.has(k)).map(section),
  }));
  const known = new Set(GROUPS.flatMap((g) => g.keys));
  const other = [...present].filter((k) => !known.has(k)).sort();
  if (other.length) groups.push({ label: OTHER, sections: other.map(section) });
  return groups.filter((g) => g.sections.length);
}

/** One setting the search can find. */
export interface Setting {
  section: string;
  /** Keys from the section down; `<name>` stands for a map's entries. */
  path: string[];
  label: string;
  description: string;
}

/** Map entries are not settings of their own; their fields are, under `<name>`. */
const ENTRY = '<name>';
const MAX_DEPTH = 6;

/** Every setting in the schema, for the search. */
export function settings(schema: JsonSchema7): Setting[] {
  const out: Setting[] = [];
  const walk = (s: JsonSchema7, section: string, path: string[]) => {
    if (path.length > MAX_DEPTH) return;
    for (const [key, p] of Object.entries(s.properties ?? {}) as [string, JsonSchema7][]) {
      const here = [...path, key];
      out.push({ section, path: here, label: fieldLabel(key), description: p.description ?? '' });
      walk(p, section, here);
    }
    if (typeof s.additionalProperties === 'object') {
      walk(s.additionalProperties as JsonSchema7, section, [...path, ENTRY]);
    }
    if (s.type === 'array' && s.items && !Array.isArray(s.items)) {
      walk(s.items as JsonSchema7, section, path);
    }
  };
  for (const g of sectionGroups(schema)) {
    for (const sec of g.sections) {
      const p = (schema.properties as Record<string, JsonSchema7>)[sec.key];
      out.push({ section: sec.key, path: [], label: sec.label, description: p.description ?? '' });
      walk(p, sec.key, []);
    }
  }
  return out;
}

/**
 * The settings matching every word of `query`, in their label, path or
 * description; those whose label matches come first.
 */
export function search(all: Setting[], query: string): Setting[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return [];
  const scored: { s: Setting; score: number }[] = [];
  for (const s of all) {
    const label = s.label.toLowerCase();
    const path = [s.section, ...s.path].join('.').toLowerCase().replace(/_/g, ' ');
    const text = `${label} ${path} ${s.description.toLowerCase()}`;
    if (!words.every((w) => text.includes(w))) continue;
    const inLabel = words.filter((w) => label.includes(w)).length;
    scored.push({ s, score: inLabel * 10 - s.path.length });
  }
  return scored.sort((a, b) => b.score - a.score).map((x) => x.s);
}

/** Where a setting is, as people read it: "DHCP › each › Lease time". */
export function settingPlace(s: Setting): string {
  return [
    sectionLabel(s.section),
    ...s.path.map((k) => (k === ENTRY ? 'each' : fieldLabel(k))),
  ].join(' › ');
}
