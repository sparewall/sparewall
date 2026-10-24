import { Categorization, JsonSchema7 } from '@jsonforms/core';

/** The document's top-level sections, in the order a site is usually set up. */
const ORDER = [
  'cluster',
  'ports',
  'networks',
  'zones',
  'policy',
  'objects',
  'forwards',
  'nat',
  'dhcp',
  'dns',
  'ntp',
  'vpn',
  'management',
  'tls',
  'logging',
  'metrics',
  'backup',
  'updates',
  'raw',
];

const LABELS: Record<string, string> = {
  dhcp: 'DHCP',
  dns: 'DNS',
  ntp: 'NTP',
  nat: 'NAT',
  tls: 'TLS',
  vpn: 'VPN',
  raw: 'Raw nftables',
};

const label = (key: string) => LABELS[key] ?? key.charAt(0).toUpperCase() + key.slice(1);

/** One tab per top-level section, known ones first. */
export function configUiSchema(schema: JsonSchema7): Categorization {
  const keys = Object.keys(schema.properties ?? {}).filter((k) => k !== 'schema');
  keys.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  return {
    type: 'Categorization',
    label: 'Configuration',
    elements: keys.map((key) => ({
      type: 'Category',
      label: label(key),
      elements: [{ type: 'Control', scope: `#/properties/${key}`, label: false }],
    })),
  } as Categorization;
}

function rank(key: string): number {
  const i = ORDER.indexOf(key);
  return i < 0 ? ORDER.length : i;
}
