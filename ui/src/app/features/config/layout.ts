import { ControlElement, JsonSchema7, VerticalLayout } from '@jsonforms/core';

import { isMap } from './form-schema';

/** Words written in capitals wherever they appear in a field's name. */
const ACRONYMS = new Set([
  'acme',
  'dhcp',
  'dns',
  'ha',
  'http',
  'https',
  'icmp',
  'ip',
  'ips',
  'lacp',
  'mac',
  'mss',
  'mtu',
  'nat',
  'nic',
  'ntp',
  'psk',
  'snat',
  'ssh',
  'tcp',
  'tls',
  'udp',
  'url',
  'vip',
  'vlan',
  'vpn',
  'vrrp',
  'wan',
]);

/** How a field reads: `tcp_established_timeout` as "TCP established timeout". */
export function fieldLabel(key: string): string {
  const words = key
    .split('_')
    .filter(Boolean)
    .map((w) => (ACRONYMS.has(w.toLowerCase()) ? w.toUpperCase() : w));
  const s = words.join(' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function weight(s: JsonSchema7, required: boolean): number {
  if (required) return 0;
  if (s.type === 'object' || isMap(s)) return 3;
  if (s.type === 'array') return 2;
  return 1;
}

/**
 * One control per property: required ones first, then plain values, then
 * lists, then nested groups and maps, keeping the schema's order within
 * each. JSON Forms' own generator keeps only the schema's (alphabetical)
 * order, which puts a network's `vlan` below its `cake`.
 */
export function objectLayout(schema: JsonSchema7): VerticalLayout {
  const required = new Set(schema.required ?? []);
  const props = Object.entries(schema.properties ?? {}) as [string, JsonSchema7][];
  const ordered = props
    .map(([key, s], i) => ({ key, i, w: weight(s, required.has(key)) }))
    .sort((a, b) => a.w - b.w || a.i - b.i);
  return {
    type: 'VerticalLayout',
    elements: ordered.map(({ key }): ControlElement => ({
      type: 'Control',
      scope: `#/properties/${key}`,
      label: fieldLabel(key),
    })),
  };
}
