import {
  ControlElement,
  JsonSchema7,
  LeafCondition,
  OrCondition,
  RuleEffect,
  VerticalLayout,
} from '@jsonforms/core';

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
/** Words spelled their own way. */
const SPELLED: Record<string, string> = { id: 'ID', ipv4: 'IPv4', ipv6: 'IPv6', dhcpv6: 'DHCPv6' };

/** How a field reads: `tcp_established_timeout` as "TCP established timeout". */
export function fieldLabel(key: string): string {
  const words = key
    .split('_')
    .filter(Boolean)
    .map((w) => SPELLED[w.toLowerCase()] ?? (ACRONYMS.has(w.toLowerCase()) ? w.toUpperCase() : w));
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
 * On a field of an object with a `mode` (a network's `ipv6`): the modes
 * the field applies to. The field shows only in those.
 */
export const MODES = 'x-modes';

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
  const hasMode = !!schema.properties?.['mode'];
  return {
    type: 'VerticalLayout',
    elements: ordered.map(({ key }): ControlElement => {
      const control: ControlElement = {
        type: 'Control',
        scope: `#/properties/${key}`,
        label: fieldLabel(key),
      };
      const modes = (schema.properties?.[key] as Record<string, unknown> | undefined)?.[MODES];
      if (hasMode && Array.isArray(modes)) {
        // Value conditions, not a schema one: those need a validator, and
        // the form's passes everything (no-eval-ajv.ts).
        const leaf = (m: unknown): LeafCondition => ({
          type: 'LEAF',
          scope: '#/properties/mode',
          expectedValue: m,
        });
        control.rule = {
          effect: RuleEffect.SHOW,
          condition: { type: 'OR', conditions: modes.map(leaf) } as OrCondition,
        };
      }
      return control;
    }),
  };
}
