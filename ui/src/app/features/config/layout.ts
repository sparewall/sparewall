import {
  ControlElement,
  JsonSchema7,
  RuleEffect,
  UISchemaElement,
  ValidateFunctionCondition,
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
 * On such a field: the networks it applies to, `wan` or `inside` (any
 * other role), by the role of the network holding the object.
 */
export const ROLE = 'x-role';

/** The value at a dotted data path (`networks.wan`); the root for `''`. */
function at(data: unknown, path: string): unknown {
  return path
    .split('.')
    .filter(Boolean)
    .reduce<unknown>((d, k) => (d as Record<string, unknown> | undefined)?.[k], data);
}

/**
 * A rule's condition: the object's `mode` is one of `modes`, and, for a
 * field bound to a role, the network holding the object (one level up)
 * has it. A function, not a schema condition: those need a validator, and
 * the form's passes everything (no-eval-ajv.ts). Where the object has no
 * network above it, the role is not known and does not hide the field.
 */
function modeCondition(modes: unknown[], role?: string): ValidateFunctionCondition {
  return {
    scope: '#/properties/mode',
    validate: ({ data, fullData, path }) => {
      if (!modes.includes(data)) return false;
      if (!role || !path) return true;
      const parent = path.split('.').slice(0, -1).join('.');
      const network = at(fullData, parent) as { role?: string } | undefined;
      const wan = (network?.role ?? 'service') === 'wan';
      return role === 'wan' ? wan : !wan;
    },
  };
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
  const hasMode = !!schema.properties?.['mode'];
  return {
    type: 'VerticalLayout',
    elements: ordered.map(({ key }): UISchemaElement => {
      const control: ControlElement = {
        type: 'Control',
        scope: `#/properties/${key}`,
        label: fieldLabel(key),
      };
      const meta = schema.properties?.[key] as Record<string, unknown> | undefined;
      const modes = meta?.[MODES];
      if (!hasMode || !Array.isArray(modes)) return control;
      // The rule goes on a layout around the control: layouts honour it
      // whatever draws the field, and JSON Forms' list table does not.
      const role = meta?.[ROLE];
      return {
        type: 'VerticalLayout',
        elements: [control],
        rule: {
          effect: RuleEffect.SHOW,
          condition: modeCondition(modes, typeof role === 'string' ? role : undefined),
        },
      } as VerticalLayout;
    }),
  };
}
