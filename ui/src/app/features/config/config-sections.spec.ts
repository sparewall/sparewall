import { JsonSchema7 } from '@jsonforms/core';

import { search, sectionGroups, settingPlace, settings } from './config-sections';
import { fieldLabel } from './layout';

const schema = {
  type: 'object',
  properties: {
    schema: { type: 'integer' },
    cluster: {
      type: 'object',
      description: 'Node names and pair-wide settings.',
      properties: {
        conntrack: {
          type: 'object',
          properties: { buckets: { type: 'integer', description: 'Hash table buckets.' } },
        },
      },
    },
    dhcp: {
      type: 'object',
      properties: { lease_time: { type: 'integer', description: 'Default lease time.' } },
      additionalProperties: {
        type: 'object',
        properties: {
          lease_time: { type: 'integer' },
          pool: { type: 'string', description: 'Address range.' },
        },
      },
    },
    networks: {
      type: 'object',
      additionalProperties: { type: 'object', properties: { mtu: { type: 'integer' } } },
    },
    shiny_new: { type: 'object', properties: {} },
  },
} as JsonSchema7;

describe('config sections', () => {
  it('groups the sections, known ones first and new ones under Other', () => {
    expect(sectionGroups(schema).map((g) => [g.label, g.sections.map((s) => s.key)])).toEqual([
      ['Network', ['networks']],
      ['Services', ['dhcp']],
      ['System', ['cluster']],
      ['Other', ['shiny_new']],
    ]);
  });

  it('finds settings by label, nested and inside named entries', () => {
    const all = settings(schema);
    expect(search(all, 'buckets').map(settingPlace)).toEqual(['Cluster › Conntrack › Buckets']);
    expect(search(all, 'lease').map(settingPlace)).toEqual([
      'DHCP › Lease time',
      'DHCP › each › Lease time',
    ]);
    expect(search(all, 'MTU').map(settingPlace)).toEqual(['Networks › each › MTU']);
  });

  it('finds settings by description and needs every word', () => {
    const all = settings(schema);
    expect(search(all, 'address range').map(settingPlace)).toEqual(['DHCP › each › Pool']);
    expect(search(all, 'lease nothing')).toEqual([]);
    expect(search(all, '  ')).toEqual([]);
  });

  it('writes acronyms in capitals', () => {
    expect(fieldLabel('tcp_established_timeout')).toBe('TCP established timeout');
    expect(fieldLabel('ha')).toBe('HA');
    expect(fieldLabel('sync_network')).toBe('Sync network');
  });
});
