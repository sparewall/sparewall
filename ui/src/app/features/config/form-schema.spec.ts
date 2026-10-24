import { JsonSchema7 } from '@jsonforms/core';

import { documentSchema, isMap, OPTIONAL } from './form-schema';
import { objectLayout } from './layout';

const openapi = {
  components: {
    schemas: {
      Document: {
        type: 'object',
        properties: {
          networks: {
            type: 'object',
            additionalProperties: { $ref: '#/components/schemas/Document.Network' },
          },
          ntp: { anyOf: [{ $ref: '#/components/schemas/Document.Ntp' }, { type: 'null' }] },
        },
      },
      'Document.Network': {
        type: 'object',
        required: ['port'],
        properties: {
          cake: { anyOf: [{ $ref: '#/components/schemas/Document.Cake' }, { type: 'null' }] },
          lldp: { type: ['boolean', 'null'], description: 'Default true on untagged ports.' },
          mtu: { type: ['integer', 'null'], format: 'uint32' },
          port: { type: 'string' },
          role: { $ref: '#/components/schemas/Document.NetworkRole', description: 'What for.' },
          servers: { type: 'array', items: { type: 'string' } },
        },
      },
      'Document.Cake': { type: 'object', properties: { egress: { type: 'string' } } },
      'Document.NetworkRole': { type: 'string', enum: ['service', 'wan'] },
      'Document.Ntp': { type: 'object', properties: { serve: { type: 'array' } } },
    },
  },
};

describe('documentSchema', () => {
  const doc = documentSchema(openapi);
  const network = (doc.properties!['networks'].additionalProperties as JsonSchema7).properties!;

  it('inlines references, keeping the referring description', () => {
    expect(network['role']).toEqual({
      type: 'string',
      enum: ['service', 'wan'],
      description: 'What for.',
    });
  });

  it('reduces nullable fields to their type, marked optional', () => {
    expect(network['lldp']).toMatchObject({ type: 'boolean', [OPTIONAL]: true });
    expect(network['cake']).toMatchObject({ type: 'object', [OPTIONAL]: true });
    expect(doc.properties!['ntp']).toMatchObject({ type: 'object', [OPTIONAL]: true });
    expect(network['port']).not.toHaveProperty(OPTIONAL);
  });

  it('drops integer formats the form validator does not know', () => {
    expect(network['mtu']).toEqual({ type: 'integer', [OPTIONAL]: true });
  });

  it('tells maps of named things from objects with fields', () => {
    expect(isMap(doc.properties!['networks'] as JsonSchema7)).toBe(true);
    expect(isMap(network['cake'] as JsonSchema7)).toBe(false);
  });

  it('refuses a recursive schema rather than looping', () => {
    expect(() =>
      documentSchema({
        components: {
          schemas: { Document: { $ref: '#/components/schemas/Document' } },
        },
      }),
    ).toThrow(/recursive/);
  });
});

describe('objectLayout', () => {
  it('puts required fields first, then values, lists and groups', () => {
    const network = documentSchema(openapi).properties!['networks']
      .additionalProperties as JsonSchema7;
    const scopes = objectLayout(network).elements.map((e) =>
      (e as { scope: string }).scope.split('/').pop(),
    );
    expect(scopes).toEqual(['port', 'lldp', 'mtu', 'role', 'servers', 'cake']);
  });
});
