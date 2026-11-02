import openapi from '../../../../docs/api/openapi.json';
import { Role } from '../core/session';
import { OpenApi, allowed, apiReference, curlExample, typeName } from './api-reference';

const doc = openapi as unknown as OpenApi;
const RANK: Record<Role, number> = { monitor: 0, viewer: 1, operator: 2, admin: 3 };
const canAs = (r: Role) => (need: Role) => RANK[r] >= RANK[need];

describe('apiReference', () => {
  const ifaces = apiReference(doc);
  const calls = ifaces.flatMap((i) => i.calls);

  it('lists every call in the committed openapi.json, with its role', () => {
    const paths = Object.entries(doc.paths).filter(([p]) => p.startsWith('/call/'));
    expect(calls.length).toBe(paths.length);
    for (const [path, item] of paths) {
      const c = calls.find((x) => `/call/${x.method}` === path);
      expect(c, path).toBeDefined();
      expect(c?.role).toBe(item.post?.['x-sparewall-role']);
    }
  });

  it('groups calls by interface, in order', () => {
    const names = ifaces.map((i) => i.name);
    expect(names).toEqual([...names].sort());
    expect(names).toContain('org.sparewall.Firewall');
    for (const i of ifaces)
      for (const c of i.calls) expect(c.method.startsWith(`${i.name}.`)).toBe(true);
  });

  it('reads parameters, replies and streaming', () => {
    const history = calls.find((c) => c.method === 'org.sparewall.Firewall.History')!;
    expect(history.role).toBe('viewer');
    expect(history.parameters.map((p) => p.name)).toContain('limit');
    expect(history.reply.map((p) => p.name)).toContain('generations');
    expect(calls.find((c) => c.method === 'org.sparewall.Firewall.Subscribe')?.streams).toBe(true);
    expect(history.streams).toBe(false);
  });

  it('greys out what a role cannot call', () => {
    const status = calls.find((c) => c.method === 'org.sparewall.Firewall.Status')!;
    const apply = calls.find((c) => c.method === 'org.sparewall.Firewall.Apply')!;
    const token = calls.find((c) => c.method === 'org.sparewall.Auth.CreateToken')!;
    const login = calls.find((c) => c.method === 'org.sparewall.Auth.Login')!;
    expect([status, apply, token, login].map((c) => allowed(c, canAs('viewer')))).toEqual([
      true,
      false,
      false,
      true,
    ]);
    expect([status, apply, token].map((c) => allowed(c, canAs('operator')))).toEqual([
      true,
      true,
      false,
    ]);
    expect([status, apply, token].map((c) => allowed(c, canAs('admin')))).toEqual([
      true,
      true,
      true,
    ]);
    // A monitor reads health and metrics only.
    expect(allowed(status, canAs('monitor'))).toBe(false);
  });
});

describe('curlExample', () => {
  const calls = apiReference(doc).flatMap((i) => i.calls);
  const call = (m: string) => calls.find((c) => c.method === `org.sparewall.${m}`)!;

  it('posts the parameters with the token to the node', () => {
    expect(curlExample(call('Firewall.Status'), 'https://fw1.example')).toBe(
      'curl -s -H "Authorization: Bearer $SPAREWALL_TOKEN" --json \'{}\' \\\n    https://fw1.example/call/org.sparewall.Firewall.Status',
    );
    expect(curlExample(call('Secrets.Delete'), 'https://fw1')).toContain(
      `--json '{"name":"<name>"}'`,
    );
  });

  it('leaves a streaming call open, and a call without a role unauthenticated', () => {
    const sub = curlExample(call('Firewall.Subscribe'), 'https://fw1');
    expect(sub.startsWith('curl -sN ')).toBe(true);
    expect(sub.endsWith('/call/org.sparewall.Firewall.Subscribe?more=true')).toBe(true);
    expect(curlExample(call('Auth.Login'), 'https://fw1')).not.toContain('Authorization');
  });
});

describe('typeName', () => {
  it('names arrays, references and alternatives', () => {
    expect(typeName({ type: 'array', items: { type: 'string' } })).toBe('string[]');
    expect(typeName({ $ref: '#/components/schemas/HealthCheck' })).toBe('HealthCheck');
    expect(typeName({ type: ['integer', 'null'] })).toBe('integer or null');
    expect(typeName({ anyOf: [{ type: 'string' }, { type: 'null' }] })).toBe('string or null');
  });
});
