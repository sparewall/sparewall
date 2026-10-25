import { Schemas } from '../../api/api.model';
import { matrix, natLabel, withPolicy, zones } from './matrix';

const doc = {
  zones: { users: { networks: ['users'] }, wan: { networks: ['wan'] } },
  policy: {
    'users->wan': { action: 'accept', nat: 'masquerade' },
    'wan->self': { action: 'drop', rules: { ping: { order: 100, action: 'accept' } } },
  },
} as unknown as Schemas['Document'];

describe('the policy matrix', () => {
  it('has every zone, and self last', () => {
    expect(zones(doc)).toEqual(['users', 'wan', 'self']);
  });

  it('shows each pair, with the default where there is no policy', () => {
    const m = matrix(doc);
    const cell = (from: number, to: number) => m[from][to];
    expect(cell(0, 1)).toMatchObject({ key: 'users->wan', policy: { action: 'accept' } });
    // Unlisted pairs are dropped (input and forward chains)...
    expect(cell(1, 0)).toMatchObject({ key: 'wan->users', policy: undefined, fallback: 'drop' });
    expect(cell(1, 2)).toMatchObject({ key: 'wan->self', fallback: 'drop' });
    // ...but what the firewall sends is accepted (output chain).
    expect(cell(2, 0)).toMatchObject({ key: 'self->users', fallback: 'accept' });
    expect(cell(2, 2).none).toBe(true);
    expect(cell(0, 0).none).toBe(false);
  });

  it('sets and removes a pair without touching the rest', () => {
    const set = withPolicy(doc, 'wan->users', { action: 'reject' } as never);
    expect(set.policy!['wan->users']).toEqual({ action: 'reject' });
    expect(set.policy!['users->wan']).toEqual(doc.policy!['users->wan']);
    expect(doc.policy!['wan->users']).toBeUndefined();
    const removed = withPolicy(set, 'users->wan', undefined);
    expect(Object.keys(removed.policy!)).toEqual(['wan->self', 'wan->users']);
  });

  it('names NAT in words', () => {
    expect(natLabel('masquerade')).toBe('masquerade');
    expect(natLabel({ snat: '203.0.113.5' })).toBe('SNAT 203.0.113.5');
    expect(natLabel(undefined)).toBeUndefined();
  });
});
