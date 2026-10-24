import { formatMatch, formatUnion, parseMatch, parseUnion } from './union-text';

describe('match text', () => {
  it('shows each kind of value as it is', () => {
    expect(formatMatch(22)).toBe('22');
    expect(formatMatch('8000-8100')).toBe('8000-8100');
    expect(formatMatch('@web')).toBe('@web');
    expect(formatMatch([22, '8000-8100', '@web'])).toBe('22, 8000-8100, @web');
    expect(formatMatch(undefined)).toBe('');
  });

  it('reads numbers as numbers, the rest as strings, lists as lists', () => {
    expect(parseMatch('22')).toBe(22);
    expect(parseMatch(' 8000-8100 ')).toBe('8000-8100');
    expect(parseMatch('192.0.2.0/24')).toBe('192.0.2.0/24');
    expect(parseMatch('22, 8000-8100,@web')).toEqual([22, '8000-8100', '@web']);
    expect(parseMatch('  ')).toBeUndefined();
  });

  it('round-trips every branch', () => {
    for (const v of [443, '@admin_nets', '2001:db8::/32', [22, 443], ['10.0.0.0/8', '@lab']]) {
      expect(parseMatch(formatMatch(v))).toEqual(v);
    }
  });
});

describe('union text', () => {
  it('shows names as text and the rest as JSON', () => {
    expect(formatUnion('masquerade')).toBe('masquerade');
    expect(formatUnion({ snat: '203.0.113.5' })).toBe('{"snat":"203.0.113.5"}');
  });

  it('reads JSON and plain names, and refuses broken JSON', () => {
    expect(parseUnion('masquerade')).toEqual({ value: 'masquerade' });
    expect(parseUnion('{"snat": "203.0.113.5"}')).toEqual({ value: { snat: '203.0.113.5' } });
    expect(parseUnion('{"snat": ')).toEqual({ error: 'Not valid JSON.' });
    expect(parseUnion('')).toEqual({ value: undefined });
  });
});
