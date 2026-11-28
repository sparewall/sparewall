import { references, secretNameOk } from './references';

describe('references', () => {
  const doc = {
    backup: { credentials: 'secret:s3' },
    dns: { dynamic: { 'home.example': { credentials: 'secret:cf' } } },
    vpn: { ra: { peers: { alice: { preshared_key: 'secret:psk-alice' } } } },
    tls: { certificates: { mgmt: { acme: { dns: { credentials: 'secret:cf' } } } } },
    other: ['secret:cf', 'not-secret:cf'],
  };

  it('finds each setting that names the secret, by path', () => {
    expect(references(doc, 'cf')).toEqual([
      "dns.dynamic.'home.example'.credentials",
      'tls.certificates.mgmt.acme.dns.credentials',
      'other[0]',
    ]);
    expect(references(doc, 's3')).toEqual(['backup.credentials']);
  });

  it('finds nothing for a secret nothing names', () => {
    expect(references(doc, 'unused')).toEqual([]);
    expect(references(undefined, 'cf')).toEqual([]);
  });
});

describe('secretNameOk', () => {
  it('holds names to the node rule', () => {
    for (const n of ['s3', 'backup-password', 'cf.token_2', 'A1'])
      expect(secretNameOk(n)).toBe(true);
    for (const n of ['', '-x', '.x', 'a b', 'a/b', 'x'.repeat(65)])
      expect(secretNameOk(n)).toBe(false);
  });
});
