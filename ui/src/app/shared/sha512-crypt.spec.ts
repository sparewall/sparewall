import { hashPassword, newSalt, sha512Crypt } from './sha512-crypt';

// From Drepper's specification, "Unix crypt using SHA-256 and SHA-512".
describe('sha512Crypt', () => {
  it('matches the specification with the default rounds', async () => {
    expect(await sha512Crypt('Hello world!', 'saltstring')).toBe(
      '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1',
    );
  });

  it('matches it with more rounds and a salt cut to 16 characters', async () => {
    expect(await sha512Crypt('Hello world!', 'saltstringsaltstring', 10000)).toBe(
      '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.',
    );
  });

  it('matches it for a password longer than the digest', async () => {
    expect(
      await sha512Crypt('we have a short salt string but not a short password', 'short', 77777),
    ).toBe(
      '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0',
    );
  });

  it('salts each hash anew, as the CLI does', async () => {
    expect(newSalt()).toMatch(/^[./0-9A-Za-z]{16}$/);
    const [a, b] = await Promise.all([hashPassword('same'), hashPassword('same')]);
    expect(a).toMatch(/^\$6\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}$/);
    expect(a).not.toBe(b);
  });
});
