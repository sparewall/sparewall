import { countdown } from './countdown';

describe('countdown', () => {
  it('shows minutes and seconds', () => {
    expect(countdown(300)).toBe('5:00');
    expect(countdown(65)).toBe('1:05');
    expect(countdown(0)).toBe('0:00');
    expect(countdown(-3)).toBe('0:00');
  });
});
