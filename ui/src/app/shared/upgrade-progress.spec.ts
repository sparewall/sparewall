import { advance, outcome, started } from './upgrade-progress';

const ev = (step: string, detail = '') => ({
  kind: 'event' as const,
  event: { type: 'upgrade', step, detail },
});

describe('upgrade progress', () => {
  it('follows a standalone node through its reboot', () => {
    let p = started(['stage the new image', 'reboot']);
    p = advance(p, ev('stage', 'staging reg/sw:stable'), 'fw1');
    p = advance(p, ev('reboot', 'rebooting into the new image'), 'fw1');
    expect(p.phase).toBe('running');
    expect(p.rebootsHere).toBe(true);
    p = advance(p, { kind: 'disconnected' }, 'fw1');
    expect(p.phase).toBe('rebooting');
    expect(p.message).toBe('fw1 is rebooting into the new image.');
    p = advance(p, { kind: 'back', outcome: 'fw1 is back' }, 'fw1');
    expect(p).toMatchObject({ phase: 'done', message: 'fw1 is back' });
    expect(p.log).toEqual(['staging reg/sw:stable', 'rebooting into the new image']);
  });

  it('knows a standby is rebooted when the master stages it', () => {
    let p = started([]);
    p = advance(p, ev('stage-peer', 'fw1: staging reg/sw:stable on fw2'), 'fw2');
    expect(p.rebootsHere).toBe(true);
    expect(advance(p, { kind: 'disconnected' }, 'fw2').phase).toBe('rebooting');
    // On the master, staging the peer reboots nothing here.
    const m = advance(started([]), ev('stage-peer', 'staging reg/sw:stable on fw2'), 'fw1');
    expect(m.rebootsHere).toBe(false);
  });

  it('calls any other drop an error', () => {
    const p = advance(
      advance(started([]), ev('download', 'downloading'), 'fw1'),
      { kind: 'disconnected' },
      'fw1',
    );
    expect(p).toMatchObject({
      phase: 'failed',
      message: 'The connection to fw1 was lost during the upgrade.',
    });
  });

  it('shows the step that failed, and what ended it', () => {
    expect(
      advance(started([]), ev('failed', 'fw2 did not come back healthy'), 'fw1'),
    ).toMatchObject({
      phase: 'failed',
      message: 'fw2 did not come back healthy',
    });
    expect(
      advance(started([]), ev('done', 'both nodes already run the newest image'), 'fw1'),
    ).toMatchObject({
      phase: 'done',
      message: 'both nodes already run the newest image',
    });
  });

  it('ignores other events and anything after the end', () => {
    const p = started([]);
    expect(advance(p, { kind: 'event', event: { type: 'vrrp', state: 'BACKUP' } }, 'fw1')).toBe(p);
    const done = advance(p, ev('done', 'x'), 'fw1');
    expect(advance(done, ev('failed', 'y'), 'fw1')).toBe(done);
    expect(advance(done, { kind: 'disconnected' }, 'fw1')).toBe(done);
  });

  it('says how the node came back', () => {
    expect(
      outcome('fw1', {
        update: { running: '0.4.1' },
        health: { level: 'ok' },
        sync: { peer: 'fw2', state: 'in-sync' },
      }),
    ).toBe('fw1 is back, running 0.4.1: health ok, in-sync with fw2.');
    expect(outcome('fw1', { health: { level: 'ok' }, sync: { peer: null } })).toBe(
      'fw1 is back, running its new image: health ok.',
    );
  });
});
