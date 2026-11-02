import { SyncState, UpdateState } from '../api/status.model';
import { checkProblem, mixedImages, updateNotice } from './update-notice';

const base: UpdateState = { enabled: true, running: '0.4.0', checked: 't2', succeeded: 't2' };

describe('updateNotice', () => {
  it('says nothing when nothing is offered', () => {
    expect(updateNotice({ ...base, available: 'none' })).toBeUndefined();
    expect(updateNotice({ enabled: true, running: '0.4.0' })).toBeUndefined();
    expect(updateNotice({ enabled: false, running: '0.4.0' })).toBeUndefined();
    expect(updateNotice(undefined)).toBeUndefined();
  });

  it('names a newer release, with its notes', () => {
    expect(updateNotice({ ...base, available: 'newer', version: '0.4.1' })).toEqual({
      kind: 'newer',
      title: '0.4.1 is available',
      running: '0.4.0',
      notes: 'https://github.com/sparewall/sparewall/releases/tag/v0.4.1',
    });
    // A build between releases has no notes.
    expect(
      updateNotice({ ...base, available: 'newer', version: '0.4.1-dev.3+gabc' })?.notes,
    ).toBeUndefined();
  });

  it('names a rebuild as one', () => {
    expect(updateNotice({ ...base, available: 'rebuild', version: '0.4.0' })).toEqual({
      kind: 'rebuild',
      title: 'A rebuild of 0.4.0 is available',
      running: '0.4.0',
      notes: 'https://github.com/sparewall/sparewall/releases/tag/v0.4.0',
    });
  });

  it('names an image whose version cannot be read by where it is', () => {
    expect(
      updateNotice({ ...base, available: 'different', target: 'mirror.example/sparewall:stable' })
        ?.title,
    ).toBe('A different image is available on mirror.example/sparewall:stable');
  });
});

describe('checkProblem', () => {
  it('reports a failing check, and nothing otherwise', () => {
    expect(checkProblem({ ...base, error: 'no route to host', succeeded: 't1' })).toBe(
      'The last update check failed: no route to host. The last successful check was at t1.',
    );
    expect(checkProblem({ ...base, error: 'timed out', succeeded: undefined })).toBe(
      'The last update check failed: timed out.',
    );
    expect(checkProblem(base)).toBeUndefined();
    expect(checkProblem({ enabled: false, running: '0.4.0', error: 'x' })).toBeUndefined();
  });
});

describe('mixedImages', () => {
  const sync = (o: Partial<SyncState>) =>
    ({ peer: 'fw2', peer_reachable: true, ...o }) as SyncState;
  const a = 'ghcr.io/sparewall/sparewall:stable@sha256:aaa';
  const b = 'ghcr.io/sparewall/sparewall@sha256:bbb';

  it('says when the nodes disagree', () => {
    expect(mixedImages(sync({ image: a, peer_image: b }))).toBe(
      'This node and fw2 run different images. If an upgrade stopped halfway, running it again finishes it.',
    );
  });

  it('compares digests, and only with a reachable peer', () => {
    expect(
      mixedImages(sync({ image: a, peer_image: '10.0.2.2:5000/sparewall:candidate@sha256:aaa' })),
    ).toBeUndefined();
    expect(mixedImages(sync({ image: a, peer_image: b, peer_reachable: false }))).toBeUndefined();
    expect(mixedImages(sync({ image: a, peer: null }))).toBeUndefined();
    expect(mixedImages(undefined)).toBeUndefined();
  });
});
