import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { ActivatedRoute, convertToParamMap } from '@angular/router';

import { ApiClient } from '../../api/api-client';
import { logged } from '../policy/policy-dialog';
import { Hits, RuleHit } from './hits';

const hit = (usec: number, rule: string, packet = 'tcp 192.0.2.7:1 -> 10.0.0.2:443'): RuleHit => ({
  time: new Date(usec / 1000).toISOString(),
  usec,
  rule,
  packet,
  proto: 'tcp',
  src: null,
  dst: null,
  sport: null,
  dport: null,
  in_iface: null,
  out_iface: null,
});

function feed<T>() {
  const queue: T[] = [];
  let wake: (() => void) | null = null;
  return {
    push(v: T) {
      queue.push(v);
      wake?.();
    },
    async *iter(): AsyncGenerator<T> {
      for (;;) {
        while (queue.length) yield queue.shift()!;
        await new Promise<void>((r) => (wake = r));
        wake = null;
      }
    },
  };
}

async function render(replies: unknown[], query: Record<string, string> = {}) {
  const calls: Record<string, unknown>[] = [];
  const stream = feed<{ hit: RuleHit | null }>();
  const streams: Record<string, unknown>[] = [];
  const api = {
    call: async (_m: string, params: Record<string, unknown>) => {
      calls.push(params);
      return replies.shift();
    },
    stream: (_m: string, params: Record<string, unknown>) => {
      streams.push(params);
      return stream.iter();
    },
  };
  TestBed.configureTestingModule({
    providers: [
      provideNoopAnimations(),
      { provide: ApiClient, useValue: api },
      {
        provide: ActivatedRoute,
        useValue: { snapshot: { queryParamMap: convertToParamMap(query) } },
      },
    ],
  });
  const fixture = TestBed.createComponent(Hits);
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
  const el = fixture.nativeElement as HTMLElement;
  const settle = async () => {
    await new Promise((r) => setTimeout(r));
    await fixture.whenStable();
    fixture.detectChanges();
  };
  return { fixture, el, calls, stream, streams, settle };
}

const rows = (el: HTMLElement) =>
  [...el.querySelectorAll('tbody tr')].map((r) => r.querySelector('.rule')?.textContent);

describe('Hits', () => {
  it("starts from a link's rule, and pages back", async () => {
    const { el, calls, settle } = await render(
      [
        { hits: [hit(3e15, 'users->self:ssh'), hit(2e15, 'users->self:ssh')], older: 'p2' },
        { hits: [hit(1e15, 'users->self:ssh')], older: null },
      ],
      { rule: 'users->self:ssh' },
    );
    expect(calls[0]).toEqual({
      rule: 'users->self:ssh',
      pair: null,
      address: null,
      port: null,
      since: '-1h',
      limit: 200,
    });
    expect(rows(el)).toEqual(['users->self:ssh', 'users->self:ssh']);
    const older = [...el.querySelectorAll('button')].find((b) => b.textContent?.includes('Older'))!;
    older.click();
    await settle();
    expect(calls[1]['before']).toBe('p2');
    expect(rows(el).length).toBe(3);
  });

  it("narrows to a hit's rule when it is clicked", async () => {
    const { el, calls, settle } = await render([
      { hits: [hit(2e15, 'wan->lan:https'), hit(1e15, 'forward:web')], older: null },
      { hits: [hit(1e15, 'forward:web')], older: null },
    ]);
    (el.querySelectorAll('.rule')[1] as HTMLButtonElement).click();
    await settle();
    expect(calls[1]['rule']).toBe('forward:web');
    expect(rows(el)).toEqual(['forward:web']);
  });

  it('follows new hits at the top, with the same filters', async () => {
    const { el, fixture, stream, streams, settle } = await render(
      [{ hits: [hit(1e15, 'wan->lan:https')], older: null }],
      { pair: 'wan->lan' },
    );
    (el.querySelector('mat-slide-toggle button') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(streams[0]).toEqual({ rule: null, pair: 'wan->lan', address: null, port: null });
    stream.push({ hit: null });
    stream.push({ hit: hit(2e15, 'wan->lan:ssh') });
    await settle();
    expect(rows(el)).toEqual(['wan->lan:ssh', 'wan->lan:https']);
  });
});

describe('logged', () => {
  it("names a policy's logged default and rules as their hits do", () => {
    expect(logged('users->self', undefined)).toEqual([]);
    expect(
      logged('users->self', {
        action: 'drop',
        log: true,
        rules: {
          ssh: { order: 100, action: 'accept', log: true },
          dns: { order: 200, action: 'accept' },
          https: { order: 300, action: 'accept', log: true },
        },
      } as never),
    ).toEqual([
      { label: 'users->self:default', name: 'default' },
      { label: 'users->self:https', name: 'https' },
      { label: 'users->self:ssh', name: 'ssh' },
    ]);
  });
});
