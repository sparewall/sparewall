import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';

import { ApiClient, CallFailed } from '../../api/api-client';
import { LogEntry, Logs, priority, shortUnit } from './logs';

const entry = (usec: number, message: string, more: Partial<LogEntry> = {}): LogEntry => ({
  time: new Date(usec / 1000).toISOString(),
  usec,
  unit: 'sparewalld.service',
  priority: 6,
  identifier: 'sparewalld',
  message,
  fields: {},
  ...more,
});

/** A stream the test feeds by hand. */
function feed<T>() {
  const queue: T[] = [];
  let wake: (() => void) | null = null;
  let done = false;
  return {
    push(v: T) {
      queue.push(v);
      wake?.();
    },
    end() {
      done = true;
      wake?.();
    },
    async *iter(): AsyncGenerator<T> {
      for (;;) {
        while (queue.length) yield queue.shift()!;
        if (done) return;
        await new Promise<void>((r) => (wake = r));
        wake = null;
      }
    },
  };
}

async function render(replies: unknown[]) {
  const calls: { method: string; params: Record<string, unknown> }[] = [];
  const stream = feed<{ entry: LogEntry | null }>();
  const streams: Record<string, unknown>[] = [];
  const api = {
    call: async (method: string, params: Record<string, unknown>) => {
      calls.push({ method, params });
      const r = replies.shift();
      if (r instanceof Error) throw r;
      return r;
    },
    stream: (_m: string, params: Record<string, unknown>) => {
      streams.push(params);
      return stream.iter();
    },
  };
  TestBed.configureTestingModule({
    providers: [provideNoopAnimations(), { provide: ApiClient, useValue: api }],
  });
  const fixture = TestBed.createComponent(Logs);
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

const units = ['sparewalld.service', 'sparewall-kea.service', 'selinux'];

describe('Logs', () => {
  it('shows the newest entries of the last hour, and pages back', async () => {
    const { el, calls, settle } = await render([
      {
        entries: [entry(3e15, 'third', { priority: 3 }), entry(2e15, 'second')],
        older: 'page-2',
        units,
      },
      { entries: [entry(1e15, 'first')], older: null, units },
    ]);
    expect(calls[0].method).toBe('org.sparewall.Diagnostics.Logs');
    expect(calls[0].params).toEqual({
      units: null,
      priority: null,
      since: '-1h',
      grep: null,
      limit: 200,
      before: null,
      node: null,
    });
    const lines = () => [...el.querySelectorAll('.msg')].map((m) => m.textContent);
    expect(lines()).toEqual(['third', 'second']);
    expect(el.querySelector('li.problem .msg')!.textContent).toBe('third');
    const older = [...el.querySelectorAll('button')].find((b) => b.textContent?.includes('Older'))!;
    older.click();
    await settle();
    expect(calls[1].params['before']).toBe('page-2');
    expect(lines()).toEqual(['third', 'second', 'first']);
    expect([...el.querySelectorAll('button')].some((b) => b.textContent?.includes('Older'))).toBe(
      false,
    );
  });

  it("shows an entry's fields when opened", async () => {
    const { el, fixture } = await render([
      {
        entries: [entry(1e15, 'upgrade', { fields: { F_STEP: 'staged', F_DETAIL: 'sha256:x' } })],
        older: null,
        units,
      },
    ]);
    expect(el.querySelector('.fields')).toBeNull();
    (el.querySelector('.line') as HTMLButtonElement).click();
    fixture.detectChanges();
    const f = el.querySelector('.fields')!.textContent!;
    expect(f).toContain('F_STEP');
    expect(f).toContain('staged');
    expect(f).toContain('sparewalld');
  });

  it('follows new entries at the top, with the same filters', async () => {
    const { el, fixture, stream, streams, settle } = await render([
      { entries: [entry(1e15, 'old')], older: null, units },
    ]);
    const toggle = el.querySelector('mat-slide-toggle button') as HTMLButtonElement;
    toggle.click();
    fixture.detectChanges();
    expect(streams[0]).toEqual({ units: null, priority: null, grep: null, node: null });
    stream.push({ entry: null });
    stream.push({ entry: entry(2e15, 'new') });
    await settle();
    expect([...el.querySelectorAll('.msg')].map((m) => m.textContent)).toEqual(['new', 'old']);
  });

  it('says what went wrong', async () => {
    const { el } = await render([
      new CallFailed(503, {
        error: 'org.sparewall.Firewall.ServiceUnavailable',
        message: 'journalctl: no journal',
        parameters: {},
      } as never),
    ]);
    expect(el.querySelector('[role=alert]')!.textContent).toContain('journalctl: no journal');
  });
});

describe('log helpers', () => {
  it('names priorities and marks the worse ones', () => {
    expect(priority(3)).toEqual({ name: 'err', level: 'problem' });
    expect(priority(4)).toEqual({ name: 'warning', level: 'warning' });
    expect(priority(6)).toEqual({ name: 'info', level: '' });
  });

  it('shortens unit names', () => {
    expect(shortUnit('sparewall-kea.service')).toBe('kea');
    expect(shortUnit('sparewalld.service')).toBe('sparewalld');
    expect(shortUnit('keepalived.service')).toBe('keepalived');
    expect(shortUnit('selinux')).toBe('selinux');
  });
});
