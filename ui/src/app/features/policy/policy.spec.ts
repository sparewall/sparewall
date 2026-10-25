import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { MatDialog } from '@angular/material/dialog';
import { Router, provideRouter } from '@angular/router';
import { Subject } from 'rxjs';

import openapi from '../../../../../docs/api/openapi.json';
import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import { ConfigChanges } from '../config/config-changes';
import { Config } from '../config/config';
import { PolicyMatrix } from './policy';

const doc = (gen: number) => ({
  config: {
    schema: 1,
    zones: { users: { networks: ['users'] }, wan: { networks: ['wan'] } },
    policy: { 'users->wan': { action: 'accept' } },
    note: gen,
  },
  generation: {
    id: gen,
    applied: '',
    author: '',
    confirmed: true,
    hash: '',
    schema: 1,
    summary: [],
  },
});

function setup() {
  const count = signal(0);
  const review = vi.fn();
  const closed = new Subject<unknown>();
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      { provide: NodeEvents, useValue: { count } },
      { provide: ConfigChanges, useValue: { review } },
      { provide: MatDialog, useValue: { open: () => ({ afterClosed: () => closed }) } },
      { provide: Session, useValue: { can: () => true } },
      // The editor links to its sections; navigating goes nowhere here.
      provideRouter([]),
    ],
  });
  vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
  const http = TestBed.inject(HttpTestingController);
  const serve = (gen: number) => {
    http.match('/openapi.json').forEach((r) => r.flush(openapi));
    http.match('/call/org.sparewall.Firewall.GetConfig').forEach((r) => r.flush(doc(gen)));
  };
  return { count, review, closed, http, serve };
}

describe('PolicyMatrix', () => {
  it('applies a dialog edit on the generation it was made from', async () => {
    const t = setup();
    const fixture = TestBed.createComponent(PolicyMatrix);
    // Issue the page's requests, then answer them.
    TestBed.tick();
    t.serve(1);
    await fixture.whenStable();
    const page = fixture.componentInstance as unknown as {
      open(c: unknown): Promise<void>;
      rows(): { key: string }[][];
      review(): Promise<void>;
    };
    const cell = page.rows()[1][0]; // wan->users, no policy yet
    const editing = page.open(cell);

    // An event while the dialog is open does not reload under it.
    t.count.set(1);
    TestBed.tick();
    expect(t.http.match('/call/org.sparewall.Firewall.GetConfig')).toEqual([]);

    t.closed.next({ policy: { action: 'reject' } });
    t.closed.complete();
    await editing;
    t.review.mockResolvedValue({ applied: false, problems: [] });
    await page.review();
    const [draft, base] = t.review.mock.calls[0];
    expect(base).toBe(1);
    expect(draft.policy['wan->users']).toEqual({ action: 'reject' });
    expect(draft.policy['users->wan']).toEqual({ action: 'accept' });
  });
});

describe('PolicyMatrix, when the configuration changes under the dialog', () => {
  it('still names the old generation, so the node refuses the stale edit', async () => {
    const t = setup();
    const fixture = TestBed.createComponent(PolicyMatrix);
    TestBed.tick();
    t.serve(1);
    await fixture.whenStable();
    const page = fixture.componentInstance as unknown as {
      open(c: unknown): Promise<void>;
      rows(): { key: string }[][];
      review(): Promise<void>;
      current: { reload(): void };
    };
    const editing = page.open(page.rows()[1][0]);
    // A reload already under way when the dialog opened: generation 2.
    page.current.reload();
    TestBed.tick();
    t.serve(2);
    await fixture.whenStable();

    t.closed.next({ policy: { action: 'reject' } });
    t.closed.complete();
    await editing;
    t.review.mockResolvedValue({ applied: false, problems: [] });
    await page.review();
    const [draft, base] = t.review.mock.calls[0];
    expect(base).toBe(1);
    expect(draft.note).toBe(1);
  });
});

describe('leaving the editor', () => {
  it('stays guarded through the review, until the apply starts', async () => {
    const t = setup();
    const fixture = TestBed.createComponent(Config);
    // Issue the page's requests, then answer them.
    TestBed.tick();
    t.serve(1);
    await fixture.whenStable();
    const page = fixture.componentInstance as unknown as {
      edited(d: unknown): void;
      review(): Promise<void>;
      hasUnappliedChanges(): boolean;
    };
    page.edited({ ...doc(1).config, note: 2 });
    expect(page.hasUnappliedChanges()).toBe(true);

    let applying!: () => void;
    let finish!: (o: unknown) => void;
    t.review.mockImplementation((_d: unknown, _b: number, onApplying: () => void) => {
      applying = onApplying;
      return new Promise((r) => (finish = r));
    });
    const reviewing = page.review();
    // The dry run and the review dialog are under way: still guarded.
    expect(page.hasUnappliedChanges()).toBe(true);
    applying();
    expect(page.hasUnappliedChanges()).toBe(false);
    finish({ applied: false, problems: ['refused'] });
    await reviewing;
    // Refused: the edits are still there, and guarded again.
    expect(page.hasUnappliedChanges()).toBe(true);
  });
});
