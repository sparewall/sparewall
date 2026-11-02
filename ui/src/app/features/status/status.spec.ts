import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Subject } from 'rxjs';

import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import { Status } from './status';

const reply = (update: unknown, sync: Record<string, unknown> = {}) => ({
  node: 'fw1',
  role: 'MASTER',
  sync: { active: 3, desired_hash: 'h', applied_hash: 'h', peer: null, ...sync },
  links: {},
  vrrp: {},
  conntrack: {},
  services: {},
  tls: {},
  health: { level: 'ok', checks: [] },
  update,
});

async function render(r: object, role = 'admin') {
  const count = signal(0);
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      {
        provide: NodeEvents,
        useValue: { count, events$: new Subject(), connected: signal(true) },
      },
      {
        provide: Session,
        useValue: {
          can: (w: string) =>
            w === 'viewer' || (w === 'operator' && role !== 'viewer') || role === 'admin',
        },
      },
    ],
  });
  const fixture = TestBed.createComponent(Status);
  TestBed.tick();
  const http = TestBed.inject(HttpTestingController);
  http.expectOne('/call/org.sparewall.Firewall.Status').flush(r);
  await fixture.whenStable();
  fixture.detectChanges();
  const el = fixture.nativeElement as HTMLElement;
  return { card: el.querySelector('[data-testid=update]'), count, http, fixture, el };
}

describe('Status, updates', () => {
  it('shows nothing when nothing is offered', async () => {
    const { card } = await render(reply({ enabled: true, running: '0.4.0', available: 'none' }));
    expect(card).toBeNull();
  });

  it('names a newer version, its notes, and offers an admin the upgrade', async () => {
    const { card } = await render(
      reply({
        enabled: true,
        running: '0.4.0',
        available: 'newer',
        version: '0.4.1',
        checked: 't',
      }),
    );
    expect(card?.textContent).toContain('0.4.1 is available');
    expect(card?.textContent).toContain('Running 0.4.0');
    expect(card?.querySelector('button')?.textContent).toContain('Upgrade');
    expect(card?.querySelector('a')?.getAttribute('href')).toBe(
      'https://github.com/sparewall/sparewall/releases/tag/v0.4.1',
    );
  });

  it('tells other roles that an admin can upgrade', async () => {
    const { card } = await render(
      reply({ enabled: true, running: '0.4.0', available: 'newer', version: '0.4.1' }),
      'viewer',
    );
    expect(card?.textContent).toContain('0.4.1 is available');
    expect(card?.querySelector('button')).toBeNull();
    expect(card?.textContent).toContain('An admin can upgrade from here.');
  });

  it('names a rebuild as one', async () => {
    const { card } = await render(
      reply({ enabled: true, running: '0.4.0', available: 'rebuild', version: '0.4.0' }),
    );
    expect(card?.textContent).toContain('A rebuild of 0.4.0 is available');
    expect(card?.textContent).toContain('rebuilt with newer base packages');
  });

  it('reports a failing check without alarm', async () => {
    const { card, el } = await render(
      reply({ enabled: true, running: '0.4.0', available: 'none', error: 'no route to host' }),
    );
    expect(card?.textContent).toContain('The last update check failed: no route to host.');
    // Health stays as it is.
    expect(el.querySelector('.hero')?.className).toContain('ok');
  });

  it('says when a pair runs different images', async () => {
    const { card } = await render(
      reply(
        { enabled: true, running: '0.4.0', available: 'none' },
        {
          peer: 'fw2',
          peer_reachable: true,
          image: 'r@sha256:aaa',
          peer_image: 'r@sha256:bbb',
        },
      ),
    );
    expect(card?.textContent).toContain('This node and fw2 run different images.');
  });
});
