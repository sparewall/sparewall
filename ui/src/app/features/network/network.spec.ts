import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';

import { ApiClient } from '../../api/api-client';
import { Neighbour, Network, Route } from './network';

const neighbour = (
  address: string,
  state: string[],
  network: string | null = 'lan',
): Neighbour => ({
  address,
  family: '4',
  iface: 'lan0',
  network,
  mac: '52:54:00:00:00:10',
  state,
  router: false,
});

const route = (destination: string, more: Partial<Route> = {}): Route => ({
  destination,
  family: '4',
  table: 'main',
  kind: 'unicast',
  gateway: null,
  iface: 'wan0',
  network: 'wan',
  source: null,
  protocol: 'kernel',
  metric: null,
  expires: null,
  flags: [],
  ...more,
});

async function render(replies: Record<string, unknown[]>) {
  const calls: { method: string; params: Record<string, unknown> }[] = [];
  const api = {
    call: async (method: string, params: Record<string, unknown>) => {
      calls.push({ method, params });
      return replies[method].shift();
    },
  };
  TestBed.configureTestingModule({
    providers: [provideNoopAnimations(), { provide: ApiClient, useValue: api }],
  });
  const fixture = TestBed.createComponent(Network);
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
  return { fixture, el: fixture.nativeElement as HTMLElement, calls };
}

describe('Network', () => {
  it('lists the neighbours, a failed one marked, and the networks to filter by', async () => {
    const { el, calls, fixture } = await render({
      'org.sparewall.Diagnostics.Neighbours': [
        {
          neighbours: [
            neighbour('192.168.1.10', ['REACHABLE']),
            neighbour('203.0.113.1', ['FAILED'], 'wan'),
          ],
          cut: false,
        },
      ],
      'org.sparewall.Diagnostics.Routes': [{ routes: [route('default')], cut: false }],
    });
    expect(calls.map((c) => c.params)).toEqual([{ network: null }, { network: null }]);
    const rows = el.querySelectorAll('[data-testid=neighbours] tbody tr');
    expect(rows.length).toBe(2);
    expect(rows[1].classList).toContain('bad');
    expect(rows[0].classList).not.toContain('bad');
    expect(
      (fixture.componentInstance as unknown as { networks: () => string[] }).networks(),
    ).toEqual(['lan', 'wan']);
  });

  it("describes a route's kind, flags, source and expiry", async () => {
    const { fixture } = await render({
      'org.sparewall.Diagnostics.Neighbours': [{ neighbours: [], cut: false }],
      'org.sparewall.Diagnostics.Routes': [{ routes: [], cut: false }],
    });
    const notes = (fixture.componentInstance as unknown as { notes: (r: Route) => string }).notes;
    expect(
      notes(
        route('10.0.0.0/8', {
          kind: 'unreachable',
          flags: ['linkdown'],
          source: '10.0.0.1',
          expires: 60,
        }),
      ),
    ).toBe('unreachable, linkdown, from 10.0.0.1, expires in 60s');
    expect(notes(route('default'))).toBe('');
  });
});
