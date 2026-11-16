import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { MetricsHistory, SPECS, noHistory, si, toSeries } from './history';

const URL = '/call/org.sparewall.Metrics.QueryRange';

const matrix = (rows: { metric: Record<string, string>; values: [number, string][] }[]) => ({
  result: rows,
  result_type: 'matrix',
  warnings: [],
});

async function render() {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting()],
  });
  const fixture = TestBed.createComponent(MetricsHistory);
  TestBed.tick();
  const http = TestBed.inject(HttpTestingController);
  return { fixture, http, el: fixture.nativeElement as HTMLElement };
}

describe('MetricsHistory', () => {
  it('draws the charts from QueryRange, a step that keeps a window small', async () => {
    const { fixture, http, el } = await render();
    const reqs = http.match(URL);
    expect(reqs.length).toBe(SPECS.length);
    const body = reqs[0].request.body as {
      query: string;
      start: string;
      end: string;
      step: string;
    };
    expect(Number(body.end) - Number(body.start)).toBe(3600);
    expect(body.step).toBe('30');
    expect(body.query).toContain('node_network_receive_bytes_total[60s]');
    for (const r of reqs) {
      const q = (r.request.body as { query: string }).query;
      if (q.includes('receive')) {
        r.flush(
          matrix([
            { metric: { device: 'wan0' }, values: [[1000, '8000']] },
            { metric: { device: 'lan0' }, values: [[1000, '1500000']] },
          ]),
        );
      } else {
        r.flush(matrix([]));
      }
    }
    await fixture.whenStable();
    fixture.detectChanges();
    const traffic = el.querySelector('[data-testid=chart-in]')!;
    expect(traffic.querySelectorAll('path').length).toBe(2);
    expect(traffic.querySelector('.legend')!.textContent).toContain('lan0');
    expect(traffic.textContent).toContain('1.5 Mbit/s');
    // Rule hits only when there are any.
    expect(el.querySelector('[data-testid=chart-rules]')).toBeNull();
    expect(el.querySelector('[data-testid=no-history]')).toBeNull();
  });

  it('asks for a longer window with a longer step', async () => {
    const { fixture, http, el } = await render();
    http.match(URL).forEach((r) => r.flush(matrix([])));
    await fixture.whenStable();
    fixture.detectChanges();
    const buttons = el.querySelectorAll('mat-button-toggle button');
    (buttons[2] as HTMLButtonElement).click();
    fixture.detectChanges();
    TestBed.tick();
    const reqs = http.match(URL);
    expect(reqs.length).toBe(SPECS.length);
    const body = reqs[0].request.body as { start: string; end: string; step: string };
    expect(Number(body.end) - Number(body.start)).toBe(7 * 86400);
    expect(body.step).toBe('3600');
  });

  it('says history needs metrics.mode: local, not an error, without it', async () => {
    const { fixture, http, el } = await render();
    for (const r of http.match(URL)) {
      r.flush(
        {
          error: 'org.sparewall.Firewall.NotSupported',
          parameters: { message: 'this node keeps no history: metrics.mode is not local' },
          message: 'this node keeps no history: metrics.mode is not local',
        },
        { status: 400, statusText: 'Bad Request' },
      );
    }
    await fixture.whenStable();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid=no-history]')!.textContent).toContain(
      'metrics.mode: local',
    );
    expect(el.querySelector('[role=alert]')).toBeNull();
    expect(el.querySelector('mat-button-toggle-group')).toBeNull();
  });

  it('says what went wrong when the history cannot be read', async () => {
    const { fixture, http, el } = await render();
    for (const r of http.match(URL)) {
      r.flush(
        {
          error: 'org.sparewall.Firewall.ServiceUnavailable',
          message: 'prometheus is not answering',
        },
        { status: 503, statusText: 'Service Unavailable' },
      );
    }
    await fixture.whenStable();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid=chart-in] [role=alert]')!.textContent).toContain(
      'prometheus is not answering',
    );
  });
});

describe('history helpers', () => {
  it('writes rates with SI prefixes', () => {
    expect(si(0, 'bit/s')).toBe('0 bit/s');
    expect(si(100, 'bit/s')).toBe('100 bit/s');
    expect(si(1500000, 'bit/s')).toBe('1.5 Mbit/s');
    expect(si(2.5, 'pkt/s')).toBe('2.5 pkt/s');
  });

  it('keeps the busiest series and folds the rest into Other, by name', () => {
    const rows = Array.from({ length: 10 }, (_, i) => ({
      metric: { device: `if${i}` },
      values: [
        [0, String(i)],
        [60, String(i)],
      ] as [number, string][],
    }));
    const s = toSeries(rows, (l) => l['device']);
    expect(s.length).toBe(8);
    expect(s.map((x) => x.name)).toEqual([
      'if3',
      'if4',
      'if5',
      'if6',
      'if7',
      'if8',
      'if9',
      'Other',
    ]);
    expect(s[7].points).toEqual([
      [0, 3],
      [60, 3],
    ]);
  });

  it('names a rule by its zone pair and name', () => {
    const rules = SPECS.find((s) => s.id === 'rules')!;
    expect(rules.name({ rule: 'rule:wan->lan:https' })).toBe('wan->lan: https');
  });

  it('tells no history from other failures', () => {
    expect(noHistory(new Error('x'))).toBe(false);
  });
});
