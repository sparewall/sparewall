import { TestBed } from '@angular/core/testing';

import { Series, TimeChart, niceCeil } from './time-chart';

function render(series: Series[], max?: number) {
  const f = TestBed.createComponent(TimeChart);
  f.componentRef.setInput('series', series);
  f.componentRef.setInput('start', 0);
  f.componentRef.setInput('end', 300);
  f.componentRef.setInput('step', 60);
  f.componentRef.setInput('format', (v: number) => `${v} u`);
  if (max !== undefined) f.componentRef.setInput('max', max);
  f.componentRef.setInput('label', 'Traffic');
  f.detectChanges();
  return { f, el: f.nativeElement as HTMLElement };
}

const a: Series = {
  name: 'lan0',
  points: [
    [0, 1],
    [60, 2],
    [120, 4],
  ],
};
const b: Series = {
  name: 'wan0',
  points: [
    [0, 3],
    [60, 1],
    // A gap: no point at 120 or 180.
    [240, 2],
  ],
};

describe('TimeChart', () => {
  it('rounds the axis up to 1, 2 or 5 times a power of ten', () => {
    expect(niceCeil(0)).toBe(1);
    expect(niceCeil(3.2)).toBe(5);
    expect(niceCeil(4)).toBe(5);
    expect(niceCeil(1200)).toBe(2000);
    expect(niceCeil(0.07)).toBeCloseTo(0.1);
  });

  it('draws a line per series, broken across a gap, in its slot colour', () => {
    const { el } = render([a, b]);
    const paths = el.querySelectorAll('path');
    expect(paths.length).toBe(2);
    expect(paths[0].getAttribute('style')).toContain('--sw-series-1');
    expect(paths[1].getAttribute('style')).toContain('--sw-series-2');
    // a: one run; b: two, the second after the gap.
    expect(paths[0].getAttribute('d')!.match(/M/g)!.length).toBe(1);
    expect(paths[1].getAttribute('d')!.match(/M/g)!.length).toBe(2);
    // The axis reaches 5 for a top value of 4: its labels say so.
    expect(el.querySelector('.axis-y')!.textContent).toContain('5 u');
  });

  it('names two series or more in a legend, and one in none', () => {
    expect(render([a, b]).el.querySelector('.legend')!.textContent).toContain('wan0');
    TestBed.resetTestingModule();
    expect(render([a]).el.querySelector('.legend')).toBeNull();
  });

  it('keeps an axis top it is given, such as 1 for a share', () => {
    const { el } = render([{ name: 'cpu', points: [[0, 0.2]] }], 1);
    expect(el.querySelector('.axis-y')!.textContent).toContain('1 u');
  });

  it('reads every series at a time from the keyboard', () => {
    const { f, el } = render([a, b]);
    const plot = el.querySelector('.plot') as HTMLElement;
    // The first key reads the latest time, 240 s, where a has none.
    plot.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft' }));
    f.detectChanges();
    expect(el.querySelector('.tip')!.textContent).toContain('2 u');
    expect(el.querySelector('.tip')!.textContent).toContain('–');
    // Then one point back: 120 s, where b has none.
    plot.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft' }));
    f.detectChanges();
    const tip = el.querySelector('.tip')!;
    expect(tip.textContent).toContain('4 u');
    expect(tip.textContent).toContain('–');
    expect(el.querySelector('.cross')).not.toBeNull();
  });

  it('holds the same values in a table', () => {
    const { el } = render([a, b]);
    const rows = el.querySelectorAll('tbody tr');
    expect(rows.length).toBe(4);
    expect(rows[3].textContent).toContain('2 u');
  });

  it('says so when the window holds nothing', () => {
    const { el } = render([]);
    expect(el.textContent).toContain('No data in this window.');
    expect(el.querySelector('details')).toBeNull();
  });
});
