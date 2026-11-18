import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';

import { ApiClient, CallFailed } from '../../api/api-client';
import { CapturePanel, decode } from './capture-panel';

function b64(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes));
}

async function render(replies: unknown[] | Error) {
  const calls: { method: string; params: unknown }[] = [];
  const api = {
    stream: (method: string, params: unknown) => {
      calls.push({ method, params });
      return (async function* () {
        if (replies instanceof Error) throw replies;
        for (const r of replies) yield r;
      })();
    },
  };
  TestBed.configureTestingModule({
    providers: [provideNoopAnimations(), { provide: ApiClient, useValue: api }],
  });
  const fixture = TestBed.createComponent(CapturePanel);
  fixture.componentRef.setInput('networks', ['lan', 'wan']);
  fixture.detectChanges();
  const panel = fixture.componentInstance as unknown as {
    network: string;
    filter: string;
    seconds: number;
    maxSize: number;
    start: () => Promise<void>;
    pcap: () => { url: string; name: string } | null;
  };
  const el = fixture.nativeElement as HTMLElement;
  return { fixture, panel, el, calls };
}

describe('CapturePanel', () => {
  let made: Blob[];
  beforeEach(() => {
    made = [];
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => {
      made.push(b as Blob);
      return 'blob:capture';
    });
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
  });

  it('decodes base64', () => {
    expect([...decode(b64([0xd4, 0xc3, 0xb2, 0xa1, 0]))]).toEqual([0xd4, 0xc3, 0xb2, 0xa1, 0]);
  });

  it('captures on a network and offers the pcap, joined in order, when it ends', async () => {
    const { fixture, panel, el, calls } = await render([
      { data: b64([1, 2, 3]), bytes: 3, packets: 0, end: null },
      { data: b64([4, 5]), bytes: 5, packets: 1, end: null },
      { data: '', bytes: 5, packets: 1, end: 'time' },
    ]);
    panel.network = 'lan';
    panel.filter = '  icmp ';
    panel.seconds = 10;
    await panel.start();
    fixture.detectChanges();
    expect(calls[0]).toEqual({
      method: 'org.sparewall.Diagnostics.Capture',
      params: { network: 'lan', filter: 'icmp', seconds: 10, max_size: 8 << 20, node: null },
    });
    expect(el.querySelector('[data-testid=progress]')!.textContent).toContain(
      '1 packets, 5 bytes: it reached its time limit',
    );
    expect([...new Uint8Array(await made[0].arrayBuffer())]).toEqual([1, 2, 3, 4, 5]);
    expect(made[0].type).toBe('application/vnd.tcpdump.pcap');
    const link = el.querySelector('[data-testid=download]') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('blob:capture');
    expect(link.getAttribute('download')).toMatch(/^capture-lan-\d{8}-\d{6}\.pcap$/);
  });

  it('captures on the peer, through this node, and names the file for it', async () => {
    const { fixture, panel, calls } = await render([
      { data: b64([9]), bytes: 1, packets: 0, end: 'size' },
    ]);
    fixture.componentRef.setInput('node', 'fw2');
    panel.network = 'wan';
    panel.filter = '';
    await panel.start();
    expect((calls[0].params as { node: string; filter: unknown }).node).toBe('fw2');
    expect((calls[0].params as { filter: unknown }).filter).toBeNull();
    expect(panel.pcap()!.name).toMatch(/^capture-fw2-wan-/);
  });

  it('shows a refusal, and offers nothing', async () => {
    const { fixture, panel, el } = await render(
      new CallFailed(503, {
        error: 'org.sparewall.Firewall.ServiceUnavailable',
        message: 'capture: a capture runs on fw1 already: one at a time',
        parameters: {},
      } as never),
    );
    panel.network = 'lan';
    await panel.start();
    fixture.detectChanges();
    expect(el.querySelector('.problem')!.textContent).toContain('one at a time');
    expect(el.querySelector('[data-testid=download]')).toBeNull();
    expect(made).toEqual([]);
  });
});
