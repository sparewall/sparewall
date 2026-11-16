import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';

import { ApiClient, CallFailed } from '../../api/api-client';
import { ToolsPanel } from './tools-panel';

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
  const fixture = TestBed.createComponent(ToolsPanel);
  fixture.componentRef.setInput('networks', ['lan', 'wan']);
  fixture.detectChanges();
  const panel = fixture.componentInstance as unknown as {
    tool: string;
    target: string;
    from: string;
    record: string;
    server: string;
    run: () => Promise<void>;
  };
  const el = fixture.nativeElement as HTMLElement;
  return { fixture, panel, el, calls };
}

describe('ToolsPanel', () => {
  it('pings from a network and shows the output as it comes', async () => {
    const { fixture, panel, el, calls } = await render([
      { lines: ['PING 192.168.1.10'], exit: null },
      { lines: ['2 packets transmitted, 2 received'], exit: null },
      { lines: [], exit: 0 },
    ]);
    panel.target = '192.168.1.10';
    panel.from = 'lan';
    await panel.run();
    fixture.detectChanges();
    expect(calls[0]).toEqual({
      method: 'org.sparewall.Diagnostics.Ping',
      params: { host: '192.168.1.10', network: 'lan', count: 4 },
    });
    expect(el.querySelector('[data-testid=output]')!.textContent).toBe(
      'PING 192.168.1.10\n2 packets transmitted, 2 received',
    );
    expect(el.querySelector('.exit')).toBeNull();
  });

  it('looks a name up through a server, and says when a tool fails', async () => {
    const { fixture, panel, el, calls } = await render([{ lines: [';; no servers'], exit: 9 }]);
    panel.tool = 'lookup';
    panel.target = 'nas.home.arpa';
    panel.record = 'AAAA';
    panel.server = '192.168.1.1';
    await panel.run();
    fixture.detectChanges();
    expect(calls[0]).toEqual({
      method: 'org.sparewall.Diagnostics.Lookup',
      params: { name: 'nas.home.arpa', record: 'AAAA', server: '192.168.1.1' },
    });
    expect(el.querySelector('.exit')!.textContent).toContain('status 9');
  });

  it('traceroutes by the routes, and shows a refusal', async () => {
    const { fixture, panel, el, calls } = await render(
      new CallFailed(422, {
        error: 'org.sparewall.Firewall.ValidationFailed',
        message: 'host: "x;y" is not an address or a host name',
        parameters: {},
      } as never),
    );
    panel.tool = 'traceroute';
    panel.target = 'x;y';
    await panel.run();
    fixture.detectChanges();
    expect(calls[0]).toEqual({
      method: 'org.sparewall.Diagnostics.Traceroute',
      params: { host: 'x;y', network: null },
    });
    expect(el.querySelector('[role=alert]')!.textContent).toContain('not an address');
  });
});
