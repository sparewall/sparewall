import { TestBed } from '@angular/core/testing';
import { MAT_DIALOG_DATA } from '@angular/material/dialog';
import { provideNoopAnimations } from '@angular/platform-browser/animations';

import { ApiClient } from '../../api/api-client';
import { peerRows } from './vpn';
import { VpnConfig, VpnConfigData, qrSvg } from './vpn-config';

const CONF =
  '[Interface]\nPrivateKey = aaaa\nAddress = 10.99.0.10/32\n\n[Peer]\nPublicKey = bbbb\nEndpoint = vpn.example.org:51820\n';

describe('peerRows', () => {
  it('lists each instance’s peers, with its ports, site-to-site by endpoint', () => {
    expect(
      peerRows({
        ra: {
          listen_port: 51820,
          extra_ports: [53, 443],
          peers: {
            alice: { addresses: ['10.99.0.10/32'] },
            branch: { addresses: ['10.98.0.2/30'], endpoint: '198.51.100.9:51821' },
          },
        },
      }),
    ).toEqual([
      {
        instance: 'ra',
        peer: 'alice',
        addresses: '10.99.0.10/32',
        site: false,
        ports: [51820, 53, 443],
      },
      {
        instance: 'ra',
        peer: 'branch',
        addresses: '10.98.0.2/30',
        site: true,
        ports: [51820, 53, 443],
      },
    ]);
    expect(peerRows(undefined)).toEqual([]);
  });
});

describe('VpnConfig (#310)', () => {
  async function render(data: VpnConfigData) {
    const calls: unknown[] = [];
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [VpnConfig],
      providers: [
        provideNoopAnimations(),
        { provide: MAT_DIALOG_DATA, useValue: data },
        {
          provide: ApiClient,
          useValue: {
            call: async (m: string, p: unknown) => (calls.push([m, p]), { config: CONF }),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(VpnConfig);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const show = async () => {
      [...el.querySelectorAll('button')]
        .find((b) => b.textContent?.includes('Show the configuration'))!
        .click();
      await fixture.whenStable();
      fixture.detectChanges();
    };
    return { fixture, el, calls, show };
  }

  const alice: VpnConfigData = { instance: 'ra', peer: 'alice', ports: [51820, 53], site: false };

  it('reads nothing until asked, and says what it carries', async () => {
    const { el, calls } = await render(alice);
    expect(calls).toEqual([]);
    expect(el.textContent).toContain('carries its private key and preshared key');
    expect(el.textContent).not.toContain('PrivateKey');
  });

  it('shows the node’s configuration, with a QR code of exactly it', async () => {
    const { el, calls, show } = await render(alice);
    await show();
    expect(calls).toEqual([
      ['org.sparewall.Firewall.VpnClientConfig', { instance: 'ra', peer: 'alice', port: null }],
    ]);
    expect(el.querySelector('pre')!.textContent).toBe(CONF);
    // The same SVG as the library draws for the text, as the DOM writes it.
    const want = document.createElement('div');
    want.innerHTML = qrSvg(CONF);
    expect(el.querySelector('.qr')!.innerHTML).toBe(want.innerHTML);
    expect(el.textContent).toContain('ra-alice.conf');
  });

  it('asks for another port when one is chosen', async () => {
    const { fixture, calls, show } = await render(alice);
    (fixture.componentInstance as unknown as { port: number }).port = 53;
    await show();
    expect(calls).toEqual([
      ['org.sparewall.Firewall.VpnClientConfig', { instance: 'ra', peer: 'alice', port: 53 }],
    ]);
  });

  it('gives a site-to-site peer the other site’s configuration, without a QR code', async () => {
    const { el, show } = await render({
      instance: 'branch',
      peer: 'office',
      ports: [51821],
      site: true,
    });
    expect(el.textContent).toContain('The other site’s configuration');
    await show();
    expect(el.querySelector('.qr')).toBeNull();
    expect(el.querySelector('pre')!.textContent).toBe(CONF);
  });
});

describe('qrSvg', () => {
  it('draws a deterministic SVG holding no text of the configuration', () => {
    const svg = qrSvg(CONF);
    expect(svg).toBe(qrSvg(CONF));
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).not.toContain('aaaa');
  });
});
