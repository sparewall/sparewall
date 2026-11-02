import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';

import openapi from '../../../../../docs/api/openapi.json';
import { Role, Session } from '../../core/session';
import { Api } from './api';

const RANK: Record<Role, number> = { monitor: 0, viewer: 1, operator: 2, admin: 3 };

async function render(role: Role) {
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      provideNoopAnimations(),
      provideRouter([]),
      { provide: Session, useValue: { can: (need: Role) => RANK[role] >= RANK[need] } },
    ],
  });
  const fixture = TestBed.createComponent(Api);
  TestBed.tick();
  TestBed.inject(HttpTestingController).expectOne('/openapi.json').flush(openapi);
  await fixture.whenStable();
  fixture.detectChanges();
  const el = fixture.nativeElement as HTMLElement;
  const panel = (m: string) => el.querySelector(`[data-method="org.sparewall.${m}"]`);
  return { el, panel };
}

describe('Api page', () => {
  it('lists every call, grouped by interface', async () => {
    const { el } = await render('viewer');
    const calls = Object.keys(openapi.paths).filter((p) => p.startsWith('/call/'));
    expect(el.querySelectorAll('[data-method]').length).toBe(calls.length);
    const groups = [...el.querySelectorAll('h2')].map((h) => h.textContent?.trim());
    expect(groups).toContain('org.sparewall.Firewall');
    expect(groups).toContain('org.sparewall.Auth');
  });

  it('greys out what the role cannot call', async () => {
    const { panel } = await render('viewer');
    expect(panel('Firewall.Status')?.classList).not.toContain('unavailable');
    expect(panel('Firewall.Apply')?.classList).toContain('unavailable');
    expect(panel('Auth.CreateToken')?.classList).toContain('unavailable');
    expect(panel('Auth.Login')?.classList).not.toContain('unavailable');
    expect(panel('Firewall.Apply')?.textContent).toContain('operator');
    TestBed.resetTestingModule();
    const admin = await render('admin');
    expect(admin.el.querySelectorAll('.unavailable').length).toBe(0);
  });

  it('links to a token only for admins, and to the description for everyone', async () => {
    const viewer = await render('viewer');
    expect(viewer.el.querySelector('a[href="/tokens"]')).toBeNull();
    expect(viewer.el.querySelector('a[href="/openapi.json"]')).not.toBeNull();
    TestBed.resetTestingModule();
    const admin = await render('admin');
    expect(admin.el.querySelector('a[href="/tokens"]')).not.toBeNull();
  });

  it('shows a curl example for the node itself, and marks streaming calls', async () => {
    const { panel } = await render('admin');
    const sub = panel('Firewall.Subscribe');
    expect(sub?.textContent).toContain('streams');
    expect(sub?.querySelector('pre')?.textContent).toContain(
      `${location.origin}/call/org.sparewall.Firewall.Subscribe?more=true`,
    );
    expect(panel('Firewall.Status')?.querySelector('pre')?.textContent).toContain(
      'Authorization: Bearer $SPAREWALL_TOKEN',
    );
  });
});
