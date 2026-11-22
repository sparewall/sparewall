import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';

import openapi from '../../../../../docs/api/openapi.json';
import { CallFailed, callUrl } from '../../api/api-client';
import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import { Config, sectionOf } from './config';
import { ConfigChanges, Outcome, issues } from './config-changes';

const doc = {
  networks: {
    users: { port: 'uplink', role: 'inside', vlan: 20, mtu: 1500 },
    guests: { port: 'uplink', role: 'inside', vlan: 30 },
  },
};

async function render(outcome: Outcome) {
  const review = vi.fn().mockResolvedValue(outcome);
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      provideNoopAnimations(),
      provideRouter([]),
      { provide: ConfigChanges, useValue: { review } },
      { provide: NodeEvents, useValue: { count: signal(0) } },
      { provide: Session, useValue: { can: () => true } },
    ],
  });
  const fixture = TestBed.createComponent(Config);
  fixture.componentRef.setInput('section', 'networks');
  TestBed.tick();
  const http = TestBed.inject(HttpTestingController);
  http.expectOne('/openapi.json').flush(openapi);
  http
    .expectOne(callUrl('org.sparewall.Firewall.GetConfig'))
    .flush({ generation: { id: 1 }, config: structuredClone(doc) });
  await fixture.whenStable();
  fixture.detectChanges();
  const page = fixture.componentInstance as unknown as {
    edited(d: unknown): void;
    review(): Promise<void>;
  };
  // An edit the node will refuse, then its review.
  const edited = structuredClone(doc);
  edited.networks.users.mtu = 100;
  page.edited(edited);
  await page.review();
  await fixture.whenStable();
  fixture.detectChanges();
  return { el: fixture.nativeElement as HTMLElement, review };
}

describe('Config', () => {
  it('marks a refused field, its entry and its section, and lists every reason (#305)', async () => {
    const { el, review } = await render({
      applied: false,
      problems: ['networks.users.mtu: must be 576-9216', 'dry run: nft says no'],
      issues: [{ pointer: '/networks/users/mtu', message: 'must be 576-9216' }],
    });
    expect(review).toHaveBeenCalledOnce();
    // Every reason in the list above the form, with or without a field.
    expect([...el.querySelectorAll('ul.problems li')].map((l) => l.textContent?.trim())).toEqual([
      'networks.users.mtu: must be 576-9216',
      'dry run: nft says no',
    ]);
    // The section in the list.
    expect(el.querySelector('nav [data-section=networks] .flagged')).not.toBeNull();
    expect(el.querySelector('nav [data-section=zones] .flagged')).toBeNull();
    // The entry, marked and opened; the other one neither.
    const users = el.querySelector('[data-entry=users]')!;
    expect(users.querySelector('.faulty')).not.toBeNull();
    expect(users.classList).toContain('mat-expanded');
    const guests = el.querySelector('[data-entry=guests]')!;
    expect(guests.querySelector('.faulty')).toBeNull();
    expect(guests.classList).not.toContain('mat-expanded');
    // The field itself.
    expect(users.textContent).toContain('must be 576-9216');
  });

  it('marks nothing for reasons with no place in the document', async () => {
    const { el } = await render({ applied: false, problems: ['dry run: nft says no'], issues: [] });
    expect(el.querySelectorAll('ul.problems li').length).toBe(1);
    expect(el.querySelector('nav .flagged')).toBeNull();
    expect(el.querySelector('.faulty')).toBeNull();
  });
});

describe('refusals', () => {
  const refused = (parameters: Record<string, unknown>) =>
    new CallFailed(422, {
      error: 'org.sparewall.Firewall.ValidationFailed',
      parameters,
    } as never);

  it('keep the reasons that have a place in the document', () => {
    expect(
      issues(
        refused({
          errors: ['networks.users.mtu: must be 576-9216', 'dry run: no'],
          issues: [
            {
              path: 'networks.users.mtu',
              pointer: '/networks/users/mtu',
              message: 'must be 576-9216',
            },
            { path: null, pointer: null, message: 'dry run: no' },
          ],
        }),
      ),
    ).toEqual([{ pointer: '/networks/users/mtu', message: 'must be 576-9216' }]);
  });

  it('have none from a node before 0.8.0', () => {
    expect(issues(refused({ errors: ['networks.users.mtu: must be 576-9216'] }))).toEqual([]);
    expect(issues(new Error('offline'))).toEqual([]);
  });

  it('name their section', () => {
    expect(sectionOf('/networks/users/mtu')).toBe('networks');
    expect(sectionOf('/policy/users->wan/rules/web')).toBe('policy');
  });
});
