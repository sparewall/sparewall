import { TestBed } from '@angular/core/testing';

import { ApiClient } from '../../api/api-client';
import { PasswordCheck } from './password-check';

describe('PasswordCheck', () => {
  async function check(reply: unknown) {
    const calls: unknown[] = [];
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [PasswordCheck],
      providers: [
        {
          provide: ApiClient,
          useValue: {
            call: async (m: string, p: unknown) => {
              calls.push([m, p]);
              return reply;
            },
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(PasswordCheck);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const input = el.querySelector('input')!;
    input.value = 'correct horse';
    input.dispatchEvent(new Event('input'));
    await fixture.whenStable();
    el.querySelector('form')!.dispatchEvent(new Event('submit'));
    await fixture.whenStable();
    fixture.detectChanges();
    return { el, calls };
  }

  it('checks against the stored password and the newest bundle', async () => {
    const { el, calls } = await check({
      matches_stored: true,
      bundle: 'sparewall-fw1-20261127.tar',
      opens_bundle: true,
      secrets: ['s3', 'cf'],
      notes: [],
    });
    expect(calls).toEqual([
      ['org.sparewall.Secrets.CheckBackupPassword', { password: 'correct horse' }],
    ]);
    expect(el.textContent).toContain('It is the stored backup password.');
    expect(el.textContent).toContain('It opens the secrets in sparewall-fw1-20261127.tar: s3, cf.');
  });

  it('says what it could not check', async () => {
    const { el } = await check({
      matches_stored: false,
      bundle: null,
      opens_bundle: null,
      secrets: [],
      notes: ['No backup yet.'],
    });
    expect(el.textContent).toContain('It is not the stored backup password.');
    expect(el.textContent).toContain('No backup yet.');
  });
});
