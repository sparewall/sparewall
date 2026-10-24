import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot, UrlTree } from '@angular/router';

import { adminOnly } from './admin-only';
import { Session } from './session';

describe('adminOnly', () => {
  function run(admin: boolean) {
    TestBed.configureTestingModule({
      providers: [{ provide: Session, useValue: { can: () => admin } }],
    });
    return TestBed.runInInjectionContext(() =>
      adminOnly({} as ActivatedRouteSnapshot, {} as RouterStateSnapshot),
    );
  }

  it('lets an admin in', () => {
    expect(run(true)).toBe(true);
  });

  it('sends anyone else to the status page', () => {
    const r = run(false) as UrlTree;
    expect(TestBed.inject(Router).serializeUrl(r)).toBe('/status');
  });
});
