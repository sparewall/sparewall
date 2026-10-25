import { TestBed } from '@angular/core/testing';
import { MatDialog } from '@angular/material/dialog';
import { ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { of } from 'rxjs';

import { keepEdits } from './keep-edits';

describe('keepEdits', () => {
  const open = vi.fn(() => ({ afterClosed: () => of(false) }));
  const editor = { hasUnappliedChanges: () => true };
  const at = (url: string) => ({ url }) as RouterStateSnapshot;
  const leave = (from: string, to: string) =>
    TestBed.runInInjectionContext(() =>
      keepEdits(editor, {} as ActivatedRouteSnapshot, at(from), at(to)),
    );

  beforeEach(() => {
    open.mockClear();
    TestBed.configureTestingModule({ providers: [{ provide: MatDialog, useValue: { open } }] });
  });

  it('lets the editor move between its sections with its edits', () => {
    expect(leave('/config/dhcp', '/config/dns')).toBe(true);
    expect(leave('/config/dhcp', '/config/cluster?find=conntrack.buckets')).toBe(true);
    expect(open).not.toHaveBeenCalled();
  });

  it('asks before leaving the page with them', () => {
    leave('/config/dhcp', '/status');
    expect(open).toHaveBeenCalledOnce();
  });
});
