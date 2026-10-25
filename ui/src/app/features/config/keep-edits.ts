import { inject } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { CanDeactivateFn } from '@angular/router';
import { map } from 'rxjs';

import { ConfirmData, ConfirmDialog } from '../../shared/confirm-dialog';

/** A page that may hold edits not yet applied. */
export interface HoldsEdits {
  hasUnappliedChanges(): boolean;
}

/** A URL's page: its first path segment (`config` for `/config/dhcp?find=x`). */
const page = (url: string) => url.split(/[?#]/)[0].split('/').filter(Boolean)[0] ?? '';

/**
 * Asks before leaving such a page with its edits. Moving within it (the
 * editor's sections, which keep the page and its draft) is not leaving.
 */
export const keepEdits: CanDeactivateFn<HoldsEdits> = (editor, _route, current, next) => {
  if (!editor.hasUnappliedChanges()) return true;
  if (next && page(next.url) === page(current.url)) return true;
  return inject(MatDialog)
    .open<ConfirmDialog, ConfirmData, boolean>(ConfirmDialog, {
      data: {
        title: 'Leave without applying?',
        text: 'Your changes to the configuration have not been applied, and leaving drops them.',
        action: 'Leave',
      },
    })
    .afterClosed()
    .pipe(map((leave) => leave === true));
};
