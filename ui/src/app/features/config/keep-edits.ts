import { inject } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { CanDeactivateFn } from '@angular/router';
import { map } from 'rxjs';

import { ConfirmData, ConfirmDialog } from '../../shared/confirm-dialog';
import type { Config } from './config';

/** Asks before leaving the editor with changes not yet applied. */
export const keepEdits: CanDeactivateFn<Config> = (editor) => {
  if (!editor.hasUnappliedChanges()) return true;
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
