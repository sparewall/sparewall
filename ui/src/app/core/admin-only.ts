import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { Session } from './session';

/** Pages only an admin can use; the node refuses everyone else anyway. */
export const adminOnly: CanActivateFn = () =>
  inject(Session).can('admin') || inject(Router).createUrlTree(['/status']);
