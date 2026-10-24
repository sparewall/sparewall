import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { Session } from './session';

export const signedIn: CanActivateFn = () =>
  inject(Session).can('viewer') || inject(Router).createUrlTree(['/login']);
