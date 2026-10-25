import { Routes } from '@angular/router';

import { adminOnly } from './core/admin-only';
import { signedIn } from './core/signed-in';
import { keepEdits } from './features/config/keep-edits';
import { Shell } from './features/shell/shell';

export const routes: Routes = [
  {
    path: 'login',
    title: 'Sign in · Sparewall',
    loadComponent: () => import('./features/login/login').then((m) => m.Login),
  },
  {
    path: '',
    component: Shell,
    canActivate: [signedIn],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'status' },
      {
        path: 'status',
        title: 'Status · Sparewall',
        loadComponent: () => import('./features/status/status').then((m) => m.Status),
      },
      // The first section in the editor's list.
      { path: 'config', pathMatch: 'full', redirectTo: 'config/ports' },
      {
        // One route for every section, so moving between them keeps the
        // page and its draft; leaving for another page is guarded.
        path: 'config/:section',
        title: 'Configuration · Sparewall',
        loadComponent: () => import('./features/config/config').then((m) => m.Config),
        canDeactivate: [keepEdits],
      },
      {
        path: 'policy',
        title: 'Zone policy · Sparewall',
        loadComponent: () => import('./features/policy/policy').then((m) => m.PolicyMatrix),
        canDeactivate: [keepEdits],
      },
      {
        path: 'users',
        title: 'Users · Sparewall',
        canActivate: [adminOnly],
        loadComponent: () => import('./features/users/users').then((m) => m.Users),
      },
      {
        path: 'tokens',
        title: 'API tokens · Sparewall',
        canActivate: [adminOnly],
        loadComponent: () => import('./features/tokens/tokens').then((m) => m.Tokens),
      },
      {
        path: 'history',
        title: 'History · Sparewall',
        loadComponent: () => import('./features/history/history').then((m) => m.History),
      },
    ],
  },
  { path: '**', redirectTo: '' },
];
