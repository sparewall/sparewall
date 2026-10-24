import { Routes } from '@angular/router';

import { signedIn } from './core/signed-in';
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
      {
        path: 'history',
        title: 'History · Sparewall',
        loadComponent: () => import('./features/history/history').then((m) => m.History),
      },
    ],
  },
  { path: '**', redirectTo: '' },
];
