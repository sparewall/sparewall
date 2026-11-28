import { Route } from '@angular/router';

import { routes } from './app.routes';
import { adminOnly } from './core/admin-only';

describe('routes', () => {
  const all = (rs: Route[]): Route[] => rs.flatMap((r) => [r, ...all(r.children ?? [])]);

  it('keeps the admin pages to admins', () => {
    for (const path of ['users', 'tokens', 'secrets']) {
      const r = all(routes).find((x) => x.path === path);
      expect(r?.canActivate, path).toContain(adminOnly);
    }
  });
});
