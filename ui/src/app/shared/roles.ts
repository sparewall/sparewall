import { Role } from '../core/session';

/** The roles, lowest first, and what each one may do. */
export const ROLES: { role: Role; does: string }[] = [
  { role: 'monitor', does: 'Health and metrics only' },
  { role: 'viewer', does: 'Reads everything but secrets' },
  { role: 'operator', does: 'Changes the configuration' },
  { role: 'admin', does: 'Also users, tokens, secrets and upgrades' },
];
