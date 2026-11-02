import { httpResource } from '@angular/common/http';
import { Service, computed, inject } from '@angular/core';

import { callUrl } from '../api/api-client';
import { Reply } from '../api/api.model';
import { HealthState, UpdateState } from '../api/status.model';
import { updateNotice } from '../shared/update-notice';
import { NodeEvents } from './node-events';
import { Session } from './session';

/** The node's status, read again on each of its events, for the frame around the pages. */
@Service()
export class NodeStatus {
  private readonly events = inject(NodeEvents);
  private readonly session = inject(Session);

  readonly status = httpResource<Reply<'org.sparewall.Firewall.Status'>>(() => {
    if (!this.session.can('viewer')) return undefined;
    this.events.count();
    return { url: callUrl('org.sparewall.Firewall.Status'), method: 'POST', body: {} };
  });

  readonly node = computed(() => (this.status.hasValue() ? this.status.value().node : undefined));
  /** What the update check offers, if anything (#188). */
  readonly update = computed(() =>
    this.status.hasValue()
      ? updateNotice(this.status.value().update as unknown as UpdateState | undefined)
      : undefined,
  );
  /** ok, degraded or failed. */
  readonly level = computed(() =>
    this.status.hasValue()
      ? (this.status.value().health as unknown as HealthState | undefined)?.level
      : undefined,
  );
}
