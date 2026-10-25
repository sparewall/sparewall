import { httpResource } from '@angular/common/http';
import {
  Directive,
  computed,
  effect,
  inject,
  linkedSignal,
  signal,
  untracked,
} from '@angular/core';
import { Router } from '@angular/router';

import { callUrl } from '../../api/api-client';
import { Reply, Schemas } from '../../api/api.model';
import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import { ConfigChanges } from './config-changes';
import { documentSchema } from './form-schema';
import { HoldsEdits } from './keep-edits';

export type Document = Schemas['Document'];

/**
 * A page that edits the document (the editor, the policy matrix): the
 * active document and its schema from the node, a draft of it, and
 * reviewing and applying that draft.
 */
@Directive()
export abstract class DraftPage implements HoldsEdits {
  private readonly changes = inject(ConfigChanges);
  private readonly router = inject(Router);
  private readonly events = inject(NodeEvents);
  protected readonly session = inject(Session);

  protected readonly description = httpResource<{
    components: { schemas: Record<string, Record<string, unknown>> };
  }>(() => '/openapi.json');
  protected readonly current = httpResource<Reply<'org.sparewall.Firewall.GetConfig'>>(() => ({
    url: callUrl('org.sparewall.Firewall.GetConfig'),
    method: 'POST',
    body: {},
  }));

  protected readonly schema = computed(() =>
    this.description.hasValue() ? documentSchema(this.description.value()) : undefined,
  );

  /** The document as edited, from the active one until it changes. */
  protected readonly draft = linkedSignal<Document | undefined>(() =>
    this.current.hasValue() ? structuredClone(this.current.value().config) : undefined,
  );
  /**
   * The generation the draft was taken from, which the apply names as its
   * base: a draft of an older generation is refused (a conflict) rather
   * than applied over what changed since.
   */
  protected readonly draftBase = linkedSignal<number | undefined>(() =>
    this.current.hasValue() ? this.current.value().generation.id : undefined,
  );
  /** Edits held outside the draft for now (an open dialog): no reload meanwhile. */
  protected readonly holding = signal(0);
  protected readonly changed = computed(
    () =>
      this.current.hasValue() &&
      JSON.stringify(this.draft()) !== JSON.stringify(this.current.value().config),
  );
  protected readonly busy = signal(false);
  protected readonly problems = signal<string[]>([]);
  private applying = false;

  constructor() {
    effect(() => {
      if (!this.changed()) this.problems.set([]);
    });
    // Follow the node's configuration (an apply elsewhere, a revert) while
    // nothing is edited here; with edits, the apply's base check says so.
    effect(() => {
      this.events.count();
      if (untracked(() => !this.changed() && !this.busy() && !this.holding())) {
        this.current.reload();
      }
    });
  }

  /** Whether there are edits that leaving the page would lose. */
  hasUnappliedChanges(): boolean {
    return this.changed() && !this.applying;
  }

  protected discard(): void {
    this.current.reload();
  }

  /** Dry-run the draft, show what it does, and apply it if asked. */
  protected async review(): Promise<void> {
    const draft = this.draft();
    const base = this.draftBase();
    if (!draft || base === undefined) return;
    this.busy.set(true);
    this.problems.set([]);
    try {
      // Leaving stays guarded through the dry run and the review, until
      // the apply itself starts.
      const r = await this.changes.review(draft, base, () => (this.applying = true));
      if (r.applied) await this.router.navigate(['/status']);
      else this.problems.set(r.problems);
    } finally {
      this.applying = false;
      this.busy.set(false);
    }
  }
}
