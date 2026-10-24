import { httpResource } from '@angular/common/http';
import {
  Component,
  computed,
  effect,
  inject,
  linkedSignal,
  signal,
  untracked,
} from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router } from '@angular/router';
import { JsonFormsModule } from '@jsonforms/angular';
import { firstValueFrom } from 'rxjs';

import { ApiClient, CallFailed, callUrl } from '../../api/api-client';
import { Reply, Schemas } from '../../api/api.model';
import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import { configUiSchema } from './config-ui-schema';
import { documentSchema } from './form-schema';
import { noEvalAjv } from './no-eval-ajv';
import { configRenderers } from './renderers';
import { ReviewChange, ReviewData } from './review-change';

type Document = Schemas['Document'];

/** The configuration as a form built from its schema, and applying it. */
@Component({
  selector: 'app-config',
  imports: [JsonFormsModule, MatButtonModule, MatIconModule],
  templateUrl: './config.html',
  styleUrl: './config.scss',
})
export class Config {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(MatDialog);
  private readonly snack = inject(MatSnackBar);
  private readonly router = inject(Router);
  private readonly events = inject(NodeEvents);
  protected readonly session = inject(Session);

  protected readonly ajv = noEvalAjv;
  /** Each field's description under it: they say what a left-out field means. */
  protected readonly formConfig = { showUnfocusedDescription: true };
  protected readonly renderers = configRenderers;

  private readonly description = httpResource<{
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
  protected readonly uischema = computed(() => {
    const s = this.schema();
    return s ? configUiSchema(s) : undefined;
  });

  /** The document as edited, from the active one until it changes. */
  protected readonly draft = linkedSignal<Document | undefined>(() =>
    this.current.hasValue() ? structuredClone(this.current.value().config) : undefined,
  );
  protected readonly invalid = signal(0);
  protected readonly changed = computed(
    () =>
      this.current.hasValue() &&
      JSON.stringify(this.draft()) !== JSON.stringify(this.current.value().config),
  );
  protected readonly busy = signal(false);
  protected readonly problems = signal<string[]>([]);

  constructor() {
    effect(() => {
      if (!this.changed()) this.problems.set([]);
    });
    // Follow the node's configuration (an apply elsewhere, a revert) while
    // nothing is edited here; with edits, the apply's base check says so.
    effect(() => {
      this.events.count();
      if (untracked(() => !this.changed() && !this.busy())) this.current.reload();
    });
  }

  /** Whether there are edits that leaving the page would lose. */
  hasUnappliedChanges(): boolean {
    return this.changed() && !this.applying;
  }
  private applying = false;

  protected edited(data: Document): void {
    this.draft.set(data);
  }

  protected discard(): void {
    this.current.reload();
  }

  /** Dry-run the change, show what it does, and apply it if asked. */
  protected async review(): Promise<void> {
    const draft = this.draft();
    if (!draft || !this.current.hasValue()) return;
    const base = this.current.value().generation.id;
    this.busy.set(true);
    this.problems.set([]);
    try {
      const preview = await this.api.call('org.sparewall.Firewall.Apply', {
        config: draft,
        base,
        dry_run: true,
      });
      const data: ReviewData = { preview, base };
      const confirmSeconds = await firstValueFrom(
        this.dialog.open(ReviewChange, { data, width: '640px' }).afterClosed(),
      );
      if (confirmSeconds === undefined) return;
      this.applying = true;
      const r = await this.api.call('org.sparewall.Firewall.Apply', {
        config: draft,
        base,
        confirm_seconds: confirmSeconds,
      });
      this.snack.open(
        r.confirm_seconds
          ? `Generation ${r.generation.id} applied: confirm it within ${r.confirm_seconds} s, or it reverts.`
          : `Generation ${r.generation.id} applied.`,
        undefined,
        { duration: 6000 },
      );
      await this.router.navigate(['/status']);
    } catch (e) {
      if (e instanceof CallFailed && e.reply?.error === 'org.sparewall.Firewall.ValidationFailed') {
        this.problems.set(e.reply.parameters.errors);
      } else if (e instanceof CallFailed && e.status === 409) {
        this.problems.set([
          `${e.message.replace(/\.?$/, '.')} Discard your changes to start again from the current configuration.`,
        ]);
      } else {
        this.problems.set([e instanceof CallFailed ? e.message : 'Applying failed.']);
      }
    } finally {
      this.applying = false;
      this.busy.set(false);
    }
  }
}
