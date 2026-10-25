import {
  Component,
  ElementRef,
  afterRenderEffect,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatListModule } from '@angular/material/list';
import { Router, RouterLink } from '@angular/router';
import { UISchemaElement } from '@jsonforms/core';
import { JsonFormsModule } from '@jsonforms/angular';

import { Setting, search, sectionGroups, settingPlace, settings } from './config-sections';
import { Document, DraftPage } from './draft-page';
import { fieldLabel } from './layout';
import { noEvalAjv } from './no-eval-ajv';
import { configRenderers } from './renderers';

/**
 * The configuration as forms built from its schema, one section at a time
 * (`/config/<section>`), with a search over every setting. The draft spans
 * all sections, so edits in several are reviewed and applied together.
 */
@Component({
  selector: 'app-config',
  imports: [
    JsonFormsModule,
    MatButtonModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatListModule,
    RouterLink,
  ],
  templateUrl: './config.html',
  styleUrl: './config.scss',
})
export class Config extends DraftPage {
  private readonly nav = inject(Router);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);

  /** The section shown, from the route. */
  readonly section = input<string>();
  /** A setting to bring into view, from a search result (`?find=a.b`). */
  readonly find = input<string>();

  protected readonly ajv = noEvalAjv;
  /** Each field's description under it: they say what a left-out field means. */
  protected readonly formConfig = { showUnfocusedDescription: true };
  protected readonly renderers = configRenderers;

  protected readonly groups = computed(() => {
    const s = this.schema();
    return s ? sectionGroups(s) : [];
  });
  /** The section shown: the route's, or the first one. */
  protected readonly shown = computed(() => {
    const all = this.groups().flatMap((g) => g.sections);
    return all.find((s) => s.key === this.section()) ?? all[0];
  });
  protected readonly uischema = computed((): UISchemaElement | undefined => {
    const s = this.shown();
    return (
      s && ({ type: 'Control', scope: `#/properties/${s.key}`, label: false } as UISchemaElement)
    );
  });

  /** Sections whose draft differs from the active document. */
  protected readonly editedSections = computed(() => {
    const draft = this.draft() as Record<string, unknown> | undefined;
    if (!draft || !this.current.hasValue()) return new Set<string>();
    const active = this.current.value().config as Record<string, unknown>;
    const keys = new Set([...Object.keys(draft), ...Object.keys(active)]);
    return new Set([...keys].filter((k) => JSON.stringify(draft[k]) !== JSON.stringify(active[k])));
  });

  protected readonly query = signal('');
  private readonly index = computed(() => {
    const s = this.schema();
    return s ? settings(s) : [];
  });
  protected readonly results = computed(() => search(this.index(), this.query()).slice(0, 40));
  /** Sections with a match, while searching. */
  protected readonly matching = computed(() => new Set(this.results().map((r) => r.section)));

  protected readonly place = settingPlace;

  constructor() {
    super();
    // Bring a found setting into view once its section is drawn.
    afterRenderEffect(() => {
      const find = this.find();
      if (!find || !this.draft() || !this.uischema()) return;
      const target = this.locate(find.split('.'));
      if (!target) return;
      target.scrollIntoView({ block: 'center' });
      target.classList.add('found');
      setTimeout(() => target.classList.remove('found'), 2000);
    });
  }

  protected edited(data: Document): void {
    this.draft.set(data);
  }

  protected open(r: Setting): void {
    this.query.set('');
    const find = r.path.filter((k) => k !== '<name>').join('.');
    void this.nav.navigate(['/config', r.section], { queryParams: find ? { find } : {} });
  }

  protected searchKey(e: KeyboardEvent): void {
    const first = this.results()[0];
    if (e.key === 'Enter' && first) this.open(first);
    if (e.key === 'Escape') this.query.set('');
  }

  /**
   * The drawn field for a path: the deepest key whose label is on the page
   * (a map's entries may be collapsed, so its fields may not be drawn).
   */
  private locate(path: string[]): HTMLElement | undefined {
    const form = this.host.nativeElement.querySelector('.form');
    if (!form) return undefined;
    const labels = Array.from(
      form.querySelectorAll<HTMLElement>('mat-label, legend, label, .map h3'),
    );
    for (let i = path.length - 1; i >= 0; i--) {
      const want = fieldLabel(path[i]);
      const el = labels.find((l) => l.textContent?.replace(/\*/g, '').trim() === want);
      if (el)
        return (el.closest('mat-form-field, fieldset, .map, mat-checkbox') as HTMLElement) ?? el;
    }
    return undefined;
  }
}
