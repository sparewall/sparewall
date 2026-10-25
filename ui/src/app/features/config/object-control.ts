import { ChangeDetectionStrategy, Component } from '@angular/core';
import { JsonFormsControlWithDetail, JsonFormsModule } from '@jsonforms/angular';
import {
  ControlWithDetailProps,
  JsonSchema7,
  RankedTester,
  UISchemaElement,
  isObjectControl,
  rankWith,
  setReadonly,
} from '@jsonforms/core';

import { FIXED } from './form-schema';
import { objectLayout } from './layout';

/** What an object's named entries are, by its path. */
const ENTRY_LABELS: Record<string, string> = { dhcp: 'Served networks' };

/**
 * A nested group of fields (a network's `cake`, the cluster's `conntrack`),
 * headed by its own name rather than its whole path, with the fields in
 * the order `objectLayout` gives.
 */
@Component({
  selector: 'app-object-control',
  imports: [JsonFormsModule],
  template: `
    @if (!hidden) {
      <fieldset [class.bare]="!named">
        @if (named) {
          <legend>{{ label }}</legend>
          @if (description) {
            <p class="description">{{ description }}</p>
          }
        }
        <jsonforms-outlet [uischema]="layout" [schema]="scopedSchema" [path]="propsPath" />
        @if (entries) {
          <jsonforms-outlet [uischema]="entriesUi" [schema]="entries" [path]="propsPath" />
        }
      </fieldset>
    }
  `,
  styles: `
    fieldset {
      border: 1px solid var(--mat-sys-outline-variant);
      border-radius: 12px;
      padding: 8px 16px;
      margin: 8px 0 16px;
    }
    /* A whole section: the page names and describes it. */
    fieldset.bare {
      border: none;
      padding: 0;
      margin: 0;
    }
    legend {
      font: var(--mat-sys-title-small);
      padding: 0 4px;
    }
    .description {
      color: var(--mat-sys-on-surface-variant);
      font: var(--mat-sys-body-small);
      margin-top: 0;
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ObjectControl extends JsonFormsControlWithDetail {
  protected layout: UISchemaElement = { type: 'VerticalLayout' };
  /** Named entries beside the fields (`dhcp`'s networks), drawn as a map. */
  protected entries?: JsonSchema7;
  protected entriesUi: UISchemaElement = { type: 'Control' } as UISchemaElement;
  /** Whether it has a name to show; a whole section is drawn without one. */
  protected named = true;
  private laidOut?: JsonSchema7;

  override mapAdditionalProps(props: ControlWithDetailProps): void {
    this.named = props.label.replace(/\*/g, '').trim() !== '';
    if (props.schema !== this.laidOut) {
      const s = (this.laidOut = props.schema as JsonSchema7);
      this.layout = objectLayout(s);
      if (!this.isEnabled()) setReadonly(this.layout);
      const extra = s.additionalProperties;
      this.entries =
        typeof extra === 'object'
          ? ({
              type: 'object',
              additionalProperties: extra,
              description: extra.description,
              [FIXED]: Object.keys(s.properties ?? {}),
            } as JsonSchema7)
          : undefined;
      this.entriesUi = {
        type: 'Control',
        scope: '#',
        label: ENTRY_LABELS[props.path] ?? 'Entries',
      } as UISchemaElement;
      if (!this.isEnabled()) setReadonly(this.entriesUi);
    }
  }
}

/** Ahead of JSON Forms' own object renderer (rank 2), behind the map one. */
export const objectControlTester: RankedTester = rankWith(3, isObjectControl);
