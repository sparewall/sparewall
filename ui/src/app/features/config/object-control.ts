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

import { objectLayout } from './layout';

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
      <fieldset>
        <legend>{{ label }}</legend>
        @if (description) {
          <p class="description">{{ description }}</p>
        }
        <jsonforms-outlet [uischema]="layout" [schema]="scopedSchema" [path]="propsPath" />
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
  private laidOut?: JsonSchema7;

  override mapAdditionalProps(props: ControlWithDetailProps): void {
    if (props.schema !== this.laidOut) {
      this.laidOut = props.schema as JsonSchema7;
      this.layout = objectLayout(this.laidOut);
      if (!this.isEnabled()) setReadonly(this.layout);
    }
  }
}

/** Ahead of JSON Forms' own object renderer (rank 2), behind the map one. */
export const objectControlTester: RankedTester = rankWith(3, isObjectControl);
