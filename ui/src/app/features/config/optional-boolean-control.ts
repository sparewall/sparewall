import { ChangeDetectionStrategy, Component } from '@angular/core';
import { JsonFormsControl } from '@jsonforms/angular';
import { RankedTester, and, isBooleanControl, rankWith, schemaMatches } from '@jsonforms/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';

import { OPTIONAL } from './form-schema';

/**
 * A yes/no setting that may also be left out, so the node applies its
 * default (a network's `lldp`: on for untagged ports). A checkbox would
 * show "no" for one left out, which is not what the node does.
 */
@Component({
  selector: 'app-optional-boolean-control',
  imports: [MatFormFieldModule, MatSelectModule],
  template: `
    @if (!hidden) {
      <mat-form-field>
        <mat-label>{{ label }}</mat-label>
        <mat-select
          [value]="choice(data)"
          [disabled]="!isEnabled()"
          (selectionChange)="pick($event.value)"
        >
          <mat-option value="default">Default</mat-option>
          <mat-option value="yes">Yes</mat-option>
          <mat-option value="no">No</mat-option>
        </mat-select>
        @if (description) {
          <mat-hint>{{ description }}</mat-hint>
        }
      </mat-form-field>
    }
  `,
  styles: `
    mat-form-field {
      width: 100%;
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OptionalBooleanControl extends JsonFormsControl {
  protected choice(v: unknown): string {
    return v === true ? 'yes' : v === false ? 'no' : 'default';
  }

  protected pick(choice: string): void {
    this.onChange({ value: choice === 'yes' ? true : choice === 'no' ? false : undefined });
  }
}

export const optionalBooleanControlTester: RankedTester = rankWith(
  4,
  and(
    isBooleanControl,
    schemaMatches((s) => (s as Record<string, unknown>)[OPTIONAL] === true),
  ),
);
