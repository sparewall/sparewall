import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { JsonFormsModule } from '@jsonforms/angular';
import { JsonSchema7, UISchemaElement } from '@jsonforms/core';

import { Schemas } from '../../api/api.model';
import { objectLayout } from '../config/layout';
import { noEvalAjv } from '../config/no-eval-ajv';
import { configRenderers } from '../config/renderers';

type Policy = Schemas['Document.Policy'];

export interface PolicyData {
  key: string;
  policy?: Policy;
  fallback: 'accept' | 'drop';
  schema: JsonSchema7;
  readonly: boolean;
}

/** What the dialog decided: a policy, its removal, or nothing (cancelled). */
export type PolicyResult = { policy: Policy } | { remove: true };

/** One zone pair's policy, in the form built from its schema. */
@Component({
  selector: 'app-policy-dialog',
  imports: [JsonFormsModule, MatButtonModule, MatDialogModule],
  template: `
    <h2 mat-dialog-title>{{ data.key }}</h2>
    <mat-dialog-content>
      @if (!data.policy) {
        <p class="fallback">
          No policy yet: this pair is {{ data.fallback === 'accept' ? 'accepted' : 'dropped' }}.
        </p>
      }
      <jsonforms
        [data]="policy()"
        [schema]="data.schema"
        [uischema]="uischema"
        [renderers]="renderers"
        [ajv]="ajv"
        [readonly]="data.readonly"
        [config]="formConfig"
        validationMode="NoValidation"
        (dataChange)="policy.set($event)"
      />
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      @if (data.policy && !data.readonly) {
        <button matButton class="remove" (click)="remove()">Remove policy</button>
      }
      <span class="spacer"></span>
      <button matButton mat-dialog-close>{{ data.readonly ? 'Close' : 'Cancel' }}</button>
      @if (!data.readonly) {
        <button matButton="filled" (click)="keep()">OK</button>
      }
    </mat-dialog-actions>
  `,
  styles: `
    .fallback {
      color: var(--mat-sys-on-surface-variant);
    }
    .spacer {
      flex: 1;
    }
    .remove {
      color: var(--mat-sys-error);
    }
  `,
})
export class PolicyDialog {
  protected readonly data = inject<PolicyData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<PolicyDialog, PolicyResult>);
  protected readonly ajv = noEvalAjv;
  protected readonly renderers = configRenderers;
  protected readonly formConfig = { showUnfocusedDescription: true };
  protected readonly uischema: UISchemaElement = objectLayout(this.data.schema);
  // A new policy starts from what the pair does now.
  protected readonly policy = signal<Policy>(
    structuredClone(this.data.policy) ?? { action: this.data.fallback },
  );

  protected keep(): void {
    this.ref.close({ policy: this.policy() });
  }

  protected remove(): void {
    this.ref.close({ remove: true });
  }
}
