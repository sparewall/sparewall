import { Component, computed } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { JsonFormsModule } from '@jsonforms/angular';

import { configUiSchema } from './config-ui-schema';
import { Document, DraftPage } from './draft-page';
import { noEvalAjv } from './no-eval-ajv';
import { configRenderers } from './renderers';

/** The configuration as a form built from its schema, and applying it. */
@Component({
  selector: 'app-config',
  imports: [JsonFormsModule, MatButtonModule, MatIconModule],
  templateUrl: './config.html',
  styleUrl: './config.scss',
})
export class Config extends DraftPage {
  protected readonly ajv = noEvalAjv;
  /** Each field's description under it: they say what a left-out field means. */
  protected readonly formConfig = { showUnfocusedDescription: true };
  protected readonly renderers = configRenderers;

  protected readonly uischema = computed(() => {
    const s = this.schema();
    return s ? configUiSchema(s) : undefined;
  });

  protected edited(data: Document): void {
    this.draft.set(data);
  }
}
