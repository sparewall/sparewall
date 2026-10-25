import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { MatDialog } from '@angular/material/dialog';
import { JsonFormsModule } from '@jsonforms/angular';
import { JsonSchema7, UISchemaElement } from '@jsonforms/core';
import { of } from 'rxjs';

import openapi from '../../../../../docs/api/openapi.json';
import { documentSchema } from './form-schema';
import { noEvalAjv } from './no-eval-ajv';
import { configRenderers } from './renderers';

const doc = documentSchema(openapi as never);

@Component({
  imports: [JsonFormsModule],
  template: `
    <jsonforms
      [data]="data"
      [schema]="schema"
      [uischema]="uischema"
      [renderers]="renderers"
      [ajv]="ajv"
      validationMode="NoValidation"
      (dataChange)="changed.set($event)"
    />
  `,
})
class Host {
  readonly schema = doc;
  readonly uischema = {
    type: 'Control',
    scope: '#/properties/dhcp',
    label: false,
  } as UISchemaElement;
  readonly data = { dhcp: { lease_time: 600, users: { pool: '192.0.2.100-192.0.2.199' } } };
  readonly renderers = configRenderers;
  readonly ajv = noEvalAjv;
  readonly changed = signal<unknown>(undefined);
}

describe('named entries beside fields (dhcp)', () => {
  const open = vi.fn((_c: unknown, _o: { data: { taken: string[] } }) => ({
    afterClosed: () => of(undefined),
  }));

  beforeEach(() => {
    open.mockClear();
    TestBed.configureTestingModule({ providers: [{ provide: MatDialog, useValue: { open } }] });
  });

  it('lists the networks, not the fields, and reserves every field name', async () => {
    const fixture = TestBed.createComponent(Host);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const titles = [...el.querySelectorAll('mat-panel-title')].map((t) => t.textContent?.trim());
    expect(titles).toEqual(['users']);

    const add = [...el.querySelectorAll('button')].find((b) => b.textContent?.includes('Add'));
    add!.click();
    const taken = open.mock.calls[0][1].data.taken;
    // Set or not, a field's name cannot become a network's.
    const fields = Object.keys((doc.properties!['dhcp'] as JsonSchema7).properties!);
    expect(fields).toContain('provider');
    expect(taken).toEqual(expect.arrayContaining(['users', ...fields]));
  });
});
