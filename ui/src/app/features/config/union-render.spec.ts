import { Component, input, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { JsonFormsModule } from '@jsonforms/angular';
import { JsonSchema7, UISchemaElement } from '@jsonforms/core';

import openapi from '../../../../../docs/api/openapi.json';
import { documentSchema } from './form-schema';
import { objectLayout } from './layout';
import { noEvalAjv } from './no-eval-ajv';
import { configRenderers } from './renderers';

// The real document schema, as the page gets it.
const doc = documentSchema(openapi as never);
const entry = (section: string) => doc.properties![section].additionalProperties as JsonSchema7;
const ruleSchema = entry('policy').properties!['rules'].additionalProperties as JsonSchema7;
const policySchema = entry('policy');
const rawSchema = entry('raw');

@Component({
  imports: [JsonFormsModule],
  template: `
    <jsonforms
      [data]="data()"
      [schema]="schema()"
      [uischema]="uischema()"
      [renderers]="renderers"
      [ajv]="ajv"
      validationMode="NoValidation"
      (dataChange)="changed.set($event)"
    />
  `,
})
class Host {
  readonly data = input.required<unknown>();
  readonly schema = input.required<JsonSchema7>();
  readonly uischema = input.required<UISchemaElement>();
  readonly renderers = configRenderers;
  readonly ajv = noEvalAjv;
  readonly changed = signal<unknown>(undefined);
}

async function render(schema: JsonSchema7, data: unknown) {
  const fixture = TestBed.createComponent(Host);
  fixture.componentRef.setInput('schema', schema);
  fixture.componentRef.setInput('uischema', objectLayout(schema));
  fixture.componentRef.setInput('data', structuredClone(data));
  await fixture.whenStable();
  const el = fixture.nativeElement as HTMLElement;
  const field = (label: string) =>
    [...el.querySelectorAll('mat-form-field')]
      // A required field's label ends in '*'.
      .find((f) => f.querySelector('mat-label')?.textContent?.trim().replace(/\*$/, '') === label)
      ?.querySelector('input') as HTMLInputElement;
  const edit = async (label: string, text: string) => {
    const i = field(label);
    i.value = text;
    i.dispatchEvent(new Event('change'));
    await fixture.whenStable();
  };
  /** The data as the form has it now: its last change, or what it was given. */
  const now = () => fixture.componentInstance.changed() ?? data;
  return { el, field, edit, now };
}

describe('the form with unions', () => {
  const rule = {
    order: 100,
    proto: 'tcp',
    dport: [22, '8000-8100'],
    sport: 1024,
    src: '@admin_nets',
    dst: '192.0.2.0/24',
    action: 'accept',
  };

  it('shows each match branch as text and leaves the data untouched', async () => {
    const f = await render(ruleSchema, rule);
    expect(f.field('Dport').value).toBe('22, 8000-8100');
    expect(f.field('Sport').value).toBe('1024');
    expect(f.field('Src').value).toBe('@admin_nets');
    expect(f.field('Dst').value).toBe('192.0.2.0/24');
    expect(f.now()).toEqual(rule);
  });

  it('changes only the field edited, to the type its text says', async () => {
    const f = await render(ruleSchema, rule);
    await f.edit('Dport', '443');
    expect(f.now()).toEqual({ ...rule, dport: 443 });
    await f.edit('Src', '10.0.0.0/8, @lab');
    expect(f.now()).toEqual({ ...rule, dport: 443, src: ['10.0.0.0/8', '@lab'] });
  });

  it('edits a policy NAT either way, and refuses broken JSON', async () => {
    const policy = { action: 'accept', nat: 'masquerade' };
    const f = await render(policySchema, policy);
    expect(f.field('NAT').value).toBe('masquerade');
    expect(f.now()).toEqual(policy);
    await f.edit('NAT', '{"snat": "203.0.113.5"}');
    expect(f.now()).toEqual({ ...policy, nat: { snat: '203.0.113.5' } });
    await f.edit('NAT', '{"snat": ');
    expect(f.el.textContent).toContain('Not valid JSON.');
    expect(f.now()).toEqual({ ...policy, nat: { snat: '203.0.113.5' } });
  });

  it("shows a raw statement's place as JSON, untouched", async () => {
    const raw = { at: { hook: 'input' }, nft: 'tcp dport 23 drop' };
    const f = await render(rawSchema, raw);
    expect(f.field('At').value).toBe('{"hook":"input"}');
    expect(f.now()).toEqual(raw);
  });
});
