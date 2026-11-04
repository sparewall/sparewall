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

describe("a network's IPv6, by mode", () => {
  const ipv6 = entry('networks').properties!['ipv6'] as JsonSchema7;

  it('gives each mode-bound field a rule from the schema', () => {
    const rules = Object.fromEntries(
      objectLayout(ipv6).elements.map((e) => {
        const c = e as {
          scope: string;
          rule?: { condition: { conditions: { expectedValue: string }[] } };
        };
        return [c.scope.split('/').pop(), c.rule?.condition.conditions.map((l) => l.expectedValue)];
      }),
    );
    expect(rules).toEqual({
      mode: undefined,
      prefix_length: ['dhcpv6'],
      subnet_id: ['delegated'],
      prefix: ['static'],
      gateway: ['static'],
      dns: ['delegated', 'static'],
      addresses: ['static'],
    });
  });

  it("shows only the chosen mode's fields", async () => {
    // A control is hidden by a `display: none` on itself or a parent.
    const shown = (el: HTMLElement, label: string) => {
      const f = [...el.querySelectorAll('mat-form-field')].find(
        (f) => f.querySelector('mat-label')?.textContent?.trim().replace(/\*$/, '') === label,
      );
      for (let n = f as HTMLElement | null; n && n !== el; n = n.parentElement) {
        if (n.style?.display === 'none') return false;
      }
      return !!f;
    };
    const delegated = await render(ipv6, { mode: 'delegated', subnet_id: 1 });
    expect(shown(delegated.el, 'Subnet ID')).toBe(true);
    expect(shown(delegated.el, 'Prefix length')).toBe(false);
    expect(shown(delegated.el, 'Gateway')).toBe(false);
    TestBed.resetTestingModule();
    const dhcpv6 = await render(ipv6, { mode: 'dhcpv6' });
    expect(shown(dhcpv6.el, 'Prefix length')).toBe(true);
    expect(shown(dhcpv6.el, 'Subnet ID')).toBe(false);
    // Nested in a network, as the editor draws it.
    TestBed.resetTestingModule();
    const network = await render(entry('networks'), {
      port: 'eth1',
      role: 'wan',
      ipv6: { mode: 'dhcpv6' },
    });
    expect(shown(network.el, 'Prefix length')).toBe(true);
    expect(shown(network.el, 'Subnet ID')).toBe(false);
  });
});
