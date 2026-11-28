import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';

import { ApiClient } from '../api/api-client';
import { NodeStatus } from '../core/node-status';
import { ExportMenu, exportName } from './export-menu';

describe('ExportMenu', () => {
  async function exportAs(format: 'YAML' | 'JSON', reply: unknown) {
    const calls: unknown[] = [];
    const saved: { name: string; blob: Blob }[] = [];
    const create = vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => {
      saved.push({ name: '', blob: b as Blob });
      return 'blob:x';
    });
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      saved.at(-1)!.name = this.download;
    });
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [ExportMenu],
      providers: [
        provideNoopAnimations(),
        {
          provide: ApiClient,
          useValue: { call: async (m: string, p: unknown) => (calls.push([m, p]), reply) },
        },
        { provide: NodeStatus, useValue: { node: () => 'fw1' } },
      ],
    });
    const fixture = TestBed.createComponent(ExportMenu);
    fixture.componentRef.setInput('generation', 7);
    await fixture.whenStable();
    (fixture.nativeElement as HTMLElement).querySelector('button')!.click();
    await fixture.whenStable();
    const item = [...document.querySelectorAll<HTMLButtonElement>('[mat-menu-item]')].find(
      (b) => b.textContent?.trim() === format,
    )!;
    item.click();
    await fixture.whenStable();
    create.mockRestore();
    click.mockRestore();
    return { calls, saved };
  }

  it('saves the node’s own text, named as the CLI names it', async () => {
    const text = 'schema: 8\ncluster:\n  nodes: [fw1]\n';
    const { calls, saved } = await exportAs('YAML', { config: {}, text });
    expect(calls).toEqual([['org.sparewall.Firewall.Export', { id: 7, format: 'yaml' }]]);
    expect(saved[0].name).toBe('sparewall-fw1-gen7.yaml');
    expect(await saved[0].blob.text()).toBe(text);
    expect(saved[0].blob.type).toBe('application/yaml');
  });

  it('exports JSON as well', async () => {
    const text = '{\n  "schema": 8\n}\n';
    const { calls, saved } = await exportAs('JSON', { config: {}, text });
    expect(calls).toEqual([['org.sparewall.Firewall.Export', { id: 7, format: 'json' }]]);
    expect(saved[0].name).toBe('sparewall-fw1-gen7.json');
    expect(await saved[0].blob.text()).toBe(text);
  });

  it('saves nothing from a node that sent no text', async () => {
    const { saved } = await exportAs('YAML', { config: {} });
    expect(saved).toEqual([]);
  });

  it('names files by node and generation', () => {
    expect(exportName('fw2', 12, 'json')).toBe('sparewall-fw2-gen12.json');
    expect(exportName(undefined, 1, 'yaml')).toBe('sparewall-node-gen1.yaml');
  });
});
