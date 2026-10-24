import { ChangeDetectionStrategy, ChangeDetectorRef, Component, inject } from '@angular/core';
import { JsonFormsControl, JsonFormsModule } from '@jsonforms/angular';
import {
  Actions,
  ControlProps,
  Generate,
  JsonSchema7,
  RankedTester,
  UISchemaElement,
  rankWith,
  schemaMatches,
} from '@jsonforms/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatIconModule } from '@angular/material/icon';

import { firstValueFrom } from 'rxjs';

import { ConfirmData, ConfirmDialog } from '../../shared/confirm-dialog';
import { NameData, NameDialog } from '../../shared/name-dialog';
import { isMap } from './form-schema';
import { objectLayout } from './layout';

/**
 * A map of named things (networks, zones, policies, ...): one panel per
 * name with the entry's own form, and adding, renaming and removing names.
 * JSON Forms has no renderer for `additionalProperties`.
 */
@Component({
  selector: 'app-map-control',
  imports: [JsonFormsModule, MatButtonModule, MatExpansionModule, MatIconModule],
  templateUrl: './map-control.html',
  styleUrl: './map-control.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MapControl extends JsonFormsControl {
  private readonly cd = inject(ChangeDetectorRef);
  private readonly dialog = inject(MatDialog);
  protected names: string[] = [];
  protected entrySchema: JsonSchema7 = {};
  protected entryUiSchema: UISchemaElement = { type: 'VerticalLayout' };

  override mapAdditionalProps(props: ControlProps): void {
    const data = (props.data ?? {}) as Record<string, unknown>;
    this.names = Object.keys(data);
    const entry = (props.schema as JsonSchema7).additionalProperties as JsonSchema7;
    if (entry !== this.entrySchema) {
      this.entrySchema = entry;
      this.entryUiSchema = isMap(entry)
        ? Generate.controlElement('#')
        : entry.type === 'object'
          ? objectLayout(entry)
          : Generate.uiSchema(entry, 'VerticalLayout', undefined, this.rootSchema);
    }
    this.cd.markForCheck();
  }

  protected entryPath(name: string): string {
    return this.propsPath ? `${this.propsPath}.${name}` : name;
  }

  private update(f: (m: Record<string, unknown>) => Record<string, unknown>): void {
    this.jsonFormsService.updateCore(
      Actions.update(this.propsPath, (m: Record<string, unknown> | undefined) =>
        f({ ...(m ?? {}) }),
      ),
    );
  }

  protected async add(): Promise<void> {
    const name = await this.askName('Add', '');
    if (!name) return;
    const empty = this.entrySchema.type === 'object' ? {} : undefined;
    this.update((m) => ({ ...m, [name]: empty }));
  }

  protected async rename(from: string): Promise<void> {
    const to = await this.askName(`Rename ${from}`, from);
    if (!to || to === from) return;
    // Keep the order: the new name takes the old one's place.
    this.update((m) =>
      Object.fromEntries(Object.entries(m).map(([k, v]) => [k === from ? to : k, v])),
    );
  }

  protected async remove(name: string): Promise<void> {
    const ok = await firstValueFrom(
      this.dialog
        .open<ConfirmDialog, ConfirmData, boolean>(ConfirmDialog, {
          data: {
            title: `Remove ${name}?`,
            text: 'It goes when the change is applied; until then, Discard changes brings it back.',
            action: 'Remove',
          },
        })
        .afterClosed(),
    );
    if (!ok) return;
    this.update((m) => {
      delete m[name];
      return m;
    });
  }

  private askName(title: string, name: string): Promise<string | undefined> {
    return firstValueFrom(
      this.dialog
        .open<NameDialog, NameData, string>(NameDialog, {
          data: { title, name, taken: this.names },
          width: '400px',
        })
        .afterClosed(),
    );
  }
}

export const mapControlTester: RankedTester = rankWith(
  5,
  schemaMatches((s) => isMap(s as JsonSchema7)),
);
