import { ChangeDetectionStrategy, ChangeDetectorRef, Component, inject } from '@angular/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { JsonFormsControl } from '@jsonforms/angular';
import { JsonSchema7, RankedTester, rankWith, schemaMatches } from '@jsonforms/core';

import { formatMatch, formatUnion, parseMatch, parseUnion } from './union-text';

const alternatives = (s: JsonSchema7): JsonSchema7[] => (s.anyOf ?? s.oneOf ?? []) as JsonSchema7[];

/** `Document.Match`: an integer, a string, or a list of either. */
export function isMatch(s: JsonSchema7): boolean {
  const types = alternatives(s).map((a) => a.type);
  return (
    types.includes('integer') &&
    types.includes('string') &&
    types.every((t) => t === 'integer' || t === 'string' || t === 'array')
  );
}

/** Any other union whose branches are not all named values (those are a choice list). */
export function isUnion(s: JsonSchema7): boolean {
  const alts = alternatives(s);
  return alts.length > 1 && !alts.every((a) => 'const' in a);
}

const TEMPLATE = `
  @if (!hidden) {
    <mat-form-field>
      <mat-label>{{ label }}</mat-label>
      <input
        matInput
        [value]="text"
        [disabled]="!isEnabled()"
        (change)="read($any($event.target).value)"
      />
      @if (description) {
        <mat-hint>{{ description }}</mat-hint>
      }
    </mat-form-field>
    @if (problem) {
      <p class="problem" role="alert">{{ problem }}</p>
    }
  }
`;

const STYLES = `
  mat-form-field {
    width: 100%;
  }
  .problem {
    color: var(--mat-sys-error);
    font: var(--mat-sys-body-small);
    margin: 0 0 8px;
  }
`;

/**
 * A union edited as text. Showing a value never writes it back: only a
 * change the user makes does, so an untouched value keeps its type.
 * (A component, as JSON Forms' own base class is one.)
 */
@Component({ template: '' })
abstract class TextUnionControl extends JsonFormsControl {
  private readonly cd = inject(ChangeDetectorRef);
  protected text = '';
  protected problem = '';

  protected abstract format(v: unknown): string;
  protected abstract parse(text: string): { value: unknown } | { error: string };

  override mapAdditionalProps(): void {
    if (!this.problem) this.text = this.format(this.data);
    this.cd.markForCheck();
  }

  protected read(text: string): void {
    this.text = text;
    const r = this.parse(text);
    if ('error' in r) {
      this.problem = r.error;
    } else {
      this.problem = '';
      this.onChange({ value: r.value });
    }
    this.cd.markForCheck();
  }
}

/** A match as text: `22`, `8000-8100`, `@web`, or `22, 443`. */
@Component({
  selector: 'app-match-control',
  imports: [MatFormFieldModule, MatInputModule],
  template: TEMPLATE,
  styles: STYLES,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MatchControl extends TextUnionControl {
  protected format(v: unknown): string {
    return formatMatch(v);
  }
  protected parse(text: string) {
    return { value: parseMatch(text) };
  }
}

/** Another union as text: plain text for a name (`masquerade`), JSON for the rest. */
@Component({
  selector: 'app-union-control',
  imports: [MatFormFieldModule, MatInputModule],
  template: TEMPLATE,
  styles: STYLES,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UnionControl extends TextUnionControl {
  protected format(v: unknown): string {
    return formatUnion(v);
  }
  protected parse(text: string) {
    return parseUnion(text);
  }
}

/** Ahead of every JSON Forms renderer, which would take the first branch. */
export const matchControlTester: RankedTester = rankWith(
  7,
  schemaMatches((s) => isMatch(s as JsonSchema7)),
);
export const unionControlTester: RankedTester = rankWith(
  6,
  schemaMatches((s) => isUnion(s as JsonSchema7)),
);
