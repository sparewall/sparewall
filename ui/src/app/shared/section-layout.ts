import { Component, input } from '@angular/core';
import { MatListModule } from '@angular/material/list';
import { RouterLink } from '@angular/router';

/** One entry in a page's section list. */
export interface NavSection {
  key: string;
  label: string;
  /** Listed but not usable, e.g. for a role the user doesn't hold. */
  disabled?: boolean;
  /** A short note beside the label, e.g. the role a disabled section needs. */
  hint?: string;
}

/** Sections under an optional heading. */
export interface NavGroup {
  label?: string;
  sections: NavSection[];
}

/**
 * A page's sections listed on the left, each its own route
 * (`<base>/<key>`), with the page's content beside them; under 840px the
 * list moves above the content (#304). Content marked `sectionNavTop` goes
 * above the list, such as a search field.
 */
@Component({
  selector: 'app-section-layout',
  imports: [MatListModule, RouterLink],
  template: `
    <nav [attr.aria-label]="navLabel()">
      <ng-content select="[sectionNavTop]" />
      @if (showSections()) {
        @for (g of groups(); track $index) {
          @if (g.label) {
            <h2>{{ g.label }}</h2>
          }
          <mat-nav-list>
            @for (s of g.sections; track s.key) {
              @if (s.disabled) {
                <mat-list-item disabled [attr.data-section]="s.key" aria-disabled="true">
                  <span matListItemTitle>{{ s.label }}</span>
                  @if (s.hint) {
                    <span matListItemMeta class="hint">{{ s.hint }}</span>
                  }
                </mat-list-item>
              } @else {
                <a
                  mat-list-item
                  [attr.data-section]="s.key"
                  [routerLink]="[base(), s.key]"
                  [activated]="s.key === active()"
                  [attr.aria-current]="s.key === active() ? 'page' : null"
                >
                  <span matListItemTitle>{{ s.label }}</span>
                  @if (marked().has(s.key)) {
                    <span matListItemMeta class="marked" [title]="markTitle()">●</span>
                  } @else if (s.hint) {
                    <span matListItemMeta class="hint">{{ s.hint }}</span>
                  }
                </a>
              }
            }
          </mat-nav-list>
        }
      }
    </nav>
    <div class="content">
      <ng-content />
    </div>
  `,
  styles: `
    :host {
      display: grid;
      grid-template-columns: 240px minmax(0, 1fr);
      gap: 24px;
      align-items: start;
    }

    nav {
      position: sticky;
      top: 0;
      max-height: calc(100vh - 160px);
      overflow-y: auto;

      h2 {
        font: var(--mat-sys-label-medium);
        color: var(--mat-sys-on-surface-variant);
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin: 12px 16px 0;
      }

      mat-nav-list {
        padding-top: 0;
        --mat-list-list-item-one-line-container-height: 40px;
        // A disabled section reads as unavailable, not as selected.
        --mat-list-list-item-disabled-state-layer-opacity: 0;
      }

      .marked {
        color: var(--mat-sys-tertiary);
        font-size: 1.25em;
      }

      .hint {
        font: var(--mat-sys-label-small);
        color: var(--mat-sys-on-surface-variant);
      }
    }

    // Narrow screens: the sections above the content.
    @media (max-width: 840px) {
      :host {
        grid-template-columns: minmax(0, 1fr);
      }

      nav {
        position: static;
        max-height: none;
      }
    }
  `,
})
export class SectionLayout {
  /** The list's accessible name, e.g. "Network sections". */
  readonly navLabel = input.required<string>();
  readonly groups = input.required<NavGroup[]>();
  /** The page's route; each section is `<base>/<key>`. */
  readonly base = input.required<string>();
  /** The section shown. */
  readonly active = input<string>();
  /** Sections to mark, e.g. with edits not yet applied. */
  readonly marked = input<ReadonlySet<string>>(new Set());
  /** What a mark means, as its tooltip. */
  readonly markTitle = input('');
  /** False hides the list, e.g. while search results stand in for it. */
  readonly showSections = input(true);
}
