import { Component, inject, input, output } from '@angular/core';
import { MatButtonToggleModule } from '@angular/material/button-toggle';

import { NodeStatus } from '../core/node-status';

/**
 * Which node of a pair a diagnostics page reads (#268): this one, or its
 * peer through it. Shown only in a pair. `null` is this node.
 */
@Component({
  selector: 'app-node-switch',
  imports: [MatButtonToggleModule],
  template: `
    @if (peer(); as p) {
      <mat-button-toggle-group
        hideSingleSelectionIndicator
        aria-label="Node"
        [value]="node() ?? ''"
        (change)="nodeChange.emit($event.value || null)"
      >
        <mat-button-toggle value="" data-testid="this-node">{{
          self() ?? 'This node'
        }}</mat-button-toggle>
        <mat-button-toggle [value]="p" data-testid="peer-node">{{ p }}</mat-button-toggle>
      </mat-button-toggle-group>
    }
  `,
})
export class NodeSwitch {
  private readonly status = inject(NodeStatus);

  /** The node read now: `null` for this one. */
  readonly node = input<string | null>(null);
  readonly nodeChange = output<string | null>();

  protected readonly peer = this.status.peer;
  protected readonly self = this.status.node;
}
