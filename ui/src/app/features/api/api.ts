import { httpResource } from '@angular/common/http';
import { Component, computed, inject } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatIconModule } from '@angular/material/icon';
import { RouterLink } from '@angular/router';

import { Session } from '../../core/session';
import { Call, OpenApi, allowed, apiReference, curlExample } from '../../shared/api-reference';

const README = 'https://github.com/sparewall/sparewall/blob/main/docs/api/README.md';

/**
 * The HTTP API for scripts (#161), built from the node's own
 * /openapi.json: every call by interface, the role it needs (greyed out
 * above the user's), its parameters and reply, and a curl example.
 * Read-only: nothing here calls the API but to read its description.
 */
@Component({
  selector: 'app-api',
  imports: [MatCardModule, MatChipsModule, MatExpansionModule, MatIconModule, RouterLink],
  templateUrl: './api.html',
  styleUrl: './api.scss',
})
export class Api {
  protected readonly session = inject(Session);
  protected readonly readme = README;
  protected readonly origin = typeof location === 'undefined' ? 'https://NODE' : location.origin;

  protected readonly doc = httpResource<OpenApi>(() => '/openapi.json');
  protected readonly interfaces = computed(() =>
    this.doc.hasValue() ? apiReference(this.doc.value()) : [],
  );

  protected allowed(c: Call): boolean {
    return allowed(c, (r) => this.session.can(r));
  }

  protected curl(c: Call): string {
    return curlExample(c, this.origin);
  }

  /** `Firewall.Status` for `org.sparewall.Firewall.Status`. */
  protected short(method: string): string {
    return method.replace(/^org\.sparewall\./, '');
  }
}
