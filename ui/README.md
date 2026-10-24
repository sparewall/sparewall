# Sparewall web UI

The browser interface to a Sparewall node: Angular with Angular Material,
built into a static bundle that `sparewall-httpd` serves from
`/usr/share/sparewall/ui` once the document turns on `management.web`
(design: "Web UI and HTTP API").

It talks to the node only through the HTTP API (`docs/api`), as the
signed-in user: a session cookie the page cannot read, and the
`X-Sparewall-Request` header on every call. The node checks every call
against the user's role; the page only decides what to offer.

## Working on it

```shell
npm ci --ignore-scripts
npm start                    # http://localhost:4200, proxied to a node
npm test
npm run build                # dist/sparewall-ui/browser
```

`npm start` proxies `/call` and `/openapi.json` to `SPAREWALL_NODE`
(default `https://localhost:8443`), a node with `management.web` on; its
self-signed certificate is accepted.

`src/app/api/api.model.ts` holds the types of every call, generated from
`docs/api/openapi.json`. After the API changes, run `npm run api`; CI
fails when they differ (`npm run api:check`).

## Rules

- Nothing is loaded from elsewhere: fonts and icons are bundled, and the
  gateway's Content-Security-Policy allows only the node itself (so no
  inline scripts either; critical-CSS inlining is off for that reason).
- Every package the bundle ships must have a license on the list in
  `scripts/licenses.mjs` (`npm run licenses`) and a license file, and no
  advisories (`npm audit --omit=dev`). The image ships every one's
  license text in `/usr/share/licenses/sparewall-ui/NOTICES`, the fonts'
  included (Roboto, OFL-1.1; Material Symbols, Apache-2.0), and the UI
  serves the same text at `/licenses.txt`, since the fonts go to every
  browser that opens it.
