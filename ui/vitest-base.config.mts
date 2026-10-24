import { defineConfig } from 'vitest/config';

// JSON Forms' Angular packages import lodash by bare path (`lodash/cloneDeep`),
// which Node's ESM loader cannot resolve; Vite bundles them for the tests
// instead, as the application build does.
export default defineConfig({
  test: {
    server: {
      deps: {
        inline: [/@jsonforms\//],
      },
    },
  },
});
