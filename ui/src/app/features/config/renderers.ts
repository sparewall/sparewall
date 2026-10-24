import { JsonFormsRendererRegistryEntry } from '@jsonforms/core';
import { angularMaterialRenderers } from '@jsonforms/angular-material';

import { MapControl, mapControlTester } from './map-control';
import { ObjectControl, objectControlTester } from './object-control';
import { OptionalBooleanControl, optionalBooleanControlTester } from './optional-boolean-control';
import {
  MatchControl,
  matchControlTester,
  UnionControl,
  unionControlTester,
} from './union-controls';

/** JSON Forms' Material renderers, and ours for what they lack. */
export const configRenderers: JsonFormsRendererRegistryEntry[] = [
  ...angularMaterialRenderers,
  { tester: mapControlTester, renderer: MapControl },
  { tester: objectControlTester, renderer: ObjectControl },
  { tester: optionalBooleanControlTester, renderer: OptionalBooleanControl },
  { tester: matchControlTester, renderer: MatchControl },
  { tester: unionControlTester, renderer: UnionControl },
];
