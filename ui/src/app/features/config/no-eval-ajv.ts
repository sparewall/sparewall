import type Ajv from 'ajv';

/**
 * A stand-in for the validator JSON Forms would create. Ajv compiles each
 * schema into code with `new Function`, which the gateway's
 * Content-Security-Policy refuses ('unsafe-eval' is not allowed, nor
 * should it be). The node validates every change itself (`Validate`, and
 * the dry run before an apply), so the form does not: this compiles to a
 * check that passes, and JSON Forms runs with `NoValidation`.
 */
const pass = Object.assign(() => true, { errors: null });

export const noEvalAjv = {
  compile: () => pass,
  validate: () => true,
  getSchema: () => pass,
  addSchema() {
    return this;
  },
  addFormat() {
    return this;
  },
  errors: null,
} as unknown as Ajv;
