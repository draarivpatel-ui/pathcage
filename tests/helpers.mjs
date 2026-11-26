import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/** CJS entry point (require()). */
export const cjs = require('../cjs/index.cjs');
/** ESM entry point (import()). */
export const esm = await import('../src/index.mjs');

export const ROOT = path.resolve('/app/uploads');

/** Assert that fn throws a PathCageError with the given code. */
export function throwsCode(fn, code, message) {
  let error;
  const label = message || 'expected PathCageError ' + code;
  assert.throws(fn, (caught) => {
    error = caught;
    return true;
  }, label);
  assert.equal(error.name, 'PathCageError', label);
  assert.equal(error.code, code, label);
  assert.ok(typeof error.reason === 'string' && error.reason.length > 0, label);
  assert.ok('input' in error, label);
  return error;
}

/** Fresh temp directory in os.tmpdir() with an automatic cleanup function. */
export function tempDir(label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pathcage-' + label + '-'));
  return {
    dir,
    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}

export function rootOption(root) {
  return { root };
}
