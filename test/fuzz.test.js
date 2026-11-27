import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fc from 'fast-check';
import { CODE, PathCageError, isInside, resolveSafePath } from '../src/index.mjs';

const ROOT = path.resolve('/app/uploads');

function outcome(fn) {
  try {
    return { value: fn(), error: null };
  } catch (error) {
    return { value: null, error };
  }
}

const hostileUnit = fc.constantFrom(
  '', '.', '..', '....', '..;', 'safe', 'a', 'etc', 'passwd',
  '%2e%2e', '%252e', '%2f', '/', '\\', '\0', 'C:', 'CON', '＼', 'é'
);
const hostilePath = fc.string({ unit: hostileUnit, minLength: 1, maxLength: 10 });

test('fast-check adversarial paths either fail closed or resolve inside the root', () => {
  fc.assert(fc.property(hostilePath, fc.boolean(), (input, decodeCheck) => {
    const result = outcome(() => resolveSafePath(input, { root: ROOT, decodeCheck }));
    if (result.error) {
      assert.ok(result.error instanceof PathCageError, 'unexpected error type');
      assert.match(result.error.code, /^ERR_PATHCAGE_/);
      return;
    }
    assert.equal(typeof result.value, 'string');
    assert.equal(isInside(ROOT, result.value), true, 'resolved path escaped the root');
    assert.equal(result.value.includes('\0'), false);
    const relative = path.relative(ROOT, result.value);
    assert.ok(relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
  }), { seed: 0x1a7c4e, numRuns: 250 });
});

test('fast-check parent traversal beyond the current depth is always rejected', () => {
  fc.assert(fc.property(
    fc.integer({ min: 0, max: 5 }),
    fc.integer({ min: 1, max: 5 }),
    (depth, extraParents) => {
      const input = 'a/'.repeat(depth) + '../'.repeat(depth + extraParents) + 'secret.txt';
      const result = outcome(() => resolveSafePath(input, { root: ROOT, decodeCheck: true }));
      assert.ok(result.error instanceof PathCageError, 'escaping traversal was accepted: ' + JSON.stringify(input));
      assert.match(result.error.code, /^ERR_PATHCAGE_/);
    }
  ), { seed: 0x7c11, numRuns: 120 });
});

test('fast-check null byte insertion always fails with the null-byte code', () => {
  const safeUnit = fc.constantFrom('a', 'b', 'x', '1', 'file', '.txt');
  const safeText = fc.string({ unit: safeUnit, minLength: 0, maxLength: 8 });
  fc.assert(fc.property(safeText, safeText, (left, right) => {
    const input = left + '\0' + right;
    assert.throws(
      () => resolveSafePath(input, { root: ROOT }),
      (error) => error instanceof PathCageError && error.code === CODE.NULL_BYTE
    );
  }), { seed: 0x00b1e, numRuns: 100 });
});
