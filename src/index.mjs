import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const core = require('./core.cjs');

export const PathCageError = core.PathCageError;
export const CODE = core.CODE;
export const resolveSafePath = core.resolveSafePath;
export const assertSafePath = core.assertSafePath;
export const sanitizeFilename = core.sanitizeFilename;
export const validateArchiveEntry = core.validateArchiveEntry;
export const createArchiveGuard = core.createArchiveGuard;
export const createCage = core.createCage;
export const isInside = core.isInside;
export const assertLexicalInside = core.assertLexicalInside;

export default {
  PathCageError,
  CODE,
  resolveSafePath,
  assertSafePath,
  sanitizeFilename,
  validateArchiveEntry,
  createArchiveGuard,
  createCage
};
