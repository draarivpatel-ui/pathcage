'use strict';

const core = require('../src/core.cjs');

module.exports = {
  PathCageError: core.PathCageError,
  CODE: core.CODE,
  resolveSafePath: core.resolveSafePath,
  assertSafePath: core.assertSafePath,
  sanitizeFilename: core.sanitizeFilename,
  validateArchiveEntry: core.validateArchiveEntry,
  createArchiveGuard: core.createArchiveGuard,
  createCage: core.createCage,
  isInside: core.isInside,
  assertLexicalInside: core.assertLexicalInside
};

module.exports.default = module.exports;
