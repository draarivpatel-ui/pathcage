/** Error codes emitted by pathcage. */
export const CODE: Readonly<{
  INVALID_INPUT: 'ERR_PATHCAGE_INVALID_INPUT';
  INVALID_ROOT: 'ERR_PATHCAGE_INVALID_ROOT';
  NULL_BYTE: 'ERR_PATHCAGE_NULL_BYTE';
  CONTROL_CHARACTER: 'ERR_PATHCAGE_CONTROL_CHARACTER';
  ABSOLUTE_PATH: 'ERR_PATHCAGE_ABSOLUTE_PATH';
  TRAVERSAL: 'ERR_PATHCAGE_TRAVERSAL';
  ENCODED_TRAVERSAL: 'ERR_PATHCAGE_ENCODED_TRAVERSAL';
  WINDOWS_DRIVE: 'ERR_PATHCAGE_WINDOWS_DRIVE';
  WINDOWS_UNC: 'ERR_PATHCAGE_WINDOWS_UNC';
  WINDOWS_PREFIX: 'ERR_PATHCAGE_WINDOWS_PREFIX';
  WINDOWS_DEVICE: 'ERR_PATHCAGE_WINDOWS_DEVICE';
  ALTERNATE_DATA_STREAM: 'ERR_PATHCAGE_ALTERNATE_DATA_STREAM';
  TRAILING_DOT_OR_SPACE: 'ERR_PATHCAGE_TRAILING_DOT_OR_SPACE';
  BACKSLASH_SEPARATOR: 'ERR_PATHCAGE_BACKSLASH_SEPARATOR';
  OUTSIDE_ROOT: 'ERR_PATHCAGE_OUTSIDE_ROOT';
  FORBIDDEN_SYMLINK: 'ERR_PATHCAGE_FORBIDDEN_SYMLINK';
  SYMLINK_ESCAPE: 'ERR_PATHCAGE_SYMLINK_ESCAPE';
  DUPLICATE_PATH: 'ERR_PATHCAGE_DUPLICATE_PATH';
  LIMIT_EXCEEDED: 'ERR_PATHCAGE_LIMIT_EXCEEDED';
  ARCHIVE_PATH: 'ERR_PATHCAGE_ARCHIVE_PATH';
  ARCHIVE_TYPE: 'ERR_PATHCAGE_ARCHIVE_TYPE';
  ARCHIVE_LINK: 'ERR_PATHCAGE_ARCHIVE_LINK';
  ARCHIVE_LIMIT: 'ERR_PATHCAGE_ARCHIVE_LIMIT';
  ARCHIVE_ZIP_BOMB: 'ERR_PATHCAGE_ARCHIVE_ZIP_BOMB';
  ARCHIVE_COLLISION: 'ERR_PATHCAGE_ARCHIVE_COLLISION';
}>;

export type PathCageErrorCode =
  'ERR_PATHCAGE_INVALID_INPUT' | 'ERR_PATHCAGE_INVALID_ROOT' |
  'ERR_PATHCAGE_NULL_BYTE' | 'ERR_PATHCAGE_CONTROL_CHARACTER' |
  'ERR_PATHCAGE_ABSOLUTE_PATH' | 'ERR_PATHCAGE_TRAVERSAL' |
  'ERR_PATHCAGE_ENCODED_TRAVERSAL' | 'ERR_PATHCAGE_WINDOWS_DRIVE' |
  'ERR_PATHCAGE_WINDOWS_UNC' | 'ERR_PATHCAGE_WINDOWS_PREFIX' |
  'ERR_PATHCAGE_WINDOWS_DEVICE' | 'ERR_PATHCAGE_ALTERNATE_DATA_STREAM' |
  'ERR_PATHCAGE_TRAILING_DOT_OR_SPACE' | 'ERR_PATHCAGE_BACKSLASH_SEPARATOR' |
  'ERR_PATHCAGE_OUTSIDE_ROOT' | 'ERR_PATHCAGE_FORBIDDEN_SYMLINK' |
  'ERR_PATHCAGE_SYMLINK_ESCAPE' | 'ERR_PATHCAGE_DUPLICATE_PATH' |
  'ERR_PATHCAGE_LIMIT_EXCEEDED' | 'ERR_PATHCAGE_ARCHIVE_PATH' |
  'ERR_PATHCAGE_ARCHIVE_TYPE' | 'ERR_PATHCAGE_ARCHIVE_LINK' |
  'ERR_PATHCAGE_ARCHIVE_LIMIT' | 'ERR_PATHCAGE_ARCHIVE_ZIP_BOMB' |
  'ERR_PATHCAGE_ARCHIVE_COLLISION';

/** Structured error thrown for every rejection. */
export declare class PathCageError extends Error {
  constructor(code: PathCageErrorCode | string, reason: string, input: unknown, cause?: unknown);
  readonly name: 'PathCageError';
  readonly code: PathCageErrorCode | string;
  readonly reason: string;
  readonly input: unknown;
  readonly cause?: unknown;
  toJSON(): { name: string; code: string; reason: string; input: unknown };
}

export interface ResolveOptions {
  /** Absolute root directory that all resolved paths must stay inside. */
  root: string;
  /** Decode percent-encoded path layers and reject encoded traversal. Default false. */
  decodeCheck?: boolean;
  /** Reject paths longer than this many characters. Default 4096. */
  maxPathLength?: number;
}

export interface FilenameOptions {
  /** Replacement for unsafe characters. Default '_'. */
  replacement?: string;
  /** Value used if the sanitized name is empty. */
  fallback?: string;
  /** Maximum length of the returned filename. Default 255. */
  maxLength?: number;
  /** Decode percent-encoded layers before sanitizing. Default false. */
  decodeCheck?: boolean;
  /** Reject paths longer than this many characters. Default 4096. */
  maxPathLength?: number;
}

export interface CageOptions {
  /** Reject every symlink component. Default true. */
  noSymlinks?: boolean;
  /** Allow symlinks whose resolved target remains inside the root. Default false. */
  allowSymlinksInsideRoot?: boolean;
  /** Detect duplicate and case-insensitive colliding paths in validateBatch. Default true. */
  caseInsensitive?: boolean;
  /** Fail at cage creation if the root does not exist. Default false. */
  mustExist?: boolean;
  /** Decode percent-encoded path layers. Default false. */
  decodeCheck?: boolean;
  /** Reject paths longer than this many characters. Default 4096. */
  maxPathLength?: number;
}

export interface Cage {
  readonly root: string;
  readonly rootReal: string;
  /** Lexically resolve an input path underneath the root. */
  resolve(input: string, options?: Partial<CageOptions>): string;
  /** Resolve and verify real filesystem path and every symlink hop. */
  realpathCheck(candidate: string, options?: Partial<CageOptions>): string;
  /** Alias of realpathCheck. */
  assertInside(candidate: string, options?: Partial<CageOptions>): string;
  /** Assert a batch of paths, rejecting duplicates and collisions. */
  validateBatch(inputs: readonly string[], options?: Partial<CageOptions>): string[];
}

export type ArchiveEntryType = 'file' | 'directory' | 'symlink' | 'hardlink';

export interface ArchiveEntry {
  /** Entry path as it appears in the archive. */
  path: string;
  type?: ArchiveEntryType;
  /** Uncompressed size in bytes. Default 0. */
  size?: number;
  /** Compressed size in bytes. Defaults to size. */
  compressedSize?: number;
  /** Link destination, required for symlink and hardlink entries. */
  linkTarget?: string;
}

export interface ValidatedArchiveEntry {
  path: string;
  type: ArchiveEntryType;
  size: number;
  compressedSize: number;
  linkTarget: string | null;
  key: string;
}

export interface ArchiveOptions {
  /** Maximum number of entries. Default 10000. */
  maxFiles?: number;
  /** Maximum uncompressed size of a single entry. Default 10485760. */
  maxFileSize?: number;
  /** Maximum total uncompressed size. Default 104857600. */
  maxTotalSize?: number;
  /** Maximum uncompressed to compressed size ratio. Default 100. */
  maxCompressionRatio?: number;
  /** Reject paths with case-insensitive duplicates. Default true. */
  caseInsensitive?: boolean;
  /** Accept symlink entries if the target resolves inside the archive. Default false. */
  allowSymlinks?: boolean;
  /** Accept hardlink entries if the target resolves inside the archive. Default false. */
  allowHardlinks?: boolean;
  /** Decode percent-encoded layers before inspection. Default true. */
  decodeCheck?: boolean;
  /** Reject paths longer than this many characters. Default 4096. */
  maxPathLength?: number;
}

export interface ArchiveGuard {
  /** Validate and record a single entry. */
  validate(entry: ArchiveEntry | string): ValidatedArchiveEntry;
  /** Validate and record an array of entries. */
  validateBatch(entries: ReadonlyArray<ArchiveEntry | string>): ValidatedArchiveEntry[];
  /** Snapshot of consumed limits. */
  stats(): { files: number; totalSize: number; paths: number };
  /** Forget all recorded entries and counters. */
  reset(): void;
}

/** Resolve a relative input path inside root. Throws PathCageError on violation. */
export declare function resolveSafePath(input: string, options: ResolveOptions): string;
/** Alias of resolveSafePath. */
export declare function assertSafePath(input: string, options: ResolveOptions): string;
/** Reduce arbitrary text to one safe flat filename. */
export declare function sanitizeFilename(input: string, options?: FilenameOptions): string;
/** Validate a single archive entry against limits and collision state. */
export declare function validateArchiveEntry(
  entry: ArchiveEntry | string,
  options?: ArchiveOptions & { state?: unknown }
): ValidatedArchiveEntry;
/** Create a stateful archive validator with cumulative limits. */
export declare function createArchiveGuard(options?: ArchiveOptions): ArchiveGuard;
/** Create a cage bound to one root directory. */
export declare function createCage(rootDir: string, options?: CageOptions): Cage;
/** Segment-aware containment check that avoids string-prefix confusion. */
export declare function isInside(rootDir: string, candidate: string): boolean;
/** Throw PathCageError unless candidate is lexically inside rootDir. */
export declare function assertLexicalInside(
  rootDir: string,
  candidate: string,
  input?: unknown
): string;

declare const pathcage: {
  PathCageError: typeof PathCageError;
  CODE: typeof CODE;
  resolveSafePath: typeof resolveSafePath;
  assertSafePath: typeof assertSafePath;
  sanitizeFilename: typeof sanitizeFilename;
  validateArchiveEntry: typeof validateArchiveEntry;
  createArchiveGuard: typeof createArchiveGuard;
  createCage: typeof createCage;
};

export default pathcage;
