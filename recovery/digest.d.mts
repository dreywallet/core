/**
 * Types for `digest.mjs`.
 *
 * That module is deliberately plain JavaScript with no imports beyond
 * `node:crypto`, `node:fs`, and `node:path`, so a third party can read it end to
 * end and re-run it without a toolchain. This declaration exists only so the
 * test suite can call into it under `tsc`; it is not part of the source digest,
 * because it cannot change what the program computes.
 */
export declare const SOURCE_ROOTS: string[];
export declare const SOURCE_FILES: string[];
export declare const ARTIFACT_PATH: string;
export declare function sourceFileList(base: string): string[];
export declare function treeDigest(base: string, files: string[]): string;
export declare function sourceDigest(base: string): string;
export declare function artifactDigest(base: string): string;
