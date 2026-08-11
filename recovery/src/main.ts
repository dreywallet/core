/**
 * Bundle entry point. Kept separate from `cli.ts` so the verb implementations
 * stay importable by the test suite without executing anything.
 */
import { main } from './cli';

main(process.argv.slice(2)).then((code) => { process.exitCode = code });
