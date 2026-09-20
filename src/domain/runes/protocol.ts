import { assertRuneAtomic, parseRuneId, RUNE_U128_MAX, RUNE_U32_MAX, RUNE_U64_MAX } from './amounts';

/** Reference: ordinals/ord tag 0.27.1, crates/ordinals/src/runestone{,/message,/tag}.rs
 * and src/index/updater/rune_updater.rs. Limits are wallet policy, NOT cenotaph rules.
 * Resource-limit errors must block review; they must never be interpreted as absent.
 */
export const RUNE_PROTOCOL_REFERENCE = 'ordinals/ord@0.27.1';
export const RUNE_PROTOCOL_LIMITS = Object.freeze({ outputs: 4096, scriptBytes: 400_000, payloadBytes: 16_384, edicts: 1024, balances: 4096 });
export class RuneResourceLimitError extends Error {
  constructor() { super('Rune interpreter resource limit exceeded'); this.name = 'RuneResourceLimitError'; }
}
export interface RuneEdict { readonly id: string; readonly amount: bigint; readonly output: number }
export interface RuneEtching {
  readonly fields: ReadonlyMap<number, bigint>;
  readonly terms: boolean;
  readonly turbo: boolean;
}
export interface Runestone {
  readonly kind: 'runestone';
  readonly edicts: readonly RuneEdict[];
  readonly pointer?: number;
  readonly mint?: string;
  readonly etching?: RuneEtching;
}
export type RuneFlaw = 'opcode' | 'invalid_script' | 'varint' | 'trailing_integers' | 'edict_rune_id'
  | 'edict_output' | 'truncated_field' | 'supply_overflow' | 'unrecognized_flag' | 'unrecognized_even_tag';
export type RuneArtifact = { readonly kind: 'absent' }
  | { readonly kind: 'cenotaph'; readonly flaw: RuneFlaw; readonly mint?: string }
  | Runestone;

function bound(condition: boolean): void { if (!condition) throw new RuneResourceLimitError(); }
function outputBounds(scripts: readonly Uint8Array[]): void {
  bound(scripts.length <= RUNE_PROTOCOL_LIMITS.outputs);
  let bytes = 0;
  for (const script of scripts) { bytes += script.length; bound(bytes <= RUNE_PROTOCOL_LIMITS.scriptBytes); }
}

/** Includes non-minimal varints, which ord accepts, but rejects >128 bits or >19 bytes. */
function integers(payload: readonly number[]): bigint[] | undefined {
  const result: bigint[] = [];
  for (let i = 0; i < payload.length;) {
    let value = 0n;
    let done = false;
    for (let j = 0; j < 19; j++) {
      const byte = payload[i++];
      if (byte === undefined || (j === 18 && (byte & 0x7f) > 3)) return undefined;
      value |= BigInt(byte & 0x7f) << BigInt(j * 7);
      if ((byte & 0x80) === 0) { done = true; break; }
    }
    if (!done) return undefined;
    result.push(value);
  }
  return result;
}

function parsePayload(payload: readonly number[], outputCount: number): RuneArtifact {
  const values = integers(payload);
  if (!values) return { kind: 'cenotaph', flaw: 'varint' };
  const fields = new Map<bigint, bigint[]>();
  const edicts: RuneEdict[] = [];
  let flaw: RuneFlaw | undefined;
  for (let i = 0; i < values.length; i += 2) {
    const tag = values[i]!;
    if (tag === 0n) {
      let block = 0n;
      let tx = 0n;
      for (let j = i + 1; j < values.length; j += 4) {
        if (j + 4 > values.length) { flaw = 'trailing_integers'; break; }
        const delta = values[j]!;
        block += delta;
        tx = delta === 0n ? tx + values[j + 1]! : values[j + 1]!;
        if (block > RUNE_U64_MAX || tx > BigInt(RUNE_U32_MAX) || (block === 0n && tx !== 0n)) {
          flaw = 'edict_rune_id'; break;
        }
        const output = values[j + 3]!;
        if (output > BigInt(outputCount)) { flaw = 'edict_output'; break; }
        bound(edicts.length < RUNE_PROTOCOL_LIMITS.edicts);
        edicts.push({ id: `${block}:${tx}`, amount: values[j + 2]!, output: Number(output) });
      }
      break;
    }
    if (i + 1 === values.length) { flaw = 'truncated_field'; break; }
    const field = fields.get(tag) ?? [];
    field.push(values[i + 1]!);
    fields.set(tag, field);
  }
  // A field is consumed only when the entire value passes ord's conversion.
  function take(tag: number, count: number, accept: (values: bigint[]) => boolean = () => true): bigint[] | undefined {
    const queue = fields.get(BigInt(tag));
    if (!queue || queue.length < count) return undefined;
    const slice = queue.slice(0, count);
    if (!accept(slice)) return undefined;
    queue.splice(0, count);
    if (!queue.length) fields.delete(BigInt(tag));
    return slice;
  }
  let flags = take(2, 1)?.[0] ?? 0n;
  function flag(mask: bigint): boolean { const set = (flags & mask) !== 0n; flags &= ~mask; return set; }
  let etching: RuneEtching | undefined;
  if (flag(1n)) {
    const data = new Map<number, bigint>();
    function field(tag: number, accept?: (values: bigint[]) => boolean): void {
      const v = take(tag, 1, accept);
      if (v) data.set(tag, v[0]!);
    }
    field(1, ([v]) => v! <= 38n);
    field(6); field(4);
    field(3, ([v]) => v! <= 0x7fff_fffn);
    field(5, ([v]) => v! <= 0x10ffffn && !(v! >= 0xd800n && v! <= 0xdfffn));
    const terms = flag(2n);
    if (terms) {
      field(8); field(10);
      for (const tag of [12, 14, 16, 18]) field(tag, ([v]) => v! <= RUNE_U64_MAX);
    }
    etching = { fields: data, terms, turbo: flag(4n) };
    const supply = (data.get(6) ?? 0n) + (data.get(8) ?? 0n) * (data.get(10) ?? 0n);
    if (supply > RUNE_U128_MAX) flaw ??= 'supply_overflow';
  }
  const mintParts = take(20, 2, ([block, tx]) => block! <= RUNE_U64_MAX
    && tx! <= BigInt(RUNE_U32_MAX) && !(block === 0n && tx !== 0n));
  const mint = mintParts ? `${mintParts[0]}:${mintParts[1]}` : undefined;
  const pointerValue = take(22, 1, ([v]) => v! < BigInt(outputCount))?.[0];
  if (flags !== 0n) flaw ??= 'unrecognized_flag';
  if ([...fields.keys()].some(tag => tag % 2n === 0n)) flaw ??= 'unrecognized_even_tag';
  if (flaw) return { kind: 'cenotaph', flaw, ...(mint !== undefined ? { mint } : {}) };
  return { kind: 'runestone', edicts, ...(pointerValue !== undefined ? { pointer: Number(pointerValue) } : {}),
    ...(mint !== undefined ? { mint } : {}), ...(etching ? { etching } : {}) };
}

/** First OP_RETURN OP_13 wins, including a malformed first candidate. */
export function decodeRunestone(outputScripts: readonly Uint8Array[]): RuneArtifact {
  outputBounds(outputScripts);
  for (const script of outputScripts) {
    if (script[0] !== 0x6a || script[1] !== 0x5d) continue;
    const payload: number[] = [];
    for (let i = 2; i < script.length;) {
      const op = script[i++]!;
      let length: number;
      if (op <= 75) length = op;
      else if (op >= 76 && op <= 78) {
        const bytes = 1 << (op - 76);
        if (i + bytes > script.length) return { kind: 'cenotaph', flaw: 'invalid_script' };
        length = 0;
        for (let b = 0; b < bytes; b++) length += script[i++]! * 2 ** (8 * b);
      } else return { kind: 'cenotaph', flaw: 'opcode' };
      if (i + length > script.length) return { kind: 'cenotaph', flaw: 'invalid_script' };
      bound(payload.length + length <= RUNE_PROTOCOL_LIMITS.payloadBytes);
      for (const byte of script.subarray(i, i + length)) payload.push(byte);
      i += length;
    }
    return parsePayload(payload, outputScripts.length);
  }
  return { kind: 'absent' };
}

function writeVarint(value: bigint, target: number[]): void {
  assertRuneAtomic(value);
  do {
    const byte = Number(value & 0x7fn);
    value >>= 7n;
    target.push(byte | (value ? 0x80 : 0));
  } while (value);
}

/** Transfer-only encoder. Output index equal to outputCount has ord's distribution meaning. */
export function encodeRunestone(stone: { readonly edicts: readonly RuneEdict[]; readonly pointer?: number }, outputCount: number): Uint8Array {
  if (!Number.isInteger(outputCount) || outputCount < 1) throw new Error('Invalid output count');
  bound(outputCount <= RUNE_PROTOCOL_LIMITS.outputs && stone.edicts.length <= RUNE_PROTOCOL_LIMITS.edicts);
  const payload: number[] = [];
  if (stone.pointer !== undefined) {
    if (!Number.isInteger(stone.pointer) || stone.pointer < 0 || stone.pointer >= outputCount) throw new Error('Invalid Rune pointer');
    writeVarint(22n, payload); writeVarint(BigInt(stone.pointer), payload);
  }
  const sorted = stone.edicts.map(edict => ({ ...edict, parsed: parseRuneId(edict.id) }));
  sorted.sort((a, b) => a.parsed.block < b.parsed.block ? -1 : a.parsed.block > b.parsed.block ? 1 : a.parsed.tx - b.parsed.tx);
  let block = 0n;
  let tx = 0;
  if (sorted.length) payload.push(0);
  for (const edict of sorted) {
    if (!Number.isInteger(edict.output) || edict.output < 0 || edict.output > outputCount) throw new Error('Invalid edict output');
    writeVarint(edict.parsed.block - block, payload);
    writeVarint(BigInt(edict.parsed.block === block ? edict.parsed.tx - tx : edict.parsed.tx), payload);
    writeVarint(edict.amount, payload); writeVarint(BigInt(edict.output), payload);
    block = edict.parsed.block; tx = edict.parsed.tx;
  }
  bound(payload.length <= RUNE_PROTOCOL_LIMITS.payloadBytes);
  const prefix = [0x6a, 0x5d];
  if (payload.length) {
    if (payload.length <= 75) prefix.push(payload.length);
    else if (payload.length <= 255) prefix.push(76, payload.length);
    else prefix.push(77, payload.length & 255, payload.length >> 8);
  }
  return Uint8Array.from([...prefix, ...payload]);
}

export interface RuneBalance { readonly id: string; readonly amount: bigint }
export interface RuneAllocation {
  readonly artifact: RuneArtifact;
  readonly outputs: readonly ReadonlyMap<string, bigint>[];
  readonly burned: ReadonlyMap<string, bigint>;
}

/** Evaluate only existing input supply. Mint/etch requires index state and is rejected,
 * even on cenotaphs (ord can execute a valid mint before burning its result).
 */
export function evaluateRuneAllocations(outputScripts: readonly Uint8Array[], inputBalances: readonly RuneBalance[]): RuneAllocation {
  const artifact = decodeRunestone(outputScripts);
  if ((artifact.kind !== 'absent' && artifact.mint !== undefined)
    || (artifact.kind === 'runestone' && artifact.etching !== undefined)) throw new Error('Mint/etch allocation unsupported');
  bound(inputBalances.length <= RUNE_PROTOCOL_LIMITS.balances);
  const unallocated = new Map<string, bigint>();
  const outputs = outputScripts.map(() => new Map<string, bigint>());
  const burned = new Map<string, bigint>();
  function add(map: Map<string, bigint>, id: string, amount: bigint): void {
    if (amount !== 0n) map.set(id, assertRuneAtomic((map.get(id) ?? 0n) + amount));
  }
  for (const balance of inputBalances) {
    parseRuneId(balance.id);
    if (balance.id === '0:0') throw new Error('Etching sentinel is not an input Rune ID');
    add(unallocated, balance.id, assertRuneAtomic(balance.amount));
  }
  const destinations = outputScripts.flatMap((script, i) => script[0] === 0x6a ? [] : [i]);
  if (artifact.kind === 'cenotaph') {
    for (const [id, amount] of unallocated) add(burned, id, amount);
    return { artifact, outputs, burned };
  }
  function allocate(id: string, amount: bigint, output: number): void {
    const balance = unallocated.get(id) ?? 0n;
    const taken = amount < balance ? amount : balance;
    unallocated.set(id, balance - taken);
    add(outputScripts[output]![0] === 0x6a ? burned : outputs[output]!, id, taken);
  }
  if (artifact.kind === 'runestone') {
    for (const edict of artifact.edicts) {
      const balance = unallocated.get(edict.id) ?? 0n;
      if (balance === 0n || edict.id === '0:0') continue;
      if (edict.output === outputScripts.length) {
        if (!destinations.length) continue;
        if (edict.amount === 0n) {
          const each = balance / BigInt(destinations.length);
          const remainder = Number(balance % BigInt(destinations.length));
          for (const [i, output] of destinations.entries()) allocate(edict.id, each + (i < remainder ? 1n : 0n), output);
        } else for (const output of destinations) allocate(edict.id, edict.amount, output);
      } else allocate(edict.id, edict.amount === 0n ? balance : edict.amount, edict.output);
    }
  }
  const pointer = artifact.kind === 'runestone' ? artifact.pointer ?? destinations[0] : destinations[0];
  for (const [id, amount] of unallocated) {
    if (pointer === undefined) add(burned, id, amount);
    else allocate(id, amount, pointer);
  }
  return { artifact, outputs, burned };
}
