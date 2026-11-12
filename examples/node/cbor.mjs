// Minimal CBOR (RFC 8949) for the subset a Common Access Token uses: integers, byte strings,
// text strings, arrays, maps, tags, and true/false/null.
//
// Encoding is deterministic (shortest-form integers and lengths, definite lengths only).
// Decoding is strict: it rejects anything an encoder following those rules would not produce,
// plus duplicate map keys and trailing data.
//
// CBOR maps are JavaScript Maps so integer keys stay integers.

export class Tagged {
  constructor(tag, value) {
    this.tag = tag;
    this.value = value;
  }
}

export function encode(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('only integers are supported');
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  if (value instanceof Map) {
    const parts = [head(5, value.size)];
    for (const [k, v] of value) parts.push(encode(k), encode(v));
    return Buffer.concat(parts);
  }
  if (value instanceof Tagged) return Buffer.concat([head(6, value.tag), encode(value.value)]);
  if (value === false) return Buffer.from([0xf4]);
  if (value === true) return Buffer.from([0xf5]);
  if (value === null) return Buffer.from([0xf6]);
  throw new Error(`cannot encode ${typeof value}`);
}

// The initial byte: major type in the top 3 bits, then the argument in its shortest form.
function head(major, n) {
  const m = major << 5;
  if (n < 24) return Buffer.from([m | n]);
  if (n < 0x100) return Buffer.from([m | 24, n]);
  if (n < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = m | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  if (n < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = m | 26;
    b.writeUInt32BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = m | 27;
  b.writeBigUInt64BE(BigInt(n), 1);
  return b;
}

// Decodes exactly one item and throws if anything follows it.
export function decode(bytes) {
  const data = Buffer.from(bytes);
  const state = { data, pos: 0 };
  const value = read(state);
  if (state.pos !== data.length) throw new Error('trailing data');
  return value;
}

function read(s) {
  const initial = byte(s);
  const major = initial >> 5;
  const info = initial & 0x1f;

  if (major === 7) {
    if (info === 20) return false;
    if (info === 21) return true;
    if (info === 22) return null;
    throw new Error('unsupported simple or floating-point value');
  }

  const n = argument(s, info);
  switch (major) {
    case 0:
      return n;
    case 1:
      return -1 - n;
    case 2:
      return take(s, n);
    case 3:
      return new TextDecoder('utf-8', { fatal: true }).decode(take(s, n));
    case 4: {
      const items = [];
      for (let i = 0; i < n; i++) items.push(read(s));
      return items;
    }
    case 5: {
      const map = new Map();
      for (let i = 0; i < n; i++) {
        const key = read(s);
        if (typeof key !== 'number' && typeof key !== 'string') throw new Error('unsupported map key');
        if (map.has(key)) throw new Error('duplicate map key');
        map.set(key, read(s));
      }
      return map;
    }
    default:
      return new Tagged(n, read(s));
  }
}

function argument(s, info) {
  if (info < 24) return info;
  if (info > 27) throw new Error('indefinite or reserved length');
  const size = 1 << (info - 24);
  const raw = take(s, size);
  const n = size === 8 ? raw.readBigUInt64BE() : BigInt(raw.readUIntBE(0, size));
  const smallest = [24n, 0x100n, 0x10000n, 0x100000000n][info - 24];
  if (n < smallest) throw new Error('integer not in shortest form');
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('integer too large');
  return Number(n);
}

function byte(s) {
  if (s.pos >= s.data.length) throw new Error('unexpected end of data');
  return s.data[s.pos++];
}

function take(s, n) {
  if (s.pos + n > s.data.length) throw new Error('unexpected end of data');
  const out = s.data.subarray(s.pos, s.pos + n);
  s.pos += n;
  return out;
}
