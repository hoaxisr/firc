export const POLICY_PREFIX = "policy:";
export const MAC_PREFIX = "mac:";

export function normalizeMac(text: string): string | null {
  const m =
    /^([0-9a-fA-F]{2})([:-])([0-9a-fA-F]{2})\2([0-9a-fA-F]{2})\2([0-9a-fA-F]{2})\2([0-9a-fA-F]{2})\2([0-9a-fA-F]{2})$/.exec(
      text,
    );
  if (m === null) return null;
  const octets = [m[1], m[3], m[4], m[5], m[6], m[7]].map((o) => o.toLowerCase());
  if (octets.every((o) => o === "00")) return null;
  return octets.join(":");
}

export function parseV4(text: string): number[] | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const bytes: number[] = [];
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes.push(value);
  }
  return bytes;
}

export function parseV6(text: string): number[] | null {
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const compressed = halves.length === 2;

  const groups: number[] = [];
  const push = (chunk: string, last: boolean): boolean => {
    if (last && chunk.includes(".")) {
      const v4 = parseV4(chunk);
      if (v4 === null) return false;
      groups.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      return true;
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(chunk)) return false;
    groups.push(parseInt(chunk, 16));
    return true;
  };

  const readHalf = (half: string, tail: boolean): number | null => {
    if (half === "") return 0;
    const chunks = half.split(":");
    for (let i = 0; i < chunks.length; i++) {
      /* an embedded v4 quad is only ever the final group */
      const last = tail && i === chunks.length - 1;
      if (!push(chunks[i], last)) return null;
    }
    return groups.length;
  };

  const before = readHalf(halves[0], !compressed);
  if (before === null) return null;
  if (compressed) {
    if (readHalf(halves[1], true) === null) return null;
    if (groups.length >= 8) return null; /* "::" must stand for at least one group */
  } else if (groups.length !== 8) {
    return null;
  }

  const filled = new Array(8).fill(0);
  for (let i = 0; i < before; i++) filled[i] = groups[i];
  for (let i = before; i < groups.length; i++) filled[8 - (groups.length - i)] = groups[i];

  const bytes: number[] = [];
  for (const group of filled) bytes.push(group >> 8, group & 0xff);
  return bytes;
}

function isV4Mapped(bytes: number[]): boolean {
  for (let i = 0; i < 10; i++) if (bytes[i] !== 0) return false;
  return bytes[10] === 0xff && bytes[11] === 0xff;
}

export function isValidDeviceEntry(text: string): boolean {
  if (text.startsWith(MAC_PREFIX)) return normalizeMac(text.slice(MAC_PREFIX.length)) !== null;

  if (text.startsWith(POLICY_PREFIX)) {
    const name = text.slice(POLICY_PREFIX.length);
    return name.length > 0 && !name.startsWith(" ") && !name.endsWith(" ");
  }

  const slash = text.indexOf("/");
  const addr = slash === -1 ? text : text.slice(0, slash);
  const bytes = addr.includes(":") ? parseV6(addr) : parseV4(addr);
  if (bytes === null) return false;

  const host = bytes.length * 8;
  let prefix = host;
  if (slash !== -1) {
    const rest = text.slice(slash + 1);
    if (!/^[0-9]+$/.test(rest)) return false;
    prefix = Number(rest);
    if (!Number.isFinite(prefix) || prefix > host) return false;
  }

  if (bytes.length === 16 && isV4Mapped(bytes) && prefix < 96) return false;

  return true;
}

export function invalidDeviceEntries(entries: string[]): string[] {
  return entries.filter((entry) => !isValidDeviceEntry(entry));
}
