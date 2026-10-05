import { parseV4, parseV6 } from "./device-validators";

function isValidNamePattern(pattern: string, allowGlob: boolean): boolean {
  const folded = pattern.replace(/^[ \t]+|[ \t]+$/g, "").replace(/\.$/, "");
  if (folded === "") return false;
  if (folded.length > 253) return false;
  if (folded.startsWith(".")) return false;
  const labels = folded.split(".");
  const label = allowGlob ? /^[a-zA-Z0-9\-_*?]+$/ : /^[a-zA-Z0-9\-_]+$/;
  return labels.every((l) => l.length > 0 && l.length <= 63 && label.test(l));
}

export function isValidWildcard(pattern: string): boolean {
  return isValidNamePattern(pattern, true);
}

export function isValidDomain(pattern: string): boolean {
  return isValidNamePattern(pattern, false);
}

export function isValidNamespace(pattern: string): boolean {
  return isValidDomain(pattern);
}

export function isValidSubnet(pattern: string): boolean {
  const slash = pattern.indexOf("/");
  const addr = slash === -1 ? pattern : pattern.slice(0, slash);
  if (parseV4(addr) === null) return false;
  if (slash === -1) return true;
  const rest = pattern.slice(slash + 1);
  if (!/^[0-9]+$/.test(rest)) return false;
  return Number(rest) <= 32;
}

function isValidIPv6(ip: string): boolean {
  return parseV6(ip) !== null;
}

export function isValidSubnet6(pattern: string): boolean {
  const parts = pattern.split("/");
  if (parts.length === 1) {
    return isValidIPv6(parts[0]);
  }

  if (parts.length !== 2) return false;

  if (!/^[0-9]+$/.test(parts[1])) return false;
  if (Number(parts[1]) > 128) return false;

  return isValidIPv6(parts[0]);
}

const PCRE2_ONLY = /\(\?[>(]|\(\?[a-zA-Z-]+[):]|[*+?}]\+|\\[AzZKGhHRNX]|\\k<|\(\?R\)|\(\?[0-9]/;

export function isValidRegex(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return PCRE2_ONLY.test(pattern);
  }
}

const PORTS_MAX_SLOTS = 15;

export function isValidPorts(ports: string): boolean {
  if (ports === "") return true;
  let slots = 0;
  for (const entry of ports.split(",")) {
    const bounds = entry.split("-");
    if (bounds.length > 2) return false;
    const [low, high = low] = bounds;
    if (!/^[0-9]{1,5}$/.test(low) || !/^[0-9]{1,5}$/.test(high)) return false;
    const from = Number(low);
    const to = Number(high);
    if (from < 1 || to > 65535 || from > to) return false;
    slots += from === to ? 1 : 2;
    if (slots > PORTS_MAX_SLOTS) return false;
  }
  return true;
}

export const VALIDATOP_MAP: Record<string, (pattern: string) => boolean> = {
  regex: isValidRegex,
  wildcard: isValidWildcard,
  domain: isValidDomain,
  namespace: isValidNamespace,
  subnet: isValidSubnet,
  subnet6: isValidSubnet6,
};
