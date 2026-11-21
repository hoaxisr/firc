import { parseV4, parseV6 } from "./device-validators";

export type ResolverAddrProblem = "syntax" | "port" | "sink" | "mapped";

export type ResolverListProblem = ResolverAddrProblem | "url" | "empty" | "too-many" | "duplicate";

export const MAX_RESOLVERS = 4;
const MAX_URL_BYTES = 255;

function dohKey(text: string): { key: string } | { problem: "url" } {
  const m = /^https:\/\/(\[[0-9a-fA-F:.]+\]|[^\s/:@[\]?#]+)(?::([0-9]+))?(\/[^\s?#]*)$/i.exec(text);
  if (m === null || new TextEncoder().encode(text).length > MAX_URL_BYTES)
    return { problem: "url" };
  if (m[2] !== undefined && (Number(m[2]) < 1 || Number(m[2]) > 65535)) return { problem: "url" };
  if (m[1].startsWith("[") && parseV6(m[1].slice(1, -1)) === null) return { problem: "url" };
  return { key: text };
}

function parseResolver(text: string): { key: string } | { problem: ResolverAddrProblem } {
  if (text === "") return { problem: "syntax" };
  let host: string;
  let port: string | null = null;
  let v6Only = false;
  if (text.startsWith("[")) {
    const close = text.indexOf("]");
    if (close < 0) return { problem: "syntax" };
    host = text.slice(1, close);
    const rest = text.slice(close + 1);
    if (rest.startsWith(":")) port = rest.slice(1);
    else if (rest !== "") return { problem: "syntax" };
    v6Only = true;
  } else {
    const first = text.indexOf(":");
    if (first >= 0 && first === text.lastIndexOf(":")) {
      host = text.slice(0, first);
      port = text.slice(first + 1);
    } else {
      host = text;
    }
  }
  if (host === "") return { problem: "syntax" };
  let bytes = v6Only ? null : parseV4(host);
  const v6 = bytes === null;
  if (bytes === null) bytes = parseV6(host);
  if (bytes === null) return { problem: "syntax" };
  if (port !== null) {
    const n = Number(port);
    if (!/^[0-9]{1,5}$/.test(port) || n < 1 || n > 65535) {
      const looksLikeAPort = port.length > 0 && /^[+-]?[0-9]*$/.test(port);
      return { problem: looksLikeAPort ? "port" : "syntax" };
    }
  }
  if (v6 && bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return { problem: "mapped" };
  }
  if (!v6 && (bytes.every((b) => b === 0) || bytes[0] === 127)) return { problem: "sink" };
  if (v6 && bytes.slice(0, 15).every((b) => b === 0) && (bytes[15] === 0 || bytes[15] === 1))
    return { problem: "sink" };
  return { key: `${bytes.join(".")}#${port === null ? 53 : Number(port)}` };
}

export function resolverAddrProblem(text: string): ResolverAddrProblem | null {
  const r = parseResolver(text);
  return "problem" in r ? r.problem : null;
}

export function resolverListProblem(
  text: string,
): { problem: ResolverListProblem; entry: string } | null {
  const entries = text.split(",").map((e) => e.replace(/^[ \t]+|[ \t]+$/g, ""));
  const seen: string[] = [];
  for (const [i, entry] of entries.entries()) {
    if (entry === "") return { problem: "empty", entry: "" };
    if (i === MAX_RESOLVERS) return { problem: "too-many", entry: "" };
    const r = entry.includes("://") ? dohKey(entry) : parseResolver(entry);
    if ("problem" in r) return { problem: r.problem, entry };
    if (seen.includes(r.key)) return { problem: "duplicate", entry };
    seen.push(r.key);
  }
  return null;
}
