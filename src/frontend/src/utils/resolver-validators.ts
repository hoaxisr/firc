import { parseV4, parseV6 } from "./device-validators";

export type ResolverAddrProblem = "syntax" | "port" | "sink" | "mapped";

export function resolverAddrProblem(text: string): ResolverAddrProblem | null {
  if (text === "") return "syntax";
  let host: string;
  let port: string | null = null;
  let v6Only = false;
  if (text.startsWith("[")) {
    const close = text.indexOf("]");
    if (close < 0) return "syntax";
    host = text.slice(1, close);
    const rest = text.slice(close + 1);
    if (rest.startsWith(":")) port = rest.slice(1);
    else if (rest !== "") return "syntax";
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
  if (host === "") return "syntax";
  let bytes = v6Only ? null : parseV4(host);
  const v6 = bytes === null;
  if (bytes === null) bytes = parseV6(host);
  if (bytes === null) return "syntax";
  if (port !== null) {
    const n = Number(port);
    if (!/^[0-9]{1,5}$/.test(port) || n < 1 || n > 65535) {
      const looksLikeAPort = port.length > 0 && /^[+-]?[0-9]*$/.test(port);
      return looksLikeAPort ? "port" : "syntax";
    }
  }
  if (v6 && bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return "mapped";
  }
  if (!v6 && (bytes.every((b) => b === 0) || bytes[0] === 127)) return "sink";
  if (v6 && bytes.slice(0, 15).every((b) => b === 0) && (bytes[15] === 0 || bytes[15] === 1))
    return "sink";
  return null;
}
