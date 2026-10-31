import type { AutolistCandidate } from "../types";
import { counted } from "./plural";

type Say = (key: string) => string;

function two(n: number): string {
  return String(n).padStart(2, "0");
}

function stamp(at: number): string {
  const d = new Date(at * 1000);
  return `${two(d.getDate())}.${two(d.getMonth() + 1)} ${two(d.getHours())}:${two(d.getMinutes())}`;
}

function reason(c: AutolistCandidate, t: Say, locale: string): string {
  if (c.why === "freeze") return t("froze after the first bytes");
  const base =
    c.why === "reset"
      ? t("reset the connection before the answer")
      : t("did not answer ClientHello");
  if (c.fails <= 0) return base;
  const times = counted(
    c.fails,
    locale,
    t("{n} time in a row"),
    t("{n} times in a row (2-4)"),
    t("{n} times in a row"),
  ).replace("{n}", String(c.fails));
  return `${base} ${times}`;
}

export function autolistTip(
  pattern: string,
  candidates: AutolistCandidate[],
  names: Map<string, string>,
  t: Say,
  locale: string,
): string {
  const c = candidates.find((x) => x.domain === pattern);
  const first = c
    ? t("Added automatically {time}: {host} {why} ({device}).")
        .replace("{time}", stamp(c.lastAt))
        .replace("{host}", c.host)
        .replace("{why}", reason(c, t, locale))
        .replace("{device}", c.clients.map((a) => names.get(a.toLowerCase()) ?? a).join(", "))
    : t("Added automatically for {host}.").replace("{host}", pattern);
  return `${first}\n${t("If you switch the rule off or change it, it becomes yours and the automation no longer touches it.")}`;
}
