import type { TunnelHeader } from "../../types";

export type HeaderKind = "default" | "changed" | "removed" | "added";
export type HeaderRow = { name: string; value: string; kind: HeaderKind };

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
const defaultOf = (defaults: readonly TunnelHeader[], name: string) =>
  defaults.find((d) => same(d.name, name));

export function headerRows(
  defaults: readonly TunnelHeader[],
  overrides: Record<string, string> = {},
): HeaderRow[] {
  const own = Object.entries(overrides);
  const rows: HeaderRow[] = defaults.map((d) => {
    const hit = own.find(([name]) => same(name, d.name));
    if (!hit) return { name: d.name, value: d.value, kind: "default" };
    if (hit[1] === "") return { name: hit[0], value: d.value, kind: "removed" };
    return { name: hit[0], value: hit[1], kind: hit[1] === d.value ? "default" : "changed" };
  });
  for (const [name, value] of own) {
    if (!defaultOf(defaults, name)) rows.push({ name, value, kind: "added" });
  }
  return rows;
}

export function overridesOf(rows: readonly HeaderRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const row of rows) {
    if (row.kind === "changed") out[row.name] = row.value;
    else if (row.kind === "removed") out[row.name] = "";
    else if (row.kind === "added" && row.name.trim() !== "") out[row.name.trim()] = row.value;
  }
  return out;
}

export function withValue(
  defaults: readonly TunnelHeader[],
  rows: readonly HeaderRow[],
  index: number,
  value: string,
): HeaderRow[] {
  return rows.map((row, i) => {
    if (i !== index) return row;
    if (row.kind === "added") return { ...row, value };
    const d = defaultOf(defaults, row.name);
    return { ...row, value, kind: d && d.value === value ? "default" : "changed" };
  });
}

export function withName(rows: readonly HeaderRow[], index: number, name: string): HeaderRow[] {
  return rows.map((row, i) => (i === index && row.kind === "added" ? { ...row, name } : row));
}

export function removed(
  defaults: readonly TunnelHeader[],
  rows: readonly HeaderRow[],
  index: number,
): HeaderRow[] {
  if (rows[index]?.kind === "added") return rows.filter((_, i) => i !== index);
  return rows.map((row, i) =>
    i === index
      ? {
          name: row.name,
          value: defaultOf(defaults, row.name)?.value ?? row.value,
          kind: "removed",
        }
      : row,
  );
}

export function restored(
  defaults: readonly TunnelHeader[],
  rows: readonly HeaderRow[],
  index: number,
): HeaderRow[] {
  return rows.map((row, i) =>
    i === index
      ? {
          name: row.name,
          value: defaultOf(defaults, row.name)?.value ?? row.value,
          kind: "default",
        }
      : row,
  );
}

export function added(rows: readonly HeaderRow[]): HeaderRow[] {
  return [...rows, { name: "", value: "", kind: "added" }];
}

export function changedCount(rows: readonly HeaderRow[]): number {
  return rows.filter((row) => row.kind !== "default").length;
}

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}$/;
const REFUSED = ["host", "content-length", "transfer-encoding", "connection"];
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const OWN_MAX = 16;
const VALUE_MAX = 512;

export function headersProblem(rows: readonly HeaderRow[], t: (key: string) => string): string {
  const names: string[] = [];
  for (const row of rows) {
    const name = row.name.trim();
    if (row.kind === "added" && name === "") {
      if (row.value !== "") return t("A header needs a name");
      continue;
    }
    if (row.kind !== "default") {
      if (!TOKEN.test(name))
        return t("A header name is 1 to 64 letters, digits or !#$%&'*+-.^_`|~");
      if (REFUSED.includes(name.toLowerCase()))
        return t("Header {name} is set by the fetch itself").replace("{name}", () => name);
      const value = row.kind === "removed" ? "" : row.value;
      if (new TextEncoder().encode(value).length > VALUE_MAX || CONTROL.test(value))
        return t("The value of {name} is up to 512 bytes without control characters").replace(
          "{name}",
          () => name,
        );
    }
    if (row.kind === "added" && names.some((n) => same(n, name)))
      return t("Header {name} is given twice").replace("{name}", () => name);
    names.push(name);
  }
  if (Object.keys(overridesOf(rows)).length > OWN_MAX) return t("At most 16 own headers");
  return "";
}
