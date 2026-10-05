type T = (key: string) => string;

export const MANUAL = 0;

export type IntervalOption = { value: string; label: string; description?: string };

export function intervalOptions(t: T): IntervalOption[] {
  return [
    { value: "3600", label: t("once an hour") },
    { value: "21600", label: t("every 6 hours") },
    { value: "86400", label: t("once a day") },
    { value: "604800", label: t("once a week") },
    {
      value: String(MANUAL),
      label: t("manually"),
      description: t("once after each daemon start"),
    },
  ];
}

export function intervalLabel(seconds: number, t: T): string {
  const known = intervalOptions(t).find((o) => o.value === String(seconds));
  if (known) return known.label;
  if (seconds % 86400 === 0) return t("every {n} d").replace("{n}", String(seconds / 86400));
  if (seconds % 3600 === 0) return t("every {n} h").replace("{n}", String(seconds / 3600));
  if (seconds % 60 === 0) return t("every {n} min").replace("{n}", String(seconds / 60));
  return t("every {n} s").replace("{n}", String(seconds));
}

export function intervalOptionsFor(current: number, t: T): IntervalOption[] {
  const options = intervalOptions(t);
  if (options.some((o) => o.value === String(current))) return options;
  return [...options, { value: String(current), label: intervalLabel(current, t) }];
}

export function parseIntervalSeconds(value: string): number | null {
  if (value.trim() === "") return null;
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0) return null;
  return next;
}
