import type { TunnelSubUsage } from "../../types";

type T = (key: string) => string;
export type UsageTone = "" | "orange" | "red";

export const EXPIRE_SOON_S = 3 * 86400;
export const USED_HIGH = 0.9;

function oneDecimal(n: number): string {
  return n.toFixed(1).replace(/\.0$/, "");
}

export function formatSize(bytes: number, t: T): string {
  const b = Math.max(0, bytes);
  if (b >= 2 ** 40) return t("{n} TB").replace("{n}", () => oneDecimal(b / 2 ** 40));
  if (b >= 2 ** 30) return t("{n} GB").replace("{n}", () => oneDecimal(b / 2 ** 30));
  if (b >= 2 ** 20) return t("{n} MB").replace("{n}", () => oneDecimal(b / 2 ** 20));
  return t("{n} KB").replace("{n}", () => oneDecimal(b / 2 ** 10));
}

function day(unix: number): string {
  const d = new Date(unix * 1000);
  const two = (n: number) => String(n).padStart(2, "0");
  return `${two(d.getDate())}.${two(d.getMonth() + 1)}.${d.getFullYear()}`;
}

export function trafficText(u: TunnelSubUsage, t: T): string {
  return u.total > 0
    ? t("{used} of {total}")
        .replace("{used}", () => formatSize(u.used, t))
        .replace("{total}", () => formatSize(u.total, t))
    : t("{used}, no limit").replace("{used}", () => formatSize(u.used, t));
}

export function expiryText(u: TunnelSubUsage, now: number, t: T): string {
  if (u.expire <= 0) return t("no end date");
  return t(u.expire <= now ? "ended {date}" : "until {date}").replace("{date}", () =>
    day(u.expire),
  );
}

export function trafficTone(u: TunnelSubUsage): UsageTone {
  if (u.total <= 0) return "";
  if (u.used >= u.total) return "red";
  return u.used >= u.total * USED_HIGH ? "orange" : "";
}

export function expiryTone(u: TunnelSubUsage, now: number): UsageTone {
  if (u.expire <= 0) return "";
  if (u.expire <= now) return "red";
  return u.expire - now <= EXPIRE_SOON_S ? "orange" : "";
}

export function usageAlert(
  u: TunnelSubUsage | null | undefined,
  now: number,
  t: T,
): { text: string; tone: Exclude<UsageTone, ""> } | null {
  if (!u) return null;
  const traffic = trafficTone(u);
  const expiry = expiryTone(u, now);
  if (expiry === "red") return { text: t("has ended"), tone: "red" };
  if (traffic === "red") return { text: t("traffic used up"), tone: "red" };
  if (expiry === "orange") {
    const days = Math.max(1, Math.ceil((u.expire - now) / 86400));
    return { text: t("ends in {n} d").replace("{n}", String(days)), tone: "orange" };
  }
  if (traffic === "orange") {
    const pct = Math.floor((u.used / u.total) * 100);
    return { text: t("{n}% of traffic used").replace("{n}", String(pct)), tone: "orange" };
  }
  return null;
}
