import type { Tunnel, TunnelSource } from "../../types";
import { HttpError } from "../../utils/fetcher";
import { randomId } from "../../utils/random-id";

export const MAX_TUNNELS = 8 as const;

export type TunnelFieldError = { tunnel: string; field: string; error: string };

export type ClientTunnel = Tunnel & { key: string };

export function normalizeSource(source: Partial<TunnelSource>): TunnelSource {
  const { id, ...rest } = source;
  return { ...(id ? { id } : {}), ...rest, kind: source.kind ?? "link" } as TunnelSource;
}

export function withKey(tunnel: Tunnel): ClientTunnel {
  return { ...tunnel, key: randomId() };
}

export function plain(tunnels: readonly Tunnel[]): Tunnel[] {
  return tunnels.map((tn) => {
    const { key: _key, ...rest } = tn as ClientTunnel;
    return rest;
  });
}

export function normalizeTunnel(raw: Partial<Tunnel>): Tunnel {
  return {
    id: raw.id ?? "",
    device: raw.device ?? "",
    enable: raw.enable ?? true,
    active: raw.active ?? 1,
    by: raw.by ?? "connection",
    interval: raw.interval ?? 60,
    silence: raw.silence ?? 20,
    filter: raw.filter ?? "",
    order: [...(raw.order ?? [])],
    exclude: [...(raw.exclude ?? [])],
    sources: (raw.sources ?? []).map(normalizeSource),
    uplink: { kind: raw.uplink?.kind ?? "auto", ref: raw.uplink?.ref ?? "" },
    advanced: {
      ca: raw.advanced?.ca ?? "",
      insecure: raw.advanced?.insecure ?? false,
      timeout: raw.advanced?.timeout ?? 8,
    },
  };
}

export function freeDevice(tunnels: { device: string }[]): string {
  const used = new Set(tunnels.map((t) => t.device));
  for (let n = 0; n < 100; n++) if (!used.has(`tunvless${n}`)) return `tunvless${n}`;
  return "";
}

export function freeId(tunnels: { id: string }[]): string {
  const used = new Set(tunnels.map((t) => t.id));
  for (let n = 1; ; n++) if (!used.has(`tunnel${n}`)) return `tunnel${n}`;
}

export function defaultTunnel(existing: Tunnel[]): Tunnel {
  return normalizeTunnel({ id: freeId(existing), device: freeDevice(existing) });
}

export function savedNotApplied(error: unknown): boolean {
  if (!(error instanceof HttpError) || error.status !== 500) return false;
  try {
    return (JSON.parse(error.message) as { error?: string }).error === "saved, but not applied";
  } catch {
    return false;
  }
}

export function fieldRefusal(error: unknown): TunnelFieldError | null {
  if (!(error instanceof HttpError) || error.status !== 400) return null;
  try {
    const body = JSON.parse(error.message) as {
      error?: string;
      field?: string | null;
      tunnel?: string | null;
    };
    return {
      tunnel: body.tunnel ?? "",
      field: body.field ?? "",
      error: body.error ?? error.message,
    };
  } catch {
    return { tunnel: "", field: "", error: error.message };
  }
}

export function probeRefusal(error: unknown, t: (key: string) => string): string {
  if (error instanceof HttpError && error.status === 409) {
    let text = "";
    try {
      text = String((JSON.parse(error.message) as { error?: string }).error ?? "");
    } catch {
      text = error.message;
    }
    return text.includes("save first")
      ? t("Save the tunnel and let it start: it is checked through its own uplink")
      : t("A check is already running");
  }
  if (error instanceof HttpError && error.status === 400) {
    return fieldRefusal(error)?.error ?? t("Request failed");
  }
  return t("Request failed");
}
