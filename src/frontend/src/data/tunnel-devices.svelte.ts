import type { TunnelsRes } from "../types";
import { fetcher } from "../utils/fetcher";

export const tunnelDevices = $state({ list: [] as { device: string }[] });

let pending: Promise<void> | null = null;

export function loadTunnelDevices(): Promise<void> {
  pending ??= fetcher
    .get<TunnelsRes>("/tunnels", { quiet: true })
    .then((answer) => {
      tunnelDevices.list = (answer.tunnels ?? []).map((tn) => ({ device: tn.device }));
    })
    .catch(() => {})
    .finally(() => {
      pending = null;
    });
  return pending;
}
