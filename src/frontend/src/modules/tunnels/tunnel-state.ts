import type { TunnelStatus } from "../../types";

export type TunnelIcon =
  | "CircleCheck"
  | "LoaderCircle"
  | "CircleDashed"
  | "CircleX"
  | "Unplug"
  | "RotateCw"
  | "PowerOff"
  | "CircleHelp";

export const TUNNEL_STATUSES: readonly TunnelStatus[] = [
  "off",
  "starting",
  "up",
  "no_node",
  "backoff",
  "bad_config",
  "waiting",
  "uplink_down",
];

export type TunnelLook = { icon: TunnelIcon; color: string; label: string };

export function tunnelLook(
  state: { status: string; backoffS: number },
  t: (key: string) => string,
): TunnelLook {
  const n = Math.max(0, Math.floor(state.backoffS || 0));
  switch (state.status) {
    case "up":
      return { icon: "CircleCheck", color: "var(--green)", label: t("Running") };
    case "starting":
      return { icon: "LoaderCircle", color: "var(--text-2)", label: t("Starting") };
    case "waiting":
      return { icon: "CircleDashed", color: "var(--text-2)", label: t("No nodes") };
    case "no_node":
      return {
        icon: "Unplug",
        color: "var(--orange)",
        label: t(n > 0 ? "No node answers, retry in {n} s" : "No node answers").replace(
          "{n}",
          String(n),
        ),
      };
    case "backoff":
      return {
        icon: "RotateCw",
        color: "var(--orange)",
        label: t(n > 0 ? "Restart in {n} s" : "Restarting").replace("{n}", String(n)),
      };
    case "uplink_down":
      return { icon: "Unplug", color: "var(--orange)", label: t("Uplink unavailable") };
    case "bad_config":
      return { icon: "CircleX", color: "var(--red)", label: t("Configuration error") };
    case "off":
      return { icon: "PowerOff", color: "var(--text-2)", label: t("Off") };
    default:
      return { icon: "CircleHelp", color: "var(--text-2)", label: state.status };
  }
}
