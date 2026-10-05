export type LiveReason = "disabled" | "not-enabled" | "no-interface" | "not-written";

/* `liveReason` rides only with `live: false`. */
export type GroupLive = { live: boolean; liveReason?: LiveReason };

export type NetfilterState = {
  ok: boolean;
  firstWritePending?: boolean;
  error?: string;
  since?: number;
};

export type LiveKind =
  | "live"
  | "not-enabled"
  | "no-interface"
  | "not-written"
  | "disabled"
  | "unsaved"
  | "no-answer";

const REASONS: readonly string[] = ["disabled", "not-enabled", "no-interface", "not-written"];

export function liveKind(
  group: { enable: boolean },
  dirty: boolean,
  live: GroupLive | undefined,
  noAnswer = false,
): LiveKind | null {
  if (dirty) return "unsaved";
  if (noAnswer) return "no-answer";
  if (!group.enable) return "disabled";
  if (!live) return null;
  if (live.live) return "live";
  return live.liveReason && REASONS.includes(live.liveReason) ? live.liveReason : null;
}

export type LiveIcon =
  | "CircleCheck"
  | "CircleX"
  | "Unplug"
  | "RefreshCw"
  | "PowerOff"
  | "CircleDashed"
  | "CircleHelp";

export const LIVE_LOOK: Record<LiveKind, { icon: LiveIcon; color: string }> = {
  live: { icon: "CircleCheck", color: "var(--green)" },
  "not-enabled": { icon: "CircleX", color: "var(--red)" },
  "no-interface": { icon: "Unplug", color: "var(--orange)" },
  "not-written": { icon: "RefreshCw", color: "var(--orange)" },
  disabled: { icon: "PowerOff", color: "var(--text-2)" },
  unsaved: { icon: "CircleDashed", color: "var(--text-2)" },
  "no-answer": { icon: "CircleHelp", color: "var(--text-2)" },
};

export type LiveTooltip = {
  title: string;
  lines: string[];
  /* The committer's own error, shown monospace; absent when it sent none. */
  error?: string;
  footer: boolean;
};

type T = (key: string) => string;

export function liveTooltip(
  kind: LiveKind,
  /* `silentFor`: ms since the last answer, for "no-answer". */
  ctx: { iface: string; netfilter?: NetfilterState | null; silentFor?: number },
  t: T,
  clock: (unixSeconds: number) => string,
): LiveTooltip {
  const iface = (text: string) => text.replaceAll("{iface}", ctx.iface);
  switch (kind) {
    case "live":
      return {
        title: t("Working"),
        lines: [
          iface(
            t(
              "The group's rules are written into the router's kernel; its traffic goes through {iface}.",
            ),
          ),
        ],
        footer: true,
      };
    case "not-enabled":
      return {
        title: t("Did not come up — the daemon keeps trying"),
        lines: [
          t("The group could not be enabled. Until it comes up, its traffic goes direct."),
          t(
            "The daemon retries by itself: after 1 s, then less often, down to once a minute. If the icon does not turn green within a couple of minutes, the reason is in the Journal.",
          ),
        ],
        footer: true,
      };
    case "no-interface":
      return {
        title: iface(t("Waiting for interface {iface}")),
        lines: [
          iface(
            t(
              "Tunnel {iface} is off or not connected, so the group's sites do not open right now.",
            ),
          ),
          iface(
            t(
              "The group will start working by itself when {iface} comes up. Or choose another interface for it.",
            ),
          ),
        ],
        footer: true,
      };
    case "not-written": {
      const nf = ctx.netfilter;
      if (nf?.firstWritePending && !nf.error) {
        return {
          title: t("First write of the rules since start"),
          lines: [
            t(
              "The daemon has just started and is writing the rules. This usually takes a fraction of a second.",
            ),
          ],
          footer: true,
        };
      }
      const first =
        nf?.since !== undefined
          ? t(
              "Since {time} the router has not accepted firc's rules, and the daemon keeps rewriting them by itself. This usually happens while the firmware rebuilds its tables, and passes within a few seconds.",
            ).replace("{time}", clock(nf.since))
          : t(
              "The router is not accepting firc's rules, and the daemon keeps rewriting them by itself. This usually happens while the firmware rebuilds its tables, and passes within a few seconds.",
            );
      return {
        title: t("Rules are being rewritten"),
        lines: [
          first,
          t(
            "Until it passes, the group's traffic may go direct. If it lasts longer than a minute, open the Journal.",
          ),
        ],
        error: nf?.error || undefined,
        footer: true,
      };
    }
    case "disabled":
      return {
        title: t("Group off"),
        lines: [t("The group is switched off. Its names resolve as usual, without firc.")],
        footer: false,
      };
    case "unsaved":
      return {
        title: t("Changes not saved"),
        lines: [
          t(
            "The state will appear after saving: right now it would describe what is in the daemon, not what is on screen.",
          ),
        ],
        footer: false,
      };
    case "no-answer":
      return {
        title: t("No answer from the daemon"),
        lines: [
          t(
            "The page has had no answer from firc for {ago}. The groups' state is unknown: the router is rebooting, the daemon is stopped or the connection is lost. The page keeps asking by itself.",
          ).replace("{ago}", agoText(ctx.silentFor ?? 0, t)),
        ],
        footer: false,
      };
  }
}

export function agoText(ms: number, t: T): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  if (seconds < 60) return t("{n} s").replace("{n}", String(seconds));
  return t("{n} min").replace("{n}", String(Math.floor(seconds / 60)));
}

/* How long ago the last answer taken was asked for. */
export function checkedText(checkedAt: number, now: number, t: T): string {
  return t("Checked {ago} ago · updates by itself, no need to reload the page").replace(
    "{ago}",
    agoText(now - checkedAt, t),
  );
}
