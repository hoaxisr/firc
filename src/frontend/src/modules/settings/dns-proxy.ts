export type DnsProxyState = {
  listening: boolean;
  port: number;
  proto: string;
  error: string;
  holder: { name: string; pid: number } | null;
};

export const DNS_POLL_MS = 10_000;
export const DNS_LISTENING_POLL_MS = 60_000;
export const DNS_SNOOZE_MS = 60_000;

export function warningShown(
  state: DnsProxyState | null,
  snoozedUntil: number,
  now: number,
  restarting: boolean,
): boolean {
  return state !== null && state.listening === false && now >= snoozedUntil && !restarting;
}

export function dnsPollMs(state: DnsProxyState | null): number {
  return state?.listening === true ? DNS_LISTENING_POLL_MS : DNS_POLL_MS;
}

export type DnsWarning = { taken: string; effect: string; todo: string; after: string };

export function dnsWarning(state: DnsProxyState, t: (key: string) => string): DnsWarning {
  const where = `${state.port}/${state.proto}`;
  const holder = state.holder;
  const taken = holder
    ? t("Port {port} is taken by {name} (pid {pid}).")
        .replace("{port}", () => where)
        .replace("{name}", () => holder.name)
        .replace("{pid}", () => String(holder.pid))
    : t("Port {port} is taken by another program.").replace("{port}", () => where);
  const todo = holder
    ? t("Stop {name}, or give firc another DNS proxy port in Settings and restart firc.").replace(
        "{name}",
        () => holder.name,
      )
    : t("Stop that program, or give firc another DNS proxy port in Settings and restart firc.");
  return {
    taken,
    effect: t(
      "firc is running, but it answers no DNS: no new name gets a fake address, so name rules do not apply. Subnet rules and addresses already handed out still route.",
    ),
    todo,
    after: t(
      "firc takes the port by itself within seconds once it is free, and this warning goes away.",
    ),
  };
}
