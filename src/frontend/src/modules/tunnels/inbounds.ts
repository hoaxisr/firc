import type { Tunnel, TunnelInbound, TunnelInboundState } from "../../types";

export const MAX_INBOUNDS = 16 as const;
export const WHOLE_GROUP = "*" as const;
const FIRST_PORT = 1080 as const;

type T = (key: string) => string;
export type InboundRefusal = { index: number; field: string; text: string };

export function inboundRefusal(
  list: TunnelInbound[],
  others: { inbounds: TunnelInbound[] }[],
  link: string[],
  t: T = (key) => key,
): InboundRefusal | null {
  if (list.length > MAX_INBOUNDS) {
    return { index: MAX_INBOUNDS, field: `inbounds[${MAX_INBOUNDS}]`, text: t("at most 16 ports") };
  }
  for (const [index, ib] of list.entries()) {
    const refuse = (field: string, text: string) => ({
      index,
      field: `inbounds[${index}].${field}`,
      text,
    });
    if (link.length > 0 && !link.includes(ib.listen)) {
      return refuse(
        "listen",
        t("{iface} is not in the LAN list (app.link)").replace("{iface}", () => ib.listen),
      );
    }
    if (!Number.isInteger(ib.port) || ib.port < 1 || ib.port > 65535) {
      return refuse("port", t("a port from 1 to 65535"));
    }
    if (ib.port === 53 || (ib.port >= 3600 && ib.port <= 3699)) {
      return refuse("port", t("this port is firc's own"));
    }
    if (list.slice(0, index).some((o) => o.port === ib.port)) {
      return refuse("port", t("used twice in this tunnel"));
    }
    if (others.some((o) => o.inbounds.some((x) => x.port === ib.port && x.listen === ib.listen))) {
      return refuse("port", t("port used twice on this interface"));
    }
    if (ib.node === "") return refuse("node", t("choose a node"));
    if ((ib.user === "") !== (ib.password === "")) {
      return refuse("user", t("user and password: both or neither"));
    }
    if (ib.user.includes(":")) return refuse("user", t("no ':' in a user"));
  }
  return null;
}

export function inboundPortsByNode(tunnel: Pick<Tunnel, "inbounds">): Map<string, number[]> {
  const out = new Map<string, number[]>();
  for (const ib of tunnel.inbounds) out.set(ib.node, [...(out.get(ib.node) ?? []), ib.port]);
  return out;
}

export function nextInboundPort(list: TunnelInbound[]): number {
  const used = new Set(list.map((ib) => ib.port));
  let port = FIRST_PORT;
  while (used.has(port) || (port >= 3600 && port <= 3699)) port++;
  return port;
}

export type InboundLook = { text: string; tone: "green" | "red" | "orange" | "grey" };

export function inboundLook(state: TunnelInboundState["state"], listen: string, t: T): InboundLook {
  switch (state) {
    case "up":
      return { text: t("listens"), tone: "green" };
    case "busy":
      return { text: t("port is busy"), tone: "red" };
    case "no-node":
      return { text: t("node is gone"), tone: "orange" };
    case "no-address":
      return { text: t("{iface} has no IPv4").replace("{iface}", () => listen), tone: "orange" };
    case "not-lan":
      return {
        text: t("{iface} is not in the LAN list").replace("{iface}", () => listen),
        tone: "orange",
      };
    case "starting":
      return { text: t("starting"), tone: "grey" };
    default:
      return { text: t("tunnel is off"), tone: "grey" };
  }
}
