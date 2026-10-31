import { knownGroups } from "../../data/known-groups.svelte";
import { t } from "../../data/locale.svelte";

import { AUTOLIST_MODES, secondsToHours, type SettingValue } from "./settings";

export type Control =
  | {
      kind: "text";
      placeholder?: () => string;
      width?: string;
      suggest?: { label: () => string; value: string };
    }
  | { kind: "number"; unit?: () => string; width?: string }
  | { kind: "hours" }
  | { kind: "switch"; invert?: boolean; caption?: string }
  | { kind: "segment"; options: { value: string; label: () => string }[] }
  | { kind: "tags" }
  | { kind: "group" }
  | { kind: "iface" }
  | { kind: "names"; placeholder?: () => string };

export type Field = { key: string; label: () => string; control: Control };
export type Row = { label: () => string; hint: () => string; fields: Field[]; joiner?: string };
export type Section = { id: string; title: () => string; rows: Row[] };

const row = (label: () => string, hint: () => string, fields: Field[], joiner?: string): Row => ({
  label,
  hint,
  fields,
  joiner,
});

export const SECTIONS: Section[] = [
  {
    id: "dns",
    title: () => t("DNS proxy"),
    rows: [
      row(
        () => t("Upstream DNS"),
        () => t("Where the daemon forwards client queries"),
        [
          {
            key: "app.dnsProxy.upstream.address",
            label: () => t("Upstream DNS"),
            control: { kind: "text" },
          },
          {
            key: "app.dnsProxy.upstream.port",
            label: () => t("Upstream DNS port"),
            control: { kind: "number", width: "5.5rem" },
          },
        ],
      ),
      row(
        () => t("Drop AAAA"),
        () => t("For group domains, when IPv6 is not routed"),
        [
          {
            key: "app.dnsProxy.disableDropAAAA",
            label: () => t("Drop AAAA"),
            control: { kind: "switch", invert: true },
          },
        ],
      ),
      row(
        () => t("TTL of answers outside the rules"),
        () =>
          t(
            "How soon a newly enabled rule takes effect for devices that already asked for the name; 0 keeps the upstream's TTL",
          ),
        [
          {
            key: "app.dnsProxy.unmatchedTtl",
            label: () => t("TTL of answers outside the rules"),
            control: { kind: "number", unit: () => t("s") },
          },
        ],
      ),
      row(
        () => t("DNS stats"),
        () =>
          t(
            "Count the devices' queries over the last day for the Journal; off, it holds no memory",
          ),
        [
          {
            key: "app.dnsProxy.disableStats",
            label: () => t("DNS stats"),
            control: { kind: "switch", invert: true },
          },
        ],
      ),
      row(
        () => t("Query timeout"),
        () => t("How long to wait for the upstream DNS"),
        [
          {
            key: "app.dnsProxy.timeout",
            label: () => t("Query timeout"),
            control: { kind: "number", unit: () => t("ms") },
          },
        ],
      ),
      row(
        () => t("Concurrent queries"),
        () => t("Past the limit new queries are dropped"),
        [
          {
            key: "app.dnsProxy.maxConcurrent",
            label: () => t("Concurrent queries"),
            control: { kind: "number" },
          },
        ],
      ),
      row(
        () => t("Idle connections"),
        () => t("Kept open to the upstream DNS in reserve"),
        [
          {
            key: "app.dnsProxy.maxIdleConns",
            label: () => t("Idle connections"),
            control: { kind: "number" },
          },
        ],
      ),
      row(
        () => t("Proxy address"),
        () => t("Where the daemon listens for DNS"),
        [
          {
            key: "app.dnsProxy.host.address",
            label: () => t("Proxy address"),
            control: { kind: "text" },
          },
          {
            key: "app.dnsProxy.host.port",
            label: () => t("Proxy port"),
            control: { kind: "number", width: "5.5rem" },
          },
        ],
      ),
      row(
        () => t("Port 53 interception"),
        () => t("Redirect clients' DNS to the proxy"),
        [
          {
            key: "app.dnsProxy.disableRemap53",
            label: () => t("Port 53 interception"),
            control: { kind: "switch", invert: true },
          },
        ],
      ),
    ],
  },
  {
    id: "pool",
    title: () => t("Address pool"),
    rows: [
      row(
        () => t("TTL ceiling"),
        () => t("No client keeps an answer longer; the quarantine counts from it too"),
        [
          {
            key: "app.addressPool.ttlClamp",
            label: () => t("TTL ceiling"),
            control: { kind: "number", unit: () => t("s") },
          },
        ],
      ),
      row(
        () => t("Domains in the pool, at most"),
        () => t("Past the limit a blackhole address is issued"),
        [
          {
            key: "app.addressPool.maxNames",
            label: () => t("Domains in the pool, at most"),
            control: { kind: "number" },
          },
        ],
      ),
      row(
        () => t("IPv4 pool"),
        () => t("Range and a group's chunk size"),
        [
          {
            key: "app.addressPool.v4.pool",
            label: () => t("IPv4 pool"),
            control: { kind: "text" },
          },
          {
            key: "app.addressPool.v4.chunk",
            label: () => t("IPv4 pool chunk"),
            control: { kind: "number", width: "4.5rem" },
          },
        ],
        "/",
      ),
      row(
        () => t("IPv6 pool"),
        () => t("Empty means the generated ULA /48"),
        [
          {
            key: "app.addressPool.v6.pool",
            label: () => t("IPv6 pool"),
            control: { kind: "text", placeholder: () => t("auto") },
          },
          {
            key: "app.addressPool.v6.chunk",
            label: () => t("IPv6 pool chunk"),
            control: { kind: "number", width: "4.5rem" },
          },
        ],
        "/",
      ),
    ],
  },
  {
    id: "netfilter",
    title: () => t("Netfilter"),
    rows: [
      row(
        () => t("Address families"),
        () => t("Which ones kernel rules are written for"),
        [
          {
            key: "app.netfilter.disableIPv4",
            label: () => t("IPv4 rules"),
            control: { kind: "switch", invert: true, caption: "IPv4" },
          },
          {
            key: "app.netfilter.disableIPv6",
            label: () => t("IPv6 rules"),
            control: { kind: "switch", invert: true, caption: "IPv6" },
          },
        ],
      ),
      row(
        () => t("LAN interfaces"),
        () => t("Which interfaces traffic is intercepted on"),
        [{ key: "app.link", label: () => t("LAN interfaces"), control: { kind: "tags" } }],
      ),
      row(
        () => t("iptables chain prefix"),
        () => t("Every chain firc writes starts with it"),
        [
          {
            key: "app.netfilter.iptables.chainPrefix",
            label: () => t("iptables chain prefix"),
            control: { kind: "text" },
          },
        ],
      ),
      row(
        () => t("Starting mark and table index"),
        () => t("Change only if it clashes with other software"),
        [
          {
            key: "app.netfilter.startMarkTableIndex",
            label: () => t("Starting mark and table index"),
            control: { kind: "text" },
          },
        ],
      ),
    ],
  },
  {
    id: "autolist",
    title: () => t("Automatic list"),
    rows: [
      row(
        () => t("Look for sites that do not open"),
        () =>
          t(
            "Watches the TLS connections of the devices of the chosen group that go around the tunnel",
          ),
        [
          {
            key: "app.autolist.enabled",
            label: () => t("Look for sites that do not open"),
            control: { kind: "switch" },
          },
        ],
      ),
      row(
        () => t("What to do with what is found"),
        () => t("Suggest waits for your decision; Add by itself adds a site once it keeps failing"),
        [
          {
            key: "app.autolist.mode",
            label: () => t("What to do with what is found"),
            control: {
              kind: "segment",
              options: [
                { value: AUTOLIST_MODES[0], label: () => t("Suggest") },
                { value: AUTOLIST_MODES[1], label: () => t("Add by itself") },
              ],
            },
          },
        ],
      ),
      row(
        () => t("Group"),
        () =>
          t(
            "Where to add; watches only the devices it covers. A domain is added as example.com with its subdomains",
          ),
        [
          {
            key: "app.autolist.group",
            label: () => t("Group"),
            control: { kind: "group" },
          },
        ],
      ),
      row(
        () => t("Failures in a row"),
        () => t("How many failed connections make a domain a candidate, 1 to 20"),
        [
          {
            key: "app.autolist.failThreshold",
            label: () => t("Failures in a row"),
            control: { kind: "number", width: "5.5rem" },
          },
        ],
      ),
      row(
        () => t("Time between failures"),
        () => t("A longer pause starts the count over, 10 to 3600 seconds"),
        [
          {
            key: "app.autolist.failTime",
            label: () => t("Time between failures"),
            control: { kind: "number", unit: () => t("s") },
          },
        ],
      ),
      row(
        () => t("ClientHello resent"),
        () => t("How many repeats with no answer count as a failure, 1 to 8"),
        [
          {
            key: "app.autolist.retransThreshold",
            label: () => t("ClientHello resent"),
            control: { kind: "number", width: "5.5rem" },
          },
        ],
      ),
      row(
        () => t("Never add"),
        () => t("One domain a line; its subdomains are kept out too"),
        [
          {
            key: "app.autolist.exclude",
            label: () => t("Never add"),
            control: { kind: "names", placeholder: () => "example.com" },
          },
        ],
      ),
      row(
        () => t("Recheck added sites"),
        () =>
          t(
            "The router opens each added domain itself; one that opens is switched off until it is blocked again",
          ),
        [
          {
            key: "app.autolist.recheck",
            label: () => t("Recheck added sites"),
            control: { kind: "switch" },
          },
        ],
      ),
      row(
        () => t("Recheck every"),
        () => t("From 1 to 168 hours"),
        [
          {
            key: "app.autolist.recheckInterval",
            label: () => t("Recheck every"),
            control: { kind: "hours" },
          },
        ],
      ),
      row(
        () => t("Check through"),
        () =>
          t(
            "Which interface the router opens sites through: when rechecking, on the Not opening button and when a freeze is suspected",
          ),
        [
          {
            key: "app.autolist.checkInterface",
            label: () => t("Check through"),
            control: { kind: "iface" },
          },
        ],
      ),
    ],
  },
  {
    id: "check",
    title: () => t("Interface check"),
    rows: [
      row(
        () => t("Check URL"),
        () => t("A GET through each interface of a list; only a 204 answer counts as alive"),
        [
          {
            key: "app.check.url",
            label: () => t("Check URL"),
            control: {
              kind: "text",
              width: "18rem",
              suggest: {
                label: () => t("Cloudflare"),
                value: "http://cp.cloudflare.com/generate_204",
              },
            },
          },
        ],
      ),
      row(
        () => t("WAN check URL"),
        () =>
          t(
            "For the provider's interfaces and the control request. Empty means the same as the check URL. If the provider lets only some sites through (whitelists), give an allowed address",
          ),
        [
          {
            key: "app.check.wanUrl",
            label: () => t("WAN check URL"),
            control: {
              kind: "text",
              width: "18rem",
              placeholder: () => t("same as the check URL"),
              suggest: {
                label: () => t("Yandex"),
                value: "http://api.browser.yandex.ru/generate_204",
              },
            },
          },
        ],
      ),
      row(
        () => t("Check interval"),
        () => t("Seconds between two checks of one interface, 10 to 3600"),
        [
          {
            key: "app.check.interval",
            label: () => t("Check interval"),
            control: { kind: "number", unit: () => t("s") },
          },
        ],
      ),
      row(
        () => t("Check timeout"),
        () => t("Seconds a check may take, 1 to 30"),
        [
          {
            key: "app.check.timeout",
            label: () => t("Check timeout"),
            control: { kind: "number", unit: () => t("s") },
          },
        ],
      ),
    ],
  },
  {
    id: "webui",
    title: () => t("WebUI"),
    rows: [
      row(
        () => t("WebUI address"),
        () => t("Where this page is served"),
        [
          {
            key: "app.httpWeb.host.address",
            label: () => t("WebUI address"),
            control: { kind: "text" },
          },
          {
            key: "app.httpWeb.host.port",
            label: () => t("WebUI port"),
            control: { kind: "number", width: "5.5rem" },
          },
        ],
      ),
    ],
  },
  {
    id: "updates",
    title: () => t("Updates"),
    rows: [
      row(
        () => t("Check for updates daily"),
        () => t("Asks GitHub once a day; off by default"),
        [
          {
            key: "app.update.check",
            label: () => t("Check for updates daily"),
            control: { kind: "switch" },
          },
        ],
      ),
    ],
  },
];

export const FIELDS: Record<string, Field> = Object.fromEntries(
  SECTIONS.flatMap((s) => s.rows.flatMap((r) => r.fields)).map((f) => [f.key, f]),
);

export function formatValue(key: string, value: SettingValue | undefined): string {
  if (value === undefined || value === null) return "";
  const control = FIELDS[key]?.control;
  if (typeof value === "boolean") {
    const shown = control?.kind === "switch" && control.invert ? !value : value;
    return shown ? t("on") : t("off");
  }
  if (Array.isArray(value))
    return value.length === 0 && control?.kind === "names" ? t("none") : value.join(", ");
  if (control?.kind === "group") {
    if (value === "") return t("not chosen");
    return knownGroups.list.find((g) => g.id === value)?.name || String(value);
  }
  if (control?.kind === "iface" && value === "") return t("Default route");
  if (control?.kind === "hours" && typeof value === "number")
    return `${secondsToHours(value)} ${t("h")}`;
  if (value === "" && key === "app.addressPool.v6.pool") return t("auto");
  const unit = control?.kind === "number" && control.unit ? ` ${control.unit()}` : "";
  return `${value}${unit}`;
}
