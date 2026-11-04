import { DNS_SNOOZE_MS, type DnsProxyState } from "../modules/settings/dns-proxy";
import { fetcher } from "../utils/fetcher";

export const dnsProxy = $state({
  state: null as DnsProxyState | null,
  snoozedUntil: 0,
  now: Date.now(),
});

export async function loadDnsProxy(): Promise<void> {
  try {
    dnsProxy.state = await fetcher.get<DnsProxyState>("/system/dnsproxy", { quiet: true });
  } catch {
    return;
  } finally {
    dnsProxy.now = Date.now();
  }
}

let wake: ReturnType<typeof setTimeout> | undefined;

export function snoozeDnsWarning(): void {
  dnsProxy.now = Date.now();
  dnsProxy.snoozedUntil = dnsProxy.now + DNS_SNOOZE_MS;
  clearTimeout(wake);
  wake = setTimeout(() => (dnsProxy.now = Date.now()), DNS_SNOOZE_MS);
}
