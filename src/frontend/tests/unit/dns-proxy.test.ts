import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import ru from "../../src/locales/ru.json" with { type: "json" };
import {
  DNS_LISTENING_POLL_MS,
  DNS_POLL_MS,
  dnsPollMs,
  dnsWarning,
  warningShown,
  type DnsProxyState,
} from "../../src/modules/settings/dns-proxy.ts";

const t = (key: string) => key;
const tr = (key: string) => (ru as Record<string, string>)[key] ?? `MISSING ${key}`;

const down = (over: Partial<DnsProxyState> = {}): DnsProxyState => ({
  listening: false,
  port: 3553,
  proto: "udp",
  error: "[::]:3553/udp: address already in use by socat (pid 812)",
  holder: { name: "socat", pid: 812 },
  ...over,
});

describe("the DNS proxy warning", () => {
  // Catches a warning over a listening proxy, one with no answer at all, or a snooze that never ends or never starts.
  it("shows while the proxy is down and the snooze is over", () => {
    assert.strictEqual(warningShown(null, 0, 1000, false), false);
    assert.strictEqual(
      warningShown(down({ listening: true, holder: null }), 0, 1000, false),
      false,
    );
    assert.strictEqual(warningShown(down(), 0, 1000, false), true);
    assert.strictEqual(warningShown(down(), 1001, 1000, false), false);
    assert.strictEqual(warningShown(down(), 1000, 1000, false), true);
  });

  // Catches the warning drawn over the restart overlay, where its last answer is stale.
  it("stays under the restart overlay", () => {
    assert.strictEqual(warningShown(down(), 0, 1000, true), false);
  });

  // Catches a fast poll left running once the proxy listens, or a slow one while it does not.
  it("polls fast only while the proxy is down or unknown", () => {
    assert.strictEqual(dnsPollMs(null), DNS_POLL_MS);
    assert.strictEqual(dnsPollMs(down()), DNS_POLL_MS);
    assert.strictEqual(dnsPollMs(down({ listening: true, holder: null })), DNS_LISTENING_POLL_MS);
    assert.ok(DNS_LISTENING_POLL_MS > DNS_POLL_MS);
  });

  // Catches the port, protocol, program or pid missing from the line, or the advice not naming the program.
  it("names the port and the program that holds it", () => {
    const w = dnsWarning(down({ port: 13553, proto: "tcp" }), t);
    assert.strictEqual(w.taken, "Port 13553/tcp is taken by socat (pid 812).");
    assert.strictEqual(
      w.todo,
      "Stop socat, or give firc another DNS proxy port in Settings and restart firc.",
    );
  });

  // Catches an empty name or "pid undefined" when /proc did not show the holder.
  it("says another program when the holder is unknown", () => {
    const w = dnsWarning(down({ holder: null }), t);
    assert.strictEqual(w.taken, "Port 3553/udp is taken by another program.");
    assert.strictEqual(
      w.todo,
      "Stop that program, or give firc another DNS proxy port in Settings and restart firc.",
    );
  });

  // Catches a Russian page left with English text or with an unfilled placeholder.
  it("is translated, with every placeholder filled", () => {
    for (const state of [down(), down({ holder: null })]) {
      for (const line of Object.values(dnsWarning(state, tr))) {
        assert.ok(!line.startsWith("MISSING"), line);
        assert.ok(!/\{[a-z]+\}/.test(line), line);
      }
    }
    assert.strictEqual(
      dnsWarning(down(), tr).taken,
      "Порт 3553/udp занят программой socat (pid 812).",
    );
  });
});
