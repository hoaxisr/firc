import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import type { BypassEvent, DnsEvent, LogEvent } from "../../src/data/events.svelte";

import {
  describeBypassTail,
  describeDns,
  describeDnsTail,
  groupFilterOptions,
  matches,
  matchesQuery,
  type JournalFilter,
} from "../../src/modules/logs/journal";

const id = (s: string) => s;
const stamp = (_at: number) => "12:00:03";
const bypass = (o: Partial<BypassEvent>): BypassEvent => ({
  seq: 1,
  at: 0,
  kind: "bypass",
  client: "192.168.1.42",
  dst: "142.250.1.1",
  port: 443,
  proto: "udp",
  how: "addr",
  name: "cdn.example.net",
  group: { id: "g1", name: "media" },
  last: { decision: "issued", at: 1789647203, fake: "198.18.0.5" },
  repeats: 0,
  ...o,
});
const dns = (o: Partial<DnsEvent>): DnsEvent => ({
  seq: 1,
  at: 0,
  kind: "dns",
  client: "192.168.1.42",
  name: "youtube.com",
  qtype: "A",
  rcode: "NOERROR",
  decision: "issued",
  group: { id: "g1", name: "media" },
  fake: "198.18.0.5",
  reals: ["142.250.1.1"],
  ...o,
});
const log = (o: Partial<LogEvent>): LogEvent => ({
  seq: 2,
  at: 0,
  kind: "log",
  level: "info",
  message: "netfilter rebuilt",
  ...o,
});
const all = (o: Partial<JournalFilter> = {}): JournalFilter => ({
  kinds: new Set(["log", "dns", "bypass"]),
  minLevel: "trace",
  group: "",
  ...o,
});

describe("journal filter", () => {
  it("keeps only the kinds asked for", () => {
    assert.strictEqual(matches(dns({}), all({ kinds: new Set(["log"]) })), false);
    assert.strictEqual(matches(log({}), all({ kinds: new Set(["log"]) })), true);
  });
  it("applies the level to log events only", () => {
    assert.strictEqual(matches(log({ level: "debug" }), all({ minLevel: "info" })), false);
    assert.strictEqual(matches(dns({}), all({ minLevel: "error" })), true);
  });
  it("matches a group by id, and hides log lines while it is set", () => {
    assert.strictEqual(matches(dns({}), all({ group: "g1" })), true);
    assert.strictEqual(matches(dns({ group: undefined }), all({ group: "g1" })), false);
    assert.strictEqual(matches(log({}), all({ group: "g1" })), false);
  });
  it("keeps the bypass kind only when it is asked for", () => {
    assert.strictEqual(matches(bypass({}), all({ kinds: new Set(["dns"]) })), false);
    assert.strictEqual(matches(bypass({}), all({ kinds: new Set(["bypass"]) })), true);
  });
  it("applies the group filter to a bypass event too", () => {
    assert.strictEqual(matches(bypass({}), all({ group: "g1" })), true);
    assert.strictEqual(matches(bypass({ group: undefined }), all({ group: "g1" })), false);
  });
});

describe("matchesQuery", () => {
  it("matches a client by substring, case-insensitively", () => {
    assert.strictEqual(matchesQuery(dns({ client: "192.168.1.42" }), "168.1.4"), true);
    assert.strictEqual(matchesQuery(dns({ client: "192.168.1.42" }), "10.0.0"), false);
    assert.strictEqual(matchesQuery(dns({ client: "2001:DB8::1" }), "db8"), true);
  });
  it("matches a name by substring, case-insensitively", () => {
    assert.strictEqual(matchesQuery(dns({ name: "youtube.com" }), "TUBE"), true);
    assert.strictEqual(matchesQuery(dns({ name: "youtube.com" }), "ya.ru"), false);
  });
  it("matches a bypass event's client or name the same way", () => {
    assert.strictEqual(matchesQuery(bypass({ client: "192.168.1.42" }), "192.168.1.42"), true);
    assert.strictEqual(matchesQuery(bypass({ name: "cdn.example.net" }), "EXAMPLE"), true);
    assert.strictEqual(matchesQuery(bypass({}), "10.0.0.1"), false);
  });
  it("matches a log event's message, not its client or name -- it has none", () => {
    assert.strictEqual(matchesQuery(log({ message: "netfilter rebuilt" }), "rebuilt"), true);
    assert.strictEqual(matchesQuery(log({ message: "netfilter rebuilt" }), "REBUILT"), true);
    assert.strictEqual(matchesQuery(log({ message: "netfilter rebuilt" }), "youtube"), false);
  });
  it("matches everything when the query is empty or blank", () => {
    assert.strictEqual(matchesQuery(dns({}), ""), true);
    assert.strictEqual(matchesQuery(log({}), "   "), true);
    assert.strictEqual(matchesQuery(bypass({}), ""), true);
  });
});

describe("describeBypassTail", () => {
  it("says what firc last issued and that the client did not use it", () => {
    assert.strictEqual(
      describeBypassTail(bypass({}), id, stamp),
      "→ 142.250.1.1:443/udp · media · by address · firc issued 198.18.0.5 at 12:00:03, the client did not use it",
    );
  });
  it("says firc remembers no question from this address, without promising a full 30 minutes", () => {
    assert.strictEqual(
      describeBypassTail(bypass({ last: undefined }), id, stamp),
      "→ 142.250.1.1:443/udp · media · by address · firc remembers no question from this address (it keeps 30 minutes at most)",
    );
  });
  it("says an issued answer carried no address of the flow's family", () => {
    assert.strictEqual(
      describeBypassTail(bypass({ last: { decision: "issued", at: 1789647203 } }), id, stamp),
      "→ 142.250.1.1:443/udp · media · by address · firc issued, but no address of this family at 12:00:03",
    );
  });
  it("says what firc answered when the last answer was not issued", () => {
    assert.strictEqual(
      describeBypassTail(bypass({ last: { decision: "not-covered", at: 1789647203 } }), id, stamp),
      "→ 142.250.1.1:443/udp · media · by address · firc answered not-covered at 12:00:03",
    );
  });
  it("counts the flows folded into this one since the last event", () => {
    assert.strictEqual(
      describeBypassTail(bypass({ repeats: 3 }), id, stamp),
      "→ 142.250.1.1:443/udp · media · by address · firc issued 198.18.0.5 at 12:00:03, the client did not use it (×3)",
    );
  });
  it("says a ClientHello was judged by SNI, not by address", () => {
    const line = describeBypassTail(bypass({ how: "sni", name: "news.example.com" }), id, stamp);
    assert.match(line, /by SNI/);
    assert.doesNotMatch(line, /by address/);
  });
  it("omits the group when the name belongs to none", () => {
    assert.strictEqual(
      describeBypassTail(bypass({ group: undefined }), id, stamp),
      "→ 142.250.1.1:443/udp · by address · firc issued 198.18.0.5 at 12:00:03, the client did not use it",
    );
  });
  it("omits the port for a protocol that has none", () => {
    assert.strictEqual(
      describeBypassTail(bypass({ port: undefined, proto: "icmp" }), id, stamp),
      "→ 142.250.1.1/icmp · media · by address · firc issued 198.18.0.5 at 12:00:03, the client did not use it",
    );
  });
});

describe("describeDns", () => {
  it("says what was issued, and for what", () => {
    assert.strictEqual(
      describeDns(dns({}), id),
      "youtube.com A → media · issued 198.18.0.5 (142.250.1.1)",
    );
  });
  it("says an issued name got no address of the queried family", () => {
    assert.strictEqual(
      describeDns(dns({ fake: undefined, reals: ["2001:db8::1"] }), id),
      "youtube.com A → media · issued, but no address of this family in the answer",
    );
  });
  it("says a name matched no group", () => {
    assert.strictEqual(
      describeDns(dns({ decision: "no-match", group: undefined, fake: undefined, reals: [] }), id),
      "youtube.com A → no group, answered as is",
    );
  });
  it("says the client is outside the group's devices", () => {
    assert.strictEqual(
      describeDns(dns({ decision: "not-covered", fake: undefined }), id),
      "youtube.com A → media · this client is not in the group's devices",
    );
  });
  // pool-refused covers both exhaustion and failed allocation; the wording must be true of both.
  it("says the pool refused", () => {
    assert.strictEqual(
      describeDns(dns({ decision: "pool-refused", fake: "198.18.255.255" }), id),
      "youtube.com A → media · pool refused, answered 198.18.255.255",
    );
  });
  it("says a failed answer was passed with its rcode", () => {
    assert.strictEqual(
      describeDns(
        dns({
          decision: "passed",
          rcode: "NXDOMAIN",
          group: undefined,
          fake: undefined,
          reals: [],
        }),
        id,
      ),
      "youtube.com A → passed, NXDOMAIN",
    );
    assert.strictEqual(
      describeDns(dns({ decision: "passed", qtype: "HTTPS", fake: undefined, reals: [] }), id),
      "youtube.com HTTPS → media · address hints removed",
    );
    assert.strictEqual(
      describeDns(dns({ decision: "passed", qtype: "MX", fake: undefined, reals: [] }), id),
      "youtube.com MX → media · passed, no address in the answer",
    );
  });
});

describe("describeDnsTail", () => {
  it("is everything after the name", () => {
    const e = dns({ name: "a.very.long.name.example" });
    assert.strictEqual(describeDnsTail(e, id), "A → media · issued 198.18.0.5 (142.250.1.1)");
    assert.strictEqual(describeDns(e, id), `a.very.long.name.example ${describeDnsTail(e, id)}`);
  });
});

describe("describeDns, where the answer came from", () => {
  // Catches the common upstream's ordinary answer growing a note, a group answer unsaid, or a fallback without a reason.
  it("says nothing for the common upstream and names the rest", () => {
    assert.strictEqual(
      describeDns(dns({}), id),
      "youtube.com A → media · issued 198.18.0.5 (142.250.1.1)",
    );
    assert.strictEqual(
      describeDns(dns({ resolver: "upstream" }), id),
      "youtube.com A → media · issued 198.18.0.5 (142.250.1.1)",
    );
    assert.strictEqual(
      describeDns(dns({ resolver: "group" }), id),
      "youtube.com A → media · issued 198.18.0.5 (142.250.1.1) · via the group's DNS",
    );
    assert.strictEqual(
      describeDns(dns({ resolver: "fallback_timeout" }), id),
      "youtube.com A → media · issued 198.18.0.5 (142.250.1.1) · the group's DNS did not answer in time; the common upstream answered",
    );
    for (const r of [
      "fallback_unreachable",
      "fallback_servfail",
      "fallback_refused",
      "fallback_sink",
      "health_skip",
    ] as const) {
      assert.match(describeDns(dns({ resolver: r }), id), /the common upstream answered$/, r);
    }
  });
  // Catches a cache hit unsaid, or said as a fallback.
  it("names an answer from the group's DNS cache", () => {
    assert.strictEqual(
      describeDns(dns({ resolver: "cache" }), id),
      "youtube.com A → media · issued 198.18.0.5 (142.250.1.1) · from the group's DNS cache",
    );
  });
});

describe("the group filter's options", () => {
  const ru = (k: string) => ({ "any group": "любая группа", "(deleted)": "(удалена)" })[k] ?? k;
  const known = [
    { id: "a", name: "media" },
    { id: "b", name: "work" },
  ];

  // Catches the daemon's groups not offered with an empty buffer, or "any group" not first.
  it("offers every group the daemon holds, with nothing seen", () => {
    assert.deepStrictEqual(groupFilterOptions(known, [], ru), [
      { value: "", label: "любая группа" },
      { value: "a", label: "media" },
      { value: "b", label: "work" },
    ]);
  });

  // Catches a seen group listed twice or under its old name, or a vanished one dropped or unmarked.
  it("adds the groups only the journal has seen, marked deleted", () => {
    const seen = [
      { id: "b", name: "work (old name)" },
      { id: "c", name: "gone" },
    ];
    assert.deepStrictEqual(groupFilterOptions(known, seen, ru), [
      { value: "", label: "любая группа" },
      { value: "a", label: "media" },
      { value: "b", label: "work" },
      { value: "c", label: "gone (удалена)" },
    ]);
  });

  // Catches every seen group called deleted just because the daemon's list has not arrived.
  it("marks nothing deleted while the daemon's groups are unknown", () => {
    assert.deepStrictEqual(groupFilterOptions(null, [{ id: "c", name: "gone" }], ru), [
      { value: "", label: "любая группа" },
      { value: "c", label: "gone" },
    ]);
  });
});
