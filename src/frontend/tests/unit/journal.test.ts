import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import type { BypassEvent, DnsEvent, LogEvent } from "../../src/data/events.svelte";

import {
  DEFAULT_LEVELS,
  describeBypassTail,
  describeDns,
  describeDnsTail,
  deviceNames,
  groupFilterOptions,
  matches,
  matchesQuery,
  sourceCounts,
  sourceOf,
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
  source: "fircd",
  message: "netfilter rebuilt",
  ...o,
});
const all = (o: Partial<JournalFilter> = {}): JournalFilter => ({
  sources: new Set(["fircd", "tunnels", "dns", "bypass"]),
  levels: new Set(["debug", "info", "warn", "error"]),
  group: "",
  ...o,
});

describe("journal filter", () => {
  // Catches a tunnel's line counted as fircd's, or fircd's as a tunnel's.
  it("files a log line under fircd or the tunnels by its source", () => {
    assert.strictEqual(sourceOf(log({ source: "fircd" })), "fircd");
    assert.strictEqual(sourceOf(log({ source: "tunvless0" })), "tunnels");
    assert.strictEqual(sourceOf(log({ source: "tunvless12" })), "tunnels");
    assert.strictEqual(sourceOf(dns({})), "dns");
    assert.strictEqual(sourceOf(bypass({})), "bypass");
  });
  // Catches a source button that hides another source's rows, or none.
  it("keeps only the sources asked for", () => {
    const only = (s: "fircd" | "tunnels" | "dns" | "bypass") => all({ sources: new Set([s]) });
    assert.strictEqual(matches(log({}), only("fircd")), true);
    assert.strictEqual(matches(log({ source: "tunvless0" }), only("fircd")), false);
    assert.strictEqual(matches(log({ source: "tunvless0" }), only("tunnels")), true);
    assert.strictEqual(matches(log({}), only("tunnels")), false);
    assert.strictEqual(matches(dns({}), only("bypass")), false);
    assert.strictEqual(matches(bypass({}), only("bypass")), true);
    assert.strictEqual(matches(dns({}), only("dns")), true);
  });
  // Catches the level buttons read as a minimum instead of four independent switches.
  it("keeps a log line exactly when its own level is on", () => {
    const order = ["debug", "info", "warn", "error"] as const;
    for (const on of order) {
      for (const lv of order) {
        assert.strictEqual(
          matches(log({ level: lv }), all({ levels: new Set([on]) })),
          lv === on,
          `${lv} with only ${on} on`,
        );
      }
    }
    assert.strictEqual(matches(log({ level: "warn" }), all({ levels: new Set() })), false);
  });
  // Catches DNS or bypass rows hidden by the level buttons, which they have no level for.
  it("applies the levels to log lines only", () => {
    const none = all({ levels: new Set() });
    assert.strictEqual(matches(dns({}), none), true);
    assert.strictEqual(matches(bypass({}), none), true);
    assert.strictEqual(
      matches(log({ source: "tunvless0", level: "debug" }), all({ levels: new Set(["info"]) })),
      false,
    );
  });
  // Catches a default that shows debug or hides one of the other three.
  it("starts with info, warn and error on and debug off", () => {
    assert.deepStrictEqual([...DEFAULT_LEVELS].sort(), ["error", "info", "warn"]);
  });
  it("matches a group by id, and hides log lines while it is set", () => {
    assert.strictEqual(matches(dns({}), all({ group: "g1" })), true);
    assert.strictEqual(matches(dns({ group: undefined }), all({ group: "g1" })), false);
    assert.strictEqual(matches(log({}), all({ group: "g1" })), false);
  });
  it("applies the group filter to a bypass event too", () => {
    assert.strictEqual(matches(bypass({}), all({ group: "g1" })), true);
    assert.strictEqual(matches(bypass({ group: undefined }), all({ group: "g1" })), false);
  });
});

describe("sourceCounts", () => {
  // Catches a count taken over the shown rows instead of everything held, or a tunnel counted as fircd.
  it("counts every event held under its source", () => {
    const held = [
      log({}),
      log({ level: "debug" }),
      log({ source: "tunvless0", level: "warn" }),
      log({ source: "tunvless1", level: "error" }),
      log({ source: "tunvless1" }),
      dns({}),
      bypass({}),
      bypass({ name: "x.example" }),
    ];
    assert.deepStrictEqual(sourceCounts(held), { fircd: 2, tunnels: 3, dns: 1, bypass: 2 });
    assert.deepStrictEqual(sourceCounts([]), { fircd: 0, tunnels: 0, dns: 0, bypass: 0 });
  });
});

describe("matchesQuery", () => {
  // Catches a tunnel's device left out of the search, so its badge click finds nothing.
  it("matches a log line by its source device as well as its message", () => {
    assert.strictEqual(
      matchesQuery(log({ source: "tunvless0", message: "active A" }), "tunvless0"),
      true,
    );
    assert.strictEqual(
      matchesQuery(log({ source: "tunvless1", message: "active A" }), "tunvless0"),
      false,
    );
    assert.strictEqual(
      matchesQuery(log({ source: "tunvless1", message: "active A" }), "ACTIVE"),
      true,
    );
  });
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

const host = (ip: string, name: string, ip6: string[] = []) => ({
  mac: "aa:00:00:00:00:01",
  name,
  ip,
  ip6,
  active: true,
  registered: true,
  policy: "",
});

describe("deviceNames", () => {
  // Catches a device known only by an IPv6 address, or one compared case-sensitively, shown without its name.
  it("names every address a device holds, both families", () => {
    const names = deviceNames([host("192.168.1.7", "Phone", ["FD00::7"]), host("192.168.1.8", "")]);
    assert.strictEqual(names.get("192.168.1.7"), "Phone");
    assert.strictEqual(names.get("fd00::7"), "Phone");
    assert.strictEqual(names.has("192.168.1.8"), false);
  });
});

describe("matchesQuery by device", () => {
  // Catches the search ignoring the name the row shows, so typing "phone" finds nothing.
  it("matches an event by the name of the device that asked", () => {
    const names = deviceNames([host("192.168.1.42", "Phone")]);
    assert.strictEqual(matchesQuery(dns({ client: "192.168.1.42" }), "PHONE", names), true);
    assert.strictEqual(matchesQuery(bypass({ client: "192.168.1.42" }), "phone", names), true);
    assert.strictEqual(matchesQuery(dns({ client: "192.168.1.43" }), "phone", names), false);
  });
});
