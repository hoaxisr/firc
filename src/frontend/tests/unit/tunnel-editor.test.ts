import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  agoText,
  descriptionProblem,
  deviceProblem,
  formatRate,
  keepHidden,
  latencyOf,
  linkName,
  linkProblem,
  middleEllipsis,
  orderAfterDrop,
  orderByLatency,
  parseUplink,
  restartingDevices,
  subscriptionError,
  subscriptionIntervals,
  subscriptionProblem,
  toggleExclude,
  uniqueByKey,
  uplinkOptions,
  uplinkValue,
  wouldCycle,
} from "../../src/modules/tunnels/tunnel-editor.ts";
import type { Tunnel } from "../../src/types.ts";

const t = (key: string) => key;

const tn = (id: string, device: string, extra: Partial<Tunnel> = {}): Tunnel => ({
  id,
  device,
  enable: true,
  active: 1,
  by: "connection",
  interval: 60,
  silence: 20,
  filter: "",
  order: [],
  exclude: [],
  sources: [],
  uplink: { kind: "auto", ref: "" },
  advanced: { ca: "", insecure: false, timeout: 8, kernelTcp: false },
  ...extra,
});

const probe = (key: string, ms: number | null) => ({
  key,
  ok: ms !== null,
  why: ms === null ? "timeout" : "",
  handshakeMs: ms,
  firstByteMs: ms === null ? null : ms + 20,
});

describe("dropping a node", () => {
  // Catches a drop that writes only the moved key, leaving the rest of the visible order to the daemon's source order.
  it("writes the whole visible order with the node moved before the target", () => {
    assert.deepStrictEqual(orderAfterDrop(["a", "b", "c", "d"], "d", "b", "before"), [
      "a",
      "d",
      "b",
      "c",
    ]);
  });

  // Catches the drop edge ignored, so a node dropped on the lower half lands above its target.
  it("puts the node after the target on the lower edge", () => {
    assert.deepStrictEqual(orderAfterDrop(["a", "b", "c", "d"], "a", "c", "after"), [
      "b",
      "c",
      "a",
      "d",
    ]);
  });

  // Catches a drop onto itself or onto a vanished row duplicating or losing a key.
  it("leaves the order as it is when the node is dropped on itself or on an unknown row", () => {
    assert.deepStrictEqual(orderAfterDrop(["a", "b", "c"], "b", "b", "after"), ["a", "b", "c"]);
    assert.deepStrictEqual(orderAfterDrop(["a", "b", "c"], "b", "zz", "before"), ["a", "b", "c"]);
    assert.deepStrictEqual(orderAfterDrop(["a", "b", "c"], "zz", "a", "before"), ["a", "b", "c"]);
  });
});

describe("keys the filter hides", () => {
  // Catches a drop writing only the visible rows, erasing the place of a node the filter hides right now.
  it("keeps hidden ordered keys after the visible ones on a drop", () => {
    const moved = orderAfterDrop(["a", "b"], "b", "a", "before");
    assert.deepStrictEqual(keepHidden(moved, ["a", "h", "b"]), ["b", "a", "h"]);
  });

  // Catches the latency sort erasing hidden ordered keys the same way.
  it("keeps hidden ordered keys after the visible ones on a latency sort", () => {
    const sorted = orderByLatency(["a", "b"], { a: probe("a", 80), b: probe("b", 10) });
    assert.deepStrictEqual(keepHidden(sorted, ["a", "h", "b"]), ["b", "a", "h"]);
  });
});

describe("sorting by latency", () => {
  // Catches a sort by the handshake, which ranks a near relay of a far exit first.
  it("ranks by the first byte through the node, not the handshake to it", () => {
    const probes = {
      jp: { key: "jp", ok: true, why: "", handshakeMs: 18, firstByteMs: 1400 },
      nl: { key: "nl", ok: true, why: "", handshakeMs: 113, firstByteMs: 300 },
    };
    assert.deepStrictEqual(orderByLatency(["jp", "nl"], probes), ["nl", "jp"]);
  });

  // Catches a sort by name instead of the measured latency.
  it("puts measured nodes first, fastest first", () => {
    const probes = {
      a: probe("a", 90),
      b: probe("b", 15),
      c: probe("c", 40),
    };
    assert.deepStrictEqual(orderByLatency(["a", "b", "c"], probes), ["b", "c", "a"]);
  });

  // Catches a failed node sorted as zero milliseconds, so the dead one goes first.
  it("puts failed nodes last and unmeasured ones between, each keeping its place", () => {
    const probes = {
      a: probe("a", null),
      c: probe("c", 50),
      d: probe("d", null),
      e: probe("e", 10),
    };
    assert.deepStrictEqual(orderByLatency(["a", "b", "c", "d", "e", "f"], probes), [
      "e",
      "c",
      "b",
      "f",
      "a",
      "d",
    ]);
  });

  // Catches an unstable sort reshuffling nodes of equal latency.
  it("keeps the order of nodes with the same latency", () => {
    const probes = { a: probe("a", 30), b: probe("b", 30), c: probe("c", 5) };
    assert.deepStrictEqual(orderByLatency(["a", "b", "c"], probes), ["c", "a", "b"]);
  });
});

describe("rows from the daemon", () => {
  // Catches a repeated key kept, or the later copy kept instead of the first.
  it("keeps the first row of each key in its place", () => {
    const rows = [
      { key: "c", n: 1 },
      { key: "a", n: 2 },
      { key: "a", n: 3 },
      { key: "b", n: 4 },
      { key: "c", n: 5 },
    ];
    assert.deepStrictEqual(uniqueByKey(rows), [
      { key: "c", n: 1 },
      { key: "a", n: 2 },
      { key: "b", n: 4 },
    ]);
  });
});

describe("the include switch", () => {
  // Catches the switch adding a key twice or never taking it back out.
  it("adds a key to exclude and removes it again", () => {
    assert.deepStrictEqual(toggleExclude(["x"], "y"), ["x", "y"]);
    assert.deepStrictEqual(toggleExclude(["x", "y"], "x"), ["y"]);
  });
});

describe("the uplink choice", () => {
  // Catches a chain walk that stops after one hop and lets 0 -> 1 -> 2 -> 0 through.
  it("sees a cycle through a chain of tunnels", () => {
    const set = [
      tn("t0", "tunvless0"),
      tn("t1", "tunvless1", { uplink: { kind: "tunnel", ref: "t2" } }),
      tn("t2", "tunvless2", { uplink: { kind: "tunnel", ref: "t0" } }),
    ];
    assert.strictEqual(wouldCycle(set, "t0", "t1"), true);
    assert.strictEqual(wouldCycle(set, "t0", "t2"), true);
    assert.strictEqual(wouldCycle(set, "t1", "t0"), false);
  });

  // Catches a tunnel offered itself as its own way out.
  it("calls choosing itself a cycle", () => {
    assert.strictEqual(wouldCycle([tn("t0", "tunvless0")], "t0", "t0"), true);
  });

  // Catches the walk looping forever on a cycle that does not pass through the asking tunnel.
  it("ends on a cycle among other tunnels", () => {
    const set = [
      tn("t0", "tunvless0"),
      tn("t1", "tunvless1", { uplink: { kind: "tunnel", ref: "t2" } }),
      tn("t2", "tunvless2", { uplink: { kind: "tunnel", ref: "t1" } }),
    ];
    assert.strictEqual(wouldCycle(set, "t0", "t1"), false);
  });

  // Catches blackhole, a tunnel's own device, a LAN or other interface offered as an uplink, a description lost, or a cyclic tunnel left choosable.
  it("offers auto, wan and tunnel interfaces and other tunnels, the cyclic one disabled", () => {
    const set = [
      tn("t0", "tunvless0"),
      tn("t1", "tunvless1", { uplink: { kind: "tunnel", ref: "t0" } }),
      tn("t2", "tunvless2"),
    ];
    const ifaces = [
      { id: "ppp0", name: "Internet", role: "wan" as const },
      { id: "blackhole" },
      { id: "tunvless1", role: "tunnel" as const },
      { id: "tunvless7", role: "tunnel" as const },
      { id: "br0", name: "Home", role: "lan" as const },
      { id: "eth2.1", role: "other" as const },
      { id: "nwg1", ndmsName: "Wireguard1", role: "tunnel" as const },
    ];
    const options = uplinkOptions(set[0], set, ifaces, t);
    assert.deepStrictEqual(
      options.map((o) => [o.value, Boolean(o.disabled)]),
      [
        ["auto", false],
        ["iface:ppp0", false],
        ["iface:nwg1", false],
        ["tunnel:t1", true],
        ["tunnel:t2", false],
      ],
    );
    assert.ok(options.find((o) => o.value === "tunnel:t1")?.hint);
    assert.deepStrictEqual([options[1].label, options[1].description], ["Internet", "ppp0"]);
    assert.deepStrictEqual([options[2].label, options[2].description], ["Wireguard1", "nwg1"]);
  });

  // Catches the saved interface vanishing from the list when it is down, so the select reads empty.
  it("keeps the chosen interface even when the router does not list it", () => {
    const self = tn("t0", "tunvless0", { uplink: { kind: "iface", ref: "Wireguard3" } });
    const options = uplinkOptions(self, [self], [{ id: "PPPoE0" }], t);
    assert.ok(options.some((o) => o.value === "iface:Wireguard3"));
  });

  // Catches the select value and the uplink drifting apart, writing iface:auto or an empty tunnel ref.
  it("round-trips the uplink through the select value", () => {
    for (const u of [
      { kind: "auto", ref: "" },
      { kind: "iface", ref: "PPPoE0" },
      { kind: "tunnel", ref: "t1" },
    ] as const) {
      assert.deepStrictEqual(parseUplink(uplinkValue(u)), u);
    }
    assert.strictEqual(uplinkValue({ kind: "auto", ref: "x" }), "auto");
  });
});

describe("which tunnels a save restarts", () => {
  const base = () => [
    tn("t0", "tunvless0", {
      sources: [{ id: "0000000a", kind: "link", link: "vless://a@h:1#A" }],
    }),
    tn("t1", "tunvless1"),
  ];

  // Catches a run-affecting field left out of the comparison, so the warning stays silent.
  it("names a tunnel whose run-affecting field changed", () => {
    const edits: ((x: Tunnel) => void)[] = [
      (x) => (x.device = "tunvless5"),
      (x) => (x.active = 2),
      (x) => (x.by = "site"),
      (x) => (x.interval = 30),
      (x) => (x.silence = 5),
      (x) => (x.advanced.timeout = 3),
      (x) => (x.advanced.insecure = true),
      (x) => (x.advanced.ca = "/opt/ca.pem"),
      (x) => (x.uplink = { kind: "iface", ref: "PPPoE0" }),
      (x) => (x.enable = false),
    ];
    for (const edit of edits) {
      const after = base();
      edit(after[0]);
      assert.deepStrictEqual(restartingDevices(base(), after), [after[0].device], String(edit));
    }
  });

  // Catches a node-list edit, which the daemon sends to the running tunvless, announced as a restart.
  it("names nothing for an edit of the nodes alone", () => {
    const withSub = () => [
      tn("t0", "tunvless0", {
        sources: [
          { id: "0000000a", kind: "link", link: "vless://a@h:1#A" },
          { id: "0000000b", kind: "subscription", name: "P", url: "https://a.b/c", interval: 3600 },
        ],
      }),
    ];
    const edits: ((x: Tunnel) => void)[] = [
      (x) => (x.sources[0] = { id: "0000000a", kind: "link", link: "vless://b@h:1#A" }),
      (x) => (x.sources = x.sources.slice(1)),
      (x) => (x.order = ["0000000a:A"]),
      (x) => (x.exclude = ["0000000a:A"]),
      (x) => (x.filter = "NL"),
      (x) => Object.assign(x.sources[1], { url: "https://a.b/d" }),
      (x) => Object.assign(x.sources[1], { interval: 86400 }),
      (x) => Object.assign(x.sources[1], { name: "Q" }),
    ];
    for (const edit of edits) {
      const after = withSub();
      edit(after[0]);
      assert.deepStrictEqual(restartingDevices(withSub(), after), [], String(edit));
    }
  });

  // Catches every tunnel named on any edit, or new tunnels announced as restarts.
  it("names neither untouched nor new tunnels", () => {
    const after = [...base(), tn("t9", "tunvless9")];
    after[1].silence = 1;
    assert.deepStrictEqual(restartingDevices(base(), after), ["tunvless1"]);
  });

  // Catches a tunnel switched on or off left out, though its connections drop all the same.
  it("names a tunnel switched off, but not one that stays off", () => {
    const after = base();
    after[0].enable = false;
    assert.deepStrictEqual(restartingDevices(base(), after), ["tunvless0"]);
    const offBefore = base();
    offBefore[1].enable = false;
    const offAfter = base();
    offAfter[1].enable = false;
    offAfter[1].active = 3;
    assert.deepStrictEqual(restartingDevices(offBefore, offAfter), []);
  });

  // Catches a kernelTcp toggle left out of the comparison, though the daemon restarts the tunnel for it.
  it("restartingDevices names a kernelTcp toggle", () => {
    const on = base();
    on[0].advanced.kernelTcp = true;
    assert.deepStrictEqual(restartingDevices(base(), on), ["tunvless0"]);
    assert.deepStrictEqual(restartingDevices(on, base()), ["tunvless0"]);
  });
});

describe("device names", () => {
  // Catches a device name the daemon refuses passing in the editor, or a taken one.
  it("refuses names outside tunvless0..99 and names used twice", () => {
    const set = [tn("t0", "tunvless0"), tn("t1", "tunvless1")];
    assert.strictEqual(deviceProblem("tunvless1", set, "t0") !== null, true);
    assert.strictEqual(deviceProblem("tunvless01", set, "t0") !== null, true);
    assert.strictEqual(deviceProblem("tunvless100", set, "t0") !== null, true);
    assert.strictEqual(deviceProblem("eth0", set, "t0") !== null, true);
    assert.strictEqual(deviceProblem("tunvless0", set, "t0"), null);
    assert.strictEqual(deviceProblem("tunvless99", set, "t0"), null);
  });
});

describe("the description field", () => {
  // Catches the 63-byte limit counted in characters, which lets 40 Cyrillic letters through to a 400.
  it("counts the limit in UTF-8 bytes, not characters", () => {
    assert.strictEqual(descriptionProblem("", t), null);
    assert.strictEqual(descriptionProblem("a".repeat(63), t), null);
    assert.notStrictEqual(descriptionProblem("a".repeat(64), t), null);
    assert.strictEqual(descriptionProblem("П".repeat(31) + "1", t), null);
    assert.notStrictEqual(descriptionProblem("П".repeat(32), t), null);
  });

  // Catches a tab, newline, DEL or C1 control character passed on for the daemon to refuse.
  it("refuses control characters", () => {
    for (const bad of ["a\tb", "a\nb", "\u0001", "a\u007f", "a\u009b"]) {
      assert.notStrictEqual(descriptionProblem(bad, t), null, JSON.stringify(bad));
    }
    assert.strictEqual(descriptionProblem("ПРАВ-1: NL «x»", t), null);
  });

  // Catches a description edit announced as a restart, though the daemon restarts nothing for it.
  it("names no restart for a description edit", () => {
    const before = [tn("a", "tunvless0")];
    const after = [tn("a", "tunvless0", { description: "PRAW-1" })];
    assert.deepStrictEqual(restartingDevices(before, after), []);
  });
});

describe("showing a link", () => {
  // Catches the name read raw, so a percent-encoded fragment shows as %20 soup.
  it("names a link by its decoded fragment", () => {
    assert.strictEqual(linkName("vless://u@h:443?security=none#my%20vps"), "my vps");
  });

  // Catches an empty name for a link without a fragment, leaving a blank row.
  it("falls back to the host without a fragment", () => {
    assert.strictEqual(linkName("vless://u@my.host:443?security=none"), "my.host");
    assert.strictEqual(linkName("vless://u@h:443#bad%E0"), "bad%E0");
  });

  // Catches the ellipsis cutting the tail, where the fragment and parameters a reader looks for are.
  it("cuts the middle of a long link and keeps both ends", () => {
    assert.strictEqual(middleEllipsis("abcdefghij", 7), "abc…hij");
    assert.strictEqual(middleEllipsis("abcdefghij", 6), "abc…ij");
    assert.strictEqual(middleEllipsis("short", 10), "short");
  });
});

describe("the card's numbers", () => {
  // Catches bytes per second shown as bits, an eighth of the real rate.
  it("shows the device's bytes per second as bits", () => {
    assert.strictEqual(formatRate(1_550_000, t), "12.4 Mbit/s");
    assert.strictEqual(formatRate(1200, t), "9.6 Kbit/s");
    assert.strictEqual(formatRate(0, t), "0 Kbit/s");
  });

  // Catches a down node's age in raw seconds or a negative age from a skewed clock.
  it("says how long ago in the largest whole unit", () => {
    assert.strictEqual(agoText(1000, 1000 - 42, t), "42 s");
    assert.strictEqual(agoText(1000, 1000 - 150, t), "2 min");
    assert.strictEqual(agoText(100000, 100000 - 7300, t), "2 h");
    assert.strictEqual(agoText(1000000, 1000000 - 3 * 86400, t), "3 d");
    assert.strictEqual(agoText(1000, 1100, t), "0 s");
  });

  // Catches the latency column showing the handshake to the node instead of the whole path.
  it("shows the first byte as the latency and nothing for a failed node", () => {
    assert.strictEqual(
      latencyOf({ key: "a", ok: true, why: "", handshakeMs: 18, firstByteMs: 1400 }),
      1400,
    );
    assert.strictEqual(latencyOf(probe("a", null)), null);
    assert.strictEqual(latencyOf(undefined), null);
  });
});

describe("the subscription interval", () => {
  // Catches a saved interval outside the list showing as an empty select.
  it("offers the fixed choices and keeps an unusual saved one", () => {
    const values = (n: number) => subscriptionIntervals(n, t).map((o) => o.value);
    assert.deepStrictEqual(values(21600), ["0", "3600", "21600", "43200", "86400", "604800"]);
    assert.deepStrictEqual(values(7200), [
      "0",
      "3600",
      "21600",
      "43200",
      "86400",
      "604800",
      "7200",
    ]);
  });
});

describe("a new source", () => {
  // Catches a name the daemon refuses passing the dialog, a Cyrillic or a 64-byte one among them.
  it("takes a subscription name of 1..63 ASCII letters, digits, space . _ -", () => {
    assert.strictEqual(subscriptionProblem("Provider A-1.x_y", "https://a.b/c", [], t), null);
    assert.notStrictEqual(subscriptionProblem("", "https://a.b/c", [], t), null);
    assert.notStrictEqual(subscriptionProblem("Провайдер", "https://a.b/c", [], t), null);
    assert.notStrictEqual(subscriptionProblem("x".repeat(64), "https://a.b/c", [], t), null);
    assert.strictEqual(subscriptionProblem("x".repeat(63), "https://a.b/c", [], t), null);
  });

  // Catches two subscriptions of one name, which would share node keys' labels in the table.
  it("refuses a name another subscription of the tunnel has", () => {
    assert.notStrictEqual(subscriptionProblem("A", "https://a.b/c", ["A"], t), null);
  });

  // Catches a non-http URL or a vless link pasted as a subscription.
  it("takes only http and https URLs", () => {
    assert.notStrictEqual(subscriptionProblem("A", "ftp://a.b/c", [], t), null);
    assert.notStrictEqual(subscriptionProblem("A", "vless://u@h:1", [], t), null);
    assert.strictEqual(subscriptionProblem("A", "http://a.b/c", [], t), null);
  });

  // Catches a link of another protocol or with stray whitespace reaching the daemon.
  it("takes one vless link", () => {
    assert.strictEqual(linkProblem("vless://u@h:443#A", t), null);
    assert.notStrictEqual(linkProblem("vmess://u@h:443", t), null);
    assert.notStrictEqual(linkProblem("vless://u@h:443 vless://v@h:1", t), null);
    assert.notStrictEqual(linkProblem("", t), null);
  });
});

describe("subscription errors", () => {
  // Catches the server's own words left untranslated, or another error rewritten.
  it("translates the placeholder prefix only", () => {
    const tr = (k: string) => (k === "the server answered: {s}" ? "сервер ответил: {s}" : k);
    assert.strictEqual(
      subscriptionError("the server answered: Please turn on HWID", tr),
      "сервер ответил: Please turn on HWID",
    );
    assert.strictEqual(subscriptionError("HTTP 503", tr), "HTTP 503");
  });

  // Catches the server's words used as a replacement pattern, so $& or $' in them turns into other text.
  it("shows dollar patterns in the server's words as they are", () => {
    assert.strictEqual(
      subscriptionError("the server answered: pay $& or $' or $$ now", t),
      "the server answered: pay $& or $' or $$ now",
    );
  });
});
