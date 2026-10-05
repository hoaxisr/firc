import { deepStrictEqual, strictEqual } from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  addressCovers,
  coverageLabel,
  flipPolicy,
  flipRow,
  foldManual,
  hostRows,
  joinSelector,
  policyChips,
  rowState,
  selectorMode,
  setEntry,
  setMode,
  splitSelector,
  visibleRows,
  type Host,
  type Mode,
  type PickerPolicy,
} from "../../src/utils/device-picker.ts";

const POLICIES: PickerPolicy[] = [
  { name: "Policy0", description: "Kids", devices: 2 },
  { name: "Policy1", devices: 1 },
];

const HOSTS: Host[] = [
  {
    mac: "aa:00:00:00:00:01",
    name: "TV",
    ip: "192.168.1.5",
    ip6: ["fd00::5"],
    active: true,
    registered: true,
    policy: "Policy0",
  },
  {
    mac: "aa:00:00:00:00:02",
    name: "Laptop",
    ip: "192.168.1.6",
    ip6: [],
    active: false,
    registered: true,
    policy: "",
  },
  {
    mac: "aa:00:00:00:00:03",
    name: "Phone",
    ip: "192.168.1.7",
    ip6: [],
    active: true,
    registered: true,
    policy: "Policy0",
  },
  {
    mac: "aa:00:00:00:00:04",
    name: "",
    ip: "192.168.1.8",
    ip6: [],
    active: true,
    registered: false,
    policy: "Policy1",
  },
];

const t = (key: string) => key;
const macsOf = (rows: { mac: string }[]) => rows.map((r) => r.mac.slice(-2));

describe("splitting a selector into what the dialog shows", () => {
  // Catches an address entry becoming a row, a non-canonical mac:, or a join that reorders or loses entries.
  it("puts each entry in one place and joins it back", () => {
    const p = splitSelector({
      allow: ["policy:Kids", "mac:AA-00-00-00-00-01", "192.168.1.0/24"],
      deny: ["mac:aa:00:00:00:00:02", "fd00::/64"],
    });
    deepStrictEqual([...p.policies], [["Kids", "allow"]]);
    deepStrictEqual(
      [...p.macs],
      [
        ["aa:00:00:00:00:01", "allow"],
        ["aa:00:00:00:00:02", "deny"],
      ],
    );
    deepStrictEqual(p.manual, { allow: ["192.168.1.0/24"], deny: ["fd00::/64"] });
    deepStrictEqual(joinSelector(p), {
      allow: ["policy:Kids", "mac:aa:00:00:00:00:01", "192.168.1.0/24"],
      deny: ["mac:aa:00:00:00:00:02", "fd00::/64"],
    });
  });

  // Catches a malformed entry being dropped or shown as a row it cannot be cleared from.
  it("keeps a malformed mac: or policy: entry as text for the manual block", () => {
    const p = splitSelector({ allow: ["mac:zz", "policy: Kids"], deny: [] });
    strictEqual(p.macs.size, 0);
    strictEqual(p.policies.size, 0);
    deepStrictEqual(p.manual.allow, ["mac:zz", "policy: Kids"]);
  });

  // Catches a typed mac: line saved beside its row or non-canonical, or a typed policy: left as text.
  it("folds a valid mac: or policy: line typed by hand into its row or chip", () => {
    const picked = setEntry(
      splitSelector({ allow: [], deny: [] }),
      "mac",
      "aa:00:00:00:00:01",
      "allow",
    );
    const typed = {
      ...picked,
      manual: {
        allow: ["mac:AA-00-00-00-00-01", "policy:Kids", "10.0.0.0/8"],
        deny: ["mac:aa-00-00-00-00-02"],
      },
    };
    deepStrictEqual(joinSelector(typed), {
      allow: ["policy:Kids", "mac:aa:00:00:00:00:01", "10.0.0.0/8"],
      deny: ["mac:aa:00:00:00:00:02"],
    });
  });

  // Catches a key in both lists collapsing to one side, which turns "nobody" into "everyone but X".
  it("keeps a policy: key stored in both lists as text on both sides", () => {
    const sel = { allow: ["policy:Kids", "10.0.0.0/8"], deny: ["policy:Kids"] };
    const p = splitSelector(sel);
    strictEqual(p.policies.size, 0);
    deepStrictEqual(p.manual, sel);
    deepStrictEqual(joinSelector(p), sel);
  });

  it("keeps a mac: key stored in both lists as text on both sides, as spelled", () => {
    const sel = { allow: ["mac:aa:00:00:00:00:01"], deny: ["mac:AA-00-00-00-00-01"] };
    const p = splitSelector(sel);
    strictEqual(p.macs.size, 0);
    deepStrictEqual(p.manual, sel);
    deepStrictEqual(joinSelector(p), sel);
    const typed = {
      ...setEntry(splitSelector(undefined), "mac", "aa:00:00:00:00:03", "allow"),
      manual: { allow: ["mac:aa:00:00:00:00:02"], deny: ["mac:aa-00-00-00-00-02"] },
    };
    const folded = foldManual(typed);
    deepStrictEqual([...folded.macs], [["aa:00:00:00:00:03", "allow"]]);
    deepStrictEqual(folded.manual, typed.manual);
  });
});

describe("foldManual's deny wins a conflict", () => {
  // Catches a typed "allow" overruling the row's deny, or the entry folded in twice.
  it("a mac: row denied, 'allow' typed by hand: stays denied, once", () => {
    const denied = setEntry(
      splitSelector({ allow: [], deny: [] }),
      "mac",
      "aa:00:00:00:00:01",
      "deny",
    );
    const draft = foldManual({ ...denied, manual: { allow: ["mac:AA-00-00-00-00-01"], deny: [] } });
    strictEqual(draft.macs.get("aa:00:00:00:00:01"), "deny");
    strictEqual(draft.macs.size, 1);
    deepStrictEqual(joinSelector(draft), { allow: [], deny: ["mac:aa:00:00:00:00:01"] });
  });

  // Catches the row's allow surviving a typed "deny".
  it("a mac: row allowed, 'deny' typed by hand: becomes denied", () => {
    const allowed = setEntry(
      splitSelector({ allow: [], deny: [] }),
      "mac",
      "aa:00:00:00:00:01",
      "allow",
    );
    const draft = foldManual({
      ...allowed,
      manual: { allow: [], deny: ["mac:AA-00-00-00-00-01"] },
    });
    strictEqual(draft.macs.get("aa:00:00:00:00:01"), "deny");
    strictEqual(draft.macs.size, 1);
    deepStrictEqual(joinSelector(draft), { allow: [], deny: ["mac:aa:00:00:00:00:01"] });
  });

  // Catches a typed "allow" overruling the chip's deny.
  it("a policy: chip denied, 'allow' typed by hand: stays denied, once", () => {
    const denied = setEntry(splitSelector({ allow: [], deny: [] }), "policy", "Kids", "deny");
    const draft = foldManual({ ...denied, manual: { allow: ["policy:Kids"], deny: [] } });
    strictEqual(draft.policies.get("Kids"), "deny");
    strictEqual(draft.policies.size, 1);
    deepStrictEqual(joinSelector(draft), { allow: [], deny: ["policy:Kids"] });
  });

  // Catches the chip's allow surviving a typed "deny".
  it("a policy: chip allowed, 'deny' typed by hand: becomes denied", () => {
    const allowed = setEntry(splitSelector({ allow: [], deny: [] }), "policy", "Kids", "allow");
    const draft = foldManual({ ...allowed, manual: { allow: [], deny: ["policy:Kids"] } });
    strictEqual(draft.policies.get("Kids"), "deny");
    strictEqual(draft.policies.size, 1);
    deepStrictEqual(joinSelector(draft), { allow: [], deny: ["policy:Kids"] });
  });
});

describe("rows and chips", () => {
  // Catches an unlisted mac: entry getting no row, or being lost on open and close.
  it("gives unknown mac entries rows, and they survive a round trip", () => {
    const sel = { allow: ["mac:aa:00:00:00:00:99"], deny: [] };
    const p = splitSelector(sel);
    const rows = hostRows(HOSTS, p);
    strictEqual(rows.length, 5);
    const last = rows[4];
    deepStrictEqual(
      [last.mac, last.unknown, last.side, last.name],
      ["aa:00:00:00:00:99", true, "allow", ""],
    );
    strictEqual(hostRows([], p).length, 1);
    deepStrictEqual(joinSelector(p), sel);
  });

  // Catches a chip rewriting a stored description to the internal name, or a missing chip for an absent policy.
  it("keeps the stored key, the router's order, and a chip for a policy the router lacks", () => {
    const p = splitSelector({ allow: ["policy:Kids"], deny: ["policy:Gone"] });
    deepStrictEqual(policyChips(p, POLICIES), [
      { id: "Policy0", key: "Kids", label: "Kids", devices: 2, side: "allow", takenBy: null },
      { id: "Policy1", key: "Policy1", label: "Policy1", devices: 1, side: null, takenBy: null },
      { id: "Gone", key: "Gone", label: "Gone", devices: null, side: "deny", takenBy: null },
    ]);
  });
});

describe("order and search", () => {
  // Catches a dropped or reversed sort key, or a host with an entry pulled to the top.
  it("orders online, by name, unnamed last, whatever is selected", () => {
    const p = splitSelector({ allow: ["mac:aa:00:00:00:00:02"], deny: [] });
    deepStrictEqual(macsOf(visibleRows(hostRows(HOSTS, p), "")), ["03", "01", "04", "02"]);
  });

  // Catches an unsearched field, or a MAC typed with '-' not found.
  it("finds by name, IP, IPv6 or MAC", () => {
    const rows = hostRows(HOSTS, splitSelector(undefined));
    deepStrictEqual(macsOf(visibleRows(rows, "PHONE")), ["03"]);
    deepStrictEqual(macsOf(visibleRows(rows, "192.168.1.8")), ["04"]);
    deepStrictEqual(macsOf(visibleRows(rows, "fd00::5")), ["01"]);
    deepStrictEqual(macsOf(visibleRows(rows, "AA-00-00-00-00-01")), ["01"]);
  });

  // Catches a flip moving a row, in either mode.
  it("does not move a row that is switched", () => {
    for (const mode of ["all", "only"] as Mode[]) {
      const p = splitSelector(undefined);
      const before = macsOf(visibleRows(hostRows(HOSTS, p), ""));
      const tv = hostRows(HOSTS, p)[0];
      const next = flipRow(p, tv, POLICIES, mode);
      strictEqual(next.macs.size, 1);
      deepStrictEqual(macsOf(visibleRows(hostRows(HOSTS, next), "")), before);
    }
  });

  // Catches an opened-with MAC losing its row once nothing names it, or a kept MAC getting a second row.
  it("keeps a row for a MAC the dialog opened with", () => {
    const rows = hostRows(HOSTS, splitSelector(undefined), [
      "aa:00:00:00:00:99",
      "aa:00:00:00:00:01",
    ]);
    strictEqual(rows.length, 5);
    deepStrictEqual(
      [rows[4].mac, rows[4].unknown, rows[4].side],
      ["aa:00:00:00:00:99", true, null],
    );
  });
});

type Sel = { allow: string[]; deny: string[] };
const draftOf = (sel: Sel) => foldManual(splitSelector(sel));
const rowOf = (sel: Sel, mac: string) =>
  hostRows(HOSTS, draftOf(sel)).find((r) => r.mac === `aa:00:00:00:00:${mac}`)!;
const stateOf = (sel: Sel, mode: Mode, mac: string) =>
  rowState(rowOf(sel, mac), draftOf(sel), POLICIES, mode);
const flipped = (sel: Sel, mode: Mode, mac: string) =>
  joinSelector(flipRow(draftOf(sel), rowOf(sel, mac), POLICIES, mode));

describe("the mode a stored selector opens in", () => {
  // Catches a deny-only selector opening as only-selected, or any allow opening as all-devices.
  it("is «only» exactly when something is allowed", () => {
    strictEqual(selectorMode(splitSelector(undefined)), "all");
    strictEqual(selectorMode(splitSelector({ allow: [], deny: ["mac:aa:00:00:00:00:02"] })), "all");
    strictEqual(selectorMode(splitSelector({ allow: ["policy:Kids"], deny: [] })), "only");
    strictEqual(
      selectorMode(splitSelector({ allow: ["mac:aa:00:00:00:00:02"], deny: [] })),
      "only",
    );
    strictEqual(selectorMode(splitSelector({ allow: ["10.0.0.0/8"], deny: [] })), "only");
  });

  // Catches all-devices keeping an allow or dropping a deny, or only-selected writing anything.
  it("«для всех» drops every allow and keeps the denies", () => {
    const p = splitSelector({
      allow: ["policy:Kids", "mac:aa:00:00:00:00:01", "10.0.0.0/8"],
      deny: ["mac:aa:00:00:00:00:02", "policy:Policy1", "fd00::/64"],
    });
    deepStrictEqual(joinSelector(setMode(p, "all")), {
      allow: [],
      deny: ["policy:Policy1", "mac:aa:00:00:00:00:02", "fd00::/64"],
    });
    deepStrictEqual(joinSelector(setMode(p, "only")), joinSelector(p));
  });
});

describe("a device's switch, as the daemon decides", () => {
  // Catches all-devices not meaning every device not excluded.
  it("«для всех»: on, and off with its own deny", () => {
    deepStrictEqual(stateOf({ allow: [], deny: [] }, "all", "01"), {
      on: true,
      locked: false,
      note: null,
    });
    deepStrictEqual(stateOf({ allow: [], deny: ["mac:aa:00:00:00:00:02"] }, "all", "02"), {
      on: false,
      locked: false,
      note: { kind: "excluded" },
    });
  });

  // Deny comes first: catches a denied policy checked after the mode or the host's own allow.
  it("is locked off by a denied policy, even with its own allow", () => {
    const off = { on: false, locked: true, note: { kind: "policy-off", policy: "Kids" } };
    deepStrictEqual(stateOf({ allow: [], deny: ["policy:Kids"] }, "all", "01"), off);
    deepStrictEqual(
      stateOf({ allow: ["mac:aa:00:00:00:00:01"], deny: ["policy:Policy0"] }, "only", "01"),
      off,
    );
  });

  // Catches a manual deny covering the host's address not being read or not locking it.
  it("is locked off by a manual deny that covers its address", () => {
    deepStrictEqual(stateOf({ allow: [], deny: ["192.168.1.8"] }, "all", "04"), {
      on: false,
      locked: true,
      note: { kind: "manual-off" },
    });
  });

  // Catches only-selected showing a host on that nothing allows, or off when its allow, policy or manual line does.
  it("«только для выбранных»: on through its own allow, its policy or a manual line", () => {
    deepStrictEqual(stateOf({ allow: [], deny: [] }, "only", "01"), {
      on: false,
      locked: false,
      note: null,
    });
    deepStrictEqual(stateOf({ allow: ["mac:aa:00:00:00:00:02"], deny: [] }, "only", "02"), {
      on: true,
      locked: false,
      note: null,
    });
    deepStrictEqual(stateOf({ allow: ["policy:Kids"], deny: [] }, "only", "03"), {
      on: true,
      locked: false,
      note: { kind: "via", policy: "Kids" },
    });
    const prefix = { allow: ["192.168.1.6/31"], deny: [] };
    deepStrictEqual(stateOf(prefix, "only", "02"), {
      on: true,
      locked: false,
      note: { kind: "manual-on" },
    });
    strictEqual(stateOf(prefix, "only", "01").on, false);
    strictEqual(stateOf({ allow: ["fd00::/64"], deny: [] }, "only", "01").on, true);
  });

  // Catches an own deny under an allowed policy not naming the policy it is an exception from.
  it("an own deny under an allowed policy is an exception from it", () => {
    deepStrictEqual(
      stateOf({ allow: ["policy:Kids"], deny: ["mac:aa:00:00:00:00:03"] }, "only", "03"),
      { on: false, locked: false, note: { kind: "excluded-from", policy: "Kids" } },
    );
  });

  // Catches a segment's policy description (Guests) not resolved to the host's effective policy.
  it("covers a host in a policy through its segment", () => {
    const policies: PickerPolicy[] = [
      ...POLICIES,
      { name: "Policy9", description: "Guests", devices: 1 },
    ];
    const guest: Host = { ...HOSTS[1], mac: "aa:00:00:00:00:09", policy: "Policy9" };
    const p = draftOf({ allow: ["policy:Guests"], deny: [] });
    const row = hostRows([guest], p)[0];
    deepStrictEqual(rowState(row, p, policies, "only").note, { kind: "via", policy: "Guests" });
  });
});

describe("flipping a switch", () => {
  const none = { allow: [], deny: [] };

  // Catches all-devices off being anything but a deny of the MAC, or on not removing it.
  it("«для всех»: off denies the device, on removes the deny", () => {
    deepStrictEqual(flipped(none, "all", "02"), { allow: [], deny: ["mac:aa:00:00:00:00:02"] });
    deepStrictEqual(flipped({ allow: [], deny: ["mac:aa:00:00:00:00:02"] }, "all", "02"), none);
  });

  // Catches only-selected on being anything but an allow of the MAC, or off leaving it.
  it("«только для выбранных»: on allows the device, off removes the allow", () => {
    deepStrictEqual(flipped(none, "only", "02"), { allow: ["mac:aa:00:00:00:00:02"], deny: [] });
    deepStrictEqual(flipped({ allow: ["mac:aa:00:00:00:00:02"], deny: [] }, "only", "02"), none);
  });

  // Catches switching off a policy-on host only removing nothing, so it stays on.
  it("off for a host on through its policy is an exception, and back", () => {
    const kids = { allow: ["policy:Kids"], deny: [] };
    const out = { allow: ["policy:Kids"], deny: ["mac:aa:00:00:00:00:03"] };
    deepStrictEqual(flipped(kids, "only", "03"), out);
    deepStrictEqual(flipped(out, "only", "03"), kids);
    deepStrictEqual(
      flipped({ allow: ["policy:Kids", "mac:aa:00:00:00:00:03"], deny: [] }, "only", "03"),
      out,
    );
    deepStrictEqual(flipped({ allow: ["192.168.1.6/31"], deny: [] }, "only", "02"), {
      allow: ["192.168.1.6/31"],
      deny: ["mac:aa:00:00:00:00:02"],
    });
  });

  // Catches a locked row writing anything.
  it("leaves a host locked by its policy alone", () => {
    const sel = { allow: [], deny: ["policy:Kids"] };
    deepStrictEqual(flipped(sel, "all", "01"), sel);
  });

  // Catches a policy switch writing the wrong side, or a denied policy switched on only losing its deny.
  it("a policy: off is a deny in «для всех», on is an allow in «только»", () => {
    const flipP = (sel: Sel, mode: Mode) =>
      joinSelector(flipPolicy(draftOf(sel), "Policy0", POLICIES, mode));
    deepStrictEqual(flipP(none, "all"), { allow: [], deny: ["policy:Policy0"] });
    deepStrictEqual(flipP({ allow: [], deny: ["policy:Policy0"] }, "all"), none);
    deepStrictEqual(flipP(none, "only"), { allow: ["policy:Policy0"], deny: [] });
    deepStrictEqual(flipP({ allow: ["policy:Policy0"], deny: [] }, "only"), none);
    deepStrictEqual(flipP({ allow: [], deny: ["policy:Policy0"] }, "only"), {
      allow: ["policy:Policy0"],
      deny: [],
    });
  });
});

describe("a policy's switch reads every entry that names it", () => {
  // Catches the switch reading only its built-from key, or the other spelling getting a second chip.
  it("one switch per router policy, off when either spelling is denied", () => {
    const p = draftOf({ allow: ["policy:Policy0"], deny: ["policy:Kids"] });
    deepStrictEqual(
      policyChips(p, POLICIES).map((c) => [c.id, c.key, c.label, c.devices, c.side]),
      [
        ["Policy0", "Policy0", "Kids", 2, "deny"],
        ["Policy1", "Policy1", "Policy1", 1, null],
      ],
    );
  });

  // Catches a click writing a second allow beside a key already on both sides instead of replacing both.
  it("a key on both sides is off, and a click replaces both lines", () => {
    const sel = { allow: ["policy:Policy0"], deny: ["policy:Policy0"] };
    strictEqual(policyChips(draftOf(sel), POLICIES)[0].side, "deny");
    deepStrictEqual(joinSelector(flipPolicy(draftOf(sel), "Policy0", POLICIES, "only")), {
      allow: ["policy:Policy0"],
      deny: [],
    });
  });

  // Catches switching on a policy denied by both spellings removing only one of them.
  it("a click removes the other spelling too", () => {
    const sel = { allow: [], deny: ["policy:Kids", "policy:Policy0"] };
    deepStrictEqual(joinSelector(flipPolicy(draftOf(sel), "Policy0", POLICIES, "only")), {
      allow: ["policy:Kids"],
      deny: [],
    });
  });

  // Catches a key matched against descriptions before names, resolving "Policy1" to the wrong policy.
  it("resolves a key by the first alias in the router's order", () => {
    const hosts: Host[] = [
      { ...HOSTS[0], policy: "Policy0" },
      { ...HOSTS[1], policy: "Policy1" },
    ];
    const sel = { allow: ["policy:Policy1"], deny: [] };
    const p = draftOf(sel);
    const read = (policies: PickerPolicy[]) => ({
      rows: hostRows(hosts, p).map((r) => rowState(r, p, policies, "only").on),
      card: coverageLabel(sel, hosts, policies, t, "en"),
      chips: policyChips(p, policies).map((c) => [c.id, c.side]),
    });
    deepStrictEqual(
      read([
        { name: "Policy1", description: "", devices: 1 },
        { name: "Policy0", description: "Policy1", devices: 1 },
      ]),
      {
        rows: [false, true],
        card: "1 device",
        chips: [
          ["Policy1", "allow"],
          ["Policy0", null],
        ],
      },
    );
    deepStrictEqual(
      read([
        { name: "Policy0", description: "Policy1", devices: 1 },
        { name: "Policy1", description: "", devices: 1 },
      ]),
      {
        rows: [true, false],
        card: "1 device",
        chips: [
          ["Policy0", "allow"],
          ["Policy1", null],
        ],
      },
    );
  });

  // Catches a live switch for an unreachable policy (it would switch Policy1), or no reason given.
  it("a policy no key reaches gets a locked switch that writes nothing", () => {
    const policies: PickerPolicy[] = [
      { name: "Policy1", description: "Policy0", devices: 1 },
      { name: "Policy0", description: "", devices: 2 },
    ];
    const p = draftOf({ allow: [], deny: [] });
    const chips = policyChips(p, policies);
    deepStrictEqual(
      chips.map((c) => [c.id, c.takenBy]),
      [
        ["Policy1", null],
        ["Policy0", "Policy1"],
      ],
    );
    deepStrictEqual(joinSelector(flipPolicy(p, chips[1].id, policies, "all")), {
      allow: [],
      deny: [],
    });
  });
});

describe("the card's label", () => {
  // Catches entries counted instead of devices, a host counted twice, or the plural chosen wrongly.
  it("counts devices once and subtracts the denied", () => {
    const say = (sel: { allow: string[]; deny: string[] }, locale = "en", hosts = HOSTS) =>
      coverageLabel(sel, hosts, POLICIES, t, locale);
    strictEqual(say({ allow: [], deny: [] }), "Every device");
    strictEqual(say({ allow: ["policy:Kids", "mac:aa:00:00:00:00:01"], deny: [] }), "2 devices");
    strictEqual(say({ allow: ["policy:Kids"], deny: ["mac:aa:00:00:00:00:03"] }), "1 device");
    strictEqual(say({ allow: [], deny: ["mac:aa:00:00:00:00:02", "192.168.1.0/30"] }), "All but 2");
    strictEqual(say({ allow: ["192.168.1.4/30"], deny: [] }, "ru"), "3 devices (2-4)");
    strictEqual(say({ allow: ["policy:Gone"], deny: [] }), "0 devices");
    strictEqual(say({ allow: ["policy:Kids"], deny: [] }, "en", []), "2 devices");
  });
});

describe("a host in a policy through its segment", () => {
  const policies: PickerPolicy[] = [
    ...POLICIES,
    { name: "Policy9", description: "Guests", devices: 1 },
  ];
  const guest: Host = {
    mac: "aa:00:00:00:00:09",
    name: "Guest phone",
    ip: "192.168.2.9",
    ip6: [],
    active: true,
    registered: false,
    policy: "Policy9",
  };
  const hosts = [...HOSTS, guest];
  const sel = { allow: ["policy:Guests"], deny: [] };

  it("counts in the card's label", () => {
    strictEqual(coverageLabel(sel, hosts, policies, t, "en"), "1 device");
  });
});

describe("a MAC the firmware lists twice", () => {
  // Two rows with one MAC are a duplicate-key error in Svelte; catches both kept or the offline one winning.
  it("is one row, the active host's", () => {
    const offline: Host = { ...HOSTS[0], ip: "192.168.1.50", active: false };
    const rows = hostRows([offline, HOSTS[0], HOSTS[1]], splitSelector(undefined));
    deepStrictEqual(macsOf(rows), ["01", "02"]);
    deepStrictEqual([rows[0].ip, rows[0].active], ["192.168.1.5", true]);
    const twice = hostRows(
      [HOSTS[1], { ...HOSTS[1], ip: "192.168.1.60" }],
      splitSelector(undefined),
    );
    deepStrictEqual(
      twice.map((r) => r.ip),
      ["192.168.1.6"],
    );
  });
});

describe("an address entry covering an address", () => {
  // Catches a byte-rounded mask or a match crossing address families.
  it("masks by bits and never crosses families", () => {
    strictEqual(addressCovers("192.168.1.0/24", "192.168.1.200"), true);
    strictEqual(addressCovers("192.168.1.0/24", "192.168.2.1"), false);
    strictEqual(addressCovers("192.168.1.4/30", "192.168.1.8"), false);
    strictEqual(addressCovers("fd00::/64", "fd00::5"), true);
    strictEqual(addressCovers("192.168.1.5", "192.168.1.5"), true);
    strictEqual(addressCovers("192.168.1.5", "fd00::5"), false);
  });
});
