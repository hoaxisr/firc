import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const {
  blockTargets,
  deviceAddresses,
  ownerAbove,
  relativeTime,
  rowDevices,
  rowAbove,
  rowStatus,
  statsDevices,
} = await import("../../src/data/dnsstats.svelte");

const host = (mac: string, name: string, ip: string, ip6: string[] = []) => ({
  mac,
  name,
  ip,
  ip6,
  active: true,
  registered: true,
  policy: "",
});

const echo = (s: string) => s;

const group = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  name: id,
  interface: "block",
  enable: true,
  devices: { allow: [] as string[], deny: [] as string[] },
  rules: [],
  resolve: { tunnel: true, server: "" },
  ...extra,
});

describe("dnsstats devices", () => {
  // Catches a phone's v4 and v6 listed as two devices, or its v6 missing from device=.
  it("a host's v4 and v6 are one device", () => {
    const hosts = [host("aa:00:00:00:00:03", "Phone", "192.168.1.7", ["fd00::7", "2001:db8::7"])];
    const devices = statsDevices(hosts, ["192.168.1.7", "FD00::7"]);
    assert.deepStrictEqual(devices, [
      {
        key: "mac:aa:00:00:00:00:03",
        label: "Phone",
        entry: "mac:aa:00:00:00:00:03",
        addresses: ["192.168.1.7", "fd00::7", "2001:db8::7"],
      },
    ]);
    assert.deepStrictEqual(
      rowDevices(
        [
          { address: "fd00::7", queries: 3 },
          { address: "192.168.1.7", queries: 5 },
        ],
        devices,
      ),
      [{ key: "mac:aa:00:00:00:00:03", label: "Phone", address: "192.168.1.7", queries: 8 }],
    );
  });

  // Catches an address no host names dropped from the select or the row, or given a host's name.
  it("an address no host claims is its own device", () => {
    const hosts = [host("", "", "192.168.1.8"), host("aa:00:00:00:00:01", "TV", "192.168.1.5")];
    const devices = statsDevices(hosts, ["192.168.1.99", "192.168.1.5"]);
    assert.deepStrictEqual(
      devices.map((d) => [d.label, d.entry, d.addresses]),
      [
        ["192.168.1.8", "192.168.1.8", ["192.168.1.8"]],
        ["TV", "mac:aa:00:00:00:00:01", ["192.168.1.5"]],
        ["192.168.1.99", "192.168.1.99", ["192.168.1.99"]],
      ],
    );
    assert.deepStrictEqual(
      rowDevices(
        [
          { address: "192.168.1.99", queries: 2 },
          { address: "192.168.1.5", queries: 7 },
        ],
        devices,
      ).map((d) => [d.label, d.address, d.queries]),
      [
        ["TV", "192.168.1.5", 7],
        ["192.168.1.99", "192.168.1.99", 2],
      ],
    );
  });

  // Catches a host the router lists twice under one MAC (v4 and v6 apart) shown as two devices.
  it("one MAC in two host entries is one device", () => {
    const hosts = [
      host("aa:00:00:00:00:03", "", "192.168.1.7"),
      host("aa:00:00:00:00:03", "Phone", "", ["fd00::7"]),
    ];
    assert.deepStrictEqual(statsDevices(hosts, ["fd00::7"]), [
      {
        key: "mac:aa:00:00:00:00:03",
        label: "Phone",
        entry: "mac:aa:00:00:00:00:03",
        addresses: ["192.168.1.7", "fd00::7"],
      },
    ]);
  });

  // Catches a device of more than 12 addresses cut blindly, dropping the ones that asked.
  it("past 12 addresses the ones seen asking go first", () => {
    const many = Array.from({ length: 14 }, (_, i) => `fd00::${i + 1}`);
    const device = { key: "k", label: "Phone", entry: "k", addresses: many };
    const picked = deviceAddresses(device, ["fd00::14", "fd00::13"]);
    assert.strictEqual(picked.length, 12);
    assert.deepStrictEqual(picked.slice(0, 2), ["fd00::13", "fd00::14"]);
    assert.deepStrictEqual(picked.slice(2), many.slice(0, 10));
    assert.deepStrictEqual(deviceAddresses({ ...device, addresses: many.slice(0, 3) }, []), [
      "fd00::1",
      "fd00::2",
      "fd00::3",
    ]);
  });

  // Catches minutes shown as hours, or a fresh query not read as just now.
  it("the last query reads as just now, minutes or hours ago", () => {
    const now = 1_790_000_000;
    assert.strictEqual(relativeTime(now - 30, now, echo), "just now");
    assert.strictEqual(relativeTime(now + 5, now, echo), "just now");
    assert.strictEqual(relativeTime(now - 600, now, echo), "10 min ago");
    assert.strictEqual(relativeTime(now - 3599, now, echo), "59 min ago");
    assert.strictEqual(relativeTime(now - 5 * 3600 - 10, now, echo), "5 h ago");
  });
});

describe("block targets", () => {
  // Catches a disabled, routing, device-scoped or deny-carrying group offered for everyone.
  it("for everyone only enabled block groups with an empty selector", () => {
    const groups = [
      group("route", { interface: "nwg0" }),
      group("off", { enable: false }),
      group("kids", { devices: { allow: ["mac:aa:00:00:00:00:03"], deny: [] } }),
      group("deny", { devices: { allow: [], deny: ["192.168.1.9"] } }),
      group("ads"),
    ];
    assert.deepStrictEqual(
      blockTargets(groups as any, null).map((g) => g.id),
      ["ads"],
    );
  });

  // Catches a group that admits more than the one device offered as its own.
  it("for one device only a block group whose allow is exactly its entry", () => {
    const groups = [
      group("two", { devices: { allow: ["mac:aa:00:00:00:00:03", "192.168.1.9"], deny: [] } }),
      group("other", { devices: { allow: ["mac:aa:00:00:00:00:04"], deny: [] } }),
      group("ads"),
      group("kids", { devices: { allow: ["mac:aa:00:00:00:00:03"], deny: [] } }),
    ];
    assert.deepStrictEqual(
      blockTargets(groups as any, "mac:aa:00:00:00:00:03").map((g) => g.id),
      ["kids"],
    );
  });

  // Catches a hand-typed MAC spelling missed, so a duplicate device group gets created.
  it("a device group is found whatever the MAC's spelling", () => {
    const groups = [group("kids", { devices: { allow: ["mac:AA-00-00-00-00-03"], deny: [] } })];
    assert.deepStrictEqual(
      blockTargets(groups as any, "mac:aa:00:00:00:00:03").map((g) => g.id),
      ["kids"],
    );
  });

  // Catches the warning given for a group below the target, a block owner, or a new group.
  it("the owner warns only when it is a routing group above the target", () => {
    const groups = [
      group("route", { interface: "nwg0" }),
      group("ads"),
      group("low", { interface: "nwg0" }),
    ];
    assert.strictEqual(ownerAbove(groups as any, "route", "ads")?.id, "route");
    assert.strictEqual(ownerAbove(groups as any, "low", "ads"), null);
    assert.strictEqual(ownerAbove(groups as any, "ads", "ads"), null);
    assert.strictEqual(ownerAbove(groups as any, "route", null), null);
    assert.strictEqual(ownerAbove(groups as any, "gone", "ads"), null);
    const two = [group("top"), group("ads")];
    assert.strictEqual(ownerAbove(two as any, "top", "ads"), null);
  });
});

describe("row status", () => {
  const row = (owner: Record<string, unknown> | null) => ({
    name: "ya.ru",
    queries: 1,
    blocked: 0,
    last: 0,
    owner,
    clients: [],
    clientsTotal: 1,
  });
  const clean = () => false;
  const rule = (extra: Record<string, unknown> = {}) => ({
    id: "r1r1r1r1",
    enable: true,
    rule: "ya.ru",
    type: "domain",
    ...extra,
  });
  const PHONE = "mac:aa:00:00:00:00:03";

  // Catches the daemon's owner interface or blocked flag trusted over the Groups store.
  it("в «X» follows the Groups store, not the daemon's owner fields", () => {
    const groups = [group("ads", { name: "Ads" }), group("ex", { name: "Ex", interface: "nwg0" })];
    const stale = { id: "ads", name: "Ads", interface: "nwg0", blocked: false };
    assert.deepStrictEqual(rowStatus(row(stale) as any, groups as any, null, clean), {
      group: "Ads",
      unsaved: false,
    });
    const wrong = { id: "ex", name: "Ex", interface: "block", blocked: true };
    assert.strictEqual(rowStatus(row(wrong) as any, groups as any, null, clean), null);
  });

  // Catches a device group's rule claimed for every device, or for another device.
  it("a held rule counts only in a group that applies to the devices in view", () => {
    const groups = [
      group("kids", { name: "Kids", devices: { allow: [PHONE], deny: [] }, rules: [rule()] }),
    ];
    assert.strictEqual(rowStatus(row(null) as any, groups as any, null, clean), null);
    assert.deepStrictEqual(rowStatus(row(null) as any, groups as any, PHONE, clean), {
      group: "Kids",
      unsaved: false,
    });
    assert.strictEqual(
      rowStatus(row(null) as any, groups as any, "mac:aa:00:00:00:00:04", clean),
      null,
    );
    assert.deepStrictEqual(
      rowStatus(row(null) as any, groups as any, PHONE, () => true),
      {
        group: "Kids",
        unsaved: true,
      },
    );
  });

  // Catches a saved block claimed while a routing group above still owns the name.
  it("a saved rule under a routing owner above is not claimed", () => {
    const groups = [
      group("ex", { name: "Ex", interface: "nwg0" }),
      group("ads", { name: "Ads", rules: [rule()] }),
    ];
    const ex = { id: "ex", name: "Ex", interface: "nwg0", blocked: false };
    assert.strictEqual(rowStatus(row(ex) as any, groups as any, null, clean), null);
    assert.deepStrictEqual(rowStatus(row(null) as any, groups as any, null, clean), {
      group: "Ads",
      unsaved: false,
    });
  });

  // Catches a disabled rule, or one in a disabled group, read as blocking.
  it("a disabled rule or group holds nothing", () => {
    const off = [group("ads", { name: "Ads", rules: [rule({ enable: false })] })];
    assert.strictEqual(
      rowStatus(row(null) as any, off as any, null, () => true),
      null,
    );
    const gone = [group("ads", { name: "Ads", enable: false, rules: [rule()] })];
    assert.strictEqual(
      rowStatus(row(null) as any, gone as any, null, () => true),
      null,
    );
  });

  // Catches the most recent asker's device group read as blocking for every device, or a disabled owner.
  it("a block owner claims only where it applies and while it is on", () => {
    const kids = group("kids", { name: "Kids", devices: { allow: [PHONE], deny: [] } });
    const owner = { id: "kids", name: "Kids", interface: "block", blocked: true };
    assert.strictEqual(rowStatus(row(owner) as any, [kids] as any, null, clean), null);
    assert.deepStrictEqual(rowStatus(row(owner) as any, [kids] as any, PHONE, clean), {
      group: "Kids",
      unsaved: false,
    });
    const off = group("ads", { name: "Ads", enable: false });
    const ads = { id: "ads", name: "Ads", interface: "block", blocked: true };
    assert.strictEqual(rowStatus(row(ads) as any, [off] as any, null, clean), null);
    assert.strictEqual(rowStatus(row(ads) as any, [off] as any, PHONE, clean), null);
  });

  // Catches the routing group above left unnamed on a row whose block does not take effect.
  it("the row names a routing owner above its held rule", () => {
    const groups = [
      group("ex", { name: "Ex", interface: "nwg0" }),
      group("ads", { name: "Ads", rules: [rule()] }),
      group("low", { name: "Low", interface: "nwg0" }),
    ];
    const ex = { id: "ex", name: "Ex", interface: "nwg0", blocked: false };
    const low = { id: "low", name: "Low", interface: "nwg0", blocked: false };
    assert.strictEqual(rowAbove(row(ex) as any, groups as any, null), "Ex");
    assert.strictEqual(rowAbove(row(low) as any, groups as any, null), "");
    assert.strictEqual(rowAbove(row(null) as any, groups as any, null), "");
    assert.strictEqual(rowAbove(row(ex) as any, groups.slice(0, 1) as any, null), "");
  });
});
