import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const { groupChoices, ifaceTitle, lanChoices } = await import("../../src/data/iface-choices");
const { uplinkOptions } = await import("../../src/modules/tunnels/tunnel-editor");
const { interfaces } = await import("../../src/data/interfaces.svelte");
const { defaultGroup } = await import("../../src/utils/defaults");

type Item = {
  id: string;
  name?: string;
  ndmsName?: string;
  role?: "tunnel" | "wan" | "lan" | "other";
};

const LIST: Item[] = [
  { id: "blackhole" },
  { id: "block" },
  { id: "eth2.1", role: "other" },
  { id: "br0", name: "Home network", role: "lan" },
  { id: "nwg0", name: "WARP", role: "tunnel" },
  { id: "ppp0", name: "Broadband", ndmsName: "PPPoE0", role: "wan" },
  { id: "nwg2", ndmsName: "Wireguard2", role: "tunnel" },
  { id: "br1", role: "lan" },
  { id: "eth3", role: "wan" },
  { id: "tunvless0", name: "VLESS", role: "tunnel" },
];

const ids = (xs: { id: string }[]) => xs.map((x) => x.id);

describe("interface choices", () => {
  // Catches a non-tunnel among the first rows, the tunnels reordered, or the blackhole lost.
  it("tunnels come first in the daemon's order, then the blackhole", () => {
    const c = groupChoices(LIST, ["nwg0"]);
    assert.deepStrictEqual(ids(c.head), ["nwg0", "nwg2", "tunvless0"]);
    assert.strictEqual(c.blackhole?.id, "blackhole");
  });

  // Catches the rest out of wan, lan, other order, an entry of a group dropped, or a tunnel or the blackhole among them.
  it("the rest is wan, then lan, then other", () => {
    assert.deepStrictEqual(ids(groupChoices(LIST, ["nwg0"]).rest), [
      "ppp0",
      "eth3",
      "br0",
      "br1",
      "eth2.1",
    ]);
  });

  // Catches the rest hidden while a chosen entry is in it, or open while every entry is a tunnel or the blackhole.
  it("the rest starts open only when a chosen entry is in it", () => {
    assert.strictEqual(groupChoices(LIST, ["nwg0"]).expanded, false);
    assert.strictEqual(groupChoices(LIST, ["blackhole"]).expanded, false);
    assert.strictEqual(groupChoices(LIST, ["gone0"]).expanded, false);
    assert.strictEqual(groupChoices(LIST, ["ppp0"]).expanded, true);
    assert.strictEqual(groupChoices(LIST, ["nwg0", "br1"]).expanded, true);
  });

  // Catches a chosen entry the router lacks left out of the picker, so it can be neither seen nor removed.
  it("a chosen entry the router lacks is offered after the tunnels", () => {
    const c = groupChoices(LIST, ["nwg0", "nwg3", "ppp0", "nwg4"]);
    assert.deepStrictEqual(ids(c.head), ["nwg0", "nwg2", "tunvless0", "nwg3", "nwg4"]);
    assert.strictEqual(ids(c.rest).includes("nwg3"), false);
  });

  // Catches an interface without a role dropped instead of counted among the rest.
  it("an interface without a role is one of the rest", () => {
    assert.deepStrictEqual(ids(groupChoices([{ id: "eth9" }], []).rest), ["eth9"]);
  });

  // Catches the NDMS name shown over a description, the system name lost, or a bare id given a second line.
  it("a row shows the description, else the NDMS name, over the system name", () => {
    assert.deepStrictEqual(ifaceTitle({ id: "ppp0", name: "Broadband", ndmsName: "PPPoE0" }), {
      title: "Broadband",
      sub: "ppp0",
    });
    assert.deepStrictEqual(ifaceTitle({ id: "nwg2", ndmsName: "Wireguard2" }), {
      title: "Wireguard2",
      sub: "nwg2",
    });
    assert.deepStrictEqual(ifaceTitle({ id: "eth9" }), { title: "eth9", sub: undefined });
  });

  // Catches the segments missing on an empty query, a search blind to names, or the blackhole or a tunnel offered as a LAN.
  it("LAN choices are the segments, or every match of a search", () => {
    assert.deepStrictEqual(ids(lanChoices(LIST, "")), ["br0", "br1"]);
    assert.deepStrictEqual(ids(lanChoices(LIST, "ETH2")), ["eth2.1"]);
    assert.deepStrictEqual(ids(lanChoices(LIST, "pppoe")), ["ppp0"]);
    assert.deepStrictEqual(ids(lanChoices(LIST, "home")), ["br0"]);
    assert.deepStrictEqual(ids(lanChoices(LIST, "vless")), []);
    assert.deepStrictEqual(ids(lanChoices(LIST, "black")), []);
    assert.deepStrictEqual(
      ids(
        lanChoices([{ id: "tunvless99" }, { id: "tunvless100" }, { id: "tunvless01" }], "tunvless"),
      ),
      ["tunvless100", "tunvless01"],
    );
  });

  // Catches a new group given anything but the first interface the daemon lists.
  it("a new group takes the first listed interface", () => {
    interfaces.list = [
      { id: "ppp0", name: "Broadband", role: "wan" },
      { id: "wg0", role: "tunnel" },
    ];
    assert.strictEqual(defaultGroup().interface, "ppp0");
  });

  // Catches block missing, offered before the blackhole, among the rest, or offered as a LAN or a tunnel's uplink.
  it("block_is_offered_after_blackhole_and_never_as_a_lan_or_uplink", () => {
    const c = groupChoices(LIST, ["nwg0"]);
    assert.strictEqual(c.blackhole?.id, "blackhole");
    assert.strictEqual(c.block?.id, "block");
    assert.strictEqual(ids(c.rest).includes("block"), false);
    assert.strictEqual(ids(c.head).includes("block"), false);
    assert.strictEqual(groupChoices(LIST, ["block"]).expanded, false);
    assert.deepStrictEqual(ids(lanChoices(LIST, "block")), []);
    const self = {
      id: "t0",
      device: "tunvless0",
      uplink: { kind: "auto", ref: "" },
    } as any;
    const values = uplinkOptions(self, [self], LIST as any, (k: string) => k, { opened: true }).map(
      (o) => o.value,
    );
    assert.strictEqual(values.includes("iface:block"), false);
    assert.strictEqual(values.includes("iface:blackhole"), false);
    assert.strictEqual(values.includes("iface:br0"), true);
  });
});
