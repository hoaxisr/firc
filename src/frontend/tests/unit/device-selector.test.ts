import { deepStrictEqual, strictEqual } from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { parseConfig } from "../../src/types";
import { isValidDeviceEntry, normalizeMac } from "../../src/utils/device-validators";

describe("Device selector entry", () => {
  it("accepts a bare address, which names one device", () => {
    strictEqual(isValidDeviceEntry("192.168.1.5"), true);
    strictEqual(isValidDeviceEntry("fd00::1"), true);
  });

  it("accepts a prefix", () => {
    strictEqual(isValidDeviceEntry("192.168.1.0/24"), true);
    strictEqual(isValidDeviceEntry("192.168.1.0/32"), true);
    strictEqual(isValidDeviceEntry("fd00::/64"), true);
    strictEqual(isValidDeviceEntry("::/0"), true);
  });

  // "::" stands for at least one zero group, so an address with all eight groups cannot carry it.
  it("refuses a v6 address whose :: covers nothing", () => {
    strictEqual(isValidDeviceEntry("1:2:3:4:5:6:7::8"), false);
    strictEqual(isValidDeviceEntry("1:2:3:4:5:6:7:8:9"), false);
    strictEqual(isValidDeviceEntry("1:2:3:4:5:6:7"), false);
    strictEqual(isValidDeviceEntry("fd00::1::2"), false);
  });

  // The daemon accepts leading zeros in a prefix; refusing them here would refuse a working selector.
  it("takes a prefix written with leading zeros, as the daemon does", () => {
    strictEqual(isValidDeviceEntry("192.168.1.0/024"), true);
    strictEqual(isValidDeviceEntry("1.2.3.4/0032"), true);
    strictEqual(isValidDeviceEntry("fd00::/0064"), true);
    strictEqual(isValidDeviceEntry("::1/0128"), true);
    strictEqual(isValidDeviceEntry("192.168.1.0/00000024"), true);
  });

  it("refuses a prefix longer than the family allows", () => {
    strictEqual(isValidDeviceEntry("192.168.1.0/33"), false);
    strictEqual(isValidDeviceEntry("fd00::/129"), false);
    strictEqual(isValidDeviceEntry("192.168.1.0/0033"), false);
    strictEqual(isValidDeviceEntry("192.168.1.0/+24"), false);
    strictEqual(isValidDeviceEntry("192.168.1.0/ 24"), false);
    strictEqual(isValidDeviceEntry("192.168.1.0/0x18"), false);
  });

  it("refuses an address that is not one", () => {
    strictEqual(isValidDeviceEntry("192.168.1.256"), false);
    strictEqual(isValidDeviceEntry("192.168.1"), false);
    strictEqual(isValidDeviceEntry(""), false);
    strictEqual(isValidDeviceEntry("   "), false);
  });

  it("refuses a domain: the selector names devices, not names", () => {
    strictEqual(isValidDeviceEntry("example.com"), false);
    strictEqual(isValidDeviceEntry("laptop.lan"), false);
    strictEqual(isValidDeviceEntry("www.example.com.br"), false);
    strictEqual(isValidDeviceEntry("a.b.c.d"), false);
  });

  it("accepts a policy name", () => {
    strictEqual(isValidDeviceEntry("policy:Home"), true);
    strictEqual(isValidDeviceEntry("policy:Guest network"), true);
  });

  it("refuses a policy entry the daemon would refuse", () => {
    strictEqual(isValidDeviceEntry("policy:"), false);
    strictEqual(isValidDeviceEntry("policy: Home"), false);
    strictEqual(isValidDeviceEntry("policy:Home "), false);
  });

  // Catches a v4-mapped address not following the daemon, or a prefix shorter than the mapping being accepted.
  it("follows the daemon on v4-mapped addresses", () => {
    strictEqual(isValidDeviceEntry("::ffff:192.168.1.5"), true);
    strictEqual(isValidDeviceEntry("::ffff:192.168.1.0/120"), true);
    strictEqual(isValidDeviceEntry("::ffff:0.0.0.0/95"), false);
  });
});

describe("A mac: entry", () => {
  it("is taken with ':' or '-' throughout, in either case", () => {
    strictEqual(isValidDeviceEntry("mac:aa:bb:cc:dd:ee:ff"), true);
    strictEqual(isValidDeviceEntry("mac:AA-BB-CC-DD-EE-FF"), true);
    strictEqual(isValidDeviceEntry("mac:Aa:bB:0c:Dd:eE:0f"), true);
  });

  it("is refused mixed, short, long, dotted, empty or all zero", () => {
    strictEqual(isValidDeviceEntry("mac:aa:bb-cc:dd:ee:ff"), false);
    strictEqual(isValidDeviceEntry("mac:aa:bb:cc:dd:ee"), false);
    strictEqual(isValidDeviceEntry("mac:aa:bb:cc:dd:ee:ff:00"), false);
    strictEqual(isValidDeviceEntry("mac:aabb.ccdd.eeff"), false);
    strictEqual(isValidDeviceEntry("mac:"), false);
    strictEqual(isValidDeviceEntry("mac:00:00:00:00:00:00"), false);
    strictEqual(isValidDeviceEntry("mac:gg:bb:cc:dd:ee:ff"), false);
  });

  it("is written lower case with ':', as the daemon stores it", () => {
    strictEqual(normalizeMac("AA-BB-CC-DD-EE-0F"), "aa:bb:cc:dd:ee:0f");
    strictEqual(normalizeMac("aa:bb:cc:dd:ee:0f"), "aa:bb:cc:dd:ee:0f");
    strictEqual(normalizeMac("aa:bb-cc:dd:ee:0f"), null);
  });
});

describe("Imported config", () => {
  // Catches import dropping a group's selector, which widens it to every device.
  it("keeps a group's device selector", () => {
    const { groups } = parseConfig(
      JSON.stringify({
        groups: [
          {
            id: "0a1b2c3d",
            name: "Media",
            interface: "nwg0",
            enable: true,
            rules: [],
            devices: { allow: ["192.168.1.0/24"], deny: ["192.168.1.5"] },
          },
        ],
      }),
    );
    deepStrictEqual(groups[0].devices, {
      allow: ["192.168.1.0/24"],
      deny: ["192.168.1.5"],
    });
  });

  it("gives a group with no selector an empty one, which means every device", () => {
    const { groups } = parseConfig(
      JSON.stringify({
        groups: [{ id: "0a1b2c3d", name: "Media", interface: "nwg0", enable: true, rules: [] }],
      }),
    );
    deepStrictEqual(groups[0].devices, { allow: [], deny: [] });
  });
});
