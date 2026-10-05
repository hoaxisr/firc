import { deepStrictEqual, strictEqual } from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { deriveRule, detectRuleType } from "../../src/utils/detect-rule-type";
import {
  isValidDomain,
  isValidNamespace,
  isValidPorts,
  isValidRegex,
  isValidSubnet,
  isValidSubnet6,
  isValidWildcard,
} from "../../src/utils/rule-validators";

describe("Rule validator", () => {
  it("should be valid regexp", () => {
    strictEqual(isValidRegex("^[a-zA-Z0-9]+$"), true);
    strictEqual(isValidRegex("^[a-zA-Z0-9+$"), false);
    strictEqual(isValidRegex(".*"), true);
    strictEqual(isValidRegex("a(b|c)d"), true);
    strictEqual(isValidRegex("\\d+"), true);
  });

  it("should be valid domain", () => {
    strictEqual(isValidDomain("domain.com"), true);
    strictEqual(isValidDomain("domain.com.cn"), true);
    strictEqual(isValidDomain("domain.com.cn.cn"), true);
    strictEqual(isValidDomain(".com.cn.cn.cn"), false);
    strictEqual(isValidDomain("com.cn.cn."), true);
    strictEqual(isValidDomain("sub.domain.com"), true);
    strictEqual(isValidDomain("sub-domain.com"), true);
    strictEqual(isValidDomain("sub.domain-test.com"), true);
    strictEqual(isValidDomain("123.domain.com"), true);
    strictEqual(isValidDomain("domain.123.com"), true);
    strictEqual(isValidDomain("domain.com123"), true);
    strictEqual(isValidDomain("domain.com-"), true);
    strictEqual(isValidDomain("-domain.com"), true);
    strictEqual(isValidDomain("domain.-com"), true);
    strictEqual(isValidDomain("domain..com"), false);
    strictEqual(isValidDomain(".domain"), false);
    strictEqual(isValidDomain("domain.123"), true);
    strictEqual(isValidDomain("domain.123.123"), true);
    strictEqual(isValidDomain("a.b.c.d"), true);
    strictEqual(isValidDomain("a.b.c.123"), true);
    strictEqual(isValidDomain("a.b.c.d-"), true);
    strictEqual(isValidDomain("a.b.c.-d"), true);
    strictEqual(isValidDomain("a.b.c..d"), false);
    strictEqual(isValidDomain("a.b.c."), true);
    strictEqual(isValidDomain(".a.b.c"), false);
  });

  it("should be valid wildcard", () => {
    strictEqual(isValidWildcard("*.domain.com"), true);
    strictEqual(isValidWildcard("*.sub.domain.com"), true);
    strictEqual(isValidWildcard("domain.com"), true);
    strictEqual(isValidWildcard("sub.domain.com"), true);
    strictEqual(isValidWildcard("*.domain.com.cn"), true);
    strictEqual(isValidWildcard("*.sub.domain.com.cn"), true);
    strictEqual(isValidWildcard("domain.com.cn"), true);
    strictEqual(isValidWildcard("sub.domain.com.cn"), true);
    strictEqual(isValidWildcard("*.domain.com.cn.cn"), true);
    strictEqual(isValidWildcard("*.sub.domain.com.cn.cn"), true);
    strictEqual(isValidWildcard("domain.com.cn.cn"), true);
    strictEqual(isValidWildcard("sub.domain.com.cn.cn"), true);
    strictEqual(isValidWildcard("*.domain.123"), true);
    strictEqual(isValidWildcard("domain.123"), true);
    strictEqual(isValidWildcard("*.domain.123.123"), true);
    strictEqual(isValidWildcard("domain.123.123"), true);
    strictEqual(isValidWildcard("*.domain.com-"), true);
    strictEqual(isValidWildcard("*.domain.-com"), true);
    strictEqual(isValidWildcard("*.domain..com"), false);
    strictEqual(isValidWildcard("*.domain"), true);
    strictEqual(isValidWildcard("*.domain."), true);
    strictEqual(isValidWildcard(".*.domain"), false);
    strictEqual(isValidWildcard("*."), true);
    strictEqual(isValidWildcard("domain"), true);
    strictEqual(isValidWildcard("*domain.com"), true);
  });

  it("should be valid namespace", () => {
    strictEqual(isValidNamespace("domain.com"), true);
    strictEqual(isValidNamespace("domain.com.cn"), true);
    strictEqual(isValidNamespace("domain.com.cn.cn"), true);
    strictEqual(isValidNamespace(".com.cn.cn.cn"), false);
    strictEqual(isValidNamespace("com.cn.cn."), true);
    strictEqual(isValidNamespace("sub.domain.com"), true);
    strictEqual(isValidNamespace("sub-domain.com"), true);
    strictEqual(isValidNamespace("sub.domain-test.com"), true);
    strictEqual(isValidNamespace("123.domain.com"), true);
    strictEqual(isValidNamespace("domain.123.com"), true);
    strictEqual(isValidNamespace("domain.com123"), true);
    strictEqual(isValidNamespace("domain.com-"), true);
    strictEqual(isValidNamespace("-domain.com"), true);
    strictEqual(isValidNamespace("domain.-com"), true);
    strictEqual(isValidNamespace("domain..com"), false);
    strictEqual(isValidNamespace(".domain"), false);
    strictEqual(isValidNamespace("domain.123"), true);
    strictEqual(isValidNamespace("domain.123.123"), true);
    strictEqual(isValidNamespace("a.b.c.d"), true);
    strictEqual(isValidNamespace("a.b.c.123"), true);
    strictEqual(isValidNamespace("a.b.c.d-"), true);
    strictEqual(isValidNamespace("a.b.c.-d"), true);
    strictEqual(isValidNamespace("a.b.c..d"), false);
    strictEqual(isValidNamespace("a.b.c."), true);
    strictEqual(isValidNamespace(".a.b.c"), false);
    strictEqual(isValidNamespace("."), false);
    strictEqual(isValidNamespace(".."), false);
    strictEqual(isValidNamespace("..."), false);
    strictEqual(isValidNamespace("....domain.com"), false);
    strictEqual(isValidNamespace("domain.com...."), false);
  });
});

describe("Subnet6 validator agrees with the daemon", () => {
  it("accepts what inet_pton accepts", () => {
    strictEqual(isValidSubnet6("fd00::/8"), true);
    strictEqual(isValidSubnet6("fd00::1"), true);
    strictEqual(isValidSubnet6("2001:db8::/32"), true);
    strictEqual(isValidSubnet6("::/0"), true);
    strictEqual(isValidSubnet6("::ffff:192.168.1.5"), true);
  });

  it("refuses what it refuses", () => {
    strictEqual(isValidSubnet6("::::"), false);
    strictEqual(isValidSubnet6("fd00::1::2"), false);
    strictEqual(isValidSubnet6("1:2:3:4:5:6:7::8"), false);
    strictEqual(isValidSubnet6("1:2:3:4:5:6:7"), false);
    strictEqual(isValidSubnet6("zz::1"), false);
    strictEqual(isValidSubnet6("fd00::/129"), false);
    strictEqual(isValidSubnet6("10.0.0.0/8"), false);
    strictEqual(isValidSubnet6(""), false);
  });
});

describe("Subnet validator agrees with the daemon", () => {
  it("refuses an octet with a leading zero, as inet_pton does", () => {
    strictEqual(isValidSubnet("010.0.0.1"), false);
    strictEqual(isValidSubnet("01.2.3.4"), false);
    strictEqual(isValidSubnet("1.2.3.04"), false);
  });

  it("refuses a prefix that is not plain digits", () => {
    strictEqual(isValidSubnet("1.2.3.4/+8"), false);
    strictEqual(isValidSubnet("1.2.3.4/-0"), false);
    strictEqual(isValidSubnet("1.2.3.4/ 8"), false);
    strictEqual(isValidSubnet("1.2.3.4/33"), false);
  });

  it("still takes what the daemon takes", () => {
    strictEqual(isValidSubnet("10.0.0.0/8"), true);
    strictEqual(isValidSubnet("0.0.0.0/0"), true);
    strictEqual(isValidSubnet("192.168.1.5"), true);
    strictEqual(isValidSubnet("1.2.3.4/032"), true);
  });
});

// The UI and daemon must refuse the same patterns; the daemon is the authority.
Deno.test("a name the daemon routes is not refused here", () => {
  strictEqual(isValidDomain("_dmarc.example.com"), true);
  strictEqual(isValidDomain("_acme-challenge.example.com"), true);
  strictEqual(isValidNamespace("_dmarc.example.com"), true);
  strictEqual(isValidDomain("xn--80ak6aa92e.com"), true);
  strictEqual(isValidDomain("Google.COM"), true);
  strictEqual(isValidDomain("example.com."), true);
  strictEqual(isValidDomain("  example.com  "), true);
  strictEqual(isValidWildcard("*.Example.COM"), true);
});

Deno.test("a pattern no queried name can equal is refused here too", () => {
  strictEqual(isValidDomain("https://vk.com"), false);
  strictEqual(isValidDomain("vk.com/feed"), false);
  strictEqual(isValidDomain("exa mple.com"), false);
  strictEqual(isValidDomain(".example.com"), false);
  strictEqual(isValidDomain("example..com"), false);
  strictEqual(isValidDomain("   "), false);
  strictEqual(isValidWildcard("https://vk.com"), false);
  strictEqual(isValidDomain("2001:db8::1"), false);
  strictEqual(isValidDomain("[a-z].example.com"), false);
  strictEqual(isValidDomain("user@example.com"), false);
  strictEqual(isValidDomain("*.example.com"), false);
  strictEqual(isValidDomain("яндекс.com"), false);
  strictEqual(isValidDomain("😀.ws"), false);
  strictEqual(isValidDomain("example.com.."), false);
  strictEqual(isValidDomain("a".repeat(64) + ".example.com"), false);
  strictEqual(isValidDomain("a".repeat(63) + ".example.com"), true);
});

// Number() accepts sign, hex, exponent, spaces and empty; the daemon reads digits only.
Deno.test("a subnet6 prefix is digits, as the daemon reads it", () => {
  strictEqual(isValidSubnet6("fd00::/8"), true);
  strictEqual(isValidSubnet6("fd00::/128"), true);
  strictEqual(isValidSubnet6("fd00::/"), false);
  strictEqual(isValidSubnet6("fd00::/+5"), false);
  strictEqual(isValidSubnet6("fd00::/-0"), false);
  strictEqual(isValidSubnet6("fd00::/0x10"), false);
  strictEqual(isValidSubnet6("fd00::/1e2"), false);
  strictEqual(isValidSubnet6("fd00::/ 5"), false);
  strictEqual(isValidSubnet6("fd00::/129"), false);
});

// PCRE2 patterns like `a*+` and `(?>ab)` do not compile in JS; this side must not refuse them.
Deno.test("a regex JavaScript cannot compile is not refused here", () => {
  strictEqual(isValidRegex("a*+"), true);
  strictEqual(isValidRegex("(?>ab)"), true);
  strictEqual(isValidRegex("(?i)x"), true);
  strictEqual(isValidRegex("^[a-z"), false);
});

// Catches a guessed regex that is not written as one and anchored at both ends, so `.` matches any byte.
Deno.test("the import dialog guesses a type the way the daemon does", () => {
  strictEqual(detectRuleType("example.com"), "namespace");
  strictEqual(detectRuleType("_dmarc.example.com"), "namespace");
  strictEqual(detectRuleType("10.0.0.0/8"), "subnet");
  strictEqual(detectRuleType("fd00::/8"), "subnet6");
  strictEqual(detectRuleType("*.example.com"), "wildcard");
  strictEqual(detectRuleType("a*.example.com"), "wildcard");
  strictEqual(detectRuleType("^example\\.com$"), "regex");
  strictEqual(detectRuleType("||example.com^"), null);
  strictEqual(detectRuleType("a|b.example.com"), null);
  strictEqual(detectRuleType("^ads"), null);
  strictEqual(detectRuleType("https://vk.com"), null);
  strictEqual(detectRuleType("0.0.0.0 tracker.example"), null);
});

// `^v|q$` is anchored at neither end; the guess must wrap it as \A(?:...)\z like the daemon.
Deno.test("a guessed regex is anchored by construction, as in the daemon", () => {
  deepStrictEqual(deriveRule("^v|q$"), {
    type: "regex",
    rule: "\\A(?:^v|q$)\\z",
  });

  deepStrictEqual(deriveRule("^example\\.com$"), {
    type: "regex",
    rule: "\\A(?:^example\\.com$)\\z",
  });

  deepStrictEqual(deriveRule("example.com"), { type: "namespace", rule: "example.com" });
  deepStrictEqual(deriveRule("*.example.com"), { type: "wildcard", rule: "*.example.com" });
  strictEqual(deriveRule("||example.com^"), null);
});

// JS reads \p{L}, \N and [[:alpha:]] as literals; the gate must fail closed rather than guess.
Deno.test("a pattern this engine cannot judge is not guessed", () => {
  strictEqual(detectRuleType("^[\\p{L}.]+$"), null);
  strictEqual(detectRuleType("^\\N+$"), null);
  strictEqual(detectRuleType("^[[:alpha:].]+$"), null);
  strictEqual(detectRuleType("^\\pL+$"), null);
  strictEqual(detectRuleType("^ads(*ACCEPT)$"), null);
  strictEqual(detectRuleType("^example\\.com$"), "regex");
  strictEqual(detectRuleType("^(a|b)\\.example\\.com$"), "regex");
  strictEqual(detectRuleType("^ads[0-9]+\\.example\\.net$"), "regex");
  strictEqual(detectRuleType("^\\w+\\.\\w+$"), null);
  strictEqual(detectRuleType("^\\w+\\.\\w+\\.\\w+$"), null);
  strictEqual(detectRuleType("^.+\\..+\\..+$"), null);
  strictEqual(detectRuleType("^www\\.example\\.com$"), "regex");
});

// Catches the field accepting a port list the daemon refuses with a message that names no entry.
Deno.test("a ports list is what the daemon reads, and nothing else", () => {
  strictEqual(isValidPorts(""), true);
  strictEqual(isValidPorts("53"), true);
  strictEqual(isValidPorts("1000-2000"), true);
  strictEqual(isValidPorts("53,443,1000-2000"), true);
  strictEqual(isValidPorts("1"), true);
  strictEqual(isValidPorts("65535"), true);
  strictEqual(isValidPorts("443-443"), true);

  strictEqual(isValidPorts("0"), false);
  strictEqual(isValidPorts("0-100"), false);
  strictEqual(isValidPorts("65536"), false);
  strictEqual(isValidPorts("1000-65536"), false);
  strictEqual(isValidPorts("2000-1000"), false);
  strictEqual(isValidPorts("53,"), false);
  strictEqual(isValidPorts(","), false);
  strictEqual(isValidPorts("53,,443"), false);
  strictEqual(isValidPorts("53, 443"), false);
  strictEqual(isValidPorts(" 53"), false);
  strictEqual(isValidPorts("53 "), false);
  strictEqual(isValidPorts("a"), false);
  strictEqual(isValidPorts("53:443"), false);
  strictEqual(isValidPorts("0x35"), false);
  strictEqual(isValidPorts("+53"), false);
  strictEqual(isValidPorts("-53"), false);
  strictEqual(isValidPorts("53-"), false);
  strictEqual(isValidPorts("1-2-3"), false);
});

// xt_multiport counts ports, not entries (a range is two); too many fails the whole iptables-restore.
Deno.test("the ports ceiling is fifteen ports, and a range costs two", () => {
  const singles = (n: number) => Array.from({ length: n }, (_, i) => 1 + i).join(",");
  const ranges = (n: number) =>
    Array.from({ length: n }, (_, i) => `${1 + i * 10}-${5 + i * 10}`).join(",");

  strictEqual(isValidPorts(singles(15)), true);
  strictEqual(isValidPorts(singles(16)), false);

  strictEqual(isValidPorts(ranges(7)), true);
  strictEqual(isValidPorts(`${ranges(7)},9999`), true);
  strictEqual(isValidPorts(`${ranges(7)},9998,9999`), false);
  strictEqual(isValidPorts(ranges(8)), false);

  strictEqual(
    isValidPorts(Array.from({ length: 15 }, (_, i) => `${i + 1}-${i + 1}`).join(",")),
    true,
  );
});
