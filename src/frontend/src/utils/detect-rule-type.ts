import {
  isValidDomain,
  isValidNamespace,
  isValidRegex,
  isValidSubnet,
  isValidSubnet6,
  isValidWildcard,
} from "./rule-validators";

function writtenAsARegex(p: string): boolean {
  const head = p.startsWith("^") || p.startsWith("\\A");
  const tail = p.endsWith("$") || p.endsWith("\\z") || p.endsWith("\\Z");
  return p.length >= 2 && head && tail;
}

const CONTROLS = [
  "",
  "a",
  "qx7vnb2mklda",
  "qx7vnb2mkl.example",
  "qx7vnb2mkl.example.invalid",
  "qx7vnb2mkl.example.invalid.test",
  "qx7vnb2mkl.example.invalid.test.local",
  "qx7vnb2mkl.example.invalid.test.local.onion",
  "totally-unrelated.example",
];

const JS_READS_DIFFERENTLY = /\\[pPN]|\[\[:|\(\*/;

function matchesThingsNoRuleMayMatch(p: string): boolean {
  if (JS_READS_DIFFERENTLY.test(p)) {
    return true;
  }
  let re: RegExp;
  try {
    re = new RegExp(p);
  } catch {
    /* Also closed, and for the same reason: unjudgeable is not safe. */
    return true;
  }
  return CONTROLS.some((c) => re.test(c));
}

function anchored(p: string): string {
  return "\\A(?:" + p + ")\\z";
}

export function detectRuleType(pattern: string): string | null {
  const p = pattern.trim();
  if (isValidSubnet6(p)) return "subnet6";
  if (isValidSubnet(p)) return "subnet";
  if (isValidNamespace(p)) return "namespace";
  if (isValidDomain(p)) return "domain";
  if (isValidWildcard(p)) return "wildcard";
  if (writtenAsARegex(p) && isValidRegex(p) && !matchesThingsNoRuleMayMatch(p)) {
    return "regex";
  }
  return null;
}

export function deriveRule(pattern: string): { type: string; rule: string } | null {
  const p = pattern.trim();
  const type = detectRuleType(p);
  if (type === null) return null;
  return { type, rule: type === "regex" ? anchored(p) : p };
}
