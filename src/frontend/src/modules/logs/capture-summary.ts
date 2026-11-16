const N = String.raw`(?<n>\d+)`;

function rules(t: (key: string) => string): [RegExp, string][] {
  return [
    [
      new RegExp(
        String.raw`^(?<p>\d+) packets? read, (?<b>\d+) bypass(?:es)? reported, (?<r>\d+) repeats? not reported on its own\.$`,
      ),
      t("{p} packets read, {b} bypasses reported, {r} repeats not reported on its own."),
    ],
    [
      new RegExp(String.raw`^(?<p>\d+) packets? read, (?<b>\d+) bypass(?:es)? reported\.$`),
      t("{p} packets read, {b} bypasses reported."),
    ],
    [
      /^No packet reached the capture at all: nothing matched its rules\.$/,
      t("No packet reached the capture at all: nothing matched its rules."),
    ],
    [
      /^No bypass: every flow the capture saw was one firc had nothing to say about\.$/,
      t("No bypass: every flow the capture saw was one firc had nothing to say about."),
    ],
    [
      /^An interface this capture was watching does not exist: /,
      t(
        "An interface this capture was watching does not exist: iptables takes a name no interface has, so its rules matched nothing and it watched nothing there, whatever the numbers say.",
      ),
    ],
    [
      /^An interface this capture was watching went away during it and came back: /,
      t(
        "An interface this capture was watching went away during it and came back: while it was missing its rules matched nothing there, so part of this capture was not watched.",
      ),
    ],
    [
      new RegExp(String.raw`^${N} netfilter pass(?:es)? failed while this capture was open, `),
      t(
        "{n} netfilter passes failed while this capture was open, so its rules were not in the kernel until a later one landed: those seconds were not watched.",
      ),
    ],
    [
      new RegExp(
        String.raw`^A rule's limit of (?<l>\d+)/s may have been reached in at least ${N} seconds? on the new-connection capture: `,
      ),
      t(
        "A rule's limit of {l}/s may have been reached in at least {n} seconds on the new-connection capture: some flows may not have been seen.",
      ),
    ],
    [
      new RegExp(
        String.raw`^A rule's limit of (?<l>\d+)/s may have been reached in at least ${N} seconds? on the ClientHello capture: `,
      ),
      t(
        "A rule's limit of {l}/s may have been reached in at least {n} seconds on the ClientHello capture: some flows may not have been seen.",
      ),
    ],
    [
      /^firc had recorded no real address when the capture started; /,
      t(
        "firc had recorded no real address when the capture started; bypasses were recognised by SNI only until clients asked.",
      ),
    ],
    [
      new RegExp(String.raw`^${N} packets? could not be read as IPv4 or IPv6 at all, `),
      t(
        "{n} packets could not be read as IPv4 or IPv6 at all, which the capture rules should not have delivered: the rules and this reader disagree.",
      ),
    ],
    [
      new RegExp(String.raw`^${N} packets? carried no server name this reader could take: `),
      t(
        "{n} packets carried no server name this reader could take: a hello spanning segments reads the same as a client that sent none.",
      ),
    ],
    [
      new RegExp(String.raw`^${N} times? packets were lost before the capture read them: `),
      t("{n} times packets were lost before the capture read them: this capture is not complete."),
    ],
    [
      new RegExp(String.raw`^The dedup table filled at ${N} pairs: `),
      t(
        "The dedup table filled at {n} pairs: past that, a bypass is reported every time rather than once a minute.",
      ),
    ],
    [
      /^There was no memory to remember some pairs by: /,
      t(
        "There was no memory to remember some pairs by: those are reported every time rather than once a minute.",
      ),
    ],
    [
      new RegExp(
        String.raw`^${N} datagrams? came from another process on this machine and (?:was|were) ignored: `,
      ),
      t(
        "{n} datagrams came from another process on this machine and were ignored: the capture reads what the kernel sends it and nothing else.",
      ),
    ],
  ];
}

export function summaryLine(line: string, locale: string, t: (key: string) => string): string {
  if (locale === "en") return line;
  for (const [re, text] of rules(t)) {
    const m = re.exec(line);
    if (m) return text.replace(/\{(\w)\}/g, (_, k: string) => m.groups?.[k] ?? "");
  }
  return line;
}
