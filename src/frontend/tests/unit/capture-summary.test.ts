import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import ru from "../../src/locales/ru.json" with { type: "json" };
import { summaryLine } from "../../src/modules/logs/capture-summary.ts";

const tr = (key: string) => (ru as Record<string, string>)[key] ?? key;
const say = (line: string) => summaryLine(line, "ru", tr);

describe("the capture summary in Russian", () => {
  // Catches the counts line left in English or its three numbers swapped.
  it("puts the counts of the issue's capture in Russian", () => {
    assert.strictEqual(
      say("1850 packets read, 121 bypasses reported, 575 repeats not reported on its own."),
      "Прочитано пакетов: 1850, утечек: 121, повторов, о которых не сообщалось отдельно: 575.",
    );
    assert.strictEqual(
      say("1 packet read, 1 bypass reported."),
      "Прочитано пакетов: 1, утечек: 1.",
    );
    assert.strictEqual(
      say("1 packet read, 1 bypass reported, 1 repeat not reported on its own."),
      "Прочитано пакетов: 1, утечек: 1, повторов, о которых не сообщалось отдельно: 1.",
    );
  });

  // Catches the no-name sentence from the issue left in English or the singular form missed.
  it("puts the no-name sentence in Russian in both numbers", () => {
    const want = (n: number) =>
      `Пакетов без имени сервера, которое удалось бы прочитать: ${n}. ClientHello, разбитый на несколько сегментов, выглядит так же, как клиент, не приславший имени.`;
    const tail =
      "carried no server name this reader could take: a hello spanning segments reads the same as a client that sent none.";
    assert.strictEqual(say(`6 packets ${tail}`), want(6));
    assert.strictEqual(say(`1 packet ${tail}`), want(1));
  });

  // Catches a counted sentence whose number is dropped or whose pattern no longer matches.
  it("keeps every count of the counted sentences", () => {
    const cases: [string, string][] = [
      [
        "2 netfilter passes failed while this capture was open, so its rules were not in the kernel until a later one landed: those seconds were not watched.",
        "2",
      ],
      [
        "A rule's limit of 50/s may have been reached in at least 3 seconds on the new-connection capture: some flows may not have been seen.",
        "3",
      ],
      [
        "A rule's limit of 50/s may have been reached in at least 1 second on the ClientHello capture: some flows may not have been seen.",
        "1",
      ],
      [
        "4 packets could not be read as IPv4 or IPv6 at all, which the capture rules should not have delivered: the rules and this reader disagree.",
        "4",
      ],
      [
        "7 times packets were lost before the capture read them: this capture is not complete.",
        "7",
      ],
      [
        "The dedup table filled at 1024 pairs: past that, a bypass is reported every time rather than once a minute.",
        "1024",
      ],
      [
        "1 datagram came from another process on this machine and was ignored: the capture reads what the kernel sends it and nothing else.",
        "1",
      ],
      [
        "5 datagrams came from another process on this machine and were ignored: the capture reads what the kernel sends it and nothing else.",
        "5",
      ],
    ];
    for (const [en, n] of cases) {
      const out = say(en);
      assert.notStrictEqual(out, en, en);
      assert.ok(/[а-я]/.test(out), out);
      assert.ok(out.includes(n), out);
      assert.ok(!out.includes("{"), out);
    }
  });

  // Catches the two capture kinds of the limit sentence given the same Russian.
  it("names which capture hit its limit", () => {
    const line = (w: string) =>
      `A rule's limit of 50/s may have been reached in at least 2 seconds on the ${w} capture: some flows may not have been seen.`;
    assert.ok(say(line("new-connection")).includes("новых соединений"));
    assert.ok(say(line("ClientHello")).includes("ClientHello"));
    assert.ok(say(line("ClientHello")).includes("50/с"));
  });

  // Catches a fixed sentence left in English.
  it("puts every fixed sentence in Russian", () => {
    for (const en of [
      "No packet reached the capture at all: nothing matched its rules.",
      "No bypass: every flow the capture saw was one firc had nothing to say about.",
      "An interface this capture was watching does not exist: iptables takes a name no interface has, so its rules matched nothing and it watched nothing there, whatever the numbers say.",
      "An interface this capture was watching went away during it and came back: while it was missing its rules matched nothing there, so part of this capture was not watched.",
      "firc had recorded no real address when the capture started; bypasses were recognised by SNI only until clients asked.",
      "There was no memory to remember some pairs by: those are reported every time rather than once a minute.",
    ]) {
      const out = say(en);
      assert.notStrictEqual(out, en);
      assert.ok(/[а-я]/.test(out), out);
    }
  });

  // Catches a sentence the daemon has no template for getting lost instead of shown as it came.
  it("shows an unknown sentence as it came", () => {
    assert.strictEqual(say("Something new."), "Something new.");
  });

  // Catches English rewritten from the templates and losing the daemon's own wording.
  it("leaves English as the daemon wrote it", () => {
    const line = "1 packet read, 1 bypass reported.";
    assert.strictEqual(
      summaryLine(line, "en", (k) => k),
      line,
    );
  });
});
