import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import ru from "../../src/locales/ru.json" with { type: "json" };
import { TUNNEL_STATUSES, tunnelLook } from "../../src/modules/tunnels/tunnel-state.ts";

const t = (key: string) => key;

describe("a tunnel's status look", () => {
  // Catches a status left without a look, so a new daemon status renders as nothing.
  it("every status the daemon sends has an icon, a colour and a label", () => {
    for (const status of TUNNEL_STATUSES) {
      const look = tunnelLook({ status, backoffS: 0 }, t);
      assert.ok(look.icon && look.color && look.label, status);
    }
  });

  // Catches statuses mapped to the wrong word, the operator reading a dead tunnel as running.
  it("maps each status to its own label", () => {
    const label = (status: any, backoffS = 0) => tunnelLook({ status, backoffS }, t).label;
    assert.strictEqual(label("up"), "Running");
    assert.strictEqual(label("starting"), "Starting");
    assert.strictEqual(label("waiting"), "No nodes");
    assert.strictEqual(label("uplink_down"), "Uplink unavailable");
    assert.strictEqual(label("off"), "Off");
    assert.strictEqual(label("bad_config"), "Configuration error");
  });

  // Catches the countdown dropped from a restart or a no-node retry, or {n} shown raw.
  it("puts the seconds into the backoff and no-node labels", () => {
    const tr = (key: string) =>
      ({
        "Restart in {n} s": "перезапуск через {n} с",
        "No node answers, retry in {n} s": "ни один узел не отвечает · повтор через {n} с",
      })[key] ?? key;
    assert.strictEqual(
      tunnelLook({ status: "backoff", backoffS: 12 }, tr).label,
      "перезапуск через 12 с",
    );
    assert.strictEqual(
      tunnelLook({ status: "no_node", backoffS: 30 }, tr).label,
      "ни один узел не отвечает · повтор через 30 с",
    );
  });

  // Catches a "retry in 0 s" shown when the daemon gave no retry time.
  it("drops the countdown when there is none", () => {
    assert.strictEqual(tunnelLook({ status: "no_node", backoffS: 0 }, t).label, "No node answers");
    assert.strictEqual(tunnelLook({ status: "backoff", backoffS: 0 }, t).label, "Restarting");
  });

  // Catches a tunnel with no nodes to use shown as forever starting, with a loader.
  it("shows waiting as no nodes with a still, neutral icon", () => {
    const look = tunnelLook({ status: "waiting", backoffS: 0 }, t);
    assert.strictEqual(look.icon, "CircleDashed");
    assert.strictEqual(look.color, "var(--text-2)");
  });

  // Catches a healthy colour on a failing status and the reverse.
  it("colours working green, trouble red or orange, quiet grey", () => {
    const color = (status: any) => tunnelLook({ status, backoffS: 1 }, t).color;
    assert.strictEqual(color("up"), "var(--green)");
    assert.strictEqual(color("bad_config"), "var(--red)");
    assert.strictEqual(color("no_node"), "var(--orange)");
    assert.strictEqual(color("uplink_down"), "var(--orange)");
    assert.strictEqual(color("off"), "var(--text-2)");
  });

  // Catches an unknown status throwing while the page renders.
  it("falls back to a neutral look for a status it does not know", () => {
    const look = tunnelLook({ status: "from_the_future" as any, backoffS: 0 }, t);
    assert.strictEqual(look.icon, "CircleHelp");
  });

  // Catches the Russian labels drifting from the lowercase wording of the spec.
  it("words the Russian labels in lowercase", () => {
    const r = ru as Record<string, string>;
    assert.strictEqual(r["Running"], "работает");
    assert.strictEqual(r["Starting"], "запускается");
    assert.strictEqual(
      r["No node answers, retry in {n} s"],
      "ни один узел не отвечает · повтор через {n} с",
    );
    assert.strictEqual(r["Uplink unavailable"], "выход недоступен");
    assert.strictEqual(r["Off"], "выключен");
    assert.strictEqual(r["No nodes"], "нет узлов");
    assert.strictEqual(r["Restart in {n} s"], "перезапуск через {n} с");
    assert.strictEqual(r["Configuration error"], "ошибка конфигурации");
  });
});
