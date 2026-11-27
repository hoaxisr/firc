import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  isUrlText,
  presetProviders,
  providerOf,
  providerOn,
  searchCatalog,
  visibleSources,
  wantedFiles,
  type Catalog,
} from "../../src/modules/groups/list-catalog.ts";

const src = (id: string, names: string[]) => ({
  id,
  url: `https://raw.githubusercontent.com/${id}/rules/{}.srs`,
  names,
});

describe("catalog search", () => {
  // Catches a case-sensitive match.
  it("matches regardless of case", () => {
    const r = searchCatalog({ sources: [src("a", ["youtube"])] }, "YouTube");
    assert.deepStrictEqual(
      r.rows.map((x) => x.name),
      ["youtube"],
    );
  });

  // Catches exact, prefix and inner matches sorted in list order or by length alone.
  it("orders exact, then prefix, then the rest, shorter first", () => {
    const r = searchCatalog(
      { sources: [src("a", ["youtube-dl", "youtube", "ayou", "you"])] },
      "you",
    );
    assert.deepStrictEqual(
      r.rows.map((x) => x.name),
      ["you", "youtube", "youtube-dl", "ayou"],
    );
  });

  // Catches one row per name instead of per source, or the source order lost.
  it("lists a name from each source with its own url", () => {
    const r = searchCatalog(
      { sources: [src("sagernet", ["youtube"]), src("hoaxisr", ["youtube"])] },
      "youtube",
    );
    assert.deepStrictEqual(r.rows, [
      {
        name: "youtube",
        source: "sagernet",
        url: "https://raw.githubusercontent.com/sagernet/rules/youtube.srs",
      },
      {
        name: "youtube",
        source: "hoaxisr",
        url: "https://raw.githubusercontent.com/hoaxisr/rules/youtube.srs",
      },
    ]);
  });

  // Catches a missing cap or a wrong remainder count.
  it("caps rows at 50 and counts the rest", () => {
    const names = Array.from({ length: 60 }, (_, i) => `site${i}`);
    const r = searchCatalog({ sources: [src("a", names)] }, "site");
    assert.strictEqual(r.rows.length, 50);
    assert.strictEqual(r.more, 10);
  });

  // Catches an empty query matching every name.
  it("finds nothing for an empty query", () => {
    const r = searchCatalog({ sources: [src("a", ["x"])] }, "");
    assert.deepStrictEqual(r, { rows: [], more: 0 });
  });
});

describe("url text", () => {
  // Catches a bare host path being taken for a URL, or a scheme not being recognised.
  it("is text containing a scheme separator", () => {
    assert.strictEqual(isUrlText("https://x"), true);
    assert.strictEqual(isUrlText("raw.githubusercontent.com/a"), false);
  });
});

const index = (
  sources: ReturnType<typeof src>[],
  providers?: { id: string; name: string }[],
): Catalog => ({
  generated: "g",
  fetchedAt: 0,
  stale: false,
  sources,
  ...(providers ? { providers } : {}),
});

const INDEX = index(
  [src("sagernet", ["youtube", "google"]), src("hoaxisr", ["youtube"])],
  [
    { id: "sagernet", name: "SagerNet" },
    { id: "hoaxisr", name: "hoaxisr" },
    { id: "loyalsoldier", name: "Loyalsoldier" },
    { id: "itdog", name: "ITDog" },
  ],
);
const FILES = {
  loyalsoldier: index([
    src("loyalsoldier-geoip", ["google", "ru"]),
    src("loyalsoldier-geosite", ["google"]),
  ]),
  itdog: index([src("itdog-services", ["youtube"]), src("itdog-ipv4", ["discord"])]),
};
const ids = (choices: Record<string, boolean>) =>
  visibleSources(INDEX, FILES, choices).map((s) => s.id);

describe("preset providers", () => {
  // Catches: optional providers on by default, so every router downloads their catalogs unasked.
  it("has only the built-in providers on by default", () => {
    const ps = presetProviders(INDEX);
    assert.deepStrictEqual(
      ps.map((p) => [p.id, p.builtin, providerOn({}, p)]),
      [
        ["sagernet", true, true],
        ["hoaxisr", true, true],
        ["loyalsoldier", false, false],
        ["itdog", false, false],
      ],
    );
    assert.deepStrictEqual(ids({}), ["sagernet", "hoaxisr"]);
    assert.deepStrictEqual(wantedFiles(INDEX, {}), []);
  });

  // Catches: a provider's GeoIP shown while its GeoSite is hidden, or a file asked for while it is off.
  it("turns all of a provider's sources on and off together", () => {
    assert.deepStrictEqual(ids({ loyalsoldier: true }), [
      "sagernet",
      "hoaxisr",
      "loyalsoldier-geoip",
      "loyalsoldier-geosite",
    ]);
    assert.deepStrictEqual(
      wantedFiles(INDEX, { loyalsoldier: true }).map((p) => p.id),
      ["loyalsoldier"],
    );
    assert.deepStrictEqual(ids({ loyalsoldier: true, sagernet: false }), [
      "hoaxisr",
      "loyalsoldier-geoip",
      "loyalsoldier-geosite",
    ]);
    assert.deepStrictEqual(ids({ loyalsoldier: false }), ["sagernet", "hoaxisr"]);
  });

  // Catches: an empty result treated as "nothing chosen", which would bring the defaults back.
  it("lets every provider be turned off", () => {
    assert.deepStrictEqual(ids({ sagernet: false, hoaxisr: false }), []);
    const r = searchCatalog(
      { sources: visibleSources(INDEX, FILES, { sagernet: false, hoaxisr: false }) },
      "you",
    );
    assert.deepStrictEqual(r, { rows: [], more: 0 });
  });

  // Catches: hidden rows taking places among the 50 and pushing visible ones into "more".
  it("drops a provider before ranking and the cap", () => {
    const many = Array.from({ length: 60 }, (_, i) => `site${i}`);
    const cat = index(
      [src("sagernet", many), src("hoaxisr", ["site"])],
      [
        { id: "sagernet", name: "SagerNet" },
        { id: "hoaxisr", name: "hoaxisr" },
      ],
    );
    const r = searchCatalog({ sources: visibleSources(cat, {}, { sagernet: false }) }, "site");
    assert.deepStrictEqual(
      r.rows.map((x) => x.source),
      ["hoaxisr"],
    );
    assert.strictEqual(r.more, 0);
  });

  // Catches: a provider added to the catalog later arriving switched on, or a saved choice ignored.
  it("keeps a new optional provider off and honours a saved choice", () => {
    const later = index(INDEX.sources, [
      ...INDEX.providers!,
      { id: "runetfreedom", name: "RunetFreedom" },
    ]);
    const p = presetProviders(later).find((x) => x.id === "runetfreedom")!;
    assert.strictEqual(providerOn({ loyalsoldier: true }, p), false);
    assert.strictEqual(providerOn({ runetfreedom: true }, p), true);
  });

  // Catches: an index from before providers existed offering nothing, or an unclaimed source lost.
  it("treats each unclaimed source of the index as a built-in provider of its own", () => {
    const old = index([src("sagernet", ["a"]), src("hoaxisr", ["b"])]);
    assert.deepStrictEqual(presetProviders(old), [
      { id: "sagernet", name: "sagernet", builtin: true },
      { id: "hoaxisr", name: "hoaxisr", builtin: true },
    ]);
    assert.deepStrictEqual(
      visibleSources(old, {}, {}).map((s) => s.id),
      ["sagernet", "hoaxisr"],
    );
  });

  it("only trusts explicit booleans and handles provider ids inherited by ordinary objects", () => {
    const indexWithExtraSources = index(
      [...INDEX.sources, src("third-party", ["x"])],
      [...INDEX.providers!, { id: "constructor", name: "Other provider" }],
    );
    const choices = JSON.parse('{"itdog":"false","sagernet":1}');
    assert.deepStrictEqual(
      visibleSources(indexWithExtraSources, {}, choices).map((s) => s.id),
      ["sagernet", "hoaxisr"],
    );
    assert.deepStrictEqual(wantedFiles(indexWithExtraSources, choices), []);
  });

  // Catches: the same tag of two providers collapsing into one row, or keeping one provider's URL.
  it("lists a name once per provider that has it", () => {
    const r = searchCatalog(
      { sources: visibleSources(INDEX, FILES, { loyalsoldier: true }) },
      "google",
    );
    assert.deepStrictEqual(
      r.rows.map((x) => x.source),
      ["sagernet", "loyalsoldier-geoip", "loyalsoldier-geosite"],
    );
    assert.strictEqual(new Set(r.rows.map((x) => x.url)).size, 3);
  });

  // Catches: zeta-geo's sources counted as zeta's, so one switch would hide the other provider.
  it("gives a source to the longest provider id it starts with", () => {
    const ps = [{ id: "zeta" }, { id: "zeta-geo" }];
    assert.strictEqual(providerOf("zeta-geo-ip", ps), "zeta-geo");
    assert.strictEqual(providerOf("zeta-ip", ps), "zeta");
    assert.strictEqual(providerOf("zetaplus", ps), undefined);
  });
});
