export type CatalogSource = { id: string; url: string; names: string[] };
export type CatalogProvider = { id: string; name: string };
export type Catalog = {
  generated: string;
  fetchedAt: number;
  stale: boolean;
  sources: CatalogSource[];
  providers?: CatalogProvider[];
};
export type CatalogRow = { name: string; source: string; url: string };
export type CatalogResult = { ok: true; data: Catalog } | { ok: false; error: string };
/** Built in: its sources come with the index and it is on until turned off. Otherwise its sources are in its own
 * file, which the router fetches only once the provider is turned on. */
export type PresetProvider = { id: string; name: string; builtin: boolean };
/** The owner's choices by provider id; a provider never chosen keeps its default. */
export type PresetChoices = Record<string, boolean>;

export const isUrlText = (text: string): boolean => text.includes("://");

const belongs = (sourceId: string, providerId: string) =>
  sourceId === providerId || sourceId.startsWith(providerId + "-");

/** The provider a source id is part of: the longest provider id it starts with (zeta-geo wins over zeta). */
export function providerOf(sourceId: string, providers: { id: string }[]): string | undefined {
  let best: string | undefined;
  for (const p of providers) {
    if (belongs(sourceId, p.id) && (best === undefined || p.id.length > best.length)) best = p.id;
  }
  return best;
}

/** Every provider the index names, then each of its sources no provider claims, as a provider of its own
 * (an index from before providers existed lists none). */
export function presetProviders(index: Catalog): PresetProvider[] {
  const out: PresetProvider[] = (index.providers ?? []).map((p) => ({ ...p, builtin: false }));
  for (const s of index.sources) {
    const owner = out.find((p) => p.id === providerOf(s.id, out));
    if (owner) owner.builtin = true;
    else out.push({ id: s.id, name: s.id, builtin: true });
  }
  return out;
}

export const providerOn = (choices: PresetChoices, p: PresetProvider): boolean =>
  choices[p.id] ?? p.builtin;

/** The sources a search may show: the index's sources of providers that are on, then each loaded file of an
 * optional provider that is on. A provider turned off drops out before ranking and the cap. */
export function visibleSources(
  index: Catalog,
  files: Record<string, Catalog>,
  choices: PresetChoices,
): CatalogSource[] {
  const providers = presetProviders(index);
  const on = new Set(providers.filter((p) => providerOn(choices, p)).map((p) => p.id));
  const out = index.sources.filter((s) => on.has(providerOf(s.id, providers) ?? s.id));
  for (const p of providers) {
    if (!p.builtin && on.has(p.id) && files[p.id]) out.push(...files[p.id].sources);
  }
  return out;
}

/** The optional providers that are on: the files a search needs. */
export const wantedFiles = (index: Catalog, choices: PresetChoices): PresetProvider[] =>
  presetProviders(index).filter((p) => !p.builtin && providerOn(choices, p));

export function searchCatalog(
  cat: { sources: CatalogSource[] },
  query: string,
  cap = 50,
): { rows: CatalogRow[]; more: number } {
  const q = query.trim().toLowerCase();
  if (!q) return { rows: [], more: 0 };
  const hits: { rank: number; row: CatalogRow }[] = [];
  for (const s of cat.sources) {
    for (const name of s.names) {
      const n = name.toLowerCase();
      if (!n.includes(q)) continue;
      const rank = n === q ? 0 : n.startsWith(q) ? 1 : 2;
      hits.push({ rank, row: { name, source: s.id, url: s.url.replace("{}", () => name) } });
    }
  }
  hits.sort((a, b) => a.rank - b.rank || a.row.name.length - b.row.name.length);
  return { rows: hits.slice(0, cap).map((h) => h.row), more: Math.max(0, hits.length - cap) };
}

async function fetchCatalog(path: string): Promise<CatalogResult> {
  try {
    const { fetcher } = await import("../../utils/fetcher");
    const data = await fetcher.get<Catalog>(path, { quiet: true });
    return { ok: true, data };
  } catch (e) {
    let error = "";
    try {
      const body = JSON.parse((e as Error).message);
      if (typeof body?.error === "string" && body.error) error = body.error;
    } catch {}
    return { ok: false, error };
  }
}

const cached = new Map<string, Promise<CatalogResult>>();

/** One fetch per catalog for the page's life; a failed one is forgotten, so the next ask tries again. */
function load(path: string): Promise<CatalogResult> {
  let p = cached.get(path);
  if (!p) {
    const mine = fetchCatalog(path);
    p = mine;
    cached.set(path, mine);
    mine.then((r) => {
      if (!r.ok && cached.get(path) === mine) cached.delete(path);
    });
  }
  return p;
}

export const loadCatalog = (): Promise<CatalogResult> => load("/groups/list/catalog");

export const loadProvider = (id: string): Promise<CatalogResult> =>
  load(`/groups/list/catalog?provider=${encodeURIComponent(id)}`);
