<script lang="ts">
  import { Popover } from "bits-ui";
  import { untrack } from "svelte";

  import Checkbox from "../../components/ui/Checkbox.svelte";
  import Select from "../../components/ui/Select.svelte";
  import {
    DEVICE_ADDRESSES_MAX,
    deviceAddresses,
    dnsStats,
    fetchDnsStats,
    heldIndex,
    rowAbove,
    rowStatus,
    STATS_REFRESH_MS,
    statsDevices,
    statsFilter,
    type BlockScope,
    type DnsStatsRow,
  } from "../../data/dnsstats.svelte";
  import { groupsBridge } from "../../data/groups-bridge.svelte";
  import { hosts } from "../../data/hosts.svelte";
  import { locale, t } from "../../data/locale.svelte";
  import BlockPopover from "./BlockPopover.svelte";
  import DomainsTable from "./DomainsTable.svelte";

  import { Ban, Filter, Search } from "../../components/ui/icons";
  import type { Group } from "../../types";
  import { pluralForm } from "../../utils/plural";
  import { isValidDomain } from "../../utils/rule-validators";

  let { active = false }: { active?: boolean } = $props();

  const SEARCH_DEBOUNCE_MS = 250;
  const uid = $props.id();

  let query = $state(statsFilter.q);
  const devices = $derived(statsDevices(hosts.list, statsFilter.seen));
  const device = $derived(devices.find((d) => d.key === statsFilter.device) ?? null);
  const deviceOptions = $derived([
    { value: "", label: t("all devices") },
    ...[...devices]
      .sort((a, b) => a.label.localeCompare(b.label, locale.current))
      .map((d) => ({ value: d.key, label: d.label })),
  ]);
  const addressKey = $derived(device ? deviceAddresses(device, statsFilter.seen).join(",") : "");
  const data = $derived(dnsStats.data);
  const now = $derived(data?.now ?? 0);

  const store = $derived(groupsBridge.store);
  const groups = $derived<Group[]>(store?.dataLoaded ? store.data : []);
  const held = $derived(heldIndex(groups, device?.entry ?? null));

  $effect(() => {
    const q = query;
    const timer = setTimeout(() => (statsFilter.q = q), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  });

  $effect(() => {
    if (!active) return;
    const params = {
      addresses: addressKey ? addressKey.split(",") : [],
      q: statsFilter.q,
      arpa: statsFilter.arpa,
    };
    void fetchDnsStats(params);
    const timer = setInterval(() => void fetchDnsStats(params), STATS_REFRESH_MS);
    return () => clearInterval(timer);
  });

  $effect(() => {
    if (!data || statsFilter.device) return;
    const known = new Set(untrack(() => statsFilter.seen));
    const before = known.size;
    for (const r of data.rows) for (const c of r.clients) known.add(c.address.toLowerCase());
    if (known.size > before) statsFilter.seen = [...known];
  });

  function word(n: number, one: string, few: string, many: string): string {
    const form = pluralForm(n, locale.current);
    return form === "one" ? one : form === "few" ? few : many;
  }

  const fmt = (n: number) => n.toLocaleString(locale.current === "ru" ? "ru-RU" : "en-US");

  function share(blocked: number, queries: number): string {
    const v = queries > 0 ? Math.round((blocked / queries) * 1000) / 10 : 0;
    const s = String(v);
    return `${locale.current === "ru" ? s.replace(".", ",") : s}\u00a0%`;
  }

  function stamp(at: number): string {
    const d = new Date(at * 1000);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  }

  function status(r: DnsStatsRow): { group: string; unsaved: boolean } | null {
    if (!store?.dataLoaded) {
      return r.owner?.interface === "block" ? { group: r.owner.name, unsaved: false } : null;
    }
    return rowStatus(
      r,
      groups,
      device?.entry ?? null,
      (rule) => store.tracker.isDirtyWithin(rule),
      held,
    );
  }

  async function addBlock(name: string, scope: BlockScope, targetId: string | null) {
    const st = groupsBridge.store;
    if (!st) return;
    let id = targetId;
    if (!id) {
      const own = scope === "device" ? device : null;
      const title = own ? t("Blocking · {device}").replace("{device}", own.label) : t("Blocking");
      id = await st.createBlockGroup(title, { allow: own ? [own.entry] : [], deny: [] });
      if (!id) return;
    }
    await st.blockName(id, name);
  }
</script>

{#snippet aboveHint(name: string)}
  {#if name}<span class="above">{t("«{group}» above").replace("{group}", name)}</span>{/if}
{/snippet}

{#snippet action(r: DnsStatsRow)}
  {@const s = status(r)}
  {@const above = store?.dataLoaded ? rowAbove(r, groups, device?.entry ?? null, held) : ""}
  {#if s}
    <span class="added">
      <span class="already"
        ><Ban size={14} aria-hidden="true" />{t("in «{group}»").replace("{group}", s.group)}</span
      >
      {#if s.unsaved}<span class="uns">{t("not saved yet")}</span>{@render aboveHint(above)}{/if}
    </span>
  {:else if store?.canAdd && isValidDomain(r.name)}
    <span class="added">
      <BlockPopover
        name={r.name}
        device={device ? { label: device.label, entry: device.entry } : null}
        {groups}
        ownerId={r.owner?.id ?? null}
        onadd={(scope, target) => void addBlock(r.name, scope, target)}
      />
      {@render aboveHint(above)}
    </span>
  {/if}
{/snippet}

<div class="st-bar">
  <div class="st-row">
    <label class="field search">
      <Search size={18} aria-hidden="true" />
      <input type="search" bind:value={query} placeholder={t("domain")} aria-label={t("domain")} />
    </label>
    <div class="field sel stats-device">
      <Select
        options={deviceOptions}
        selected={statsFilter.device}
        onValueChange={(v) => (statsFilter.device = v)}
        ariaLabel={t("Device")}
        showSelectedDescription={false}
      />
    </div>
    <Popover.Root>
      <Popover.Trigger
        class="jh-filter"
        aria-label={statsFilter.arpa
          ? `${t("Filter")}, ${t("{n} active").replace("{n}", "1")}`
          : t("Filter")}
      >
        <Filter size={18} aria-hidden="true" />
        <span class="st-filter-label" aria-hidden="true">{t("Filter")}</span>
        {#if statsFilter.arpa}<span class="st-badge" aria-hidden="true">1</span>{/if}
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          class="jh-panel"
          side="bottom"
          align="end"
          sideOffset={6}
          collisionPadding={8}
        >
          <label class="st-check">
            <Checkbox bind:checked={statsFilter.arpa} ariaLabelledby="{uid}-arpa-label" />
            <span id="{uid}-arpa-label">{t("show service names")}</span>
          </label>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  </div>
  {#if device && device.addresses.length > DEVICE_ADDRESSES_MAX}
    <div class="st-note">
      {t("Counts {max} of this device's {n} addresses, those seen asking first")
        .replace("{max}", String(DEVICE_ADDRESSES_MAX))
        .replace("{n}", String(device.addresses.length))}
    </div>
  {/if}
  {#if data}
    <div class="stats-sum">
      <span
        >{data.since > now - data.window
          ? t("since {time}").replace("{time}", stamp(data.since))
          : t("in 24 h")}:</span
      >
      <span
        ><b>{fmt(data.queries)}</b>
        {word(data.queries, t("query"), t("queries (2-4)"), t("queries"))}</span
      >
      <span
        >· <b>{fmt(data.domains)}</b>
        {word(data.domains, t("domain"), t("domains (2-4)"), t("domains"))}</span
      >
      <span>· {t("blocked")} <b class="red">{share(data.blocked, data.queries)}</b></span>
    </div>
  {/if}
  {#if dnsStats.failed}
    <div class="st-err">{t("The daemon did not answer for the stats.")}</div>
  {/if}
</div>

<DomainsTable
  rows={data?.rows ?? []}
  {devices}
  {now}
  empty={t("No queries in the last day match these filters.")}
  onpick={(name) => (query = name)}
  {action}
/>
{#if data && data.matched > data.rows.length}
  <p class="st-more">
    {t("The {n} busiest of {m} names are shown; search finds the rest.")
      .replace("{n}", String(data.rows.length))
      .replace("{m}", String(data.matched))}
  </p>
{/if}

<style>
  .st-bar {
    container-type: inline-size;
    margin: -0.5rem 0 0.5rem;
  }
  .st-row {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }
  .st-row > .field.search {
    flex: 0 1 30rem;
  }
  .field {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    height: 2.75rem;
    box-sizing: border-box;
    padding: 0 0.6rem;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    color: var(--text-2);
  }
  .field.search {
    min-width: 0;
    cursor: text;
  }
  .field.search input {
    all: unset;
    flex: 1;
    min-width: 0;
    color: var(--text);
    font-size: 0.92rem;
  }
  .field.sel {
    flex: 0 0 auto;
    padding: 0 0.3rem;
  }
  .st-badge {
    min-width: 1.15rem;
    height: 1.15rem;
    box-sizing: border-box;
    padding: 0 0.3rem;
    border-radius: 0.6rem;
    background: var(--accent);
    color: var(--bg-dark);
    font-size: 0.72rem;
    font-weight: 700;
    line-height: 1.2rem;
    text-align: center;
  }
  .st-check {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    font-size: 0.9rem;
    cursor: pointer;
  }
  .stats-sum {
    display: flex;
    flex-wrap: wrap;
    gap: 0.1rem 0.3rem;
    margin-top: 0.55rem;
    font-size: 0.82rem;
    color: var(--text-2);
  }
  .stats-sum span {
    white-space: nowrap;
  }
  .stats-sum b {
    color: var(--text);
    font-weight: 600;
  }
  .stats-sum b.red {
    color: var(--red);
  }
  .st-note {
    margin-top: 0.4rem;
    font-size: 0.8rem;
    color: var(--orange);
  }
  .st-err {
    margin-top: 0.4rem;
    font-size: 0.85rem;
    color: var(--red);
  }
  .st-more {
    margin: 0.5rem 0 0;
    font-size: 0.8rem;
    color: var(--text-2);
  }
  .added {
    display: inline-flex;
    flex-direction: column;
    align-items: flex-end;
    min-width: 0;
    line-height: 1.25;
  }
  .already {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    max-width: 100%;
    font-size: 0.8rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: color-mix(in srgb, var(--red) 80%, var(--text-2));
  }
  .uns,
  .above {
    color: var(--orange);
    font-size: 0.72rem;
    white-space: nowrap;
  }
  @container (max-width: 640px) {
    .st-row {
      flex-wrap: wrap;
      gap: 0.4rem;
    }
    .st-row > .field.search {
      flex: 1 1 0;
      min-width: 5rem;
    }
    .field.sel.stats-device {
      order: 3;
      flex: 1 1 100%;
    }
    .st-filter-label {
      display: none;
    }
    :global(.st-row .jh-filter) {
      padding: 0 0.65rem;
    }
  }
</style>
