<script lang="ts">
  import type { Snippet } from "svelte";

  import {
    relativeTime,
    rowDevices,
    type DnsStatsRow,
    type StatsDevice,
  } from "../../data/dnsstats.svelte";
  import { t } from "../../data/locale.svelte";

  let {
    rows,
    devices,
    now,
    empty,
    onpick,
    action,
  }: {
    rows: DnsStatsRow[];
    devices: StatsDevice[];
    now: number;
    empty: string;
    onpick: (name: string) => void;
    action: Snippet<[DnsStatsRow]>;
  } = $props();

  const pct = (r: DnsStatsRow) => (r.queries > 0 ? Math.round((r.blocked / r.queries) * 100) : 0);
</script>

<div class="card">
  <div class="pane">
    <div class="head" aria-hidden="true">
      <span>{t("Domain")}</span>
      <span class="num">{t("Queries")}</span>
      <span>{t("Blocked")}</span>
      <span>{t("Devices")}</span>
      <span>{t("Last")}</span>
      <span></span>
    </div>
    {#if rows.length === 0}
      <p class="empty">{empty}</p>
    {/if}
    {#each rows as r (r.name)}
      {@const devs = rowDevices(r.clients, devices)}
      {@const more = devs.length - 2 + (r.clientsTotal - r.clients.length)}
      <div class="stats-row">
        <button type="button" class="dom" title={r.name} onclick={() => onpick(r.name)}
          >{r.name}</button
        >
        <span class="num qcell"
          ><span class="total">{r.queries}</span><span class="unit">{t("q.")}</span></span
        >
        <span class="share" class:none={r.blocked === 0}>
          <span class="bar"><span class="fill" style:width="{pct(r)}%"></span></span>
          <span class="pct">{r.blocked === 0 ? "—" : `${pct(r)}\u00a0%`}</span>
        </span>
        <span class="devs">
          {#each devs.slice(0, 2) as d (d.key)}
            <span class="dev">
              <span class="dn">{d.label}</span>
              {#if d.label !== d.address}<span class="da">{d.address}</span>{/if}
            </span>
          {/each}
          {#if more > 0}
            <span class="more">{t("and {n} more").replace("{n}", String(more))}</span>
          {/if}
        </span>
        <span class="last">{relativeTime(r.last, now, t)}</span>
        <span class="act">{@render action(r)}</span>
      </div>
    {/each}
  </div>
</div>

<style>
  .card {
    container-type: inline-size;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.6rem;
    overflow: hidden;
  }
  .pane {
    height: calc(100vh - 16rem);
    min-height: 16rem;
    overflow: auto;
    font-size: 0.88rem;
  }
  .head,
  .stats-row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 4.5rem 8.5rem 19.5rem 6.5rem 8.5rem;
    gap: 0.8rem;
    align-items: center;
    padding: 0.45rem 0.9rem;
  }
  .head {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--bg-light);
    border-bottom: 1px solid var(--bg-light-extra);
    color: var(--text-2);
    font-size: 0.74rem;
    letter-spacing: 0.03em;
  }
  .stats-row {
    border-bottom: 1px solid color-mix(in srgb, var(--bg-light-extra) 60%, transparent);
  }
  .stats-row:hover {
    background: var(--bg-dark);
  }
  .num {
    text-align: right;
  }
  .total {
    font-family: var(--font-mono);
    font-size: 0.82rem;
    font-variant-numeric: tabular-nums;
  }
  .unit {
    display: none;
  }
  .dom {
    all: unset;
    cursor: pointer;
    font-weight: 600;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dom:hover {
    text-decoration: underline;
  }
  .dom:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .share {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .bar {
    flex: 1;
    height: 6px;
    border-radius: 3px;
    background: var(--bg-light-extra);
    overflow: hidden;
  }
  .fill {
    display: block;
    height: 100%;
    background: var(--red);
    border-radius: 3px;
  }
  .pct {
    width: 2.8rem;
    text-align: right;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--red);
    font-variant-numeric: tabular-nums;
  }
  .share.none .pct {
    color: var(--text-2);
  }
  .devs {
    display: grid;
    grid-template-columns: 7rem 7rem auto;
    gap: 0.6rem;
    align-items: start;
    min-width: 0;
  }
  .dev {
    display: flex;
    flex-direction: column;
    line-height: 1.2;
    min-width: 0;
  }
  .dn {
    font-size: 0.84rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .da {
    font-family: var(--font-mono);
    font-size: 0.7rem;
    color: var(--text-2);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .more {
    align-self: center;
    font-size: 0.76rem;
    color: var(--text-2);
    white-space: nowrap;
  }
  .last {
    color: var(--text-2);
    font-size: 0.8rem;
    white-space: nowrap;
  }
  .act {
    display: flex;
    justify-content: flex-end;
    min-width: 0;
  }
  .empty {
    margin: 1rem;
    color: var(--text-2);
  }
  @container (max-width: 760px) {
    .head {
      display: none;
    }
    .stats-row {
      grid-template-columns: minmax(0, 1fr) auto;
      grid-template-areas:
        "dom total"
        "share share"
        "devs devs"
        "last act";
      gap: 0.35rem 0.6rem;
      padding: 0.6rem 0.8rem;
    }
    .dom {
      grid-area: dom;
    }
    .qcell {
      grid-area: total;
    }
    .unit {
      display: inline;
      margin-left: 0.3em;
      font-family: var(--font);
      color: var(--text-2);
      font-size: 0.74rem;
    }
    .share {
      grid-area: share;
    }
    .share.none {
      display: none;
    }
    .devs {
      grid-area: devs;
      display: flex;
      flex-wrap: wrap;
      gap: 0.2rem 0.8rem;
      align-items: baseline;
    }
    .dev {
      flex-direction: row;
      gap: 0.3rem;
      align-items: baseline;
    }
    .last {
      grid-area: last;
    }
    .act {
      grid-area: act;
    }
  }
</style>
