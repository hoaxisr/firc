<script lang="ts">
  import { Popover } from "bits-ui";
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
    note,
  }: {
    rows: DnsStatsRow[];
    devices: StatsDevice[];
    now: number;
    empty: string;
    onpick: (name: string) => void;
    action: Snippet<[DnsStatsRow]>;
    note?: Snippet<[DnsStatsRow]>;
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
        <span class="domcell">
          <button type="button" class="dom" title={r.name} onclick={() => onpick(r.name)}
            >{r.name}</button
          >
          {#if note}{@render note(r)}{/if}
        </span>
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
            <Popover.Root>
              <Popover.Trigger class="more"
                >{t("and {n} more").replace("{n}", String(more))}</Popover.Trigger
              >
              <Popover.Portal>
                <Popover.Content
                  class="more-panel"
                  side="bottom"
                  align="start"
                  sideOffset={4}
                  collisionPadding={8}
                >
                  <div class="mp-title">{r.name}</div>
                  {#each devs as d (d.key)}
                    <div class="mp-row">
                      <span class="dev">
                        <span class="dn">{d.label}</span>
                        {#if d.label !== d.address}<span class="da">{d.address}</span>{/if}
                      </span>
                      <span class="mp-q">{d.queries}</span>
                    </div>
                  {/each}
                  {#if r.clientsTotal > r.clients.length}
                    <div class="mp-rest">
                      {t("{n} more addresses asked less often").replace(
                        "{n}",
                        String(r.clientsTotal - r.clients.length),
                      )}
                    </div>
                  {/if}
                </Popover.Content>
              </Popover.Portal>
            </Popover.Root>
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
    grid-template-columns: minmax(0, 1fr) 4.5rem 7rem 12rem 5.5rem 15.5rem;
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
  .domcell {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
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
    grid-template-columns: repeat(2, minmax(0, 1fr)) auto;
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
  .devs :global(.more) {
    align-self: center;
    padding: 0.15rem 0.35rem;
    border: 0;
    border-radius: 0.3rem;
    background: none;
    font: inherit;
    font-size: 0.76rem;
    color: var(--accent);
    white-space: nowrap;
    cursor: pointer;
  }
  .devs :global(.more:hover) {
    background: var(--bg-light-extra);
  }
  :global(.more-panel) {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    width: 18rem;
    max-width: calc(100vw - 1rem);
    max-height: 22rem;
    overflow-y: auto;
    box-sizing: border-box;
    padding: 0.6rem 0.75rem;
    background-color: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
    color: var(--text);
    z-index: 30;
    outline: none;
  }
  .mp-title {
    font-size: 0.8rem;
    color: var(--text-2);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .mp-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.75rem;
  }
  .mp-q {
    font-family: var(--font-mono);
    font-size: 0.8rem;
    color: var(--text-2);
  }
  .mp-rest {
    font-size: 0.76rem;
    color: var(--text-2);
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
        "dom dom"
        "share share"
        "devs devs"
        "last act";
      gap: 0.35rem 0.6rem;
      padding: 0.6rem 0.8rem;
    }
    .pane {
      height: auto;
      min-height: 0;
      overflow: visible;
    }
    .domcell {
      grid-area: dom;
      padding-right: 5rem;
    }
    .qcell {
      grid-area: dom;
      justify-self: end;
      align-self: start;
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
