<script lang="ts">
  import Button from "../../../components/ui/Button.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { t } from "../../../data/locale.svelte";

  import { Add, ChevronRight, Delete, RotateCcw, Undo2 } from "../../../components/ui/icons";
  import type { TunnelHeader } from "../../../types";
  import {
    added,
    changedCount,
    headerRows,
    removed,
    restored,
    withName,
    withValue,
    type HeaderRow,
  } from "../headers";

  let {
    defaults,
    rows = $bindable(),
    open = $bindable(false),
    onedit,
  }: {
    defaults: TunnelHeader[];
    rows: HeaderRow[];
    open?: boolean;
    onedit?: () => void;
  } = $props();

  const changes = $derived(changedCount(rows));

  function edit(next: HeaderRow[]) {
    rows = next;
    onedit?.();
  }

  function chip(kind: HeaderRow["kind"]): string {
    if (kind === "default") return t("default");
    if (kind === "changed") return t("edited");
    if (kind === "removed") return t("not sent");
    return t("own");
  }
</script>

<div class="hdr">
  <button
    type="button"
    class="toggle"
    aria-expanded={open}
    aria-controls="headers-editor-panel"
    onclick={() => (open = !open)}
  >
    <span class="chev" class:open><ChevronRight size={16} /></span>
    <span>{t("Request headers")}</span>
    {#if changes === 0}
      <span class="sum">{t("defaults")}</span>
    {:else}
      <span class="sum ch">{t("changed: {n}").replace("{n}", String(changes))}</span>
    {/if}
  </button>

  {#if open}
    <div class="grid" id="headers-editor-panel">
      {#each rows as row, index (index)}
        <div class="row {row.kind}">
          <input
            class="name mono"
            aria-label={t("Header name")}
            maxlength="64"
            value={row.name}
            readonly={row.kind !== "added"}
            spellcheck="false"
            autocomplete="off"
            oninput={(e) => edit(withName(rows, index, e.currentTarget.value))}
          />
          <input
            class="val mono"
            aria-label={row.name
              ? t("Value of {name}").replace("{name}", () => row.name)
              : t("Header value")}
            maxlength="512"
            value={row.value}
            disabled={row.kind === "removed"}
            spellcheck="false"
            autocomplete="off"
            oninput={(e) => edit(withValue(defaults, rows, index, e.currentTarget.value))}
          />
          <span class="chip {row.kind}">{chip(row.kind)}</span>
          {#if row.kind === "removed"}
            <Tooltip value={t("Restore")}>
              <Button type="button" small onclick={() => edit(restored(defaults, rows, index))}>
                <Undo2 size={16} />
              </Button>
            </Tooltip>
          {:else}
            <Tooltip value={row.kind === "added" ? t("Delete") : t("Do not send")}>
              <Button type="button" small onclick={() => edit(removed(defaults, rows, index))}>
                <Delete size={16} />
              </Button>
            </Tooltip>
          {/if}
        </div>
      {/each}
    </div>
    <div class="foot">
      <Button type="button" small class="text-btn" onclick={() => edit(added(rows))}>
        <Add size={15} />{t("Add header")}
      </Button>
      <span class="sp"></span>
      <Button
        type="button"
        small
        class="text-btn"
        inactive={changes === 0}
        onclick={() => edit(headerRows(defaults))}
      >
        <RotateCcw size={15} />{t("Reset to defaults")}
      </Button>
    </div>
    <div class="hint">
      {t(
        "firc sends these with every fetch of the subscription. X-HWID is this router's lasting id: the panel counts it as one device, even after firc is reinstalled.",
      )}
    </div>
  {/if}
</div>

<style>
  .hdr {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    border-top: 1px solid var(--bg-light-extra);
    padding-top: 0.6rem;
  }
  .toggle {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    background: none;
    border: 0;
    color: var(--text);
    font: inherit;
    font-size: 0.9rem;
    padding: 0;
    cursor: pointer;
    text-align: left;
  }
  .chev {
    display: inline-flex;
    transition: transform 0.15s;
    color: var(--text-2);
  }
  .chev.open {
    transform: rotate(90deg);
  }
  .sum {
    font-size: 0.75rem;
    padding: 2px 8px;
    border-radius: 1rem;
    background: var(--bg-light-extra);
    color: var(--text-2);
  }
  .sum.ch {
    background: color-mix(in oklab, var(--accent) 22%, transparent);
    color: var(--accent);
  }
  .grid {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .row {
    display: grid;
    grid-template-columns: minmax(0, 9.5rem) minmax(0, 1fr) auto auto;
    gap: 6px;
    align-items: center;
  }
  .mono {
    font-family: Monaco, monospace;
    font-size: 0.8rem;
  }
  input {
    padding: 5px 8px;
    border-radius: 8px;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    color: var(--text);
    min-width: 0;
  }
  input[readonly] {
    color: var(--text-2);
    background: transparent;
  }
  .row.removed input {
    text-decoration: line-through;
    opacity: 0.5;
  }
  .row.changed .val,
  .row.added .val,
  .row.added .name {
    border-color: color-mix(in oklab, var(--accent) 60%, transparent);
  }
  .chip {
    min-width: 6.6rem;
    text-align: center;
    box-sizing: border-box;
    font-size: 0.7rem;
    padding: 1px 7px;
    border-radius: 1rem;
    white-space: nowrap;
    background: var(--bg-light-extra);
    color: var(--text-2);
  }
  .chip.changed,
  .chip.added {
    background: color-mix(in oklab, var(--accent) 22%, transparent);
    color: var(--accent);
  }
  .chip.removed {
    background: color-mix(in oklab, var(--yellow-bright) 18%, transparent);
    color: var(--yellow-bright);
  }
  .foot {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .foot :global(.text-btn) {
    font-size: 0.8rem;
    gap: 6px;
    border: 1px solid var(--bg-light-extra);
    background: var(--bg-light-extra);
    color: var(--text);
    padding: 0.2rem 0.55rem;
  }
  .sp {
    flex: 1;
  }
  .hint {
    font-size: 0.78rem;
    color: var(--text-2);
  }
  @media (max-width: 520px) {
    .row {
      grid-template-columns: minmax(0, 1fr) auto auto;
    }
    .row .name {
      grid-column: 1 / -1;
      padding: 0 2px;
      border: 0;
    }
    .row.added .name {
      padding: 5px 8px;
      border: 1px solid color-mix(in oklab, var(--accent) 60%, transparent);
    }
  }
</style>
