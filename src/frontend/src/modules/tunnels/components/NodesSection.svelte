<script lang="ts">
  import { onDestroy } from "svelte";

  import Button from "../../../components/ui/Button.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { t } from "../../../data/locale.svelte";
  import type { TunnelsStore } from "../tunnels.svelte";
  import NodeRow from "./NodeRow.svelte";

  import { Activity, LoaderCircle, SortByLatency } from "../../../components/ui/icons";
  import type { Tunnel, TunnelPreview, TunnelProbeRow } from "../../../types";
  import { HttpError } from "../../../utils/fetcher";
  import {
    keepHidden,
    orderAfterDrop,
    orderByLatency,
    toggleExclude,
    type NodeDnD,
  } from "../tunnel-editor";
  import { fieldRefusal, plain, type ClientTunnel } from "../tunnels-data";

  let { store, tunnel = $bindable() }: { store: TunnelsStore; tunnel: ClientTunnel } = $props();

  const PREVIEW_DEBOUNCE_MS = 300;

  let preview = $state<TunnelPreview | null>(null);
  let previewError = $state("");
  let filterRefused = $state(false);
  let probes = $state<Record<string, TunnelProbeRow>>({});
  let probing = $state(false);
  let now = $state(Math.floor(Date.now() / 1000));

  const live = $derived(store.stateOf(tunnel.id));
  const draft = $derived(JSON.stringify(plain([$state.snapshot(tunnel) as Tunnel])[0]));
  const fetched = $derived(
    (live?.subscriptions ?? []).map((s) => `${s.name}:${s.lastOk}`).join("|"),
  );
  const rows = $derived(preview?.nodes ?? []);
  const visible = $derived(rows.map((r) => r.key));
  const measured = $derived(Object.keys(probes).length > 0);
  const saved = $derived(store.isSaved(tunnel.id));
  const sourcesShape = $derived(JSON.stringify($state.snapshot(tunnel.sources)));
  let probedSources = "";

  let timer: ReturnType<typeof setTimeout> | null = null;
  let inflight: AbortController | null = null;

  $effect(() => {
    const body = draft;
    void fetched;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => void runPreview(JSON.parse(body) as Tunnel), PREVIEW_DEBOUNCE_MS);
  });

  $effect(() => {
    if (sourcesShape !== probedSources) probes = {};
  });

  $effect(() => {
    void live;
    now = Math.floor(Date.now() / 1000);
  });

  onDestroy(() => {
    if (timer) clearTimeout(timer);
    inflight?.abort();
  });

  async function runPreview(body: Tunnel) {
    inflight?.abort();
    const mine = new AbortController();
    inflight = mine;
    try {
      const answer = await store.preview(body, mine.signal);
      if (inflight !== mine) return;
      preview = answer;
      previewError = "";
      filterRefused = false;
    } catch (error) {
      if (inflight !== mine || mine.signal.aborted) return;
      const refusal =
        error instanceof HttpError && error.status === 400 ? fieldRefusal(error) : null;
      filterRefused = Boolean(refusal?.field.endsWith("filter"));
      previewError = refusal
        ? refusal.field && !filterRefused
          ? `${refusal.field}: ${refusal.error}`
          : refusal.error
        : t("The node list is not available right now");
    }
  }

  function reorder(newVisible: string[]) {
    const order = keepHidden(newVisible, tunnel.order);
    tunnel.order = order;
    if (preview) {
      const at = new Map(order.map((key, i) => [key, i]));
      preview.nodes = [...preview.nodes].sort(
        (a, b) => (at.get(a.key) ?? 0) - (at.get(b.key) ?? 0),
      );
    }
  }

  function drop(source: NodeDnD, target: NodeDnD) {
    reorder(orderAfterDrop(visible, source.key, target.key, target.edge ?? "before"));
  }

  async function probe() {
    if (probing || !saved) return;
    probing = true;
    try {
      const shape = sourcesShape;
      const answer = await store.probe(JSON.parse(draft) as Tunnel);
      if (answer && shape === sourcesShape) {
        probedSources = shape;
        probes = Object.fromEntries(answer.map((row) => [row.key, row]));
      }
    } finally {
      probing = false;
    }
  }
</script>

<section class="sec">
  <div class="sec-h">
    <span>{t("Nodes")}</span>
    <span class="sp"></span>
    <Tooltip value={t(saved ? "Check every node now" : "Save the tunnel first")}>
      <Button small class="text-btn" inactive={probing || !saved} onclick={() => void probe()}>
        {#if probing}
          <span class="spin"><LoaderCircle size={15} /></span>
        {:else}
          <Activity size={15} />
        {/if}
        {t("Check nodes")}
      </Button>
    </Tooltip>
    <Tooltip value={t(measured ? "Sort by the measured latency" : "Check the nodes first")}>
      <Button
        small
        class="text-btn"
        inactive={!measured}
        onclick={() => reorder(orderByLatency(visible, probes))}
      >
        <SortByLatency size={15} />
        {t("By latency")}
      </Button>
    </Tooltip>
  </div>

  {#if previewError && !filterRefused}
    <div class="problem top" role="alert">{previewError}</div>
  {/if}

  <div class="row">
    <div class="label">
      <div class="name">{t("Filter by name")}</div>
      <div class="hint">{t("New subscription nodes that match the filter join by themselves")}</div>
    </div>
    <div class="controls">
      <input
        type="text"
        aria-label={t("Filter by name")}
        placeholder="NL|Netherlands"
        class:invalid={filterRefused}
        bind:value={tunnel.filter}
      />
      {#if preview}
        <span class="unit">
          {t("{n} of {m} match")
            .replace("{n}", String(preview.matched))
            .replace("{m}", String(preview.total))}
        </span>
      {/if}
    </div>
  </div>
  {#if previewError && filterRefused}
    <div class="problem" role="alert">{previewError}</div>
  {/if}

  {#if rows.length > 0}
    <div class="table" role="list">
      <div class="head" aria-hidden="true">
        <span></span>
        <span>{t("Node")}</span>
        <span>{t("Source")}</span>
        <span>{t("State")}</span>
        <span class="r">{t("Latency")}</span>
        <span class="r">{t("Enabled")}</span>
      </div>
      {#each rows as row (row.key)}
        <NodeRow
          {row}
          scope={tunnel.key}
          excluded={tunnel.exclude.includes(row.key)}
          live={live?.nodes.find((n) => n.key === row.key)}
          probe={probes[row.key]}
          {now}
          onToggle={() => (tunnel.exclude = toggleExclude(tunnel.exclude, row.key))}
          onDrop={drop}
        />
      {/each}
    </div>
  {:else if preview}
    <div class="empty">
      {t(
        tunnel.sources.length === 0
          ? "Add a source to see its nodes"
          : "No nodes yet: a new subscription is fetched after saving",
      )}
    </div>
  {/if}
</section>

<style>
  .sec {
    border-bottom: 1px solid var(--bg-light-extra);
  }
  .sec-h {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 14px;
    font-weight: 600;
    font-size: 1.05rem;
    background: var(--bg-light);
  }
  .sp {
    flex: 1;
  }
  .sec-h :global(.text-btn) {
    font-size: 0.85rem;
    gap: 6px;
    border: 1px solid var(--bg-light-extra);
    background: var(--bg-light-extra);
    color: var(--text);
    padding: 0.25rem 0.6rem;
  }
  .spin {
    display: inline-flex;
    animation: spin 1s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 320px;
    align-items: center;
    gap: 24px;
    padding: 12px;
    border-top: 1px solid var(--bg-light);
  }
  .hint {
    font-size: 0.85rem;
    color: var(--text-2);
  }
  .controls {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }
  .unit {
    color: var(--text-2);
    font-size: 0.85rem;
  }
  input {
    width: 11rem;
    padding: 6px 10px;
    border-radius: 8px;
    background: var(--bg-light);
    border: 1px solid var(--bg-light);
    color: var(--text);
    font: inherit;
  }
  input.invalid {
    border-color: var(--danger);
  }
  .problem.top {
    padding-top: 10px;
  }
  .problem {
    color: var(--red);
    font-size: 0.85rem;
    padding: 0 12px 10px;
  }
  .table {
    display: flex;
    flex-direction: column;
  }
  .head {
    display: grid;
    grid-template-columns: 1.5rem minmax(0, 3fr) minmax(0, 1.4fr) minmax(0, 2fr) 4.5rem 4rem;
    gap: 0.5rem;
    padding: 0.35rem 0.6rem;
    color: var(--text-2);
    font-size: 0.85rem;
  }
  .r {
    text-align: right;
  }
  .empty {
    padding: 10px 14px;
    color: var(--text-2);
    font-size: 0.9rem;
    border-top: 1px solid var(--bg-light-extra);
  }
  @media (max-width: 700px) {
    .row {
      grid-template-columns: 1fr;
      gap: 8px;
    }
    .head {
      display: none;
    }
  }
</style>
