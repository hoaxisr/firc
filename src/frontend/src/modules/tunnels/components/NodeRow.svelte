<script lang="ts">
  import Switch from "../../../components/ui/Switch.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { t } from "../../../data/locale.svelte";

  import { Grip } from "../../../components/ui/icons";
  import { dnd_state, draggable, droppable } from "../../../lib/dnd";
  import type { TunnelNodeState, TunnelPreviewRow, TunnelProbeRow } from "../../../types";
  import { agoText, latencyOf, type NodeDnD } from "../tunnel-editor";

  type Props = {
    row: TunnelPreviewRow;
    scope: string;
    excluded: boolean;
    live: TunnelNodeState | undefined;
    probe: TunnelProbeRow | undefined;
    now: number;
    onToggle: () => void;
    onDrop: (source: NodeDnD, target: NodeDnD) => void;
  };

  let { row, scope, excluded, live, probe, now, onToggle, onDrop }: Props = $props();

  let edge = $state<"before" | "after">("before");

  const latency = $derived(latencyOf(probe));

  const look = $derived.by(() => {
    if (excluded) return { dot: "", text: t("excluded by hand") };
    if (row.missing) return { dot: "", text: t("not in the sources") };
    if (row.skipReason) return { dot: "red", text: row.skipReason };
    if (row.overCap) return { dot: "", text: t("past the 256-node cap") };
    switch (live?.state) {
      case "active":
        return { dot: "green", text: t("active") };
      case "down":
        return {
          dot: "red",
          text:
            live.since > 0
              ? t("not answering · {ago}").replace("{ago}", agoText(now, live.since, t))
              : t("not answering"),
        };
      case "reserve":
        return { dot: "grey", text: t("in reserve") };
      default:
        return { dot: "", text: "" };
    }
  });

  function track(event: DragEvent) {
    if (dnd_state.source_scope !== "tunnel-node") return;
    const box = (event.currentTarget as HTMLElement).getBoundingClientRect();
    edge = event.clientY - box.top > box.height / 2 ? "after" : "before";
  }
</script>

<div
  class="node"
  class:ex={excluded}
  data-key={row.key}
  data-drop-edge={edge}
  role="listitem"
  ondragenter={track}
  ondragover={track}
  use:draggable={{
    data: { scope, key: row.key } as NodeDnD,
    scope: "tunnel-node",
    handle: ".grip",
    effects: { effectAllowed: "move", dropEffect: "move" },
  }}
  use:droppable={{
    data: { scope, key: row.key, edge },
    scope: "tunnel-node",
    canDrop: (src: NodeDnD) => src.scope === scope && src.key !== row.key,
    onDrop: (src: NodeDnD) => onDrop(src, { scope, key: row.key, edge }),
  }}
>
  <div class="grip" title={t("Drag node")}><Grip size={16} /></div>
  <div class="nm">
    <span class="name">{row.name}</span>
    {#if row.isNew && !row.missing}<span class="badge blue">{t("new")}</span>{/if}
  </div>
  <div class="src"><span class="badge">{row.source === "link" ? t("link") : row.source}</span></div>
  <div class="state">
    {#if look.dot}<span class="dot {look.dot}"></span>{/if}{look.text}
  </div>
  <div class="lat">
    {#if latency !== null}
      {latency} {t("ms")}
    {:else if probe}
      <Tooltip value={probe.why || t("did not answer")}><span class="fail">—</span></Tooltip>
    {/if}
  </div>
  <div class="on">
    <Tooltip value={t(excluded ? "Include the node" : "Exclude the node")}>
      <Switch
        aria-label={t(excluded ? "Include the node" : "Exclude the node")}
        checked={!excluded}
        onCheckedChange={() => onToggle()}
      />
    </Tooltip>
  </div>
</div>

<style>
  .node {
    display: grid;
    grid-template-columns: 1.5rem minmax(0, 3fr) minmax(0, 1.4fr) minmax(0, 2fr) 4.5rem 4rem;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.6rem;
    border-top: 1px solid var(--bg-light-extra);
    font-size: 0.95rem;
  }
  .node:nth-child(even) {
    background: var(--bg-light);
  }
  .node:global(.dragover) {
    outline: 1px solid var(--accent);
  }
  .node:global(.dragover)[data-drop-edge="before"] {
    box-shadow: inset 0 2px 0 var(--accent);
  }
  .node:global(.dragover)[data-drop-edge="after"] {
    box-shadow: inset 0 -2px 0 var(--accent);
  }
  .grip {
    display: flex;
    align-items: center;
    color: var(--text-2);
    cursor: grab;
    user-select: none;
    -webkit-user-drag: none;
  }
  .grip:hover {
    color: var(--text);
  }
  .nm {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }
  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ex .name,
  .ex .state,
  .ex .lat {
    color: var(--text-2);
  }
  .ex .name {
    text-decoration: line-through;
  }
  .src {
    min-width: 0;
    overflow: hidden;
  }
  .state {
    font-size: 0.8rem;
    color: var(--text-2);
  }
  .dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
  }
  .dot.green {
    background: var(--green);
  }
  .dot.red {
    background: var(--red);
  }
  .dot.grey {
    background: var(--text-2);
  }
  .lat {
    font-family: Monaco, monospace;
    font-size: 0.8rem;
    color: var(--text-2);
    text-align: right;
  }
  .fail {
    color: var(--red);
  }
  .on {
    display: flex;
    justify-content: flex-end;
  }
  .badge {
    font-size: 0.75rem;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 1rem;
    background: var(--bg-light-extra);
    color: var(--text-2);
    white-space: nowrap;
  }
  .badge.blue {
    background: color-mix(in oklab, var(--accent) 22%, transparent);
    color: var(--accent);
  }
  @media (max-width: 700px) {
    .node {
      grid-template-columns: 1.2rem minmax(0, 1fr) auto auto;
      grid-template-areas:
        "grip nm lat on"
        "grip src state state";
    }
    .grip {
      grid-area: grip;
    }
    .nm {
      grid-area: nm;
    }
    .src {
      grid-area: src;
    }
    .state {
      grid-area: state;
    }
    .lat {
      grid-area: lat;
    }
    .on {
      grid-area: on;
    }
  }
</style>
