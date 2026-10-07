<script lang="ts">
  import { Collapsible } from "bits-ui";
  import { slide } from "svelte/transition";

  import Button from "../../../components/ui/Button.svelte";
  import Switch from "../../../components/ui/Switch.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { locale, t } from "../../../data/locale.svelte";
  import type { TunnelsStore } from "../tunnels.svelte";
  import FailoverSection from "./FailoverSection.svelte";
  import NodesSection from "./NodesSection.svelte";
  import SourcesSection from "./SourcesSection.svelte";

  import {
    ArrowDownUp,
    CircleCheck,
    CircleDashed,
    CircleHelp,
    CircleX,
    Delete,
    GroupCollapse,
    GroupExpand,
    LayoutList,
    Link,
    LoaderCircle,
    PowerOff,
    Refresh,
    RotateCcw,
    RotateCw,
    RSS,
    Unplug,
  } from "../../../components/ui/icons";
  import { counted } from "../../../utils/plural";
  import { formatRate } from "../tunnel-editor";
  import { tunnelLook } from "../tunnel-state";
  import type { ClientTunnel } from "../tunnels-data";

  type Props = {
    store: TunnelsStore;
    tunnel: ClientTunnel;
    open: boolean;
    onOpenChange: (open: boolean) => void;
  };

  let { store, tunnel = $bindable(), open, onOpenChange }: Props = $props();

  const ICONS = {
    CircleCheck,
    CircleDashed,
    CircleHelp,
    CircleX,
    LoaderCircle,
    PowerOff,
    RotateCw,
    Unplug,
  };

  const live = $derived(store.stateOf(tunnel.id));
  const look = $derived(live ? tunnelLook(live, t) : null);
  const Icon = $derived(look ? ICONS[look.icon] : CircleHelp);
  const refusal = $derived(store.refusalFor(tunnel.id));
  const saved = $derived(store.isSaved(tunnel.id));
  const up = $derived(live?.status === "up");
  const usable = $derived(
    (live?.nodes ?? []).filter((n) => n.state !== "missing" && n.state !== "skipped").length,
  );
  const subscriptions = $derived(tunnel.sources.filter((s) => s.kind === "subscription"));
  const links = $derived(tunnel.sources.filter((s) => s.kind === "link"));
  const toned = $derived(Boolean(look) && look?.color !== "var(--text-2)");

  const sourcesText = $derived(
    [
      ...subscriptions.map((s) => s.name ?? ""),
      ...(links.length > 0
        ? [
            counted(
              links.length,
              locale.current,
              t("{n} link"),
              t("{n} links (2-4)"),
              t("{n} links"),
            ),
          ]
        : []),
      ...(tunnel.filter ? [t("filter «{f}»").replace("{f}", tunnel.filter)] : []),
      ...(live
        ? [counted(usable, locale.current, t("{n} node"), t("{n} nodes (2-4)"), t("{n} nodes"))]
        : []),
    ]
      .filter(Boolean)
      .join(" · "),
  );

  const groupsText = $derived(
    !live || live.groups.length === 0
      ? t("not used by groups")
      : `${counted(
          live.groups.length,
          locale.current,
          t("{n} group"),
          t("{n} groups (2-4)"),
          t("{n} groups"),
        )}: ${live.groups.join(", ")}`,
  );

  function remove() {
    if (!confirm(t("Delete tunnel {device}?").replace("{device}", tunnel.device))) return;
    store.removeTunnel(tunnel.id);
  }

  function restart() {
    if (
      !confirm(
        t("Restart {device}? Connections through it will drop.").replace("{device}", tunnel.device),
      )
    )
      return;
    void store.restart(tunnel.id);
  }
</script>

<div class="card" data-tunnel={tunnel.id}>
  <Collapsible.Root {open} onOpenChange={(v) => onOpenChange(v)}>
    <div class="head">
      <Tooltip value={look?.label ?? t("Not saved yet")}>
        <span class="st" style:color={look?.color ?? "var(--text-2)"}>
          <Icon size={16} />
        </span>
      </Tooltip>
      <div class="meta">
        <div class="title-row">
          <span class="title">{tunnel.device || tunnel.id}</span>
          {#if !saved}
            <span class="badge">{t("not saved")}</span>
          {:else if up && live}
            {#if live.active.length > 0}
              <span class="badge green">
                {t("active: {names}").replace("{names}", live.active.join(", "))}
              </span>
            {/if}
            <span class="badge">
              {counted(
                usable,
                locale.current,
                t("{a} of {n} node"),
                t("{a} of {n} nodes (2-4)"),
                t("{a} of {n} nodes"),
              ).replace("{a}", String(live.active.length))}
            </span>
          {:else if look}
            <span class="badge" class:toned style:--tone={look.color}>{look.label}</span>
          {/if}
        </div>
        <div class="line">
          {#if up && live}
            <ArrowDownUp size={15} />
            <span>↓ {formatRate(live.rxBps, t)} · ↑ {formatRate(live.txBps, t)}</span>
          {:else if sourcesText}
            {#if subscriptions.length > 0}<RSS size={15} />{:else}<Link size={15} />{/if}
            <span>{sourcesText}</span>
          {/if}
          {#if (up && live) || sourcesText}<span>·</span>{/if}
          <LayoutList size={15} />
          <span>{groupsText}</span>
        </div>
      </div>
      <div class="acts">
        <Tooltip value={t(tunnel.enable ? "Switch the tunnel off" : "Switch the tunnel on")}>
          <Switch
            class="enable-tunnel"
            aria-label={t(tunnel.enable ? "Switch the tunnel off" : "Switch the tunnel on")}
            bind:checked={tunnel.enable}
          />
        </Tooltip>
        <Tooltip value={t(saved ? "Refresh subscriptions" : "Save the tunnel first")}>
          <Button
            small
            inactive={!saved || subscriptions.length === 0}
            onclick={() => void store.refresh(tunnel.id)}
          >
            <Refresh size={20} />
          </Button>
        </Tooltip>
        <Tooltip value={t("Restart")}>
          <Button small inactive={!saved || !tunnel.enable} onclick={restart}>
            <RotateCcw size={20} />
          </Button>
        </Tooltip>
        <Tooltip value={t("Delete")}>
          <Button small onclick={remove}>
            <Delete size={20} />
          </Button>
        </Tooltip>
        <Tooltip value={t(open ? "Collapse" : "Expand")}>
          <Collapsible.Trigger aria-label={t(open ? "Collapse" : "Expand")}>
            {#if open}
              <GroupCollapse size={20} />
            {:else}
              <GroupExpand size={20} />
            {/if}
          </Collapsible.Trigger>
        </Tooltip>
      </div>
    </div>

    {#if refusal}
      <div class="refusal" role="alert">
        {#if refusal.field}<code>{refusal.field}</code>{/if}
        {refusal.error}
      </div>
    {/if}

    <Collapsible.Content>
      {#if open}
        <div class="body" transition:slide>
          <SourcesSection {store} bind:tunnel />
          <NodesSection {store} bind:tunnel />
          <FailoverSection {store} bind:tunnel />
        </div>
      {/if}
    </Collapsible.Content>
  </Collapsible.Root>
</div>

<style>
  .card {
    background: var(--bg-medium);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    margin-bottom: 1rem;
    overflow: hidden;
  }
  .head {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0.5rem 0.5rem 0.5rem 0.9rem;
    min-height: 52px;
    background: var(--bg-light);
  }
  .st {
    width: 26px;
    height: 26px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: color-mix(in oklab, currentColor 18%, transparent);
  }
  .meta {
    display: flex;
    flex-direction: column;
    gap: 3px;
    flex: 1 1 auto;
    min-width: 0;
  }
  .title-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
  }
  .title {
    font-size: 1.3rem;
    font-weight: 600;
  }
  .line {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    color: var(--text-2);
    font-size: 0.8rem;
  }
  .line :global(svg) {
    flex: none;
  }
  .badge {
    font-size: 0.75rem;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 1rem;
    background: var(--bg-light-extra);
    color: var(--text-2);
  }
  .badge.green {
    background: color-mix(in oklab, var(--green) 18%, transparent);
    color: var(--green);
  }
  .badge.toned {
    background: color-mix(in oklab, var(--tone) 18%, transparent);
    color: var(--tone);
  }
  .acts {
    display: flex;
    align-items: center;
    gap: 0.2rem;
  }
  .acts :global([data-switch-root]) {
    margin: 0 0.3rem;
  }
  .body {
    border-top: 1px solid var(--bg-light-extra);
  }
  .refusal {
    color: var(--red);
    font-size: 0.9rem;
    padding: 10px 14px;
  }
  @media (max-width: 700px) {
    .head {
      flex-wrap: wrap;
    }
    .acts {
      width: 100%;
      justify-content: flex-end;
    }
  }
</style>
