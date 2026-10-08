<script lang="ts">
  import Button from "../../../components/ui/Button.svelte";
  import Select from "../../../components/ui/Select.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { locale, t } from "../../../data/locale.svelte";
  import { ask } from "../../../utils/confirm.svelte";
  import type { TunnelsStore } from "../tunnels.svelte";
  import AddSourceDialog from "./AddSourceDialog.svelte";

  import {
    CloudDownload,
    Delete,
    Eye,
    EyeOff,
    Link,
    Pencil,
    Refresh,
    RSS,
  } from "../../../components/ui/icons";
  import type { TunnelSource } from "../../../types";
  import { counted } from "../../../utils/plural";
  import { linkName, middleEllipsis, subscriptionIntervals } from "../tunnel-editor";
  import type { ClientTunnel } from "../tunnels-data";

  let { store, tunnel = $bindable() }: { store: TunnelsStore; tunnel: ClientTunnel } = $props();

  let dialog = $state<{ kind: "subscription" | "link"; index: number | null } | null>(null);
  let shown = $state<Record<number, boolean>>({});
  const HIDDEN = "••••••••••••••••••••";

  const live = $derived(store.stateOf(tunnel.id));
  const saved = $derived(store.isSaved(tunnel.id));

  function subState(name: string | undefined) {
    return live?.subscriptions.find((s) => s.name === name);
  }

  function stamp(unix: number) {
    const d = new Date(unix * 1000);
    const two = (n: number) => String(n).padStart(2, "0");
    return `${two(d.getDate())}.${two(d.getMonth() + 1)}.${d.getFullYear()} ${two(d.getHours())}:${two(d.getMinutes())}`;
  }

  async function removeSource(index: number) {
    const source = tunnel.sources[index];
    const name = source.kind === "link" ? linkName(source.link ?? "") : (source.name ?? "");
    const ok = await ask({
      tone: "danger",
      title: t("Delete source «{name}»?").replace("{name}", name),
      message: t("Its nodes will be removed from the tunnel once you save."),
      confirm: t("Delete"),
    });
    if (!ok) return;
    const at = tunnel.sources.indexOf(source);
    if (at < 0) return;
    tunnel.sources.splice(at, 1);
    shown = {};
  }

  function saveSource(source: TunnelSource) {
    if (!dialog) return;
    if (dialog.index === null) tunnel.sources.push(source);
    else tunnel.sources[dialog.index] = source;
    dialog = null;
  }
</script>

<section class="sec">
  <div class="sec-h">
    <span>{t("Sources")}</span>
    <span class="sp"></span>
    <Button small class="text-btn" onclick={() => (dialog = { kind: "subscription", index: null })}>
      <RSS size={15} />{t("Subscription")}
    </Button>
    <Button small class="text-btn" onclick={() => (dialog = { kind: "link", index: null })}>
      <Link size={15} />{t("Link")}
    </Button>
  </div>

  {#if tunnel.sources.length === 0}
    <div class="empty">{t("No sources yet: add a subscription or a link")}</div>
  {/if}

  {#each tunnel.sources as source, index (source.id || `new-${index}`)}
    {#if source.kind === "subscription"}
      {@const sub = subState(source.name)}
      <div class="src">
        <span class="ico"><RSS size={20} /></span>
        <div class="main">
          <span class="n">
            {source.name}
            {#if sub}
              <span class="badge blue">
                {counted(
                  sub.nodes,
                  locale.current,
                  t("{n} node"),
                  t("{n} nodes (2-4)"),
                  t("{n} nodes"),
                )}
              </span>
            {/if}
            {#if sub?.error}
              <span class="badge red">{t("error: {e}").replace("{e}", sub.error)}</span>
            {/if}
          </span>
          <span class="line url"
            ><Link size={15} /><span class="cut">{shown[index] ? source.url : HIDDEN}</span></span
          >
          <span class="line">
            <CloudDownload size={15} />
            {#if sub && sub.lastOk > 0}
              {stamp(sub.lastOk)}{#if sub.error}&nbsp;{t("(last good)")}{/if}
            {:else}
              {t(saved ? "not fetched yet" : "fetched after saving")}
            {/if}
            · {t("Update:")}
            <Select
              ariaLabel={t("Update interval")}
              options={subscriptionIntervals(source.interval ?? 21600, t)}
              selected={String(source.interval ?? 21600)}
              onValueChange={(v: string) => (source.interval = Number(v))}
            />
          </span>
        </div>
        {@render reveal(index)}
        <Tooltip value={t(saved ? "Refresh subscriptions" : "Save the tunnel first")}>
          <Button small inactive={!saved} onclick={() => void store.refresh(tunnel.id)}>
            <Refresh size={20} />
          </Button>
        </Tooltip>
        <Tooltip value={t("Delete")}>
          <Button small onclick={() => removeSource(index)}>
            <Delete size={20} />
          </Button>
        </Tooltip>
      </div>
    {:else}
      <div class="src">
        <span class="ico"><Link size={20} /></span>
        <div class="main">
          <span class="n">{linkName(source.link ?? "")} <span class="badge">{t("link")}</span></span
          >
          <span class="mono">{shown[index] ? middleEllipsis(source.link ?? "", 96) : HIDDEN}</span>
        </div>
        {@render reveal(index)}
        <Tooltip value={t("Edit")}>
          <Button small onclick={() => (dialog = { kind: "link", index })}>
            <Pencil size={20} />
          </Button>
        </Tooltip>
        <Tooltip value={t("Delete")}>
          <Button small onclick={() => removeSource(index)}>
            <Delete size={20} />
          </Button>
        </Tooltip>
      </div>
    {/if}
  {/each}
</section>

{#snippet reveal(index: number)}
  <Tooltip value={t(shown[index] ? "Hide the address" : "Show the address")}>
    <Button
      small
      aria-pressed={Boolean(shown[index])}
      onclick={() => (shown[index] = !shown[index])}
    >
      {#if shown[index]}<EyeOff size={20} />{:else}<Eye size={20} />{/if}
    </Button>
  </Tooltip>
{/snippet}

{#if dialog}
  <AddSourceDialog
    kind={dialog.kind}
    source={dialog.index === null ? null : tunnel.sources[dialog.index]}
    taken={tunnel.sources
      .filter((s, i) => s.kind === "subscription" && i !== dialog?.index)
      .map((s) => s.name ?? "")}
    onsave={saveSource}
    onclose={() => (dialog = null)}
  />
{/if}

<style>
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
  .empty {
    padding: 10px 14px;
    color: var(--text-2);
    font-size: 0.9rem;
    border-top: 1px solid var(--bg-light-extra);
  }
  .src {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 10px 14px;
    border-top: 1px solid var(--bg-light-extra);
  }
  .ico {
    color: var(--accent);
    margin-top: 2px;
  }
  .main {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 3px;
    min-width: 0;
  }
  .n {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
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
  .line :global([data-select-trigger]) {
    font-size: 0.85rem;
  }
  .url {
    flex-wrap: nowrap;
  }
  .cut {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }
  .mono {
    font-family: Monaco, monospace;
    font-size: 0.75rem;
    color: var(--text-2);
    word-break: break-all;
  }
  .badge {
    font-size: 0.75rem;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 1rem;
    background: var(--bg-light-extra);
    color: var(--text-2);
  }
  .badge.blue {
    background: color-mix(in oklab, var(--accent) 22%, transparent);
    color: var(--accent);
  }
  .badge.red {
    background: color-mix(in oklab, var(--red) 18%, transparent);
    color: var(--red);
  }
</style>
