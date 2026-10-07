<script lang="ts">
  import { Collapsible } from "bits-ui";
  import { slide } from "svelte/transition";

  import Select from "../../../components/ui/Select.svelte";
  import { t } from "../../../data/locale.svelte";
  import type { TunnelsStore } from "../tunnels.svelte";
  import AdvancedSection from "./AdvancedSection.svelte";
  import UplinkSelect from "./UplinkSelect.svelte";

  import { ChevronRight, GroupCollapse } from "../../../components/ui/icons";
  import type { Tunnel } from "../../../types";
  import { plain, type ClientTunnel } from "../tunnels-data";

  let { store, tunnel = $bindable() }: { store: TunnelsStore; tunnel: ClientTunnel } = $props();

  let more = $state(false);

  const bad = (value: number, min: number, max: number) =>
    !Number.isInteger(value) || value < min || value > max;

  const byOptions = $derived([
    { value: "connection", label: t("by connection") },
    { value: "site", label: t("by site") },
    { value: "site-client", label: t("by site and device") },
  ]);
  const tunnels = $derived(plain(store.data as Tunnel[]));
</script>

<section class="sec">
  <div class="sec-h">{t("Failover")}</div>
  <div class="row">
    <div class="label">
      <div class="name">{t("Active nodes")}</div>
      <div class="hint">
        {t("How many nodes carry traffic at once; the rest wait in reserve, in order")}
      </div>
    </div>
    <div class="controls">
      <input
        type="number"
        min="1"
        max="8"
        aria-label={t("Active nodes")}
        class:invalid={bad(tunnel.active, 1, 8)}
        aria-invalid={bad(tunnel.active, 1, 8)}
        bind:value={tunnel.active}
      />
    </div>
  </div>
  <div class="row">
    <div class="label">
      <div class="name">{t("Distribution")}</div>
      <div class="hint">{t("How new connections are shared among the active nodes")}</div>
    </div>
    <div class="controls">
      <span class="field">
        <Select
          ariaLabel={t("Distribution")}
          options={byOptions}
          selected={tunnel.by}
          onValueChange={(v: string) => (tunnel.by = v as Tunnel["by"])}
        />
      </span>
    </div>
  </div>
  <div class="row">
    <div class="label">
      <div class="name">{t("Node check")}</div>
      <div class="hint">{t("How often to check that an active node answers")}</div>
    </div>
    <div class="controls">
      <input
        type="number"
        min="5"
        max="86400"
        aria-label={t("Node check")}
        class:invalid={bad(tunnel.interval, 5, 86400)}
        aria-invalid={bad(tunnel.interval, 5, 86400)}
        bind:value={tunnel.interval}
      />
      <span class="unit">{t("s")}</span>
    </div>
  </div>
  <div class="row">
    <div class="label">
      <div class="name">{t("Silence")}</div>
      <div class="hint">
        {t("A connection silent this long counts as broken and its node is checked at once")}
      </div>
    </div>
    <div class="controls">
      <input
        type="number"
        min="0"
        max="3600"
        aria-label={t("Silence")}
        class:invalid={bad(tunnel.silence, 0, 3600)}
        aria-invalid={bad(tunnel.silence, 0, 3600)}
        bind:value={tunnel.silence}
      />
      <span class="unit">{t("s")}</span>
    </div>
  </div>

  <Collapsible.Root bind:open={more}>
    <Collapsible.Trigger class="more">
      {#if more}<GroupCollapse size={15} />{:else}<ChevronRight size={15} />{/if}
      {t("More: connect timeout, certificate check, own CA, device name")}
    </Collapsible.Trigger>
    <Collapsible.Content>
      {#if more}
        <div transition:slide>
          <AdvancedSection {store} bind:tunnel />
        </div>
      {/if}
    </Collapsible.Content>
  </Collapsible.Root>

  <div class="row">
    <div class="label">
      <div class="name">{t("Way out to the internet")}</div>
      <div class="hint">
        {t("Where the tunnel's own connections to its servers and subscriptions go")}
      </div>
    </div>
    <div class="controls">
      <span class="field"><UplinkSelect bind:tunnel {tunnels} /></span>
    </div>
  </div>
</section>

<style>
  .sec-h {
    padding: 8px 14px;
    font-weight: 600;
    font-size: 1.05rem;
    background: var(--bg-light);
  }
  .sec :global(.row) {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 320px;
    align-items: center;
    gap: 24px;
    padding: 12px;
    border-top: 1px solid var(--bg-light);
  }
  .sec :global(.hint) {
    font-size: 0.85rem;
    color: var(--text-2);
  }
  .sec :global(.hint.bad) {
    color: var(--red);
  }
  .sec :global(.controls) {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }
  .sec :global(.field) {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .sec :global(.unit) {
    color: var(--text-2);
  }
  .sec :global(input) {
    width: 7rem;
    padding: 6px 10px;
    border-radius: 8px;
    background: var(--bg-light);
    border: 1px solid var(--bg-light);
    color: var(--text);
    font: inherit;
  }
  .sec :global(input.wide) {
    width: 14rem;
  }
  .sec :global(input.invalid) {
    border-color: var(--danger);
  }
  .sec :global(.more) {
    display: flex;
    align-items: center;
    justify-content: flex-start;
    gap: 6px;
    width: 100%;
    padding: 10px 14px;
    color: var(--text-2);
    font: inherit;
    font-size: 0.9rem;
    background: transparent;
    border: none;
    border-top: 1px solid var(--bg-light);
    border-radius: 0;
    cursor: pointer;
    text-align: left;
  }
  .sec :global(.more:hover) {
    color: var(--text);
    background: transparent;
    border: none;
    border-top: 1px solid var(--bg-light);
  }
  @media (max-width: 700px) {
    .sec :global(.row) {
      grid-template-columns: 1fr;
      gap: 8px;
    }
  }
</style>
