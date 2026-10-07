<script lang="ts">
  import { onDestroy, onMount } from "svelte";

  import PageControls from "../../components/layout/PageControls.svelte";
  import Placeholder from "../../components/ui/Placeholder.svelte";
  import { fetchInterfaces, interfaces } from "../../data/interfaces.svelte";
  import { t } from "../../data/locale.svelte";
  import TunnelCard from "./components/TunnelCard.svelte";
  import { TunnelsStore } from "./tunnels.svelte";

  import { RotateCw } from "../../components/ui/icons";

  let { active }: { active: boolean } = $props();

  const store = new TunnelsStore();
  let open = $state<Record<string, boolean>>({});

  const restarting = $derived(store.restarting);

  $effect(() => {
    void store.setActive(active);
  });

  let interfacesAsked = false;
  $effect(() => {
    if (!active || interfacesAsked) return;
    interfacesAsked = true;
    if (interfaces.list.length === 0) void fetchInterfaces();
  });

  function addTunnel() {
    if (!store.canAdd) return;
    store.addTunnel();
    const added = store.data[store.data.length - 1];
    if (added) open[added.id] = true;
  }

  onMount(() => window.addEventListener("keydown", store.handleSaveShortcut));
  onDestroy(() => {
    window.removeEventListener("keydown", store.handleSaveShortcut);
    store.destroy();
  });
</script>

<div class="tunnels-page">
  <PageControls
    addLabel={t("Add tunnel")}
    canSave={store.canSave}
    ready={store.canAdd}
    onAdd={addTunnel}
    onSave={() => void store.saveChanges()}
    saveLabel={t("Save")}
  >
    {#snippet search()}
      {#if restarting.length > 0}
        <span class="note" role="status">
          <RotateCw size={15} />
          {(restarting.length === 1
            ? t("{devices} will restart on save — connections through it will drop")
            : t("{devices} will restart on save — connections through them will drop")
          ).replace("{devices}", restarting.join(", "))}
        </span>
      {/if}
    {/snippet}
  </PageControls>

  <p class="hint">
    {t("A tunnel is an interface for groups: choose it in a group's interface list.")}
  </p>

  {#if store.fetchError && !store.loaded}
    <Placeholder variant="error" minHeight="auto" subtitle={t("Check connection or try again")}>
      {t("Failed to load tunnels")}
    </Placeholder>
  {:else if !store.loaded}
    <Placeholder variant="loading" minHeight="auto">{t("Loading tunnels...")}</Placeholder>
  {:else}
    {#if store.looseRefusal}
      <div class="refusal" role="alert">{store.looseRefusal.error}</div>
    {/if}

    {#if store.data.length === 0}
      <Placeholder variant="empty" minHeight="auto">{t("No tunnels yet")}</Placeholder>
    {/if}

    {#each store.data as tunnel, index (tunnel.key)}
      <TunnelCard
        {store}
        bind:tunnel={store.data[index]}
        open={open[tunnel.id] ?? false}
        onOpenChange={(next) => (open[tunnel.id] = next)}
      />
    {/each}
  {/if}
</div>

<style>
  .tunnels-page {
    display: flex;
    flex-direction: column;
  }
  .note {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--text-2);
    font-size: 0.85rem;
  }
  .note :global(svg) {
    flex: none;
    color: var(--yellow);
  }
  .hint {
    margin: 0 0 1rem;
    color: var(--text-2);
    font-size: 0.85rem;
  }
  .refusal {
    color: var(--red);
    font-size: 0.9rem;
    margin-bottom: 1rem;
  }
</style>
