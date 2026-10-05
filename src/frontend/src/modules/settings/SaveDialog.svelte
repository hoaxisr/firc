<script lang="ts">
  import Button from "../../components/ui/Button.svelte";
  import GenericDialog from "../../components/ui/GenericDialog.svelte";
  import { t } from "../../data/locale.svelte";
  import { settings } from "./settings.svelte";

  import { LoaderCircle, RotateCw } from "../../components/ui/icons";
  import { FIELDS, formatValue } from "./catalogue";
  import { groupChanges, WEB_PORT } from "./settings";

  type Props = {
    open: boolean;
    keys: string[];
    onclose: () => void;
    onsave: (restart: boolean) => void;
  };
  let { open, keys, onclose, onsave }: Props = $props();

  const grouped = $derived(groupChanges(keys, settings.classes));
  const portMoves = $derived(grouped.restart.includes(WEB_PORT));
  const portText = $derived(
    t("After the restart the page will open on port {port}.").replace(
      "{port}",
      String(settings.draft[WEB_PORT]),
    ),
  );
</script>

{#snippet change(key: string, klass: "live" | "restart")}
  <li class="change" class:invalid={settings.fieldError?.field === key} data-key={key}>
    <span class="name">{FIELDS[key]?.label() ?? key}</span>
    <span class="values">
      <s class="was">{formatValue(key, settings.saved[key])}</s>
      <span class="arrow">→</span>
      <span class="now {klass}">{formatValue(key, settings.draft[key])}</span>
    </span>
  </li>
{/snippet}

<GenericDialog
  {open}
  title={t("Save settings")}
  maxWidth={680}
  on:close={onclose}
  on:submit={() => {
    if (grouped.restart.length === 0) onsave(false);
  }}
>
  <div slot="body" class="save-body">
    {#if grouped.live.length > 0}
      <h3>{t("Applies at once")}</h3>
      <ul class="changes">
        {#each grouped.live as key (key)}
          {@render change(key, "live")}
        {/each}
      </ul>
    {/if}
    {#if grouped.restart.length > 0}
      <h3>{t("Needs a daemon restart")}</h3>
      <ul class="changes">
        {#each grouped.restart as key (key)}
          {@render change(key, "restart")}
        {/each}
      </ul>
      <p class="warning">
        {t("DNS will stop answering for a few seconds.")}
        {#if portMoves}{portText}{/if}
      </p>
    {/if}
    {#if settings.fieldError}
      <p class="error" role="alert">{settings.fieldError.error}</p>
    {/if}
  </div>
  <div slot="actions" class="save-actions">
    {#if grouped.restart.length > 0}
      <Button type="button" disabled={settings.saving} onclick={() => onsave(false)}>
        <span class="btn-label">{t("Apply without restart")}</span>
      </Button>
      <span class="gap"></span>
      <Button small type="button" onclick={onclose}>
        <span class="btn-label">{t("Cancel")}</span>
      </Button>
      <Button class="accent" type="button" disabled={settings.saving} onclick={() => onsave(true)}>
        <span class="icon-slot">
          {#if settings.saving}
            <LoaderCircle class="spin" size={16} />
          {:else}
            <RotateCw size={16} />
          {/if}
        </span>
        <span class="btn-label">{t("Save and restart")}</span>
      </Button>
    {:else}
      <Button class="accent" type="submit" disabled={settings.saving}>
        <span class="btn-label">{t("Save")}</span>
      </Button>
    {/if}
  </div>
</GenericDialog>

<style>
  h3 {
    margin: 0.75rem 0 0.4rem;
    font-size: 1rem;
    font-weight: 600;
  }
  .changes {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--bg-light-extra);
    border-radius: 8px;
    overflow: hidden;
  }
  .change {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 12px;
    align-items: center;
    padding: 9px 12px;
  }
  .change:nth-child(odd) {
    background: var(--bg-light);
  }
  .change.invalid {
    outline: 1px solid var(--danger);
  }
  .values {
    font-family: var(--font-mono);
    font-size: 0.85rem;
    color: var(--text-2);
  }
  .now.live {
    color: var(--accent);
  }
  .now.restart {
    color: var(--yellow-bright);
  }
  .warning {
    font-size: 0.9rem;
    color: var(--text-2);
    line-height: 1.4;
  }
  .error {
    color: var(--danger);
  }
  .save-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    width: 100%;
    gap: 0.5rem;
  }
  .save-actions :global(button) {
    flex-shrink: 0;
  }
  .gap {
    flex: 1 1 0%;
    min-width: 0;
  }
  @media (max-width: 760px) {
    .save-actions {
      flex-direction: column;
      align-items: stretch;
      justify-content: flex-start;
    }
    .save-actions :global(button) {
      width: 100%;
    }
    .save-actions :global(button.accent) {
      order: -1;
    }
    .gap {
      display: none;
    }
  }
  .btn-label {
    white-space: nowrap;
  }
  .icon-slot {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
    flex-shrink: 0;
  }
  .icon-slot :global(.spin) {
    animation: save-dialog-spin 1s linear infinite;
  }
  @keyframes save-dialog-spin {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }
</style>
