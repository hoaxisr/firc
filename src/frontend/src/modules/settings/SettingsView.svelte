<script lang="ts">
  import { untrack } from "svelte";

  import Button from "../../components/ui/Button.svelte";
  import Placeholder from "../../components/ui/Placeholder.svelte";
  import Tooltip from "../../components/ui/Tooltip.svelte";
  import { locale, t } from "../../data/locale.svelte";
  import RestartOverlay from "./RestartOverlay.svelte";
  import SaveDialog from "./SaveDialog.svelte";
  import SettingRow from "./SettingRow.svelte";
  import {
    loadSettings,
    resetDraft,
    restartDaemon,
    saveSettings,
    settings,
  } from "./settings.svelte";

  import { CircleCheck, RotateCw, Save, Undo2 } from "../../components/ui/icons";
  import { counted as countedIn } from "../../utils/plural";
  import { SECTIONS, type Row, type Section } from "./catalogue";
  import { changedKeys, groupChanges } from "./settings";

  let { active }: { active: boolean } = $props();

  $effect(() => {
    if (active && untrack(() => changedKeys(settings.saved, settings.draft).length === 0)) {
      void loadSettings();
    }
  });

  const changed = $derived(changedKeys(settings.saved, settings.draft));
  const grouped = $derived(groupChanges(changed, settings.classes));

  const counted = (n: number, one: string, few: string, many: string) =>
    countedIn(n, locale.current, one, few, many);

  const changedText = $derived(
    counted(
      changed.length,
      t("{n} setting changed"),
      t("{n} settings changed (2-4)"),
      t("{n} settings changed"),
    ),
  );
  const pendingText = $derived(
    counted(
      settings.pendingRestart.length,
      t("{n} setting waits for a restart"),
      t("{n} settings wait for a restart (2-4)"),
      t("{n} settings wait for a restart"),
    ),
  );

  const rowClass = (row: Row): "live" | "restart" =>
    row.fields.every((f) => settings.classes[f.key] === "live") ? "live" : "restart";
  const rowsOf = (section: Section, klass: "live" | "restart") =>
    section.rows.filter((r) => rowClass(r) === klass);
  const wholeRestart = (section: Section) => rowsOf(section, "live").length === 0;

  let dialogOpen = $state(false);

  async function save(restart: boolean) {
    if (!(await saveSettings())) return; /* a refusal keeps the dialog, the field marked */
    dialogOpen = false;
    if (restart) await restartDaemon();
  }
</script>

<div class="settings-page">
  {#if settings.failed && !settings.loaded}
    <Placeholder variant="error" minHeight="auto" subtitle={t("Check connection or try again")}>
      {t("Failed to load settings")}
    </Placeholder>
  {:else if !settings.loaded}
    <Placeholder variant="loading" minHeight="auto">{t("Loading settings...")}</Placeholder>
  {:else}
    <div class="bar">
      <span class="counter" data-testid="settings-counter">{changedText}</span>
      <div class="actions">
        <span class="count"
          ><CircleCheck size={18} color="var(--accent)" />{grouped.live.length}</span
        >
        <span class="count"
          ><RotateCw size={18} color="var(--yellow-bright)" />{grouped.restart.length}</span
        >
        <Tooltip value={t("Reset")}>
          <Button onclick={resetDraft} inactive={changed.length === 0}><Undo2 size={22} /></Button>
        </Tooltip>
        <Tooltip value={t("Save")}>
          <Button
            class="accent"
            onclick={() => (dialogOpen = true)}
            inactive={changed.length === 0 || settings.restarting}
          >
            <Save size={22} />
          </Button>
        </Tooltip>
      </div>
    </div>

    {#if settings.overlay}
      <RestartOverlay />
    {/if}

    {#if !settings.restarting && settings.pendingRestart.length > 0}
      <div class="banner" role="status" data-testid="settings-banner">
        <RotateCw size={18} />
        <span>{pendingText}</span>
        <span class="spacer"></span>
        {#if changed.length > 0}
          <Tooltip value={t("Save or reset your changes first")}>
            <Button small general inactive aria-label={t("Restart")}>{t("Restart")}</Button>
          </Tooltip>
        {:else}
          <Button small general onclick={() => void restartDaemon()}>{t("Restart")}</Button>
        {/if}
      </div>
    {/if}

    {#each SECTIONS as section (section.id)}
      <section class="panel" data-section={section.id}>
        <header>
          <span class="title">{section.title()}</span>
          {#if wholeRestart(section)}
            <span class="whole"
              ><RotateCw size={16} color="var(--yellow-bright)" />{t(
                "The whole section applies after a restart",
              )}</span
            >
          {/if}
        </header>
        {#if wholeRestart(section)}
          <div data-group="restart">
            {#each section.rows as row (row.fields[0].key)}
              <SettingRow {row} />
            {/each}
          </div>
        {:else}
          <div data-group="live">
            {#each rowsOf(section, "live") as row (row.fields[0].key)}
              <SettingRow {row} />
            {/each}
          </div>
          {#if rowsOf(section, "restart").length > 0}
            <div data-group="restart">
              <div class="subheading">
                <RotateCw size={16} color="var(--yellow-bright)" />{t("After a daemon restart")}
              </div>
              {#each rowsOf(section, "restart") as row (row.fields[0].key)}
                <SettingRow {row} />
              {/each}
            </div>
          {/if}
        {/if}
      </section>
    {/each}
  {/if}
  <SaveDialog
    open={dialogOpen}
    keys={changed}
    onclose={() => (dialogOpen = false)}
    onsave={(r) => void save(r)}
  />
</div>

<style>
  .settings-page {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 5px 0;
    position: sticky;
    top: 0;
    z-index: 5;
    background: var(--bg-dark);
  }
  .counter,
  .count {
    font-size: 0.9rem;
    color: var(--text-2);
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .count {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-radius: 8px;
    border: 1px solid var(--yellow-bright);
    color: var(--yellow-bright);
  }
  .spacer {
    flex: 1;
  }
  .panel {
    background: var(--bg-medium);
    border: 1px solid var(--bg-light-extra);
    border-radius: 8px;
    overflow: hidden;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 12px;
    background: var(--bg-light);
  }
  .title {
    font-weight: 600;
    font-size: 1.3rem;
  }
  .whole,
  .subheading {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.9rem;
    color: var(--text-2);
  }
  .subheading {
    padding: 16px 12px 6px;
    border-top: 1px solid var(--bg-light);
  }
</style>
