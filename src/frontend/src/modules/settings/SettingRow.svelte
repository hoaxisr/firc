<script lang="ts">
  import Switch from "../../components/ui/Switch.svelte";
  import { t } from "../../data/locale.svelte";
  import { tabRequest } from "../../data/tab-request.svelte";
  import AutolistGroup from "./AutolistGroup.svelte";
  import IfacePicker from "./IfacePicker.svelte";
  import LanCoverage from "./LanCoverage.svelte";
  import LanPicker from "./LanPicker.svelte";
  import NamesInput from "./NamesInput.svelte";
  import { settings } from "./settings.svelte";

  import type { Row } from "./catalogue";
  import {
    AUTOLIST_GROUP,
    autolistGroupMissing,
    hoursToSeconds,
    sameValue,
    secondsToHours,
    WEB_PORT,
  } from "./settings";

  let { row }: { row: Row } = $props();

  const pending = $derived(row.fields.some((f) => settings.pendingRestart.includes(f.key)));
  const classOf = (key: string): "live" | "restart" =>
    settings.classes[key] === "live" ? "live" : "restart";
  const changedClass = (key: string) =>
    sameValue(settings.saved[key], settings.draft[key]) ? "" : `changed-${classOf(key)}`;
  const invalid = (key: string) => settings.fieldError?.field === key;
  const groupMissing = $derived(autolistGroupMissing(settings.draft));
  const portMoves = $derived(
    row.fields.some((f) => f.key === WEB_PORT) &&
      !sameValue(settings.saved[WEB_PORT], settings.draft[WEB_PORT]),
  );
  const hint = $derived(
    portMoves
      ? t("The page will open on port {port}").replace("{port}", String(settings.draft[WEB_PORT]))
      : row.hint(),
  );
</script>

<div class="row" data-row={row.fields[0].key}>
  <div class="label">
    <div class="name">
      {row.label()}
      {#if pending}<span class="pending">{t("waits for a restart")}</span>{/if}
    </div>
    <div class="hint">{hint}</div>
  </div>
  <div class="controls">
    {#each row.fields as field, i (field.key)}
      {@const c = field.control}
      {#if i > 0 && row.joiner}<span class="joiner">{row.joiner}</span>{/if}
      {#if c.kind === "switch"}
        <span class="switch {changedClass(field.key)}">
          {#if c.caption}<span class="caption">{c.caption}</span>{/if}
          <Switch
            aria-label={field.label()}
            checked={c.invert ? !settings.draft[field.key] : Boolean(settings.draft[field.key])}
            onCheckedChange={(v: boolean) => (settings.draft[field.key] = c.invert ? !v : v)}
          />
        </span>
      {:else if c.kind === "tags"}
        <LanPicker
          ariaLabel={field.label()}
          values={settings.draft[field.key] as string[]}
          onchange={(v) => (settings.draft[field.key] = v)}
          invalid={invalid(field.key)}
          changed={changedClass(field.key)}
        />
      {:else if c.kind === "segment"}
        <span class="segment {changedClass(field.key)}" role="group" aria-label={field.label()}>
          {#each c.options as option (option.value)}
            <button
              type="button"
              aria-pressed={settings.draft[field.key] === option.value}
              onclick={() => (settings.draft[field.key] = option.value)}
            >
              {option.label()}
            </button>
          {/each}
        </span>
      {:else if c.kind === "group"}
        <AutolistGroup
          ariaLabel={field.label()}
          value={String(settings.draft[field.key] ?? "")}
          onchange={(v) => (settings.draft[field.key] = v)}
          required={groupMissing}
          invalid={invalid(field.key) || groupMissing}
          changed={changedClass(field.key)}
        />
      {:else if c.kind === "iface"}
        <IfacePicker
          ariaLabel={field.label()}
          value={String(settings.draft[field.key] ?? "")}
          onchange={(v) => (settings.draft[field.key] = v)}
          groupId={String(settings.draft[AUTOLIST_GROUP] ?? "")}
          invalid={invalid(field.key)}
          changed={changedClass(field.key)}
        />
      {:else if c.kind === "names"}
        <NamesInput
          ariaLabel={field.label()}
          placeholder={c.placeholder?.()}
          values={(settings.draft[field.key] as string[] | undefined) ?? []}
          onchange={(v) => (settings.draft[field.key] = v)}
          invalid={invalid(field.key)}
          changed={changedClass(field.key)}
        />
      {:else if c.kind === "hours"}
        {@const seconds = settings.draft[field.key]}
        <span class="field">
          <input
            type="number"
            min="1"
            max="168"
            step="1"
            aria-label={field.label()}
            class={changedClass(field.key)}
            class:invalid={invalid(field.key)}
            aria-invalid={invalid(field.key)}
            style:width="7rem"
            value={typeof seconds === "number" ? secondsToHours(seconds) : ""}
            oninput={(e) => {
              const hours = e.currentTarget.valueAsNumber;
              settings.draft[field.key] = Number.isFinite(hours) ? hoursToSeconds(hours) : "";
            }}
          />
          <span class="unit">{t("h")}</span>
        </span>
      {:else if c.kind === "number"}
        <span class="field">
          <input
            type="number"
            aria-label={field.label()}
            class={changedClass(field.key)}
            class:invalid={invalid(field.key)}
            aria-invalid={invalid(field.key)}
            style:width={c.width ?? "7rem"}
            bind:value={settings.draft[field.key]}
          />
          {#if c.unit}<span class="unit">{c.unit()}</span>{/if}
        </span>
      {:else}
        <span class="field">
          <input
            type="text"
            aria-label={field.label()}
            class={changedClass(field.key)}
            class:invalid={invalid(field.key)}
            aria-invalid={invalid(field.key)}
            placeholder={c.placeholder?.()}
            style:width={c.width ?? "11rem"}
            bind:value={settings.draft[field.key]}
          />
          {#if c.suggest}
            {@const suggest = c.suggest}
            <button
              type="button"
              class="suggest"
              onclick={() => (settings.draft[field.key] = suggest.value)}
            >
              {suggest.label()}
            </button>
          {/if}
        </span>
      {/if}
    {/each}
  </div>
  {#if row.fields[0].key === "app.autolist.mode"}
    <button
      type="button"
      class="journal-link"
      onclick={() => tabRequest.open("logs", "", "unopened")}
    >
      {t("Candidates are in the Journal → «Not opening»")}
    </button>
  {/if}
  {#if row.fields[0].key === "app.link"}
    <LanCoverage
      values={settings.draft["app.link"] as string[]}
      onchange={(v) => (settings.draft["app.link"] = v)}
    />
  {/if}
</div>

<style>
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
  .pending {
    display: inline-block;
    white-space: nowrap;
    margin-left: 0.5rem;
    font-size: 0.85rem;
    color: var(--yellow-bright);
  }
  .controls {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }
  .field {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    max-width: 100%;
  }
  .journal-link {
    grid-column: 1 / -1;
    justify-self: start;
    padding: 0;
    border: none;
    background: none;
    color: var(--accent);
    font: inherit;
    font-size: 0.85rem;
    cursor: pointer;
  }
  .journal-link:hover {
    text-decoration: underline;
  }
  .segment {
    display: inline-flex;
    padding: 2px;
    gap: 2px;
    border-radius: 8px;
    background: var(--bg-dark);
    border: 1px solid var(--bg-light);
  }
  .segment button {
    padding: 4px 12px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--text);
    font: inherit;
    cursor: pointer;
  }
  .segment button[aria-pressed="true"] {
    background: var(--bg-light);
    color: var(--accent);
  }
  .segment.changed-live {
    border-color: var(--accent);
  }
  .suggest {
    flex: none;
    padding: 4px 10px;
    border-radius: 8px;
    border: 1px solid var(--text-2);
    background: transparent;
    color: var(--text-2);
    font: inherit;
    font-size: 0.75rem;
    cursor: pointer;
  }
  .unit,
  .joiner,
  .caption {
    color: var(--text-2);
  }
  .switch {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 6px;
    border-radius: 8px;
    border: 1px solid transparent;
  }
  input {
    padding: 6px 10px;
    border-radius: 8px;
    background: var(--bg-light);
    border: 1px solid var(--bg-light);
    color: var(--text);
    font: inherit;
    box-sizing: border-box;
    max-width: 100%;
    min-width: 0;
  }
  input.changed-live,
  .switch.changed-live,
  .field.changed-live {
    background: var(--bg-dark);
    border: 1px solid var(--accent);
    border-radius: 8px;
  }
  input.changed-restart,
  .switch.changed-restart,
  .field.changed-restart {
    background: var(--bg-dark);
    border: 1px solid var(--yellow-bright);
    border-radius: 8px;
  }
  input.invalid {
    border-color: var(--danger);
  }
  @media (max-width: 700px) {
    .row {
      grid-template-columns: minmax(0, 1fr);
      gap: 8px;
    }
  }
</style>
