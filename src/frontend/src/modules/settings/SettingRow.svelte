<script lang="ts">
  import Select from "../../components/ui/Select.svelte";
  import Switch from "../../components/ui/Switch.svelte";
  import TagInput from "../../components/ui/TagInput.svelte";
  import { groupInterfaces } from "../../data/interfaces.svelte";
  import { t } from "../../data/locale.svelte";
  import { settings } from "./settings.svelte";

  import type { Row } from "./catalogue";
  import { sameValue, WEB_PORT } from "./settings";

  let { row }: { row: Row } = $props();

  const pending = $derived(row.fields.some((f) => settings.pendingRestart.includes(f.key)));
  const classOf = (key: string): "live" | "restart" =>
    settings.classes[key] === "live" ? "live" : "restart";
  const changedClass = (key: string) =>
    sameValue(settings.saved[key], settings.draft[key]) ? "" : `changed-${classOf(key)}`;
  const invalid = (key: string) => settings.fieldError?.field === key;
  const portMoves = $derived(
    row.fields.some((f) => f.key === WEB_PORT) &&
      !sameValue(settings.saved[WEB_PORT], settings.draft[WEB_PORT]),
  );
  const hint = $derived(
    portMoves
      ? t("The page will open on port {port}").replace("{port}", String(settings.draft[WEB_PORT]))
      : row.hint(),
  );
  const suggestions = $derived(
    groupInterfaces()
      .map((i) => i.id)
      .filter((id) => id !== "blackhole"),
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
      {:else if c.kind === "select"}
        <span class="field {changedClass(field.key)}">
          <Select
            ariaLabel={field.label()}
            options={c.options.map((o) => ({ value: o, label: o }))}
            selected={String(settings.draft[field.key])}
            onValueChange={(v: string) => (settings.draft[field.key] = v)}
          />
        </span>
      {:else if c.kind === "tags"}
        <TagInput
          ariaLabel={field.label()}
          values={settings.draft[field.key] as string[]}
          {suggestions}
          onchange={(v) => (settings.draft[field.key] = v)}
          invalid={invalid(field.key)}
          changed={changedClass(field.key)}
        />
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
        </span>
      {/if}
    {/each}
  </div>
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
      grid-template-columns: 1fr;
      gap: 8px;
    }
  }
</style>
