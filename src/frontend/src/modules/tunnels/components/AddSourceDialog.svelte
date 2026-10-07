<script lang="ts">
  import { untrack } from "svelte";

  import Button from "../../../components/ui/Button.svelte";
  import GenericDialog from "../../../components/ui/GenericDialog.svelte";
  import Select from "../../../components/ui/Select.svelte";
  import { t } from "../../../data/locale.svelte";

  import type { TunnelSource } from "../../../types";
  import { linkProblem, subscriptionIntervals, subscriptionProblem } from "../tunnel-editor";

  type Props = {
    kind: "subscription" | "link";
    source: TunnelSource | null;
    taken: string[];
    onsave: (source: TunnelSource) => void;
    onclose: () => void;
  };

  let { kind, source, taken, onsave, onclose }: Props = $props();

  const initial = untrack(() => source);
  let name = $state(initial?.name ?? "");
  let url = $state(initial?.url ?? "");
  let interval = $state(String(initial?.interval ?? 21600));
  let link = $state(initial?.link ?? "");
  let tried = $state(false);

  const problem = $derived(
    kind === "subscription"
      ? subscriptionProblem(name.trim(), url.trim(), taken, t)
      : linkProblem(link.trim(), t),
  );

  function submit() {
    tried = true;
    if (problem) return;
    const id = source?.id ? { id: source.id } : {};
    onsave(
      kind === "subscription"
        ? ({
            ...id,
            kind,
            name: name.trim(),
            url: url.trim(),
            interval: Number(interval),
          } as TunnelSource)
        : ({ ...id, kind, link: link.trim() } as TunnelSource),
    );
  }
</script>

<GenericDialog
  open={true}
  title={kind === "subscription" ? t("Subscription") : source ? t("Edit link") : t("Link")}
  maxWidth={560}
  on:close={onclose}
  on:submit={submit}
>
  <div slot="body" class="fields">
    {#if kind === "subscription"}
      <label>
        <span>{t("Name")}</span>
        <input type="text" bind:value={name} placeholder="Provider A" autocomplete="off" />
      </label>
      <label>
        <span>{t("URL")}</span>
        <input
          type="text"
          inputmode="url"
          bind:value={url}
          placeholder="https://sub.example/feed"
          autocomplete="off"
          spellcheck="false"
        />
      </label>
      <div class="row">
        <span>{t("Update:")}</span>
        <Select
          ariaLabel={t("Update interval")}
          options={subscriptionIntervals(Number(interval), t)}
          bind:selected={interval}
        />
      </div>
    {:else}
      <label>
        <span>{t("vless:// link")}</span>
        <textarea rows="4" bind:value={link} spellcheck="false" autocomplete="off"></textarea>
      </label>
    {/if}
    {#if tried && problem}
      <div class="problem" role="alert">{problem}</div>
    {/if}
  </div>
  <div slot="actions" class="buttons">
    <Button type="button" onclick={onclose}>{t("Cancel")}</Button>
    <Button type="submit" class="primary">{source ? t("Apply") : t("Add")}</Button>
  </div>
</GenericDialog>

<style>
  .fields {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.9rem;
    color: var(--text-2);
  }
  input {
    padding: 6px 10px;
    border-radius: 8px;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    color: var(--text);
    font: inherit;
  }
  input:focus,
  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }
  textarea {
    font-family: Monaco, monospace;
    font-size: 0.8rem;
    word-break: break-all;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9rem;
    color: var(--text-2);
  }
  .problem {
    color: var(--red);
    font-size: 0.85rem;
  }
  .buttons {
    display: flex;
    gap: 0.5rem;
  }
  .buttons :global(button) {
    color: var(--text);
  }
</style>
