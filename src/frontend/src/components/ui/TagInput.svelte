<script lang="ts">
  import { t } from "../../data/locale.svelte";

  import { randomId } from "../../utils/random-id";
  import { Add, X } from "./icons";

  type Props = {
    values: string[];
    suggestions?: string[];
    onchange: (values: string[]) => void;
    ariaLabel: string;
    invalid?: boolean;
    changed?: string;
  };
  let {
    values,
    suggestions = [],
    onchange,
    ariaLabel,
    invalid = false,
    changed = "",
  }: Props = $props();

  let entry = $state("");
  const listId = `tags-${randomId()}`;
  const offered = $derived(suggestions.filter((s) => !values.includes(s)));

  function add() {
    const value = entry.trim();
    entry = "";
    if (value === "" || values.includes(value)) return;
    onchange([...values, value]);
  }

  function remove(index: number) {
    onchange(values.filter((_, i) => i !== index));
  }
</script>

<div class="tags {changed}" class:invalid role="group" aria-label={ariaLabel}>
  {#each values as value, i (i)}
    <span class="tag">
      {value}
      <button
        type="button"
        class="remove"
        aria-label={`${t("Remove")} ${value}`}
        onclick={() => remove(i)}
      >
        <X size={14} />
      </button>
    </span>
  {/each}
  <input
    list={listId}
    bind:value={entry}
    aria-label={t("Interface name")}
    onkeydown={(e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        add();
      }
    }}
  />
  <datalist id={listId}>
    {#each offered as option (option)}
      <option value={option}></option>
    {/each}
  </datalist>
  <button type="button" class="add" aria-label={t("Add an interface")} onclick={add}>
    <Add size={18} />
  </button>
</div>

<style>
  .tags {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.4rem;
    padding: 0.2rem;
    border-radius: 0.5rem;
    border: 1px solid transparent;
  }
  .tags.changed-restart {
    border-color: var(--yellow-bright);
  }
  .tags.changed-live {
    border-color: var(--accent);
  }
  .tags.invalid {
    border-color: var(--danger);
  }
  .tag {
    display: inline-flex;
    align-items: center;
    gap: 0.2rem;
    padding: 4px 6px 4px 10px;
    border-radius: 8px;
    background: var(--bg-light-extra);
  }
  .remove,
  .add {
    display: inline-flex;
    padding: 0;
    border: 0;
    background: transparent;
    color: var(--text-2);
    cursor: pointer;
  }
  input {
    width: 6rem;
    padding: 4px 8px;
    border-radius: 8px;
    border: 1px solid var(--bg-light);
    background: var(--bg-light);
    color: var(--text);
    font: inherit;
  }
</style>
