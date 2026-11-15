<script lang="ts">
  import { interfaces } from "../../data/interfaces.svelte";
  import { t } from "../../data/locale.svelte";
  import { loadTunnelDevices, tunnelDevices } from "../../data/tunnel-devices.svelte";

  import { Check, SelectOpen, X } from "../../components/ui/icons";
  import { ifaceTitle, lanChoices } from "../../data/iface-choices";
  import { randomId } from "../../utils/random-id";

  type Props = {
    values: string[];
    onchange: (values: string[]) => void;
    ariaLabel: string;
    invalid?: boolean;
    changed?: string;
  };
  let { values, onchange, ariaLabel, invalid = false, changed = "" }: Props = $props();

  let open = $state(false);
  let query = $state("");
  let active = $state(-1);
  let root: HTMLElement | undefined = $state();
  let search: HTMLInputElement | undefined = $state();
  let addButton: HTMLButtonElement | undefined = $state();
  const listId = `lan-${randomId()}`;
  const offered = $derived(lanChoices(interfaces.list, query, tunnelDevices.list));
  const titleOf = (id: string) =>
    ifaceTitle(interfaces.list.find((i) => i.id === id) ?? { id }).title;

  function toggle(id: string) {
    onchange(values.includes(id) ? values.filter((v) => v !== id) : [...values, id]);
  }

  function addTyped() {
    const value = query.trim();
    if (value === "" || values.includes(value)) return;
    onchange([...values, value]);
    query = "";
  }

  function remove(index: number) {
    onchange(values.filter((_, i) => i !== index));
  }

  function show(next: boolean) {
    open = next;
    query = "";
    active = -1;
    if (next) {
      void loadTunnelDevices();
      queueMicrotask(() => search?.focus());
    }
  }

  function onKey(e: KeyboardEvent) {
    const n = offered.length;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (n === 0) return;
      if (e.key === "ArrowDown") active = (active + 1) % n;
      else active = active <= 0 ? n - 1 : active - 1;
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (active >= 0 && active < n) toggle(offered[active].id);
      else if (n === 0) addTyped();
      else if (query.trim() !== "") toggle(offered[0].id);
    } else if (e.key === "Escape") {
      e.preventDefault();
      show(false);
      addButton?.focus();
    } else if (e.key === "Tab") {
      show(false);
    }
  }

  function outside(e: PointerEvent) {
    if (open && root && !root.contains(e.target as Node)) show(false);
  }
</script>

<svelte:window onpointerdown={outside} />

<div class="tags {changed}" class:invalid role="group" aria-label={ariaLabel} bind:this={root}>
  {#each values as value, i (i)}
    <span class="tag" title={value}>
      {titleOf(value)}
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
  <button
    type="button"
    class="add"
    aria-expanded={open}
    bind:this={addButton}
    onclick={() => show(!open)}
  >
    {t("Add")}
    <span class="chevron" class:open><SelectOpen size={14} /></span>
  </button>
  {#if open}
    <div class="panel">
      <input
        bind:this={search}
        bind:value={query}
        role="combobox"
        autocomplete="off"
        placeholder={t("Search interface")}
        aria-label={t("Search interface")}
        aria-expanded="true"
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={active >= 0 && active < offered.length
          ? `${listId}-${active}`
          : undefined}
        oninput={() => (active = -1)}
        onkeydown={onKey}
      />
      {#if query.trim() === "" && offered.length > 0}
        <div class="section">{t("Segments")}</div>
      {:else if offered.length === 0}
        <div class="empty">
          {query.trim() === ""
            ? t("Type an interface name to search")
            : t("Enter adds it as typed")}
        </div>
      {/if}
      <ul id={listId} role="listbox" aria-label={ariaLabel} aria-multiselectable="true">
        {#each offered as item, i (item.id)}
          {@const label = ifaceTitle(item)}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <li
            id={`${listId}-${i}`}
            role="option"
            aria-selected={values.includes(item.id)}
            class:active={i === active}
            onpointerdown={(e) => e.preventDefault()}
            onclick={() => toggle(item.id)}
          >
            <span class="dot"></span>
            <span class="title">{label.title}</span>
            {#if label.sub}<span class="sub">{label.sub}</span>{/if}
            <span class="check"
              >{#if values.includes(item.id)}<Check size={14} />{/if}</span
            >
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</div>

<style>
  .tags {
    position: relative;
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
  .remove {
    display: inline-flex;
    padding: 0;
    border: 0;
    background: transparent;
    color: var(--text-2);
    cursor: pointer;
  }
  .add {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 4px 8px;
    border-radius: 8px;
    border: 1px solid var(--bg-light-extra);
    background: transparent;
    color: var(--text);
    font: inherit;
    cursor: pointer;
  }
  .chevron {
    display: flex;
    color: var(--text-2);
    transition: transform 0.16s ease;
  }
  .chevron.open {
    transform: rotate(180deg);
  }
  .panel {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    z-index: 30;
    box-sizing: border-box;
    width: min(20rem, calc(100vw - 2rem));
    padding: 0.3rem;
    background: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
  }
  input {
    box-sizing: border-box;
    width: 100%;
    padding: 5px 8px;
    border-radius: 6px;
    border: 1px solid var(--bg-light);
    background: var(--bg-light);
    color: var(--text);
    font: inherit;
  }
  input:focus {
    outline: none;
    border-color: var(--accent);
  }
  .section {
    margin: 0.4rem 0.3rem 0.1rem;
    color: var(--text-2);
    font-size: 0.7rem;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  .empty {
    margin: 0.4rem 0.3rem 0.2rem;
    color: var(--text-2);
    font-size: 0.8rem;
  }
  ul {
    max-height: 16rem;
    overflow-y: auto;
    margin: 0.2rem 0 0;
    padding: 0;
    list-style: none;
  }
  li {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    min-width: 0;
    padding: 0.3rem 0.4rem;
    border-radius: 0.25rem;
    white-space: nowrap;
    cursor: pointer;
  }
  li:hover,
  li.active {
    background: var(--bg-light-extra);
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex: none;
    background: #666;
  }
  .title {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .sub {
    color: var(--text-2);
    font-family: var(--font-mono);
    font-size: 0.8em;
  }
  .check {
    display: flex;
    margin-left: auto;
    color: var(--text-2);
  }
</style>
