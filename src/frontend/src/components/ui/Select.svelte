<script lang="ts">
  import { Select } from "bits-ui";
  import type { Snippet } from "svelte";

  import Tooltip from "./Tooltip.svelte";

  import { Check, Delete, SelectOpen } from "./icons";

  type Option = {
    value: string;
    label: string;
    description?: string;
    disabled?: boolean;
    hint?: string;
    ariaDescription?: string;
    mono?: boolean;
    tag?: string;
    danger?: boolean;
    warn?: boolean;
    subline?: string;
    separator?: boolean;
    hidden?: boolean;
    missing?: boolean;
    remove?: { label: string; run: () => void };
    toggle?: () => void;
    expanded?: boolean;
  };
  type Props = {
    options?: Option[];
    selected?: string;
    shown?: string;
    onValueChange?: (v: string) => void;
    onItemPointerUp?: (v: string) => void;
    ariaLabel?: string;
    disabled?: boolean;
    showSelectedDescription?: boolean;
    lead?: Snippet<[Option]>;
    closed?: Snippet;
    footer?: Snippet;
    onOpenChange?: (open: boolean) => void;
    sideOffset?: number;
    [key: string]: any;
  };

  let {
    options = [],
    selected = $bindable<string>(),
    shown,
    onValueChange,
    onItemPointerUp,
    ariaLabel = "Select",
    disabled = false,
    showSelectedDescription = true,
    lead,
    closed,
    footer,
    onOpenChange,
    sideOffset = 4,
    ...rest
  }: Props = $props();

  function onKeyCapture(e: KeyboardEvent) {
    if ((e.key === "Enter" || e.key === " ") && !e.shiftKey) {
      const trigger = (e.currentTarget as HTMLElement).querySelector("[data-select-trigger]");
      const id = trigger?.getAttribute("aria-activedescendant");
      const value = id ? document.getElementById(id)?.dataset.value : undefined;
      const option = options.find((o) => o.value === value && o.toggle);
      if (option?.toggle) {
        e.preventDefault();
        e.stopPropagation();
        option.toggle();
        return;
      }
    }
    rest.onkeydowncapture?.(e);
  }

  const shown_value = $derived(shown ?? selected);
  const selected_option = $derived(options.find((o) => o.value === shown_value));
  const selected_label = $derived(selected_option?.label ?? shown_value ?? "");
  const selected_description = $derived(
    showSelectedDescription ? (selected_option?.description ?? "") : "",
  );
  const shown_option = $derived(options.find((o) => o.value === shown_value));
  const missing_selection = $derived(
    Boolean(shown_value) && (shown_option === undefined || shown_option.missing === true),
  );
</script>

{#snippet text(option: Option)}
  <div class="option-text">
    <span
      class="option-label"
      class:danger={option.danger}
      class:warn={option.warn}
      class:gone={option.missing}>{option.label}</span
    >
    {#if option.description}
      <span class="option-description" class:mono={option.mono}>{option.description}</span>
    {/if}
    {#if option.tag}
      <span class="option-tag">{option.tag}</span>
    {/if}
  </div>
{/snippet}

{#snippet body(option: Option, selected: boolean)}
  <div class="option" class:wide={option.remove}>
    {#if lead}{@render lead(option)}{/if}
    {#if option.subline}
      <div class="option-stack">
        {@render text(option)}
        <span class="option-subline">{option.subline}</span>
      </div>
    {:else}
      {@render text(option)}
    {/if}
    <div class="option-check" class:open={option.expanded}>
      {#if option.toggle}<SelectOpen size={16} />{:else if selected}<Check size={16} />{/if}
    </div>
    {#if option.remove}
      <button
        type="button"
        class="option-remove"
        tabindex="-1"
        aria-hidden="true"
        title={option.remove.label}
        onpointerup={(e) => {
          e.preventDefault();
          e.stopPropagation();
        }}
        onclick={() => option.remove?.run()}><Delete size={16} /></button
      >
    {/if}
  </div>
{/snippet}

<div
  class="select-wrap"
  class:missing={missing_selection}
  class:disabled
  {...rest}
  onkeydowncapture={onKeyCapture}
>
  <Select.Root
    type="single"
    {onValueChange}
    {onOpenChange}
    items={options}
    bind:value={selected}
    {disabled}
  >
    <Select.Trigger aria-label={ariaLabel}>
      <div class="selected" class:has-description={selected_description}>
        <div class="selected-text">
          <div class="selected-value">
            {#if closed}{@render closed()}{:else}{selected_label}{/if}
          </div>
          {#if selected_description}
            <div
              class="selected-description"
              class:mono={selected_option?.mono}
              title={selected_description}
            >
              {selected_description}
            </div>
          {/if}
        </div>
        <div class="selected-open" aria-hidden="true">
          <SelectOpen size={16} />
        </div>
      </div>
    </Select.Trigger>

    <Select.Portal>
      <Select.Content align="start" {sideOffset} collisionPadding={8}>
        {#each options as option}
          {#if !option.hidden}
            <Select.Item
              value={option.value}
              label={option.label}
              disabled={option.disabled}
              class={option.separator ? "select-separated" : undefined}
              onpointerup={(e: PointerEvent) => {
                if (option.toggle) {
                  e.preventDefault();
                  option.toggle();
                  return;
                }
                onItemPointerUp?.(option.value);
              }}
              {...option.ariaDescription ? { "aria-description": option.ariaDescription } : {}}
              {...option.toggle ? { "aria-expanded": Boolean(option.expanded) } : {}}
            >
              {#snippet children({ selected })}
                {#if option.hint}
                  <Tooltip value={option.hint}>
                    {@render body(option, selected)}
                  </Tooltip>
                {:else}
                  {@render body(option, selected)}
                {/if}
              {/snippet}
            </Select.Item>
          {/if}
        {/each}
        {#if footer}{@render footer()}{/if}
      </Select.Content>
    </Select.Portal>
  </Select.Root>
</div>

<style>
  .option-label.gone {
    text-decoration: line-through;
    color: var(--text-2);
  }

  .option.wide {
    width: 100%;
  }

  .option-remove {
    margin-left: auto;
    display: flex;
    align-items: center;
    border: none;
    background: transparent;
    color: var(--text-2);
    cursor: pointer;
    padding: 0 0.25rem;
    border-radius: 0.3rem;
  }

  .option-remove:hover {
    color: var(--danger);
  }

  .select-wrap {
    display: inline-block;
    width: max-content;
    max-width: 90vw;
  }

  :global([data-select-root]) {
    width: max-content;
  }

  :global([data-select-trigger]) {
    display: inline-flex;
    align-items: center;
    justify-content: flex-start;
    text-align: left;
    background: transparent;
    border: none;
    border-radius: 0.5rem;
    padding: 0.2rem 0.3rem;
    font: 400 1rem var(--font);
    color: var(--text);
    width: max-content;
    height: fit-content;
    cursor: pointer;
  }
  :global([data-select-trigger]:hover) {
    background-color: var(--bg-dark);
    outline: 1px solid var(--bg-light-extra);
  }
  :global([data-select-trigger]:focus) {
    outline: none;
    background-color: var(--bg-light-extra);
  }

  :global([data-select-content]) {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
    padding: 0.2rem;
    background-color: var(--bg-dark-extra);
    border-radius: 0.5rem;
    border: 1px solid var(--bg-light-extra);
    box-shadow: var(--shadow-popover);
    max-height: min(20rem, var(--bits-select-content-available-height, 20rem));
    overflow-x: hidden;
    overflow-y: auto;
    width: max-content;
    min-width: 100%;
    max-width: calc(100vw - 1rem);
    z-index: 30;
  }

  :global([data-select-item]) {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.1rem;
    padding: 0 0.2rem;
    border-radius: 0.2rem;
    cursor: default;
    white-space: nowrap;
    min-width: 0;
  }
  :global([data-select-item]:hover) {
    background-color: var(--bg-light-extra);
  }
  :global([data-select-item][data-disabled]) {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .selected {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    width: max-content;
    max-width: 100%;
  }
  .selected-text {
    display: flex;
    min-width: 0;
    max-width: 100%;
    flex-direction: column;
    align-items: start;
    gap: 0.1rem;
  }
  .selected-value {
    flex: 0 1 auto;
    min-width: 0;
    max-width: 100%;
    padding-left: 0.3rem;
    line-height: 1.05;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .selected-description {
    max-width: 8rem;
    padding-left: 0.3rem;
    color: var(--text-2);
    font-size: 0.7em;
    line-height: 1.15;
    overflow-wrap: anywhere;
    display: -webkit-box;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    overflow: hidden;
  }
  .selected-open {
    width: 16px;
    height: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-2);
    transition: transform 0.16s ease;
  }

  .select-wrap.missing :global([data-select-trigger]) {
    color: var(--text-2);
  }

  .select-wrap.disabled {
    opacity: 0.55;
    pointer-events: none;
  }

  :global([data-select-trigger][aria-expanded="true"]) .selected-open,
  :global([data-select-trigger][data-state="open"]) .selected-open {
    transform: rotate(180deg);
  }

  .option {
    display: inline-flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.2rem;
    padding: 0.1rem;
    width: max-content;
    max-width: 100%;
    min-width: 0;
    white-space: nowrap;
  }
  .option-text {
    display: inline-flex;
    align-items: baseline;
    gap: 0.42rem;
    min-width: 0;
  }
  .option-label,
  .option-description {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .option-description {
    color: var(--text-2);
    font-size: 0.9em;
  }
  .mono {
    font-family: var(--font-mono);
    font-size: 0.8em;
  }
  .option-label.danger {
    color: var(--danger);
  }
  .option-label.warn {
    color: var(--orange);
  }
  .option-stack {
    display: flex;
    flex-direction: column;
    min-width: 0;
    padding: 0.1rem 0;
  }
  .option-subline {
    color: var(--text-2);
    font-size: 0.72rem;
    line-height: 1.25;
    white-space: normal;
  }
  .option-tag {
    color: var(--text-2);
    font-size: 0.75em;
    opacity: 0.8;
  }
  :global([data-select-item].select-separated) {
    margin-top: 0.2rem;
    padding-top: 0.2rem;
    border-top: 1px solid var(--bg-light-extra);
    border-radius: 0;
  }
  .option-check.open {
    transform: rotate(180deg);
  }
  .option-check {
    color: var(--text-2);
    width: 16px;
    height: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
</style>
