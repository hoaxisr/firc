<script lang="ts">
  import { Select } from "bits-ui";

  import { Check, SelectOpen } from "./icons";

  type Option = { value: string; label: string; description?: string };
  type Props = {
    options?: Option[];
    selected?: string;
    onValueChange?: (v: string) => void;
    ariaLabel?: string;
    disabled?: boolean;
    showSelectedDescription?: boolean;
    [key: string]: any;
  };

  let {
    options = [],
    selected = $bindable<string>(),
    onValueChange,
    ariaLabel = "Select",
    disabled = false,
    showSelectedDescription = true,
    ...rest
  }: Props = $props();

  const selected_option = $derived(options.find((o) => o.value === selected));
  const selected_label = $derived(selected_option?.label ?? selected ?? "");
  const selected_description = $derived(
    showSelectedDescription ? (selected_option?.description ?? "") : "",
  );
  const missing_selection = $derived(
    Boolean(selected) && !options.some((o) => o.value === selected),
  );
</script>

<div class="select-wrap" class:missing={missing_selection} class:disabled {...rest}>
  <Select.Root type="single" {onValueChange} items={options} bind:value={selected} {disabled}>
    <Select.Trigger aria-label={ariaLabel}>
      <div class="selected" class:has-description={selected_description}>
        <div class="selected-text">
          <div class="selected-value">{selected_label}</div>
          {#if selected_description}
            <div class="selected-description" title={selected_description}>
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
      <Select.Content align="start" sideOffset={4} collisionPadding={8}>
        {#each options as option}
          <Select.Item value={option.value} label={option.label}>
            {#snippet children({ selected })}
              <div class="option">
                <div class="option-text">
                  <span class="option-label">{option.label}</span>
                  {#if option.description}
                    <span class="option-description">{option.description}</span>
                  {/if}
                </div>
                <div class="option-check">
                  {#if selected}<Check size={16} />{/if}
                </div>
              </div>
            {/snippet}
          </Select.Item>
        {/each}
      </Select.Content>
    </Select.Portal>
  </Select.Root>
</div>

<style>
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
  .option-check {
    color: var(--text-2);
    width: 16px;
    height: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
</style>
