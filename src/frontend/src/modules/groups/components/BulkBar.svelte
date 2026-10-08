<script lang="ts">
  import { DropdownMenu } from "bits-ui";
  import { getContext } from "svelte";

  import { groupInterfaces } from "../../../data/interfaces.svelte";
  import { locale, t } from "../../../data/locale.svelte";
  import { GROUPS_STORE_CONTEXT, type GroupsStore } from "../groups.svelte";

  import {
    Check,
    Delete,
    Network,
    SelectOpen,
    ToggleLeft,
    ToggleRight,
    X,
  } from "../../../components/ui/icons";
  import { selectionCountText } from "../selection";

  type Props = {
    /* The bar's own height, for the page to keep its last card clear of it. */
    height?: number;
  };

  let { height = $bindable(0) }: Props = $props();

  let bar = $state<HTMLDivElement>();

  const store = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);
  if (!store) {
    throw new Error("GroupsStore context is missing");
  }

  let countText = $derived(selectionCountText(store.selection.length, locale.current, t));

  function handleKeydown(event: KeyboardEvent) {
    if (event.key !== "Escape" || event.defaultPrevented) return;
    /* Not while the Groups tab is hidden: the bar is not on screen. */
    if (!bar?.getClientRects().length) return;
    if (
      document.querySelector(
        "[data-dropdown-menu-content], [data-select-content], [data-popover-content], [data-dialog-content]",
      )
    ) {
      return;
    }
    const active = document.activeElement;
    if (
      active instanceof HTMLTextAreaElement ||
      (active instanceof HTMLElement && active.isContentEditable) ||
      (active instanceof HTMLInputElement &&
        !["checkbox", "radio", "button", "submit", "reset"].includes(active.type))
    ) {
      return;
    }
    store.clearSelection();
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<div
  bind:this={bar}
  class="bulk-bar"
  role="region"
  aria-label={t("Selected groups")}
  bind:offsetHeight={height}
>
  <div class="bulk-row bulk-selection">
    <strong class="bulk-count" role="status">{countText}</strong>
    <button type="button" class="bulk-button" onclick={() => store.selectAll()}>
      <Check size={18} />{t("Select all")}
    </button>
    <button type="button" class="bulk-button" onclick={() => store.clearSelection()}>
      <X size={18} />{t("Clear selection")}
    </button>
  </div>

  <span class="bulk-separator" aria-hidden="true"></span>

  <div class="bulk-row bulk-actions">
    <DropdownMenu.Root>
      <DropdownMenu.Trigger class="bulk-button">
        <Network size={18} /><span class="bulk-label">{t("Interface")}</span><SelectOpen
          size={16}
        />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          class="bulk-menu"
          side="top"
          align="start"
          sideOffset={8}
          collisionPadding={8}
        >
          {#each groupInterfaces() as item (item.id)}
            <DropdownMenu.Item
              class="bulk-menu-item"
              onSelect={() => store.setSelectedInterface(item.id)}
            >
              <span class="bulk-menu-label">{item.id}</span>
              {#if item.name}
                <span class="bulk-menu-description">{item.name}</span>
              {/if}
            </DropdownMenu.Item>
          {/each}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>

    <DropdownMenu.Root>
      <DropdownMenu.Trigger class="bulk-button">
        <ToggleLeft size={18} />
        <span class="bulk-label label-long">{t("Enable / disable")}</span>
        <span class="bulk-label label-short">{t("On/off")}</span>
        <SelectOpen size={16} />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          class="bulk-menu"
          side="top"
          align="start"
          sideOffset={8}
          collisionPadding={8}
        >
          <DropdownMenu.Item class="bulk-menu-item" onSelect={() => store.setSelectedEnable(true)}>
            <ToggleRight size={18} />
            <span class="bulk-menu-label">{t("Enable selected")}</span>
          </DropdownMenu.Item>
          <DropdownMenu.Item class="bulk-menu-item" onSelect={() => store.setSelectedEnable(false)}>
            <ToggleLeft size={18} />
            <span class="bulk-menu-label">{t("Disable selected")}</span>
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>

    <button type="button" class="bulk-button" onclick={() => store.deleteSelected()}>
      <Delete size={18} /><span class="bulk-label">{t("Delete")}</span>
    </button>
  </div>
</div>

<style>
  .bulk-bar {
    position: fixed;
    left: 50%;
    bottom: calc(1.25rem + env(safe-area-inset-bottom));
    transform: translateX(-50%);
    z-index: 6;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    width: max-content;
    max-width: calc(100vw - 2rem);
    box-sizing: border-box;
    padding: 0.55rem 0.6rem;
    border: 1px solid color-mix(in oklab, var(--accent) 55%, transparent);
    border-radius: 14px;
    background: color-mix(in oklab, var(--accent) 7%, var(--bg-dark-extra));
    box-shadow:
      0 12px 40px #0006,
      0 0 0 4px color-mix(in oklab, var(--accent) 10%, transparent);
    color: var(--text);
  }

  .bulk-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    min-width: 0;
  }

  .bulk-count {
    padding: 0 0.6rem 0 0.5rem;
    font-weight: 600;
    white-space: nowrap;
  }

  .bulk-separator {
    align-self: stretch;
    width: 1px;
    margin: 0.3rem 0.4rem;
    background: var(--bg-light-extra);
  }

  .bulk-bar :global(.bulk-button) {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.45rem;
    height: 2.6rem;
    padding: 0 0.75rem;
    box-sizing: border-box;
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    background: var(--bg-light);
    color: var(--text-2);
    font: 400 1rem var(--font);
    white-space: nowrap;
    cursor: pointer;
    transition:
      background-color 0.1s ease-in-out,
      color 0.1s ease-in-out;
  }

  .bulk-bar :global(.bulk-button:hover),
  .bulk-bar :global(.bulk-button[data-state="open"]) {
    border-color: var(--bg-light-extra);
    background: var(--bg-light-extra);
    color: var(--text);
  }

  .bulk-bar :global(.bulk-button:focus-visible) {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .bulk-bar :global(.bulk-button svg) {
    flex: none;
  }

  .bulk-label {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .label-short {
    display: none;
  }

  :global(.bulk-menu[data-dropdown-menu-content]) {
    z-index: 11;
    min-width: 13rem;
    max-width: calc(100vw - 1rem);
    box-sizing: border-box;
    padding: 0.35rem;
    border-radius: 0.6rem;
  }

  :global(.bulk-menu-item[data-dropdown-menu-item]) {
    display: flex;
    align-items: center;
    justify-content: flex-start;
    gap: 0.5rem;
    padding: 0.55rem 0.6rem;
    border-radius: 0.4rem;
    color: var(--text-2);
    cursor: pointer;
    outline: none;
  }

  :global(.bulk-menu-item[data-dropdown-menu-item][data-highlighted]) {
    background: var(--bg-light-extra);
    color: var(--text);
  }

  :global(.bulk-menu-label) {
    white-space: nowrap;
  }

  :global(.bulk-menu-description) {
    margin-left: auto;
    padding-left: 1.5rem;
    font-size: 0.8rem;
    color: var(--text-2);
    white-space: nowrap;
  }

  @media (max-width: 960px) {
    .bulk-bar {
      flex-direction: column;
      align-items: stretch;
    }

    .bulk-separator {
      display: none;
    }

    .bulk-count {
      margin-right: auto;
    }
  }

  @media (max-width: 600px) {
    .bulk-bar {
      left: 0.5rem;
      right: 0.5rem;
      bottom: calc(0.5rem + env(safe-area-inset-bottom));
      transform: none;
      width: auto;
      max-width: none;
      padding: 0.5rem;
    }

    .bulk-actions {
      gap: 0.4rem;
    }

    .bulk-actions > :global(*) {
      flex: 1 1 auto;
    }

    .bulk-bar :global(.bulk-button) {
      min-width: 0;
      gap: 0.25rem;
      padding: 0 0.3rem;
      font-size: 0.875rem;
    }

    .bulk-bar :global(.bulk-button svg) {
      width: 16px;
      height: 16px;
    }

    .label-long {
      display: none;
    }

    .label-short {
      display: inline;
    }
  }
</style>
