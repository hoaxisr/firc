<script lang="ts">
  import { Dialog } from "bits-ui";
  import { createEventDispatcher } from "svelte";

  import { Add } from "./icons";

  export let open = false;
  export let title = "";
  export let maxWidth = 300;
  export let contentClass = "";

  const dispatch = createEventDispatcher();

  function handleOpenChange(v: boolean) {
    if (!v) dispatch("close");
  }
</script>

<Dialog.Root {open} onOpenChange={handleOpenChange}>
  <Dialog.Overlay />
  <Dialog.Content
    class="dialog"
    escapeKeydownBehavior="close"
    onOpenAutoFocus={(e) => {
      e.preventDefault();
    }}
    style={`--generic-dialog-max-width: ${maxWidth}px`}
  >
    {#snippet child({ props })}
      <div {...props} class="modal {contentClass}">
        <Dialog.Title class="title">{title}</Dialog.Title>
        <Dialog.Close class="close">
          <Add size={22} style="transform:rotate(45deg)" />
        </Dialog.Close>
        <form on:submit|preventDefault={() => dispatch("submit")}>
          <div class="body">
            <slot name="body" />
          </div>

          <div class="actions">
            <slot name="actions" />
          </div>
        </form>
      </div>
    {/snippet}
  </Dialog.Content>
</Dialog.Root>

<style>
  :global([data-dialog-content] textarea) {
    width: 100%;
    font: inherit;
    padding: 0.75rem 1rem;
    border-radius: 0.5rem;
    border: 1.5px solid var(--bg-light-extra);
    background: var(--bg-light);
    color: var(--text);
    box-sizing: border-box;
    transition:
      border 0.15s,
      box-shadow 0.15s;
  }
  :global([data-dialog-content] textarea:focus) {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-light, #aaf2ff33);
  }
  :global([data-dialog-content] textarea.invalid) {
    border-color: var(--danger);
  }

  .actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 0.75rem;
    flex: 0 0 auto;
  }

  form {
    display: flex;
    flex-direction: column;
    flex: 1 1 auto;
    min-height: 0;
  }

  .body {
    width: 100%;
    margin-top: 1rem;
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    overflow-x: hidden;
    --thumb: color-mix(in srgb, var(--text-2) 40%, var(--bg-dark));
    --thumb-hover: color-mix(in srgb, var(--text-2) 65%, var(--bg-dark));
    scrollbar-gutter: stable;
    padding-right: 0.25rem;
  }

  @supports not selector(::-webkit-scrollbar) {
    .body {
      scrollbar-width: thin;
      scrollbar-color: var(--thumb) transparent;
    }
  }

  .body::-webkit-scrollbar {
    width: 0.5rem;
  }

  .body::-webkit-scrollbar-track {
    background: transparent;
  }

  .body::-webkit-scrollbar-thumb {
    background-color: var(--thumb);
    border-radius: 0.5rem;
  }

  .body::-webkit-scrollbar-thumb:hover {
    background-color: var(--thumb-hover);
  }

  .body::-webkit-scrollbar-button {
    display: none;
  }

  :global([data-dialog-overlay]) {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    background-color: rgba(0, 0, 0, 0.7);
    opacity: 0;
    transition: opacity 120ms ease;
    z-index: 15;
  }

  :global([data-dialog-overlay][data-state="open"]) {
    opacity: 1;
  }

  :global([data-dialog-content]) {
    position: fixed;
    left: 50%;
    top: 50%;
    transform: translate(-50%, -50%) scale(0.985);
    opacity: 0;
    width: 100%;
    max-width: min(var(--generic-dialog-max-width, 300px), calc(100vw - 5rem));
    max-height: calc(100dvh - 2rem);
    display: flex;
    flex-direction: column;
    box-sizing: border-box;
    background-color: var(--bg-dark);
    border-radius: 0.5rem;
    border: 1px solid var(--bg-light-extra);
    padding: 1rem;
    transition:
      opacity 120ms ease,
      transform 120ms ease;
    z-index: 16;
  }

  @media (max-width: 600px) {
    :global([data-dialog-content]) {
      max-width: calc(100vw - 2rem);
      padding: 0.75rem;
    }

    .body {
      padding-right: 0;
      scrollbar-gutter: auto;
    }
  }

  :global([data-dialog-content][data-state="open"]) {
    opacity: 1;
    transform: translate(-50%, -50%) scale(1);
  }

  :global([data-dialog-content][data-state="closed"]) {
    pointer-events: none;
  }

  :global([data-dialog-title]) {
    font-size: 1.3rem;
    font-weight: 600;
    font-family: var(--font);
    text-align: left;
    border-bottom: 1px solid var(--bg-light-extra);
    padding-bottom: 0.5rem;
    padding-right: 32px;
  }

  :global([data-dialog-description]) {
    font-size: 0.9rem;
    color: var(--text-2);
    margin-top: 0.5rem;
  }

  :global(.footer) {
    display: flex;
    justify-content: end;
    align-items: center;
    gap: 0.5rem;
    margin-top: 1rem;
  }

  .modal-close {
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
    border-radius: 50%;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.13);
    transition:
      box-shadow 0.15s,
      opacity 0.15s;
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-2);
    opacity: 0.55;
    position: static;
  }

  :global(button[data-dialog-close].close) {
    position: absolute;
    right: 0.5rem;
    top: 0.5rem;
    color: var(--text-2);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0.4rem;
    border-radius: 0.5rem;
    border: 1px solid transparent;
    background-color: transparent;
    cursor: pointer;
  }
  :global(button[data-dialog-close].close:hover) {
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.18);
    background: var(--bg-light-extra);
    opacity: 1;
  }

  :global(button[data-dialog-close].submit) {
    font-size: 1rem;
    font-weight: 400;
    font-family: var(--font);
    color: var(--text);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0.4rem;
    border-radius: 0.5rem;
    border: 1px solid var(--bg-light-extra);
    background-color: var(--bg-light);
    cursor: pointer;
  }
  :global(button[data-dialog-close].submit:hover) {
    background-color: var(--bg-light-extra);
    color: var(--text);
    border: 1px solid var(--bg-light-extra);
  }
</style>
