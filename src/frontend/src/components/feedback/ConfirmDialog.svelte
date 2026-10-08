<script lang="ts">
  import { AlertDialog } from "bits-ui";

  import { t } from "../../data/locale.svelte";
  import { answer, confirmation } from "../../utils/confirm.svelte";

  import { Delete, RotateCcw } from "../ui/icons";

  const question = $derived(confirmation.current);
  let cancel = $state<HTMLElement | null>(null);
</script>

<AlertDialog.Root
  open={question !== null}
  onOpenChange={(open) => {
    if (!open) answer(false);
  }}
>
  <AlertDialog.Portal>
    <AlertDialog.Overlay class="confirm-overlay" />
    <AlertDialog.Content
      class="confirm {question?.tone ?? 'danger'}"
      onOpenAutoFocus={(e) => {
        e.preventDefault();
        cancel?.focus();
      }}
    >
      {#if question}
        <div class="top">
          <span class="ico">
            {#if question.tone === "danger"}<Delete size={20} />{:else}<RotateCcw size={20} />{/if}
          </span>
          <div class="text">
            <AlertDialog.Title class="confirm-title">{question.title}</AlertDialog.Title>
            <AlertDialog.Description class="confirm-message">
              {question.message}
            </AlertDialog.Description>
            {#if question.items?.length}
              <ul class="items">
                {#each question.items as item, i (i)}<li>{item}</li>{/each}
              </ul>
            {/if}
          </div>
        </div>
        <div class="btns">
          <AlertDialog.Cancel bind:ref={cancel} class="confirm-cancel"
            >{t("Cancel")}</AlertDialog.Cancel
          >
          <AlertDialog.Action class="confirm-action" onclick={() => answer(true)}>
            {question.confirm}
          </AlertDialog.Action>
        </div>
      {/if}
    </AlertDialog.Content>
  </AlertDialog.Portal>
</AlertDialog.Root>

<style>
  :global(.confirm-overlay) {
    position: fixed;
    inset: 0;
    z-index: 50;
    background: #000a;
  }

  :global(.confirm) {
    position: fixed;
    left: 50%;
    top: 50%;
    transform: translate(-50%, -50%);
    z-index: 51;
    width: min(26rem, calc(100vw - 2rem));
    box-sizing: border-box;
    padding: 1.25rem 1.25rem 1rem;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 12px;
    box-shadow: 0 20px 60px #000c;
    color: var(--text);
    font-family: var(--font);
  }

  .top {
    display: flex;
    gap: 0.9rem;
    align-items: flex-start;
  }

  .ico {
    flex: 0 0 2.5rem;
    height: 2.5rem;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  :global(.confirm.danger) .ico {
    background: color-mix(in oklab, var(--red) 18%, transparent);
    color: var(--red);
  }

  :global(.confirm.warn) .ico {
    background: color-mix(in oklab, var(--orange) 18%, transparent);
    color: var(--orange);
  }

  .text {
    min-width: 0;
    overflow-wrap: anywhere;
  }

  :global(.confirm-title) {
    margin: 0.1rem 0 0.4rem;
    font-size: 1.15rem;
    font-weight: 600;
  }

  :global(.confirm-message) {
    margin: 0;
    color: var(--text-2);
    font-size: 0.92rem;
    line-height: 1.4;
  }

  .items {
    margin: 0.5rem 0 0;
    padding-left: 1.1rem;
    max-height: 12rem;
    overflow-y: auto;
    font-size: 0.9rem;
    line-height: 1.5;
  }

  .btns {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1.25rem;
  }

  :global(.confirm-cancel),
  :global(.confirm-action) {
    box-sizing: border-box;
    height: 2.6rem;
    min-width: 7rem;
    font: 400 1rem var(--font);
    border-radius: 0.5rem;
    padding: 0 1rem;
    cursor: pointer;
    color: var(--text);
  }

  :global(.confirm-cancel) {
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
  }

  :global(.confirm-cancel:hover) {
    background: var(--bg-light-extra);
  }

  :global(.confirm-action) {
    font-weight: 600;
  }

  :global(.confirm.danger .confirm-action) {
    background: color-mix(in oklab, var(--red) 85%, #000);
    border: 1px solid var(--red);
    color: #fff;
  }

  :global(.confirm.warn .confirm-action) {
    background: color-mix(in oklab, var(--accent) 22%, var(--bg-light));
    border: 1px solid color-mix(in oklab, var(--accent) 55%, transparent);
  }

  :global(.confirm-cancel:focus-visible),
  :global(.confirm-action:focus-visible) {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 2px color-mix(in oklab, var(--accent) 45%, transparent);
  }

  @media (max-width: 700px) {
    :global(.confirm) {
      top: auto;
      bottom: 0;
      transform: translateX(-50%);
      width: 100vw;
      border-radius: 14px 14px 0 0;
      padding-bottom: calc(1rem + env(safe-area-inset-bottom));
    }

    .btns {
      flex-direction: column-reverse;
    }

    :global(.confirm-cancel),
    :global(.confirm-action) {
      width: 100%;
    }
  }
</style>
