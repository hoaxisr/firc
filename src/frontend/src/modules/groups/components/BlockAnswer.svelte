<script lang="ts">
  import { Popover, RadioGroup } from "bits-ui";

  import { t } from "../../../data/locale.svelte";

  import { SelectOpen } from "../../../components/ui/icons";
  import { BLOCK_ANSWERS, type BlockAnswer } from "../../../types";
  import { blockCode } from "../resolve-choice";

  let {
    value,
    onchange,
  }: {
    value: BlockAnswer;
    onchange: (v: BlockAnswer) => void;
  } = $props();

  const title = $derived(t("What to answer for the group's names"));
  const choices = $derived([
    {
      value: "null" as const,
      label: "0.0.0.0 / ::",
      hint: t("a stand-in address: no connection starts, no retries"),
      warn: false,
    },
    { value: "nxdomain" as const, label: "NXDOMAIN", hint: t("“no such name”"), warn: false },
    {
      value: "refused" as const,
      label: "REFUSED",
      hint: t("Android and browsers with their own DoH may ask another DNS and get through"),
      warn: true,
    },
  ]);

  function pick(next: string) {
    const answer = BLOCK_ANSWERS.find((a) => a === next);
    if (answer && answer !== value) onchange(answer);
  }
</script>

<Popover.Root>
  <Popover.Trigger class="block-answer" aria-label="{title}: {blockCode(value)}">
    <span class="block-answer-code">{blockCode(value)}</span>
    <SelectOpen size={12} />
  </Popover.Trigger>
  <Popover.Portal>
    <Popover.Content
      class="block-answer-editor"
      side="bottom"
      align="end"
      sideOffset={6}
      collisionPadding={8}
    >
      <div class="block-answer-title">{title}</div>
      <RadioGroup.Root
        class="block-answer-choices"
        orientation="vertical"
        aria-label={title}
        {value}
        onValueChange={pick}
      >
        {#each choices as choice (choice.value)}
          <RadioGroup.Item class="block-answer-choice" value={choice.value}>
            {#snippet children({ checked })}
              <span class="block-answer-dot" class:on={checked}></span>
              <span class="block-answer-text">
                <span class="block-answer-label">{choice.label}</span>
                <span class="block-answer-hint" class:warn={choice.warn}>{choice.hint}</span>
              </span>
            {/snippet}
          </RadioGroup.Item>
        {/each}
      </RadioGroup.Root>
    </Popover.Content>
  </Popover.Portal>
</Popover.Root>

<style>
  :global(.block-answer) {
    display: inline-flex;
    align-items: center;
    gap: 0.15rem;
    padding: 0 0.1rem;
    border: none;
    border-bottom: 1px dashed var(--text-2);
    border-radius: 0;
    background: transparent;
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 0.72rem;
    line-height: 1.3;
    cursor: pointer;
  }

  :global(.block-answer:hover),
  :global(.block-answer:focus-visible),
  :global(.block-answer[data-state="open"]) {
    border-bottom-color: var(--text);
  }

  :global(.block-answer:focus-visible) {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  :global(.block-answer svg) {
    color: var(--text-2);
  }

  :global(.block-answer-editor) {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    width: 19rem;
    max-width: calc(100vw - 1rem);
    box-sizing: border-box;
    padding: 0.5rem 0.75rem;
    background-color: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
    color: var(--text);
    z-index: 30;
    outline: none;
  }

  .block-answer-title {
    color: var(--text-2);
    font-size: 0.75rem;
  }

  :global(.block-answer-choices) {
    display: flex;
    flex-direction: column;
  }

  :global(.block-answer-choice) {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.3rem 0.2rem;
    border: none;
    border-radius: 0.3rem;
    background: transparent;
    color: var(--text);
    font-family: var(--font);
    font-size: 0.9rem;
    text-align: left;
    cursor: pointer;
  }

  :global(.block-answer-choice:hover),
  :global(.block-answer-choice:focus-visible) {
    background: var(--bg-light);
    outline: none;
  }

  .block-answer-dot {
    flex: none;
    width: 12px;
    height: 12px;
    margin-top: 3px;
    box-sizing: border-box;
    border-radius: 50%;
    border: 2px solid var(--text-2);
  }

  .block-answer-dot.on {
    border-color: var(--accent);
    background: radial-gradient(var(--accent) 45%, transparent 50%);
  }

  .block-answer-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .block-answer-hint {
    color: var(--text-2);
    font-size: 0.76rem;
    line-height: 1.3;
  }

  .block-answer-hint.warn {
    color: var(--orange);
  }
</style>
