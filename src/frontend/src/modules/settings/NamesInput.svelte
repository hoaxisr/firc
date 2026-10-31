<script lang="ts">
  import { parseNames } from "./settings";

  type Props = {
    values: string[];
    onchange: (values: string[]) => void;
    ariaLabel: string;
    placeholder?: string;
    invalid?: boolean;
    changed?: string;
  };
  let {
    values,
    onchange,
    ariaLabel,
    placeholder = "",
    invalid = false,
    changed = "",
  }: Props = $props();

  let text = $state("");
  let editing = $state(false);
  $effect(() => {
    if (!editing) text = values.join("\n");
  });
</script>

<textarea
  class={changed}
  class:invalid
  aria-label={ariaLabel}
  aria-invalid={invalid}
  {placeholder}
  rows={Math.min(8, Math.max(3, values.length + 1))}
  bind:value={text}
  onfocus={() => (editing = true)}
  onblur={() => {
    editing = false;
    onchange(parseNames(text));
  }}
></textarea>

<style>
  textarea {
    width: 100%;
    padding: 6px 10px;
    border-radius: 8px;
    background: var(--bg-light);
    border: 1px solid var(--bg-light);
    color: var(--text);
    font: inherit;
    font-family: var(--font-mono, monospace);
    font-size: 0.85rem;
    box-sizing: border-box;
    resize: vertical;
  }
  textarea.changed-live {
    background: var(--bg-dark);
    border-color: var(--accent);
  }
  textarea.invalid {
    border-color: var(--danger);
  }
</style>
