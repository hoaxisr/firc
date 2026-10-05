<script lang="ts">
  import { setContext, type Snippet } from "svelte";

  import { hide, show } from "../../lib/tooltip/tooltip.svelte";

  import { TOOLTIP_LABEL } from "./tooltip-label";

  let { value, children }: { value: string; children: Snippet } = $props();
  let triggerEl: HTMLElement;

  let shown = $state(false);

  setContext(TOOLTIP_LABEL, () => value);

  function open() {
    shown = true;
    show(triggerEl, value);
  }

  function close() {
    shown = false;
    hide();
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  bind:this={triggerEl}
  data-value={value}
  style:display="inline-flex"
  aria-describedby={shown ? "global-tooltip" : undefined}
  onpointerenter={open}
  onpointerleave={close}
  onfocusin={open}
  onfocusout={close}
>
  {@render children()}
</div>
