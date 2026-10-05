<script lang="ts">
  import CircleCheck from "@lucide/svelte/icons/circle-check";
  import CircleDashed from "@lucide/svelte/icons/circle-dashed";
  import CircleHelp from "@lucide/svelte/icons/circle-question-mark";
  import CircleX from "@lucide/svelte/icons/circle-x";
  import PowerOff from "@lucide/svelte/icons/power-off";
  import RefreshCw from "@lucide/svelte/icons/refresh-cw";
  import Unplug from "@lucide/svelte/icons/unplug";
  import { getContext, tick } from "svelte";

  import { t } from "../../../data/locale.svelte";
  import { GROUPS_STORE_CONTEXT, type GroupsStore } from "../groups.svelte";

  import { type Group } from "../../../types";
  import { checkedText, LIVE_LOOK, liveKind, liveTooltip, type LiveIcon } from "../live-state";

  let { group }: { group: Group } = $props();

  const store = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);

  const ICONS: Record<LiveIcon, typeof CircleCheck> = {
    CircleCheck,
    CircleX,
    Unplug,
    RefreshCw,
    PowerOff,
    CircleDashed,
    CircleHelp,
  };

  /* The footer's age counts on while the tooltip is open, poll or not. */
  let now = $state(Date.now());

  let kind = $derived(
    liveKind(group, store.groupDirty(group), store.liveOf(group.id), store.noAnswer),
  );
  let look = $derived(kind ? LIVE_LOOK[kind] : null);
  let tip = $derived(
    kind
      ? liveTooltip(
          kind,
          {
            iface: group.interface,
            netfilter: store.netfilter,
            silentFor: now - store.checkedAt,
          },
          t,
          clockTime,
        )
      : null,
  );

  /* The router's clock, read in the browser's zone: `since` is Unix time. */
  function clockTime(unix: number) {
    const d = new Date(unix * 1000);
    return [d.getHours(), d.getMinutes(), d.getSeconds()]
      .map((n) => String(n).padStart(2, "0"))
      .join(":");
  }

  const popoverId = `live-tip-${Math.random().toString(36).slice(2, 10)}`;
  let anchor = $state<HTMLButtonElement>();
  let popover = $state<HTMLDivElement>();
  let open = $state(false);
  let x = $state(0);
  let y = $state(0);
  let placed = $state(false);

  $effect(() => {
    if (!open) return;
    now = Date.now();
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });

  async function show() {
    if (!tip) return;
    open = true;
    placed = false;
    await tick();
    place();
  }

  function place() {
    if (!anchor || !popover) return;
    const a = anchor.getBoundingClientRect();
    const p = popover.getBoundingClientRect();
    const PAD = 8;
    let top = a.bottom + 6;
    if (top + p.height > globalThis.innerHeight - PAD && a.top - p.height - 6 > PAD) {
      top = a.top - p.height - 6;
    }
    x = Math.max(PAD, Math.min(a.left, globalThis.innerWidth - p.width - PAD));
    y = top;
    placed = true;
  }

  $effect(() => {
    if (!open || !tip) return;
    void tick().then(place);
  });

  $effect(() => {
    if (!kind) hide();
  });

  function hide() {
    open = false;
    openedByFocus = false;
  }

  function onPointerEnter(event: PointerEvent) {
    if (event.pointerType === "mouse") void show();
  }

  function onPointerLeave(event: PointerEvent) {
    if (event.pointerType === "mouse") hide();
  }

  let openedByFocus = false;

  function onFocus() {
    if (open) return;
    openedByFocus = true;
    void show();
  }

  /* A mouse has hover for that: its click neither opens nor closes. */
  let pressedWith = "";

  function onClick() {
    const via = pressedWith;
    pressedWith = "";
    if (via === "mouse") return;
    if (openedByFocus) {
      openedByFocus = false;
      return;
    }
    if (open) hide();
    else void show();
  }

  function onDocumentKeydown(event: KeyboardEvent) {
    if (open && event.key === "Escape") {
      event.preventDefault();
      hide();
    }
  }

  function onDocumentPointerDown(event: PointerEvent) {
    if (!open || !anchor) return;
    if (!anchor.contains(event.target as Node)) hide();
  }
</script>

<svelte:window onscroll={hide} onresize={hide} />
<svelte:document onpointerdown={onDocumentPointerDown} onkeydown={onDocumentKeydown} />

{#if look && tip}
  {@const Icon = ICONS[look.icon]}
  <button
    bind:this={anchor}
    type="button"
    class="live-status"
    data-kind={kind}
    style:--live-color={look.color}
    aria-label={tip.title}
    aria-describedby={open ? popoverId : undefined}
    onpointerenter={onPointerEnter}
    onpointerleave={onPointerLeave}
    onfocus={onFocus}
    onblur={hide}
    onpointerdown={(event) => (pressedWith = event.pointerType)}
    onclick={onClick}
  >
    <Icon size={18} aria-hidden="true" />
  </button>
  {#if open}
    <div
      bind:this={popover}
      id={popoverId}
      role="tooltip"
      class="live-tip"
      style:left="{x}px"
      style:top="{y}px"
      style:visibility={placed ? "visible" : "hidden"}
    >
      <div class="live-tip-title">{tip.title}</div>
      {#each tip.lines as line}
        <p class="live-tip-line">{line}</p>
      {/each}
      {#if tip.error}
        <p class="live-tip-line">{t("Error:")} <code class="live-tip-error">{tip.error}</code></p>
      {/if}
      {#if tip.footer && store.checkedAt > 0}
        <p class="live-tip-footer">{checkedText(store.checkedAt, now, t)}</p>
      {/if}
    </div>
  {/if}
{:else}
  <span class="live-status live-status--none" aria-hidden="true"></span>
{/if}

<style>
  .live-status {
    flex: 0 0 auto;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: color-mix(in oklab, var(--live-color) 20%, transparent);
    color: var(--live-color);
    cursor: default;
  }

  .live-status:focus-visible {
    outline: 1px solid var(--accent);
    outline-offset: 2px;
  }

  .live-status--none {
    background: none;
  }

  .live-tip {
    position: fixed;
    z-index: 15;
    width: max-content;
    max-width: min(24rem, calc(100vw - 16px));
    box-sizing: border-box;
    padding: 0.6rem 0.8rem;
    border-radius: 0.5rem;
    background-color: var(--bg-light-extra);
    border: 1px solid var(--border-light);
    box-shadow: var(--shadow-popover);
    color: var(--text-2);
    font-size: 0.8rem;
    line-height: 1.45;
    pointer-events: none;
  }

  .live-tip-title {
    margin-bottom: 0.3rem;
    color: var(--text);
    font-weight: 600;
    font-size: 0.85rem;
  }

  .live-tip-line {
    margin: 0 0 0.3rem;
  }

  .live-tip-error {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--orange);
    word-break: break-word;
  }

  .live-tip-footer {
    margin: 0.5rem 0 0;
    font-size: 0.72rem;
    opacity: 0.8;
  }
</style>
