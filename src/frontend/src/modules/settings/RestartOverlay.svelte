<script lang="ts">
  import { tick } from "svelte";

  import Logo from "../../components/Logo.svelte";
  import Button from "../../components/ui/Button.svelte";
  import { t } from "../../data/locale.svelte";
  import { closeRestartOverlay, settings } from "./settings.svelte";

  const HINT_AFTER_S = 30;

  let now = $state(Date.now());
  let actions: HTMLElement | undefined = $state();
  let root: HTMLElement | undefined = $state();

  $effect(() => {
    if (!settings.restarting) return;
    now = Date.now();
    const timer = setInterval(() => (now = Date.now()), 500);
    return () => clearInterval(timer);
  });

  let failed = $derived(settings.restartFailure !== null);
  let elapsed = $derived(Math.max(0, Math.floor((now - settings.restartStartedAt) / 1000)));
  let phase = $derived(settings.restartPhase);

  let current = $derived(
    phase === "requested" || phase === "old-daemon" ? 1 : phase === "back" ? 0 : 2,
  );
  let filled = $derived(phase === "back" ? 3 : current - 1);

  let text = $derived(
    settings.restartFailure === "not-started"
      ? t("The restart did not start")
      : settings.restartFailure === "not-restarted"
        ? t("The daemon did not restart")
        : settings.restartFailure === "timeout"
          ? t("The daemon did not come back")
          : phase === "moving"
            ? t("Moving to the new port…")
            : phase === "back"
              ? t("Done")
              : current === 1
                ? t("Stopping the daemon…")
                : t("Waiting for it to start…"),
  );

  let slow = $derived(!failed && phase === "no-answer" && elapsed >= HINT_AFTER_S);

  const stateOf = (n: number) =>
    failed ? "failed" : n <= filled ? "done" : n === current ? "current" : "idle";

  const holdFocus = () => (actions?.querySelector("button") ?? root)?.focus();

  const trap = (event: KeyboardEvent) => {
    if (event.key !== "Tab") return;
    event.preventDefault();
    holdFocus();
  };

  $effect(() => {
    root?.focus();
  });

  $effect(() => {
    if (failed) void tick().then(() => actions?.querySelector("button")?.focus());
  });
</script>

<div
  class="overlay"
  data-testid="restart-overlay"
  data-failed={failed}
  role="dialog"
  aria-modal="true"
  aria-label={t("Restarting the daemon")}
  tabindex="-1"
  bind:this={root}
  onkeydown={trap}
>
  <div class="ring">
    <svg viewBox="0 0 120 120" aria-hidden="true">
      <circle class="track" cx="60" cy="60" r="54" />
      {#each [1, 2, 3] as n (n)}
        <circle
          class="seg s{n}"
          data-seg={n}
          data-state={stateOf(n)}
          cx="60"
          cy="60"
          r="54"
          pathLength="3"
          stroke-dasharray="0.96 3"
          stroke-dashoffset={1 - n}
        />
      {/each}
    </svg>
    <div class="logo"><Logo still /></div>
  </div>
  <div class="phase" role="status" aria-live="polite">{text}</div>
  {#if failed}
    <div bind:this={actions}>
      <Button onclick={closeRestartOverlay}>{t("Close")}</Button>
    </div>
  {:else}
    <div class="secs">{t("{n} s").replace("{n}", String(elapsed))}</div>
    {#if slow}
      <div class="hint">{t("Starting takes long — check the router's log")}</div>
    {/if}
  {/if}
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    z-index: 1000;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 12px;
    background: color-mix(in srgb, var(--bg-dark) 80%, transparent);
    backdrop-filter: blur(3px);
    animation: fade-in 0.2s ease-out;
  }
  .ring {
    position: relative;
    width: 120px;
    height: 120px;
  }
  svg {
    position: absolute;
    inset: 0;
    transform: rotate(-90deg);
  }
  circle {
    fill: none;
    stroke-width: 6;
  }
  .track {
    stroke: var(--bg-light-extra);
  }
  .seg {
    opacity: 0;
    transition: opacity 0.4s;
  }
  .s1 {
    stroke: #42bdf9;
  }
  .s2 {
    stroke: #3aa8fb;
  }
  .s3 {
    stroke: #3b8dff;
  }
  .seg[data-state="done"],
  .seg[data-state="current"] {
    opacity: 1;
  }
  .seg[data-state="done"] {
    transition: none;
  }
  .seg[data-state="current"] {
    animation: pulse 1s ease-in-out infinite;
  }
  .seg[data-state="failed"] {
    opacity: 1;
    stroke: var(--red);
  }
  .logo {
    position: absolute;
    inset: 22px;
  }
  .phase {
    font-weight: 600;
  }
  .secs,
  .hint {
    color: var(--text-2);
    font-size: 0.9rem;
  }
  @keyframes pulse {
    50% {
      opacity: 0.35;
    }
  }
  @keyframes fade-in {
    from {
      opacity: 0;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .overlay {
      animation: none;
    }
    .seg {
      transition: none;
    }
    .seg[data-state="current"] {
      animation: none;
    }
  }
</style>
