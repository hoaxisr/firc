<script lang="ts">
  import type { Snippet } from "svelte";

  import Button from "../../components/ui/Button.svelte";
  import { capture, CAPTURE_SECONDS, isOurs } from "../../data/capture.svelte";
  import { journal, type BypassEvent } from "../../data/events.svelte";
  import { t } from "../../data/locale.svelte";

  import { Capture, CaptureStop } from "../../components/ui/icons";

  let {
    clock,
    stamp,
    row,
    onStart,
    onStop,
  }: {
    clock: string;
    stamp: (at: number) => string;
    row: Snippet<[BypassEvent]>;
    onStart: () => void;
    onStop: () => void;
  } = $props();

  let pane = $state<HTMLDivElement | undefined>(undefined);

  const span = $derived.by(() => {
    if (capture.running) return { from: capture.endsAt - CAPTURE_SECONDS, to: Infinity };
    if (capture.last) return { from: capture.last.startedAt, to: capture.last.endedAt };
    return null;
  });
  const rows = $derived(
    span
      ? journal.events.filter(
          (e): e is BypassEvent => e.kind === "bypass" && e.at >= span.from && e.at <= span.to + 1,
        )
      : [],
  );
  const newest = $derived(rows.at(-1)?.seq ?? 0);
  const elapsed = $derived(Math.min(CAPTURE_SECONDS, CAPTURE_SECONDS - capture.secondsLeft));
  const startDisabled = $derived(capture.busy || capture.unsupported !== "");

  const hm = (at: number) => stamp(at).slice(0, 5);
  const spanText = $derived.by(() => {
    const last = capture.last;
    if (!last) return "";
    const found =
      last.leaks === 0 ? t("no leaks") : t("leaks: {n}").replace("{n}", String(last.leaks));
    return `${hm(last.startedAt)}–${hm(last.endedAt)} · ${found}`;
  });

  $effect(() => {
    void newest;
    if (capture.running && pane) pane.scrollTop = pane.scrollHeight;
  });
</script>

<div class="cap" class:idle={!capture.running && !capture.last}>
  {#if capture.running}
    <div class="cap-text">
      <div class="cap-title"><span class="cdot" aria-hidden="true"></span>{t("Capturing")}</div>
      <div class="cap-sub">
        {t("Every connection of a device past firc appears below as soon as the router sees it.")}
      </div>
      <div
        class="cap-prog"
        role="progressbar"
        aria-label={t("Capture progress")}
        aria-valuemin={0}
        aria-valuemax={CAPTURE_SECONDS}
        aria-valuenow={elapsed}
      >
        <span style:width="{(elapsed / CAPTURE_SECONDS) * 100}%"></span>
      </div>
    </div>
    <div class="cap-act">
      <span class="cap-clock" role="timer">{clock}</span>
      {#if isOurs()}
        <Button disabled={capture.busy} onclick={onStop}
          ><CaptureStop size={18} />{t("Stop")}</Button
        >
      {:else}
        <span class="cap-note">{t("Started elsewhere: only there can it be stopped.")}</span>
      {/if}
    </div>
  {:else if capture.last}
    <div class="cap-text">
      <div class="cap-title">{t("Capture finished")}</div>
      <div class="cap-sub">
        <span>{spanText}</span>
        {#if capture.last.ended === "stopped"}<span>· {t("stopped")}</span>{/if}
        {#if capture.last.ended === "failed"}<span
            >· <span class="err">{t("ended with an error")}</span></span
          >{/if}
      </div>
    </div>
    <div class="cap-act">
      <Button class="primary" disabled={startDisabled} onclick={onStart}
        ><Capture size={18} />{t("Start again")}</Button
      >
    </div>
  {:else}
    <Capture size={34} class="cap-icon" />
    <div class="cap-title">{t("Capture leaks for 5 minutes")}</div>
    <p class="cap-desc">
      {t(
        "For five minutes the router watches the traffic of LAN devices and shows the connections to your groups' domains that went past firc: the device asked another DNS, took an address from its own cache or DoH. Routing does not change, nothing is written to disk.",
      )}
    </p>
    <Button class="primary" disabled={startDisabled} onclick={onStart}
      ><Capture size={18} />{t("Start capture")}</Button
    >
  {/if}
  {#if capture.unsupported}
    <div class="cap-err">{t("This router cannot capture:")} {capture.unsupported}</div>
  {:else if capture.error}
    <div class="cap-err">{capture.error}</div>
  {:else if capture.failed}
    <div class="cap-err">{t("The daemon did not answer about the capture.")}</div>
  {/if}
  {#if journal.failed}
    <div class="cap-err">{t("The daemon did not answer for the log.")}</div>
  {/if}
</div>

{#if !capture.running && capture.last && capture.last.summary.length > 0}
  <div class="cap-sum">
    <div class="cap-sum-title">{t("The daemon's summary")}</div>
    {#each capture.last.summary as line, i (i)}<p>{line}</p>{/each}
  </div>
{/if}

{#if span}
  <div class="card">
    <div class="cap-pane" bind:this={pane}>
      {#if rows.length > 0}
        {#each rows as e (e.seq)}
          {@render row(e)}
        {/each}
      {:else if capture.running}
        <p class="empty">{t("No leaks yet. Open a site from a group on a device to check.")}</p>
      {:else if capture.last && capture.last.leaks > 0}
        <p class="empty">{t("The journal no longer holds this capture's rows.")}</p>
      {:else}
        <p class="empty">{t("This capture had no leaks.")}</p>
      {/if}
    </div>
  </div>
{/if}

<style>
  .cap {
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
    padding: 1rem 1.1rem;
    margin-bottom: 0.6rem;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.6rem;
  }
  .cap.idle {
    flex-direction: column;
    text-align: center;
    padding: 2.2rem 1.2rem;
    gap: 0.7rem;
  }
  .cap :global(.cap-icon) {
    color: var(--text-2);
  }
  .cap-text {
    flex: 1 1 18rem;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }
  .cap-title {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 1.05rem;
    font-weight: 600;
  }
  .cap-sub,
  .cap-desc {
    color: var(--text-2);
    font-size: 0.88rem;
    line-height: 1.4;
  }
  .cap-desc {
    max-width: 36rem;
    margin: 0 0 0.4rem;
  }
  .cap-sub .err {
    color: var(--red);
  }
  .cap-prog {
    height: 4px;
    margin-top: 0.4rem;
    border-radius: 2px;
    background: var(--bg-light-extra);
    overflow: hidden;
  }
  .cap-prog span {
    display: block;
    height: 100%;
    background: var(--red);
    transition: width 1s linear;
  }
  .cap-act {
    display: flex;
    align-items: center;
    gap: 0.9rem;
    flex: 0 1 auto;
    min-width: 0;
  }
  .cap-clock {
    font-family: var(--font-mono);
    font-size: 1.6rem;
    color: var(--red);
    font-variant-numeric: tabular-nums;
  }
  .cap-note {
    flex: 1 1 10rem;
    color: var(--text-2);
    font-size: 0.85rem;
  }
  .cap-err {
    flex-basis: 100%;
    color: var(--red);
    font-size: 0.85rem;
  }
  .cap-sum {
    margin-bottom: 0.6rem;
    padding: 0.7rem 1rem;
    border-left: 3px solid var(--lv-info);
    background: color-mix(in srgb, var(--lv-info) 7%, transparent);
    border-radius: 0 0.5rem 0.5rem 0;
  }
  .cap-sum-title {
    color: var(--text-2);
    font-size: 0.75rem;
  }
  .cap-sum p {
    margin: 0.25rem 0 0;
    font-size: 0.88rem;
  }
  .card {
    container-type: inline-size;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.6rem;
    overflow: hidden;
  }
  .cap-pane {
    max-height: max(12rem, calc(100vh - 22rem));
    overflow: auto;
    padding: 0.3rem 0;
    font-size: 0.88rem;
  }
  .empty {
    margin: 1rem;
    color: var(--text-2);
  }
  .cdot {
    width: 0.45rem;
    height: 0.45rem;
    border-radius: 50%;
    background: var(--red);
    animation: blink 1s infinite;
  }
  @keyframes blink {
    50% {
      opacity: 0.3;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .cdot {
      animation: none;
    }
  }
</style>
