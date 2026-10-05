<script lang="ts">
  import { onDestroy, onMount } from "svelte";

  import Button from "../../components/ui/Button.svelte";
  import Select from "../../components/ui/Select.svelte";
  import Tooltip from "../../components/ui/Tooltip.svelte";
  import {
    capture,
    isOurs,
    pollCapture,
    startCapture,
    stopCapture,
  } from "../../data/capture.svelte";
  import {
    clearJournal,
    journal,
    pollEvents,
    type DnsEvent,
    type JournalEvent,
    type LogLevel,
  } from "../../data/events.svelte";
  import { ensureKnownGroups, knownGroups } from "../../data/known-groups.svelte";
  import { locale, t } from "../../data/locale.svelte";

  import { Capture, CaptureStop, Clear, Pause, Play, Search } from "../../components/ui/icons";
  import { counted } from "../../utils/plural";
  import {
    describeBypassTail,
    describeDnsTail,
    groupFilterOptions,
    matches,
    matchesQuery,
    type Kind,
  } from "./journal";

  let { onRenderComplete }: { onRenderComplete?: () => void } = $props();

  const POLL_MS = 2000;
  const LEVELS: LogLevel[] = ["trace", "debug", "info", "warn", "error", "fatal", "panic"];
  const LEVEL_OPTIONS = LEVELS.map((l) => ({ value: l, label: l }));

  let frozen = $state.raw<JournalEvent[] | null>(null);
  let frozenSeq = 0;
  let frozenBoot = "";
  const paused = $derived(frozen !== null);
  let minLevel = $state<LogLevel>("trace");
  let kinds = $state<Set<Kind>>(new Set(["log", "dns", "bypass"]));
  let query = $state("");
  let group = $state("");
  let timer: ReturnType<typeof setInterval> | undefined;
  let captureTimer: ReturnType<typeof setTimeout> | undefined;
  let pane = $state<HTMLDivElement | undefined>(undefined);
  let resizeObserver: ResizeObserver | undefined;

  const groupOptions = $derived(
    groupFilterOptions(knownGroups.loaded ? knownGroups.list : null, journal.seenGroups, t),
  );

  const captureClock = $derived.by(() => {
    const m = Math.floor(capture.secondsLeft / 60);
    const s = capture.secondsLeft % 60;
    return `${m}:${String(s).padStart(2, "0")}`;
  });

  const filter = $derived({ kinds, minLevel, group });
  const shown = $derived(
    journal.events.filter((e) => matches(e, filter) && matchesQuery(e, query)),
  );
  const rendered = $derived(
    frozen ? frozen.filter((e) => matches(e, filter) && matchesQuery(e, query)) : shown,
  );
  const eventsText = $derived(
    counted(
      rendered.length,
      locale.current,
      t("{n} event"),
      t("{n} events (2-4)"),
      t("{n} events"),
    ),
  );
  const newCount = $derived(
    frozen ? shown.filter((e) => journal.boot !== frozenBoot || e.seq > frozenSeq).length : 0,
  );

  function pause() {
    frozen = journal.events;
    frozenSeq = journal.events.at(-1)?.seq ?? 0;
    frozenBoot = journal.boot;
  }

  function resume() {
    frozen = null;
  }

  function toggleKind(k: Kind) {
    const next = new Set(kinds);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    kinds = next;
  }

  function clearView() {
    clearJournal();
    if (frozen) frozen = [];
  }

  const stamp = (at: number) => {
    const d = new Date(at * 1000);
    const p = (n: number) => String(n).padStart(2, "0");
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  };

  const decisionClass = (e: DnsEvent) => `dns ${e.decision}`;

  function scrollToBottom() {
    if (!paused && pane) pane.scrollTop = pane.scrollHeight;
  }

  function scheduleCaptureTick() {
    if (captureTimer) clearTimeout(captureTimer);
    captureTimer = setTimeout(() => void captureTick(), capture.running ? 2000 : 10000);
  }

  async function captureTick() {
    await pollCapture();
    scheduleCaptureTick();
  }

  async function onCaptureStart() {
    await startCapture();
    scheduleCaptureTick();
  }

  async function onCaptureStop() {
    await stopCapture();
    scheduleCaptureTick();
  }

  onMount(() => {
    void ensureKnownGroups();
    void pollEvents();
    timer = setInterval(() => void pollEvents(), POLL_MS);
    void captureTick();
    if (pane) {
      resizeObserver = new ResizeObserver(scrollToBottom);
      resizeObserver.observe(pane);
    }
    onRenderComplete?.();
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
    if (captureTimer) clearTimeout(captureTimer);
    resizeObserver?.disconnect();
  });

  $effect(() => {
    void rendered;
    scrollToBottom();
  });
</script>

<div class="toolbar">
  <div class="seg" role="group" aria-label={t("Kinds")}>
    <button
      type="button"
      class:on={kinds.has("log")}
      aria-pressed={kinds.has("log")}
      onclick={() => toggleKind("log")}
    >
      {t("System")}
    </button>
    <button
      type="button"
      class:on={kinds.has("dns")}
      aria-pressed={kinds.has("dns")}
      onclick={() => toggleKind("dns")}
    >
      DNS
    </button>
    <button
      type="button"
      class:on={kinds.has("bypass")}
      aria-pressed={kinds.has("bypass")}
      onclick={() => toggleKind("bypass")}
    >
      {t("Bypass")}
    </button>
  </div>
  <label class="field search">
    <Search size={18} aria-hidden="true" />
    <input
      type="search"
      bind:value={query}
      placeholder={t("client or name")}
      aria-label={t("client or name")}
    />
  </label>
  <div class="field sel">
    <Select
      options={LEVEL_OPTIONS}
      selected={minLevel}
      onValueChange={(v) => (minLevel = v as LogLevel)}
      ariaLabel={t("Minimum level")}
    />
  </div>
  <div class="field sel grow">
    <Select
      options={groupOptions}
      selected={group}
      onValueChange={(v) => (group = v)}
      ariaLabel={t("Group")}
    />
  </div>
  <div class="actions">
    {#if capture.running}
      <span class="capturing" role="timer" aria-label={`${t("Capturing")} ${captureClock}`}>
        <span class="dot" aria-hidden="true"></span>{captureClock}
      </span>
      {#if isOurs()}
        <Tooltip value={t("Stop")}>
          <Button disabled={capture.busy} onclick={() => void onCaptureStop()}>
            <CaptureStop size={20} />
          </Button>
        </Tooltip>
      {/if}
    {:else}
      <Tooltip value={t("Capture 5 min")}>
        <Button
          disabled={capture.busy || capture.unsupported !== ""}
          onclick={() => void onCaptureStart()}
        >
          <Capture size={20} />
        </Button>
      </Tooltip>
    {/if}
    {#if paused}
      <Tooltip value={t("Resume")}>
        <Button class="on" onclick={resume}><Play size={20} /></Button>
      </Tooltip>
    {:else}
      <Tooltip value={t("Pause")}>
        <Button onclick={pause}><Pause size={20} /></Button>
      </Tooltip>
    {/if}
    <Tooltip value={t("Clear view")}>
      <Button onclick={clearView}><Clear size={20} /></Button>
    </Tooltip>
  </div>
</div>

<div class="status">
  <span>{eventsText}</span>
  {#if paused && newCount > 0}
    <button type="button" class="new-events" onclick={resume}>
      {counted(
        newCount,
        locale.current,
        t("+{n} new event"),
        t("+{n} new events (2-4)"),
        t("+{n} new events"),
      )}
    </button>
  {/if}
  {#if capture.unsupported}
    <span class="err">{t("This router cannot capture:")} {capture.unsupported}</span>
  {:else if capture.error}
    <span class="err">{capture.error}</span>
  {:else if capture.failed}
    <span class="err">{t("The daemon did not answer about the capture.")}</span>
  {/if}
  {#if journal.failed}
    <span class="err">{t("The daemon did not answer for the log.")}</span>
  {/if}
  {#if journal.dropped > 0}
    <span>{t("Events were lost before this page asked for them:")} {journal.dropped}</span>
  {/if}
</div>

<div class="card">
  <div class="pane" bind:this={pane}>
    {#if rendered.length === 0}
      <p class="empty">{t("Nothing matches. The daemon is running at:")} {journal.daemonLevel}</p>
    {/if}
    {#each rendered as e (e.seq)}
      {#if e.kind === "log"}
        <div class="row {e.level}">
          <span class="at">{stamp(e.at)}</span>
          <span class="badge lvl-{e.level}">{e.level}</span>
          <span class="msg">{e.message}</span>
        </div>
      {:else if e.kind === "dns"}
        <div class="row {decisionClass(e)}">
          <span class="at">{stamp(e.at)}</span>
          <span class="badge dns">DNS</span>
          <span class="msg">
            <button type="button" class="pick" onclick={() => (query = e.client)}>
              {e.client}
            </button>
            <button type="button" class="pick name" onclick={() => (query = e.name)}>
              {e.name}
            </button>
            <span class="tail">{describeDnsTail(e, t)}</span>
          </span>
        </div>
      {:else}
        <div class="row bypass">
          <span class="at">{stamp(e.at)}</span>
          <span class="badge bypass">{t("Bypass")}</span>
          <span
            class="msg"
            title={e.how === "addr" ? t("the last name firc recorded for this address") : undefined}
          >
            <button type="button" class="pick" onclick={() => (query = e.client)}>
              {e.client}
            </button>
            <button type="button" class="pick name" onclick={() => (query = e.name)}>
              {e.name}
            </button>
            <span class="tail">{describeBypassTail(e, t, stamp)}</span>
          </span>
        </div>
      {/if}
    {/each}
  </div>
</div>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-bottom: 0.5rem;
  }
  .seg {
    display: inline-flex;
    flex: 0 0 auto;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    padding: 0.2rem;
    gap: 0.2rem;
  }
  .seg button {
    all: unset;
    cursor: pointer;
    padding: 0.45rem 0.8rem;
    border-radius: 0.35rem;
    color: var(--text-2);
    font-size: 0.95rem;
  }
  .seg button.on {
    background: var(--bg-light-extra);
    color: var(--text);
  }
  .seg button:hover {
    color: var(--text);
  }
  .seg button:focus-visible,
  .pick:focus-visible,
  .new-events:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .field {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    height: 2.75rem;
    box-sizing: border-box;
    padding: 0 0.6rem;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    color: var(--text-2);
  }
  .field.search {
    flex: 1 1 14rem;
    min-width: 10rem;
    cursor: text;
  }
  .field.search input {
    all: unset;
    flex: 1;
    min-width: 0;
    color: var(--text);
    font-size: 0.95rem;
  }
  .field.sel {
    flex: 0 0 auto;
    padding: 0 0.3rem;
  }
  .field.grow {
    flex: 0 1 auto;
    min-width: 7rem;
  }
  .field.grow :global(.select-wrap) {
    min-width: 0;
    max-width: 100%;
  }
  .actions {
    display: inline-flex;
    flex: 0 0 auto;
    align-items: center;
    gap: 0.5rem;
    margin-left: auto;
  }
  .actions :global(button.on) {
    color: var(--accent);
  }
  .capturing {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    color: var(--red);
    font-variant-numeric: tabular-nums;
  }
  .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    background: var(--red);
    animation: blink 1s infinite;
  }
  @keyframes blink {
    50% {
      opacity: 0.3;
    }
  }
  .status {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    align-items: center;
    margin: 0 0 0.5rem;
    font-size: 0.85rem;
    color: var(--text-2);
  }
  .status .err {
    color: var(--red);
  }
  .new-events {
    all: unset;
    cursor: pointer;
    color: var(--accent);
    font-variant-numeric: tabular-nums;
  }
  .card {
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.6rem;
    overflow: hidden;
  }
  .pane {
    height: calc(100vh - 13rem);
    min-height: 16rem;
    overflow: auto;
    padding: 0.3rem 0;
    font-size: 0.88rem;
  }
  .empty {
    margin: 1rem;
    color: var(--text-2);
  }
  .row {
    display: grid;
    grid-template-columns: 4.5rem 4.6rem 1fr;
    gap: 0.6rem;
    align-items: baseline;
    padding: 0.22rem 0.8rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .row:hover {
    background: var(--bg-dark);
  }
  .at {
    color: var(--text-2);
    opacity: 0.7;
    font-family: var(--font-mono);
    font-size: 0.8rem;
    font-variant-numeric: tabular-nums;
  }
  .badge {
    justify-self: start;
    font-size: 0.72rem;
    line-height: 1;
    padding: 0.22rem 0.45rem;
    border-radius: 0.35rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    white-space: nowrap;
    background: var(--bg-light-extra);
    color: var(--text-2);
  }
  .badge.dns,
  .badge.lvl-info {
    color: var(--blue-light);
    background: color-mix(in srgb, var(--blue-light) 15%, transparent);
  }
  .badge.lvl-warn,
  .badge.bypass {
    color: var(--orange);
    background: color-mix(in srgb, var(--orange) 15%, transparent);
  }
  .badge.lvl-error,
  .badge.lvl-fatal,
  .badge.lvl-panic {
    color: var(--red);
    background: color-mix(in srgb, var(--red) 15%, transparent);
  }
  .msg {
    color: var(--text);
  }
  .row.trace .msg,
  .row.debug .msg {
    color: var(--text-2);
  }
  .row.warn .msg {
    color: var(--orange);
  }
  .row.error .msg,
  .row.fatal .msg,
  .row.panic .msg {
    color: var(--red);
  }
  .row.dns.no-match .msg,
  .row.dns.passed .msg {
    color: var(--text-2);
  }
  .row.dns.not-covered .tail,
  .row.dns.pool-refused .tail {
    color: var(--orange);
  }
  .pick {
    all: unset;
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 0.82rem;
  }
  .pick.name {
    font-weight: 600;
    font-family: inherit;
    font-size: inherit;
  }
  .pick:hover {
    text-decoration: underline;
  }

  @media (max-width: 640px) {
    .field.search {
      flex-basis: 100%;
    }
    .actions {
      margin-left: 0;
    }
  }
</style>
