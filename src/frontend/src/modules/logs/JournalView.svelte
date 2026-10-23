<script lang="ts">
  import { onDestroy, onMount, untrack } from "svelte";

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
  import { fetchHosts, hosts } from "../../data/hosts.svelte";
  import { journalFocus } from "../../data/journal-focus.svelte";
  import { ensureKnownGroups, knownGroups } from "../../data/known-groups.svelte";
  import { locale, t } from "../../data/locale.svelte";

  import { Capture, CaptureStop, Clear, Pause, Play, Search } from "../../components/ui/icons";
  import { counted } from "../../utils/plural";
  import {
    blockedPart,
    DEFAULT_LEVELS,
    describeBypassTail,
    describeDnsTail,
    deviceNames,
    groupFilterOptions,
    LEVELS,
    matches,
    matchesQuery,
    sourceCounts,
    SOURCES,
    type Source,
  } from "./journal";

  let { onRenderComplete }: { onRenderComplete?: () => void } = $props();

  const POLL_MS = 2000;
  const SOURCE_COLOR: Record<Source, string> = {
    fircd: "var(--src-fircd)",
    tunnels: "var(--src-tun)",
    dns: "var(--src-dns)",
    bypass: "var(--src-bypass)",
  };

  let frozen = $state.raw<JournalEvent[] | null>(null);
  let frozenSeq = 0;
  let frozenBoot = "";
  const paused = $derived(frozen !== null);
  let levels = $state<Set<LogLevel>>(new Set(DEFAULT_LEVELS));
  let sources = $state<Set<Source>>(new Set(SOURCES));
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

  const filter = $derived({ sources, levels, group });
  const names = $derived(deviceNames(hosts.list));
  const counts = $derived(sourceCounts(frozen ?? journal.events));
  const shown = $derived(
    journal.events.filter((e) => matches(e, filter) && matchesQuery(e, query, names)),
  );
  const rendered = $derived(
    frozen ? frozen.filter((e) => matches(e, filter) && matchesQuery(e, query, names)) : shown,
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

  function toggled<T>(set: Set<T>, v: T): Set<T> {
    const next = new Set(set);
    if (next.has(v)) next.delete(v);
    else next.add(v);
    return next;
  }

  let toolbarWidth = $state(0);

  function sourceLabel(s: Source): string {
    if (s === "tunnels") return t("Tunnels");
    if (s === "bypass") return t("Leaks");
    if (s === "dns") return "DNS";
    return toolbarWidth > 0 && toolbarWidth <= 600 ? t("core") : t("firc core");
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

  function dnsTail(e: DnsEvent): [string, string] {
    const tail = describeDnsTail(e, t);
    const red = blockedPart(e, t);
    if (!red || !tail.endsWith(red)) return [tail, ""];
    return [tail.slice(0, tail.length - red.length), red];
  }

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
    void fetchHosts();
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

  let seenFocus = untrack(() => journalFocus.request?.seq ?? 0);
  $effect(() => {
    const request = journalFocus.request;
    if (!request || request.seq <= seenFocus) return;
    seenFocus = request.seq;
    untrack(() => {
      group = request.group;
      if (!sources.has("dns")) sources = new Set([...sources, "dns"]);
    });
  });

  $effect(() => {
    void rendered;
    scrollToBottom();
  });
</script>

{#snippet dnsTailOf([before, red]: [string, string])}
  <span class="tail"
    >{before}{#if red}<span class="blocked">{red}</span>{/if}</span
  >
{/snippet}

<div class="tb" bind:clientWidth={toolbarWidth}>
  <div class="toolbar">
    <div class="seg sources" role="group" aria-label={t("Sources")}>
      {#each SOURCES as s (s)}
        <button
          type="button"
          style:--c={SOURCE_COLOR[s]}
          aria-pressed={sources.has(s)}
          onclick={() => (sources = toggled(sources, s))}
        >
          <span class="dot" aria-hidden="true"></span>{sourceLabel(s)}<span class="ct"
            >{counts[s]}</span
          >
        </button>
      {/each}
    </div>
    <div class="seg levels" role="group" aria-label={t("Levels")}>
      {#each LEVELS as l (l)}
        <button
          type="button"
          style:--c={`var(--lv-${l})`}
          aria-pressed={levels.has(l)}
          onclick={() => (levels = toggled(levels, l))}
        >
          <span class="bar" aria-hidden="true"></span>{l}
        </button>
      {/each}
    </div>
    <label class="field search">
      <Search size={18} aria-hidden="true" />
      <input
        type="search"
        bind:value={query}
        placeholder={t("client, name or tunnel")}
        aria-label={t("client, name or tunnel")}
      />
    </label>
    <div class="right">
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
            <span class="cdot" aria-hidden="true"></span>{captureClock}
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
      <p class="empty">{t("Nothing matches the filters.")}</p>
    {/if}
    {#each rendered as e (e.seq)}
      {#if e.kind === "log"}
        <div class="row l-{e.level}">
          <span class="at">{stamp(e.at)}</span>
          {#if e.source === "fircd"}
            <span class="chip" style:--c={SOURCE_COLOR.fircd}>{t("firc core")}</span>
          {:else}
            <button
              type="button"
              class="chip mono"
              style:--c={SOURCE_COLOR.tunnels}
              title={t("Show only this tunnel")}
              onclick={() => (query = e.source)}
            >
              {e.source}
            </button>
          {/if}
          <span class="msg">{e.message}</span>
        </div>
      {:else if e.kind === "dns"}
        <div class="row {decisionClass(e)}">
          <span class="at">{stamp(e.at)}</span>
          <span class="chip" style:--c={SOURCE_COLOR.dns}>DNS</span>
          <span class="msg">
            <button type="button" class="pick who" onclick={() => (query = e.client)}>
              {#if names.get(e.client.toLowerCase())}
                <span class="dev">{names.get(e.client.toLowerCase())}</span>
                <span class="addr">{e.client}</span>
              {:else}
                {e.client}
              {/if}
            </button>
            <button type="button" class="pick name" onclick={() => (query = e.name)}>
              {e.name}
            </button>
            {@render dnsTailOf(dnsTail(e))}
          </span>
        </div>
      {:else}
        <div class="row bypass">
          <span class="at">{stamp(e.at)}</span>
          <span class="chip" style:--c={SOURCE_COLOR.bypass}>{t("Leaks")}</span>
          <span
            class="msg"
            title={e.how === "addr" ? t("the last name firc recorded for this address") : undefined}
          >
            <button type="button" class="pick who" onclick={() => (query = e.client)}>
              {#if names.get(e.client.toLowerCase())}
                <span class="dev">{names.get(e.client.toLowerCase())}</span>
                <span class="addr">{e.client}</span>
              {:else}
                {e.client}
              {/if}
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
  .tb {
    container-type: inline-size;
    margin-bottom: 0.5rem;
  }
  .toolbar {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 0.5rem;
    align-items: stretch;
  }
  .right {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    justify-content: space-between;
    min-width: 0;
  }
  .seg {
    display: inline-flex;
    flex: 0 0 auto;
    box-sizing: border-box;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    padding: 0.2rem;
    gap: 0.2rem;
  }
  .seg.sources {
    display: flex;
  }
  .seg.sources button {
    flex: 1;
  }
  .seg button {
    all: unset;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.4rem;
    padding: 0.42rem 0.7rem 0.38rem;
    border-radius: 0.35rem;
    color: var(--text-2);
    font-size: 0.92rem;
    white-space: nowrap;
  }
  .seg button[aria-pressed="false"] {
    color: color-mix(in srgb, var(--text-2) 75%, transparent);
  }
  .seg button:hover {
    color: var(--text);
  }
  .seg button[aria-pressed="true"] {
    background: color-mix(in srgb, var(--c) 16%, var(--bg-light-extra));
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--c) 55%, transparent);
    color: var(--text);
  }
  .seg .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    background: var(--c);
    opacity: 0.35;
  }
  .seg .bar {
    width: 3px;
    height: 0.8rem;
    border-radius: 2px;
    background: var(--c);
    opacity: 0.35;
  }
  .seg button[aria-pressed="true"] .dot,
  .seg button[aria-pressed="true"] .bar {
    opacity: 1;
  }
  .seg .ct {
    font-family: var(--font-mono);
    font-size: 0.74rem;
    color: var(--text-2);
    font-variant-numeric: tabular-nums;
  }
  .seg.levels {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
  .seg.levels button {
    font-size: 0.76rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    padding-inline: 0.6rem;
  }
  .seg button:focus-visible,
  .pick:focus-visible,
  .chip:focus-visible,
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
    min-width: 0;
    cursor: text;
  }
  .field.search input {
    all: unset;
    flex: 1;
    min-width: 0;
    color: var(--text);
    font-size: 0.92rem;
  }
  .field.sel {
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
  .cdot {
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
  @container (max-width: 600px) {
    .toolbar {
      grid-template-columns: minmax(0, 1fr);
      gap: 0.45rem;
    }
    .seg,
    .seg.sources {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      width: 100%;
    }
    .seg button {
      padding-inline: 0.25rem;
      font-size: 0.84rem;
      gap: 0.3rem;
    }
    .seg .dot {
      display: none;
    }
    .seg.sources button[aria-pressed="true"] {
      color: var(--c);
    }
    .seg.levels button {
      font-size: 0.72rem;
      padding-inline: 0.2rem;
    }
    .field.grow {
      flex: 1 1 auto;
    }
    .actions {
      gap: 0.2rem;
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
    container-type: inline-size;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.6rem;
    overflow: hidden;
  }
  .pane {
    height: calc(100vh - 16rem);
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
    position: relative;
    display: grid;
    grid-template-columns: 4.6rem 6.4rem 1fr;
    gap: 0.6rem;
    align-items: baseline;
    padding: 0.25rem 0.8rem 0.2rem 1rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .row::before {
    content: "";
    position: absolute;
    left: 0;
    top: 3px;
    bottom: 3px;
    width: 3px;
    border-radius: 0 2px 2px 0;
    background: var(--stripe, transparent);
  }
  .row:hover {
    background: var(--bg-dark);
  }
  .row.l-debug {
    --stripe: var(--lv-debug);
  }
  .row.l-info {
    --stripe: var(--lv-info);
  }
  .row.l-warn {
    --stripe: var(--lv-warn);
  }
  .row.l-error {
    --stripe: var(--lv-error);
    background: color-mix(in srgb, var(--lv-error) 5%, transparent);
  }
  .at {
    white-space: nowrap;
    color: var(--text-2);
    opacity: 0.75;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    font-variant-numeric: tabular-nums;
  }
  .chip {
    all: unset;
    justify-self: start;
    font-size: 0.74rem;
    font-weight: 600;
    line-height: 1;
    padding: 0.25rem 0.45rem 0.2rem;
    border-radius: 0.35rem;
    white-space: nowrap;
    color: var(--c);
    background: color-mix(in srgb, var(--c) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--c) 20%, transparent);
  }
  .chip.mono {
    font-family: var(--font-mono);
  }
  button.chip {
    cursor: pointer;
  }
  .msg {
    color: var(--text);
  }
  .row.l-debug .msg {
    color: var(--text-2);
  }
  .row.l-warn .msg {
    color: var(--lv-warn);
  }
  .row.l-error .msg {
    color: var(--lv-error);
  }
  .row.dns.no-match .msg,
  .row.dns.passed .msg {
    color: var(--text-2);
  }
  .row.dns.not-covered .tail,
  .row.dns.pool-refused .tail {
    color: var(--orange);
  }
  .tail .blocked {
    color: var(--red);
    font-weight: 600;
  }
  .pick {
    all: unset;
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 0.82rem;
  }
  .pick.who .dev {
    font-family: var(--font);
    font-size: 0.86rem;
    font-weight: 500;
  }
  .pick.who .addr {
    margin-left: 0.3em;
    font-size: 0.74rem;
    color: var(--text-2);
  }
  .pick.name {
    font-weight: 600;
    font-family: inherit;
    font-size: inherit;
  }
  .pick:hover {
    text-decoration: underline;
  }
  @container (max-width: 560px) {
    .row {
      grid-template-columns: auto 1fr;
      row-gap: 3px;
      column-gap: 8px;
      padding: 0.35rem 0.6rem 0.3rem 0.8rem;
    }
    .row .msg {
      grid-column: 1 / -1;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .cdot {
      animation: none;
    }
  }
</style>
