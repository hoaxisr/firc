<script lang="ts">
  import { Popover } from "bits-ui";
  import { onDestroy, onMount, untrack } from "svelte";

  import Button from "../../components/ui/Button.svelte";
  import Select from "../../components/ui/Select.svelte";
  import Tooltip from "../../components/ui/Tooltip.svelte";
  import { capture, pollCapture, startCapture, stopCapture } from "../../data/capture.svelte";
  import { dnsStats } from "../../data/dnsstats.svelte";
  import {
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
  import CaptureTab from "./CaptureTab.svelte";
  import StatsTab from "./StatsTab.svelte";

  import { Clear, Filter, Pause, Play, Search } from "../../components/ui/icons";
  import { counted } from "../../utils/plural";
  import type { JournalView } from "../../utils/tab-path";
  import {
    blockedPart,
    compactCount,
    DEFAULT_LEVELS,
    describeBypassTail,
    describeDnsTail,
    deviceNames,
    filtersHiding,
    groupFilterOptions,
    LEVELS,
    matches,
    matchesQuery,
    sourceCounts,
    SOURCES,
    type Source,
  } from "./journal";

  let {
    onRenderComplete,
    active = false,
    view = $bindable<JournalView>("events"),
  }: { onRenderComplete?: () => void; active?: boolean; view?: JournalView } = $props();

  const POLL_MS = 2000;
  const VIEWS: JournalView[] = ["events", "stats", "capture"];
  const SOURCE_COLOR: Record<Source, string> = {
    fircd: "var(--src-fircd)",
    tunnels: "var(--src-tun)",
    dns: "var(--src-dns)",
  };
  const uid = $props.id();

  let frozen = $state.raw<JournalEvent[] | null>(null);
  let frozenSeq = 0;
  let frozenBoot = "";
  const paused = $derived(frozen !== null);
  let levels = $state<Set<LogLevel>>(new Set(DEFAULT_LEVELS));
  let sources = $state<Set<Source>>(new Set(SOURCES));
  let query = $state("");
  let group = $state("");
  let cleared = $state<{ boot: string; seq: number; dropped: number } | null>(null);
  let timer: ReturnType<typeof setInterval> | undefined;
  let captureTimer: ReturnType<typeof setTimeout> | undefined;
  let pane = $state<HTMLDivElement | undefined>(undefined);
  let toolbarWidth = $state(0);
  const narrow = $derived(toolbarWidth > 0 && toolbarWidth <= 640);

  const groupOptions = $derived(
    groupFilterOptions(knownGroups.loaded ? knownGroups.list : null, journal.seenGroups, t),
  );

  const captureClock = $derived.by(() => {
    const m = Math.floor(capture.secondsLeft / 60);
    const s = capture.secondsLeft % 60;
    return `${m}:${String(s).padStart(2, "0")}`;
  });

  const filter = $derived({ sources, levels, group });
  const hiding = $derived(filtersHiding(filter));
  const names = $derived(deviceNames(hosts.list));
  const sinceClear = $derived(cleared !== null && cleared.boot === journal.boot ? cleared : null);
  const held = $derived(
    sinceClear ? journal.events.filter((e) => e.seq > sinceClear.seq) : journal.events,
  );
  const lost = $derived(journal.dropped - (sinceClear?.dropped ?? 0));
  const counts = $derived(sourceCounts(frozen ?? held));
  const shown = $derived(held.filter((e) => matches(e, filter) && matchesQuery(e, query, names)));
  const rendered = $derived(
    frozen ? frozen.filter((e) => matches(e, filter) && matchesQuery(e, query, names)) : shown,
  );
  const newCount = $derived(
    frozen ? shown.filter((e) => journal.boot !== frozenBoot || e.seq > frozenSeq).length : 0,
  );

  function viewLabel(v: JournalView): string {
    if (v === "events") return t("Events");
    if (v === "capture") return t("Capture");
    return narrow ? t("Stats") : t("DNS stats");
  }

  function pause() {
    frozen = held;
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

  function showAll() {
    sources = new Set(SOURCES);
    levels = new Set(LEVELS);
    group = "";
  }

  function sourceLabel(s: Source): string {
    if (s === "tunnels") return t("Tunnels");
    if (s === "dns") return "DNS";
    return t("firc core");
  }

  function clearView() {
    cleared = {
      boot: journal.boot,
      seq: journal.events.at(-1)?.seq ?? 0,
      dropped: journal.dropped,
    };
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
    onRenderComplete?.();
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
    if (captureTimer) clearTimeout(captureTimer);
  });

  $effect(() => {
    if (!pane) return;
    const observer = new ResizeObserver(scrollToBottom);
    observer.observe(pane);
    return () => observer.disconnect();
  });

  let seenFocus = untrack(() => journalFocus.request?.seq ?? 0);
  $effect(() => {
    const request = journalFocus.request;
    if (!request || request.seq <= seenFocus) return;
    seenFocus = request.seq;
    untrack(() => {
      view = "events";
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

{#snippet who(client: string)}
  <button type="button" class="pick who" onclick={() => (query = client)}>
    {#if names.get(client.toLowerCase())}
      <span class="dev">{names.get(client.toLowerCase())}</span>
      <span class="addr">{client}</span>
    {:else}
      {client}
    {/if}
  </button>
{/snippet}

{#snippet eventRow(e: JournalEvent)}
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
        {@render who(e.client)}
        <button type="button" class="pick name" onclick={() => (query = e.name)}>
          {e.name}
        </button>
        {@render dnsTailOf(dnsTail(e))}
      </span>
    </div>
  {:else}
    <div class="row bypass">
      <span class="at">{stamp(e.at)}</span>
      <span
        class="msg"
        title={e.how === "addr" ? t("the last name firc recorded for this address") : undefined}
      >
        <span class="who">
          {#if names.get(e.client.toLowerCase())}
            <span class="dev">{names.get(e.client.toLowerCase())}</span>
            <span class="addr">{e.client}</span>
          {:else}
            {e.client}
          {/if}
        </span>
        <span class="name">{e.name}</span>
        <span class="tail">{describeBypassTail(e, t, stamp)}</span>
      </span>
    </div>
  {/if}
{/snippet}

<div class="tb" bind:clientWidth={toolbarWidth}>
  <div class="subtabs" role="tablist" aria-label={t("Journal")}>
    {#each VIEWS as v (v)}
      <button
        type="button"
        role="tab"
        id="{uid}-{v}"
        aria-selected={view === v}
        aria-controls="{uid}-panel"
        onclick={() => (view = v)}
        >{viewLabel(v)}{#if v === "events" && !narrow}<span class="mct" aria-hidden="true"
            >{rendered.length}</span
          >{:else if v === "stats" && !narrow && dnsStats.data}<span class="mct" aria-hidden="true"
            >{dnsStats.data.domains}</span
          >{:else if v === "capture" && capture.running}<span class="tab-clock" aria-hidden="true"
            ><span class="cdot"></span>{captureClock}</span
          >{:else if v === "capture" && capture.last && !narrow}<span class="mct" aria-hidden="true"
            >{capture.last.leaks}</span
          >{/if}</button
      >
    {/each}
  </div>
  {#if view === "events"}
    <div class="jh-row">
      <label class="field search">
        <Search size={18} aria-hidden="true" />
        <input
          type="search"
          bind:value={query}
          placeholder={t("client, name or tunnel")}
          aria-label={t("client, name or tunnel")}
        />
      </label>
      <Popover.Root>
        <Popover.Trigger
          class="jh-filter"
          aria-label={hiding > 0
            ? `${t("Filter")}, ${t("{n} active").replace("{n}", String(hiding))}`
            : t("Filter")}
        >
          <Filter size={18} aria-hidden="true" />
          <span class="jh-filter-label" aria-hidden="true">{t("Filter")}</span>
          {#if hiding > 0}<span class="jh-badge" aria-hidden="true">{hiding}</span>{/if}
        </Popover.Trigger>
        <Popover.Portal>
          <Popover.Content
            class="jh-panel"
            side="bottom"
            align="end"
            sideOffset={6}
            collisionPadding={8}
          >
            <div class="fp-sec">
              <div class="fp-title" id="{uid}-sources">{t("Sources")}</div>
              <div class="seg fp-sources" class:narrow role="group" aria-labelledby="{uid}-sources">
                {#each SOURCES as s (s)}
                  <button
                    type="button"
                    style:--c={SOURCE_COLOR[s]}
                    aria-pressed={sources.has(s)}
                    onclick={() => (sources = toggled(sources, s))}
                  >
                    <span class="dot" aria-hidden="true"></span>{sourceLabel(s)}<span class="ct"
                      >{compactCount(counts[s], locale.current)}</span
                    >
                  </button>
                {/each}
              </div>
            </div>
            <div class="fp-sec">
              <div class="fp-title" id="{uid}-levels">{t("Log levels")}</div>
              <div class="seg levels" role="group" aria-labelledby="{uid}-levels">
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
            </div>
            <div class="fp-sec">
              <div class="fp-title">{t("Group")}</div>
              <div class="field sel fp-sel">
                <Select
                  options={groupOptions}
                  selected={group}
                  onValueChange={(v) => (group = v)}
                  ariaLabel={t("Group")}
                />
              </div>
            </div>
            <div class="fp-foot">
              <button type="button" class="fp-reset" disabled={hiding === 0} onclick={showAll}
                >{t("Show all")}</button
              >
            </div>
          </Popover.Content>
        </Popover.Portal>
      </Popover.Root>
      <div class="jh-tools">
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
  {/if}
</div>

<div id="{uid}-panel" role="tabpanel" aria-labelledby="{uid}-{view}">
  {#if view === "events"}
    {#if (paused && newCount > 0) || journal.failed || lost > 0}
      <div class="status">
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
        {#if journal.failed}
          <span class="err">{t("The daemon did not answer for the log.")}</span>
        {/if}
        {#if lost > 0}
          <span>{t("Events were lost before this page asked for them:")} {lost}</span>
        {/if}
      </div>
    {/if}
    <div class="card">
      <div class="pane" bind:this={pane}>
        {#if rendered.length === 0}
          <p class="empty">{t("Nothing matches the filters.")}</p>
        {/if}
        {#each rendered as e (e.seq)}
          {@render eventRow(e)}
        {/each}
      </div>
    </div>
  {:else if view === "capture"}
    <CaptureTab
      clock={captureClock}
      {stamp}
      row={eventRow}
      onStart={() => void onCaptureStart()}
      onStop={() => void onCaptureStop()}
    />
  {:else}
    <StatsTab active={active && view === "stats"} />
  {/if}
</div>

<style>
  .tb {
    container-type: inline-size;
    margin-bottom: 0.5rem;
  }
  .subtabs {
    display: flex;
    gap: 1.4rem;
    margin-bottom: 0.6rem;
    border-bottom: 1px solid var(--bg-light-extra);
  }
  .subtabs button[role="tab"] {
    all: unset;
    cursor: pointer;
    display: inline-flex;
    align-items: baseline;
    gap: 0.45rem;
    padding: 0.3rem 0.1rem 0.55rem;
    margin-bottom: -1px;
    border-bottom: 2px solid transparent;
    color: var(--text-2);
    font-size: 1.05rem;
    font-weight: 600;
    white-space: nowrap;
  }
  .subtabs button[role="tab"]:hover,
  .subtabs button[aria-selected="true"] {
    color: var(--text);
  }
  .subtabs button[aria-selected="true"] {
    border-bottom-color: var(--accent);
  }
  .mct {
    font-family: var(--font-mono);
    font-size: 0.72rem;
    font-weight: 400;
    color: var(--text-2);
    font-variant-numeric: tabular-nums;
  }
  .jh-row {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }
  .jh-row > .field.search {
    flex: 0 1 30rem;
  }
  .jh-tools {
    display: inline-flex;
    flex: 0 0 auto;
    align-items: center;
    gap: 0.4rem;
    margin-left: auto;
  }
  .jh-tools :global(button.on) {
    color: var(--accent);
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
  :global(.jh-filter) {
    display: inline-flex;
    flex: 0 0 auto;
    align-items: center;
    gap: 0.4rem;
    height: 2.75rem;
    box-sizing: border-box;
    padding: 0 0.75rem;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    color: var(--text-2);
    font: 400 0.92rem var(--font);
    cursor: pointer;
    white-space: nowrap;
  }
  :global(.jh-filter:hover),
  :global(.jh-filter[data-state="open"]) {
    background: var(--bg-light-extra);
    color: var(--text);
  }
  :global(.jh-filter:focus-visible) {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .jh-badge {
    min-width: 1.15rem;
    height: 1.15rem;
    box-sizing: border-box;
    padding: 0 0.3rem;
    border-radius: 0.6rem;
    background: var(--accent);
    color: var(--bg-dark);
    font-size: 0.72rem;
    font-weight: 700;
    line-height: 1.2rem;
    text-align: center;
  }
  :global(.jh-panel) {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    width: 22rem;
    max-width: calc(100vw - 1rem);
    box-sizing: border-box;
    padding: 0.75rem;
    background-color: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
    color: var(--text);
    z-index: 30;
    outline: none;
  }
  .fp-sec {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }
  .fp-title {
    color: var(--text-2);
    font-size: 0.75rem;
  }
  .fp-sel {
    width: 100%;
  }
  .fp-sel :global(.select-wrap),
  .fp-sel :global([data-select-trigger]) {
    width: 100%;
    max-width: 100%;
  }
  .fp-foot {
    display: flex;
    justify-content: flex-end;
    border-top: 1px solid var(--bg-light-extra);
    padding-top: 0.55rem;
  }
  .fp-reset {
    all: unset;
    cursor: pointer;
    color: var(--accent);
    font-size: 0.85rem;
  }
  .fp-reset:disabled {
    cursor: default;
    color: var(--text-2);
    opacity: 0.6;
  }
  .seg {
    display: grid;
    box-sizing: border-box;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    padding: 0.2rem;
    gap: 0.2rem;
  }
  .seg.fp-sources {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .seg.levels {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
  .seg button {
    all: unset;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.3rem;
    padding: 0.42rem 0.45rem 0.38rem;
    border-radius: 0.35rem;
    color: var(--text-2);
    font-size: 0.92rem;
    white-space: nowrap;
  }
  .seg.fp-sources button {
    justify-content: flex-start;
  }
  .seg.fp-sources.narrow button {
    gap: 0.25rem;
    padding-inline: 0.35rem;
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
    flex: 0 0 auto;
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
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: 0.74rem;
    color: var(--text-2);
    font-variant-numeric: tabular-nums;
  }
  .seg.levels button {
    font-size: 0.76rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    padding-inline: 0.4rem;
  }
  .seg button:focus-visible,
  .subtabs button:focus-visible,
  .fp-reset:focus-visible,
  .pick:focus-visible,
  .chip:focus-visible,
  .new-events:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .tab-clock {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    align-self: center;
    color: var(--red);
    font-family: var(--font-mono);
    font-size: 0.8rem;
    font-weight: 400;
    font-variant-numeric: tabular-nums;
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
  @container (max-width: 640px) {
    .jh-row {
      gap: 0.4rem;
    }
    .jh-row > .field.search {
      flex: 1 1 0;
      min-width: 5rem;
    }
    .jh-filter-label {
      display: none;
    }
    :global(.jh-filter) {
      padding: 0 0.65rem;
    }
    .jh-tools {
      gap: 0.3rem;
    }
    .subtabs {
      gap: 1rem;
    }
    .subtabs button[role="tab"] {
      font-size: 0.98rem;
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
  .row.bypass {
    grid-template-columns: 4.6rem 1fr;
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
  }
  .who {
    font-family: var(--font-mono);
    font-size: 0.82rem;
  }
  .who .dev {
    font-family: var(--font);
    font-size: 0.86rem;
    font-weight: 500;
  }
  .who .addr {
    margin-left: 0.3em;
    font-size: 0.74rem;
    color: var(--text-2);
  }
  .name {
    font-weight: 600;
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
