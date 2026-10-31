<script lang="ts">
  import { onDestroy } from "svelte";

  import Button from "../../components/ui/Button.svelte";
  import {
    autolist,
    PROBES_PER_HOUR,
    ruleOf,
    whyClass,
    whyLabel,
  } from "../../data/autolist.svelte";
  import { relativeTime, rowDevices, statsDevices } from "../../data/dnsstats.svelte";
  import { groupsBridge } from "../../data/groups-bridge.svelte";
  import { hosts } from "../../data/hosts.svelte";
  import { knownGroups } from "../../data/known-groups.svelte";
  import { locale, t } from "../../data/locale.svelte";
  import { tabRequest } from "../../data/tab-request.svelte";
  import { loadSettings, settings } from "../settings/settings.svelte";

  import { X } from "../../components/ui/icons";
  import type { AutolistCandidate, Group } from "../../types";
  import { toast } from "../../utils/events";
  import { fetcher } from "../../utils/fetcher";
  import { counted } from "../../utils/plural";
  import { deviceNames } from "./journal";

  let { active = false }: { active?: boolean } = $props();

  const CLOCK_MS = 30_000;

  let now = $state(Math.floor(Date.now() / 1000));
  let busy = $state<Set<string>>(new Set());

  const clock = setInterval(() => (now = Math.floor(Date.now() / 1000)), CLOCK_MS);
  onDestroy(() => clearInterval(clock));

  $effect(() => {
    if (!active) return;
    now = Math.floor(Date.now() / 1000);
    if (!settings.loaded) void loadSettings();
  });

  const data = $derived(autolist.data);
  const devices = $derived(statsDevices(hosts.list, []));
  const names = $derived(deviceNames(hosts.list));
  const groupName = $derived(knownGroups.list.find((g) => g.id === data?.group)?.name ?? "");
  const ttl = $derived(Number(settings.saved["app.dnsProxy.unmatchedTtl"] ?? 0));
  const recheck = $derived(settings.saved["app.autolist.recheck"] === true);
  const recheckEvery = $derived(Number(settings.saved["app.autolist.recheckInterval"] ?? 0));
  const candidates = $derived(data?.candidates ?? []);
  const stateColumn = $derived(
    data?.mode === "add" || candidates.some((c) => c.state === "added" || c.state === "off"),
  );

  function stamp(at: number): string {
    const d = new Date(at * 1000);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  }

  function every(seconds: number): string {
    if (seconds % 3600 === 0) return t("{n} h").replace("{n}", String(seconds / 3600));
    if (seconds % 60 === 0) return t("{n} min").replace("{n}", String(seconds / 60));
    return t("{n} s").replace("{n}", String(seconds));
  }

  function failures(n: number): string {
    return counted(n, locale.current, t("{n} failure"), t("{n} failures (2-4)"), t("{n} failures"));
  }

  function failuresDay(n: number): string {
    return counted(
      n,
      locale.current,
      t("{n} failure in 24 h"),
      t("{n} failures in 24 h (2-4)"),
      t("{n} failures in 24 h"),
    );
  }

  function stalled(n: number): string {
    return counted(
      n,
      locale.current,
      t("freeze suspected: {n} connection stalled"),
      t("freeze suspected: {n} connections stalled (2-4)"),
      t("freeze suspected: {n} connections stalled"),
    );
  }

  function bypassNote(n: number, device: string): string {
    return counted(
      n,
      locale.current,
      t(
        "Not counted: {n} failure at {device}: the device asks DNS around firc (DoH or its own DNS) — adding a domain will not help it.",
      ),
      t(
        "Not counted: {n} failures at {device}: the device asks DNS around firc (DoH or its own DNS) — adding a domain will not help it. (2-4)",
      ),
      t(
        "Not counted: {n} failures at {device}: the device asks DNS around firc (DoH or its own DNS) — adding a domain will not help it.",
      ),
    ).replace("{device}", device);
  }

  function devicesOf(c: AutolistCandidate) {
    return rowDevices(
      c.clients.map((address) => ({ address, queries: 1 })),
      devices,
    );
  }

  function deviceText(c: AutolistCandidate): string {
    return devicesOf(c)
      .map((d) => d.label)
      .join(" · ");
  }

  function metaText(c: AutolistCandidate): string {
    return [c.fails > 0 ? failures(c.fails) : "", deviceText(c)].filter(Boolean).join(" · ");
  }

  function addDetails(): string {
    if (!data) return "";
    const parts = [
      t("added in the last hour: {n} of {max}")
        .replace("{n}", String(data.addedHour))
        .replace("{max}", String(PROBES_PER_HOUR)),
      t("router check: {n} of {max} in the last hour")
        .replace("{n}", String(data.probes.usedHour))
        .replace("{max}", String(PROBES_PER_HOUR)),
    ];
    if (recheck && recheckEvery > 0) {
      const every_ = t("recheck every {every}").replace("{every}", every(recheckEvery));
      parts.push(
        data.checkedAt > 0
          ? `${every_}, ${t("last at {time}").replace("{time}", stamp(data.checkedAt))}`
          : every_,
      );
    }
    if (data.ambiguousDay > 0) parts.push(ambiguousDay(data.ambiguousDay));
    return parts.join(" · ");
  }

  function ambiguousDay(n: number): string {
    return t("ambiguous today: {n}").replace("{n}", String(n));
  }

  function whyOf(c: AutolistCandidate): string {
    return whyLabel(c.why, autolist.resultFor(c.host)?.bytes ?? 0, t);
  }

  function mark(domain: string, on: boolean) {
    const next = new Set(busy);
    if (on) next.add(domain);
    else next.delete(domain);
    busy = next;
  }

  function syncGroups() {
    const store = groupsBridge.store;
    if (store?.dataLoaded && !store.tracker.isDirty) void store.mount();
  }

  async function add(c: AutolistCandidate) {
    mark(c.domain, true);
    try {
      await autolist.add(c.domain);
      toast.success(
        t("{domain} added to «{group}». It will open within {n} s — refresh the page.")
          .replace("{domain}", c.domain)
          .replace("{group}", groupName)
          .replace("{n}", String(ttl)),
      );
      syncGroups();
    } catch {
    } finally {
      mark(c.domain, false);
    }
  }

  async function dismiss(c: AutolistCandidate) {
    mark(c.domain, true);
    try {
      await autolist.dismiss(c.domain);
    } catch {
    } finally {
      mark(c.domain, false);
    }
  }

  async function probe(c: AutolistCandidate) {
    mark(c.domain, true);
    try {
      await autolist.probe(c.host);
    } catch {
    } finally {
      mark(c.domain, false);
    }
  }

  async function remove(c: AutolistCandidate) {
    if (!data?.group) return;
    mark(c.domain, true);
    try {
      const fresh = await fetcher.get<{ groups: Group[] }>("/groups?with_rules=true", {
        quiet: true,
      });
      const rule = ruleOf(fresh.groups ?? [], data.group, c.domain);
      if (rule) {
        await fetcher.delete(`/groups/${data.group}/rules/${rule.id}?save=true`);
      }
      await autolist.dismiss(c.domain);
      syncGroups();
    } catch {
    } finally {
      mark(c.domain, false);
    }
  }

  function toRule(c: AutolistCandidate) {
    tabRequest.open("groups", c.domain);
  }
</script>

{#snippet pill(cls: string, text: string, spin = false)}
  <span class="pill {cls}"
    >{#if spin}<span class="spin" aria-hidden="true"></span>{/if}{text}</span
  >
{/snippet}

{#snippet bold(text: string)}<b>{text}</b>{/snippet}

{#if data}
  {#if !data.enabled}
    <div class="strip">
      {groupName
        ? t(
            "No failures yet. firc watches the TLS connections of the devices of group «{group}» that go around the tunnel.",
          ).replace("{group}", groupName)
        : t(
            "No failures yet. firc watches the TLS connections of the devices of the chosen group that go around the tunnel.",
          )}
    </div>
    <div class="strip off">
      {t("Automatic adding is off.")}
      <Button class="primary" onclick={() => tabRequest.open("settings")}
        >{t("Turn on in settings")}</Button
      >
    </div>
  {:else}
    <div class="strip" data-testid="autolist-strip">
      {#if data.mode === "add"}
        <div>
          {t("Mode")}
          {@render bold(t("adds by itself"))} · {t("to")}
          {@render bold(`«${groupName}»`)}
          <span class="m">· {addDetails()}</span>
        </div>
      {:else}
        <div>
          {t("Mode")}
          {@render bold(t("candidates"))} · {t("add to")}
          {@render bold(`«${groupName}»`)} · {t("watches the devices of this group")}
        </div>
        <div class="m">
          {failuresDay(data.failuresDay)}{#if data.ambiguousDay > 0}{` · ${ambiguousDay(
              data.ambiguousDay,
            )}`}{/if} · {t("router check: {n} of {max} in the last hour")
            .replace("{n}", String(data.probes.usedHour))
            .replace("{max}", String(PROBES_PER_HOUR))}, {t("{n} queued").replace(
            "{n}",
            String(data.probes.queued),
          )}
          ·
          <span class="hint"
            >{t("after adding, the site opens within {n} s — refresh the page").replace(
              "{n}",
              String(ttl),
            )}</span
          >
        </div>
      {/if}
      {#if !data.running && data.whyOff}
        <div class="warn">{t("Not running: {reason}").replace("{reason}", data.whyOff)}</div>
      {/if}
      {#if data.wanWarning}
        <div class="warn" data-testid="autolist-wan-warning">
          {t(
            "The check interface has no route: the WAN check cannot pass, hosts without a connection stay unknown",
          )}
        </div>
      {/if}
    </div>

    {#if candidates.length === 0}
      <div class="strip">
        {groupName
          ? t(
              "No failures yet. firc watches the TLS connections of the devices of group «{group}» that go around the tunnel.",
            ).replace("{group}", groupName)
          : t(
              "No failures yet. firc watches the TLS connections of the devices of the chosen group that go around the tunnel.",
            )}
      </div>
    {:else}
      <div class="card">
        <div class="head" aria-hidden="true">
          <span>{t("Domain")}</span>
          <span>{t("Why")}</span>
          <span class="num">{t("Failures")}</span>
          <span>{t("Devices")}</span>
          <span>{stateColumn ? t("State") : t("Last")}</span>
          <span></span>
        </div>
        {#each candidates as c (c.domain)}
          {@const devs = devicesOf(c)}
          {@const result = autolist.resultFor(c.host)}
          {@const locked = busy.has(c.domain)}
          <div class="row" data-domain={c.domain} data-state={c.state}>
            <span class="dom"
              ><span class="name" title={c.domain}>{c.domain}</span><span class="host"
                >{c.host}</span
              ></span
            >
            <span class="why">
              {#if c.state === "checking"}
                {@render pill("off", t("checking by the router…"), true)}
                {#if c.notes > 0}<span class="sub">{stalled(c.notes)}</span>{/if}
              {:else}
                {@render pill(whyClass(c.why), whyOf(c))}
                {#if c.why === "freeze" && result?.verdict === "blocked" && c.state === "candidate"}
                  <span class="sub"
                    >{t("confirmed by the router check, {time}").replace(
                      "{time}",
                      stamp(result.at),
                    )}</span
                  >
                {/if}
              {/if}
              <span class="meta">{metaText(c)}</span>
            </span>
            <span class="num">{c.fails > 0 ? c.fails : "—"}</span>
            <span class="devs">
              {#each devs.slice(0, 2) as d (d.key)}
                <span class="dev">
                  <span class="dn">{d.label}</span>
                  {#if d.label !== d.address}<span class="da">{d.address}</span>{/if}
                </span>
              {/each}
              {#if devs.length > 2}
                <span class="more">{t("and {n} more").replace("{n}", String(devs.length - 2))}</span
                >
              {/if}
            </span>
            <span class="last">
              {#if c.state === "added"}
                {@render pill("ok", t("added"))}
                <span class="sub">{relativeTime(c.lastAt, now, t)}</span>
              {:else if c.state === "off"}
                {@render pill("off", t("switched off by the recheck"))}
                <span class="sub"
                  >{t("opens directly again, {time}").replace(
                    "{time}",
                    stamp(result?.at ?? data.checkedAt),
                  )}</span
                >
              {:else}
                {relativeTime(c.lastAt, now, t)}
              {/if}
            </span>
            <span class="act">
              {#if c.state === "added" || c.state === "off"}
                <Button onclick={() => toRule(c)} inactive={locked}>{t("To the rule")}</Button>
                <Button onclick={() => void remove(c)} inactive={locked}
                  >{t("Take out of the group")}</Button
                >
              {:else}
                <Button
                  class="primary"
                  onclick={() => void add(c)}
                  disabled={c.state === "checking" || locked || !data.running}
                  >{t("To «{group}»").replace("{group}", groupName)}</Button
                >
                <Button
                  onclick={() => void probe(c)}
                  disabled={c.state === "checking" || locked || !data.running}>{t("Check")}</Button
                >
                <Button
                  aria-label={t("Dismiss for a day")}
                  title={t("Dismiss for a day")}
                  onclick={() => void dismiss(c)}
                  inactive={locked}><X size={14} aria-hidden="true" /></Button
                >
              {/if}
            </span>
          </div>
        {/each}
      </div>
    {/if}

    {#each data.bypassed as b (b.client)}
      <div class="note">
        {bypassNote(b.fails, names.get(b.client.toLowerCase()) ?? b.client)}
      </div>
    {/each}
  {/if}
{/if}

<style>
  .strip {
    margin-bottom: 0.6rem;
    padding: 0.6rem 0.8rem;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    color: var(--text);
    font-size: 0.92rem;
    line-height: 1.6;
  }
  .strip.off {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.6rem;
  }
  .strip b {
    font-weight: 700;
  }
  .m,
  .hint,
  .sub,
  .host {
    color: var(--text-2);
  }
  .hint {
    font-size: 0.82rem;
  }
  .warn {
    color: var(--orange);
  }
  .card {
    container-type: inline-size;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.6rem;
    overflow: hidden;
    font-size: 0.88rem;
  }
  .head,
  .row {
    display: grid;
    grid-template-columns:
      minmax(0, 1.3fr) minmax(0, 1.5fr) 3.5rem minmax(0, 1.1fr) minmax(0, 0.9fr)
      19rem;
    gap: 0.8rem;
    align-items: center;
    padding: 0.55rem 0.9rem;
  }
  .head {
    text-align: left;
    border-bottom: 1px solid var(--bg-light-extra);
    color: var(--text-2);
    font-size: 0.74rem;
    letter-spacing: 0.03em;
  }
  .row {
    border-bottom: 1px solid color-mix(in srgb, var(--bg-light-extra) 60%, transparent);
  }
  .row:last-child {
    border-bottom: 0;
  }
  .dom {
    display: flex;
    flex-direction: column;
    min-width: 0;
    line-height: 1.25;
  }
  .name {
    font-weight: 700;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .host {
    font-family: var(--font-mono);
    font-size: 0.74rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .why,
  .last {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.2rem;
    min-width: 0;
  }
  .last {
    color: var(--text-2);
    font-size: 0.8rem;
  }
  .sub {
    font-size: 0.76rem;
    line-height: 1.25;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    max-width: 100%;
    padding: 0.1rem 0.5rem;
    border-radius: 0.4rem;
    font-size: 0.76rem;
    font-weight: 600;
    white-space: nowrap;
    background: color-mix(in srgb, var(--c) 18%, var(--bg-light));
    color: var(--c);
    --c: var(--text-2);
  }
  .pill.drop {
    --c: var(--orange);
  }
  .pill.rst {
    --c: var(--red);
  }
  .pill.frz {
    --c: var(--blue);
  }
  .pill.ok {
    --c: var(--green);
  }
  .spin {
    flex: 0 0 auto;
    width: 0.7rem;
    height: 0.7rem;
    margin-right: 0.4rem;
    border: 2px solid color-mix(in srgb, var(--accent) 35%, transparent);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: turn 0.9s linear infinite;
  }
  @keyframes turn {
    to {
      transform: rotate(1turn);
    }
  }
  .num {
    text-align: left;
    font-variant-numeric: tabular-nums;
  }
  .devs {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    min-width: 0;
  }
  .dev {
    display: flex;
    flex-direction: column;
    line-height: 1.2;
    min-width: 0;
  }
  .dn {
    font-size: 0.84rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .da {
    font-family: var(--font-mono);
    font-size: 0.7rem;
    color: var(--text-2);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .more {
    font-size: 0.76rem;
    color: var(--text-2);
  }
  .meta {
    display: none;
  }
  .act {
    display: flex;
    gap: 0.4rem;
    justify-content: flex-end;
    flex-wrap: nowrap;
  }
  .act :global(button) {
    padding: 0.35rem 0.7rem;
    font-size: 0.88rem;
    white-space: nowrap;
  }
  .act :global(button.primary) {
    min-width: 0;
    max-width: 12rem;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .act :global(button[aria-label]) {
    padding: 0.4rem 0.5rem;
  }
  .note {
    margin-top: 0.6rem;
    padding: 0.5rem 0.8rem;
    background: color-mix(in srgb, var(--yellow-bright) 10%, var(--bg-dark));
    border: 1px solid color-mix(in srgb, var(--yellow-bright) 28%, transparent);
    border-radius: 0.5rem;
    color: var(--yellow-bright);
    font-size: 0.85rem;
  }
  @container (max-width: 760px) {
    .head {
      display: none;
    }
    .row {
      grid-template-columns: minmax(0, 1fr) auto;
      grid-template-areas:
        "dom last"
        "why why"
        "act act";
      gap: 0.4rem 0.6rem;
      padding: 0.7rem 0.8rem;
    }
    .dom {
      grid-area: dom;
    }
    .host,
    .num,
    .devs {
      display: none;
    }
    .why {
      grid-area: why;
      flex-direction: row;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.2rem 0.6rem;
    }
    .meta {
      display: inline;
      color: var(--text-2);
      font-size: 0.8rem;
    }
    .last {
      grid-area: last;
      align-items: flex-end;
    }
    .act {
      grid-area: act;
      justify-content: flex-start;
      flex-wrap: wrap;
    }
  }
</style>
