<script lang="ts">
  import { hosts } from "../data/hosts.svelte";
  import { interfaces } from "../data/interfaces.svelte";
  import { t } from "../data/locale.svelte";
  import { policies } from "../data/policies.svelte";
  import Switch from "./ui/Switch.svelte";

  import { ifaceTitle } from "../data/iface-choices";
  import type { DeviceSelector } from "../types";
  import {
    flipPolicy,
    flipRow,
    foldManual,
    hasAllow,
    hostRows,
    joinSelector,
    policyChips,
    policyOn,
    rowState,
    selectorMode,
    setMode,
    splitSelector,
    visibleRows,
    type HostRow,
    type Mode,
    type Picked,
    type RowNote,
  } from "../utils/device-picker";
  import { invalidDeviceEntries } from "../utils/device-validators";
  import { outsideLan, policyOutside } from "../utils/lan-coverage";
  import { Search, SelectOpen } from "./ui/icons";

  type Props = {
    seed: DeviceSelector | undefined;
    seedKey: string | null;
    selector?: DeviceSelector;
    nothingChosen?: boolean;
    invalid?: boolean;
    manualOpen?: boolean;
  };

  let {
    seed,
    seedKey,
    selector = $bindable({ allow: [], deny: [] }),
    nothingChosen = $bindable(false),
    invalid = $bindable(false),
    manualOpen = $bindable(false),
  }: Props = $props();

  let picked = $state<Picked>(splitSelector(undefined));
  let allowText = $state("");
  let denyText = $state("");
  let query = $state("");
  let chosenMode = $state<Mode>("all");
  let seededFor = $state<string | null>(null);
  let seededMacs = $state<string[]>([]);

  const toLines = (entries: string[]) => entries.join("\n");
  const toEntries = (text: string) =>
    text
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

  let noHosts = $derived(hosts.loaded && hosts.list.length === 0);

  $effect(() => {
    if (seedKey === null) {
      seededFor = null;
      return;
    }
    if (seededFor === seedKey) return;
    picked = splitSelector(seed);
    allowText = toLines(picked.manual.allow);
    denyText = toLines(picked.manual.deny);
    seededMacs = [...picked.macs.keys()];
    chosenMode = selectorMode(picked);
    query = "";
    manualOpen = noHosts || picked.manual.allow.length + picked.manual.deny.length > 0;
    seededFor = seedKey;
  });

  $effect(() => {
    if (seedKey !== null && noHosts) manualOpen = true;
  });

  let draft = $derived<Picked>({
    policies: picked.policies,
    macs: picked.macs,
    manual: { allow: toEntries(allowText), deny: toEntries(denyText) },
  });
  let folded = $derived(foldManual(draft));
  let mode = $derived<Mode>(hasAllow(folded) ? "only" : chosenMode);
  let rows = $derived(hostRows(hosts.list, folded, seededMacs));
  let visible = $derived(visibleRows(rows, query));
  let chips = $derived(policyChips(folded, policies.list));
  let states = $derived(
    new Map(rows.map((r) => [r.mac, rowState(r, folded, policies.list, mode)])),
  );
  let listed = $derived(rows.filter((r) => !r.unknown));
  let onCount = $derived(listed.filter((r) => states.get(r.mac)?.on).length);
  let badAllow = $derived(invalidDeviceEntries(draft.manual.allow));
  let badDeny = $derived(invalidDeviceEntries(draft.manual.deny));
  let manualCount = $derived(draft.manual.allow.length + draft.manual.deny.length);

  $effect(() => {
    selector = joinSelector(draft);
    nothingChosen = mode === "only" && !hasAllow(folded);
    invalid = badAllow.length > 0 || badDeny.length > 0;
  });

  function apply(next: Picked) {
    chosenMode = mode;
    picked = next;
    allowText = toLines(next.manual.allow);
    denyText = toLines(next.manual.deny);
  }

  function chooseMode(m: Mode) {
    apply(setMode(folded, m));
    chosenMode = m;
  }

  function hostLabel(row: HostRow): string {
    if (row.name) return `${row.name} (${row.ip || row.mac})`;
    if (row.ip) return `${row.ip} (${row.mac})`;
    return row.mac;
  }

  const around = (text: string, slot: string) => {
    const at = text.indexOf(slot);
    return at < 0 ? [text, ""] : [text.slice(0, at), text.slice(at + slot.length)];
  };

  const segmentTitle = (id: string) =>
    ifaceTitle(interfaces.list.find((i) => i.id === id) ?? { id }).title;

  const policyOf = (note: { policy: string; segment?: string }) =>
    note.segment === undefined
      ? note.policy
      : t("{policy} of segment {segment}")
          .replace("{policy}", () => note.policy)
          .replace("{segment}", () => segmentTitle(note.segment ?? ""));

  function noteText(note: NonNullable<RowNote>): string {
    switch (note.kind) {
      case "policy-off":
        return t("off by policy {name}").replace("{name}", () => policyOf(note));
      case "manual-off":
        return t("off by a manual entry");
      case "excluded-from":
        return t("excluded from {name}").replace("{name}", () => policyOf(note));
      case "excluded":
        return t("excluded");
      case "via":
        return t("on through policy {name}").replace("{name}", () => policyOf(note));
      case "manual-on":
        return t("on through a manual entry");
    }
  }
</script>

<section class="block">
  <div class="seg" role="group" aria-label={t("Who the group works for")}>
    <button
      type="button"
      class="mode-all"
      class:on={mode === "all"}
      aria-pressed={mode === "all"}
      onclick={() => chooseMode("all")}
    >
      {t("For every device")}
    </button>
    <button
      type="button"
      class="mode-only"
      class:on={mode === "only"}
      aria-pressed={mode === "only"}
      onclick={() => chooseMode("only")}
    >
      {t("Only for the chosen")}
    </button>
  </div>
  <p class="hint mode-hint">
    {mode === "all"
      ? t("Switch off the devices the group must leave alone.")
      : t("Switch on the devices the group works for.")}
  </p>
</section>

<section class="block">
  <div class="label">{t("Policies")}</div>
  {#if chips.length > 0}
    <ul class="hosts">
      {#each chips as chip, i (chip.id)}
        {@const on = policyOn(chip.side, mode)}
        {@const noteId = `devices-policy-note-${i}`}
        {@const outside = mode === "only" && on ? policyOutside(hosts.list, chip.id) : 0}
        {@const takenBy = chip.takenBy}
        {@const note =
          takenBy !== null
            ? t("unreachable: its name is taken by the description of policy {name}").replace(
                "{name}",
                () => takenBy,
              )
            : chip.side === "deny"
              ? t("excluded")
              : ""}
        <li class="host policy" class:off={!on} data-policy={chip.id}>
          <Switch
            bind:checked={() => on, () => apply(flipPolicy(folded, chip.id, policies.list, mode))}
            disabled={chip.takenBy !== null}
            aria-label={chip.label}
            aria-describedby={[note ? noteId : "", outside > 0 ? `${noteId}-lan` : ""]
              .filter(Boolean)
              .join(" ") || undefined}
          />
          <div class="who">
            <div class="name">{chip.label}</div>
            {#if note}
              <div class="note denied" id={noteId}>{note}</div>
            {/if}
            {#if outside > 0}
              {@const [before, after] = around(
                t("Devices outside LAN interfaces: {n}; domains do not work for them"),
                "{n}",
              )}
              <div class="note lan" id={`${noteId}-lan`}>
                {before}<span class="lan-mark">{outside}</span>{after}
              </div>
            {/if}
          </div>
          {#if chip.devices !== null}
            <span class="count">{chip.devices}</span>
          {/if}
        </li>
      {/each}
    </ul>
  {:else if policies.loaded}
    <p class="hint">{t("This router has no policies.")}</p>
  {/if}
</section>

<section class="block">
  <div class="label-row">
    <div class="label">{t("Devices")}</div>
    {#if listed.length > 0}
      <span class="works-for">
        {t("works for {n} of {m}")
          .replace("{n}", String(onCount))
          .replace("{m}", String(listed.length))}
      </span>
    {/if}
  </div>
  {#if rows.length > 0}
    <label class="search">
      <Search size={16} aria-hidden="true" />
      <input
        type="search"
        class="host-search"
        bind:value={query}
        placeholder={t("Search by name, IP or MAC")}
        aria-label={t("Search by name, IP or MAC")}
        onkeydown={(e) => {
          if (e.key === "Enter") e.preventDefault();
        }}
      />
    </label>
    {#if visible.length > 0}
      <ul class="hosts">
        {#each visible as row (row.mac)}
          {@const st = states.get(row.mac)!}
          {@const lan = mode === "only" && st.on && outsideLan(row) && row.segment !== undefined}
          <li class="host" class:off={!st.on} data-mac={row.mac}>
            <Switch
              bind:checked={() => st.on, () => apply(flipRow(folded, row, policies.list, mode))}
              disabled={st.locked}
              aria-label={hostLabel(row)}
              aria-describedby={[
                st.note ? `devices-note-${row.mac}` : "",
                lan ? `devices-lan-${row.mac}` : "",
              ]
                .filter(Boolean)
                .join(" ") || undefined}
            />
            <span
              class="dot"
              class:online={row.active}
              role="img"
              aria-label={row.active ? t("online") : t("offline")}
              title={row.active ? t("online") : t("offline")}
            ></span>
            <div class="who">
              <div class="name">{row.name || row.mac}</div>
              {#if st.note}
                <div class="note" class:denied={!st.on} id={`devices-note-${row.mac}`}>
                  {noteText(st.note)}
                </div>
              {/if}
              {#if lan}
                {@const [before, after] = around(
                  t("{segment} is not in LAN interfaces: domains do not work"),
                  "{segment}",
                )}
                <div class="note lan" id={`devices-lan-${row.mac}`}>
                  {before}<span class="lan-mark">{segmentTitle(row.segment ?? "")}</span>{after}
                </div>
              {/if}
            </div>
            <div class="meta">
              {#if row.unknown}
                <span class="gone">{t("not on the network now")}</span>
              {:else}
                {#if row.ip}<span class="ip">{row.ip}</span><span class="sep"> · </span>{/if}<span
                  class="mac">{row.mac}</span
                >
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
  <p class="future" class:all={mode === "all"}>
    {mode === "all"
      ? t("New devices: the group will work for them.")
      : t("New devices: the group will not work for them until you switch them on.")}
  </p>
  {#if rows.length > 0}
    <p class="hint">
      {t("A device is remembered by its MAC: a new address from DHCP keeps it selected.")}
    </p>
  {/if}
</section>

<section class="block manual">
  <button
    type="button"
    class="manual-toggle"
    aria-expanded={manualOpen}
    onclick={() => (manualOpen = !manualOpen)}
  >
    <span class="chevron" class:open={manualOpen}><SelectOpen size={16} /></span>
    {t("Manual")}{manualCount > 0 ? ` (${manualCount})` : ""}
  </button>
  {#if manualOpen}
    {#if noHosts}
      <p class="hint warn">
        {t("The router lists no devices: add addresses and prefixes by hand.")}
      </p>
    {/if}
    <p class="hint">{t("One entry per line: an address or a CIDR prefix.")}</p>
    <label class="field" for="devices-allow">{t("Allow also")}</label>
    <textarea
      id="devices-allow"
      bind:value={allowText}
      class:invalid={badAllow.length > 0}
      placeholder={"192.168.1.0/24"}
      rows="3"
    ></textarea>
    {#if badAllow.length > 0}
      <p class="error">{t("Not a device")}: {badAllow.join(", ")}</p>
    {/if}
    <label class="field" for="devices-deny">{t("Deny")}</label>
    <textarea
      id="devices-deny"
      bind:value={denyText}
      class:invalid={badDeny.length > 0}
      placeholder={"192.168.1.5"}
      rows="3"
    ></textarea>
    {#if badDeny.length > 0}
      <p class="error">{t("Not a device")}: {badDeny.join(", ")}</p>
    {/if}
  {/if}
</section>

<style>
  .block {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    min-width: 0;
  }

  .block:not(:first-child) {
    border-top: 1px solid var(--border-light);
    padding-top: 0.9rem;
  }

  .label {
    font-size: 0.95em;
    font-weight: 600;
    color: var(--text);
  }

  .label-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
  }

  .works-for {
    font-size: 0.85em;
    color: var(--text-2);
    font-variant-numeric: tabular-nums;
  }

  .seg {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(12.5rem, 1fr));
    background: var(--bg-dark);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    padding: 0.2rem;
    gap: 0.2rem;
  }

  .seg button {
    all: unset;
    box-sizing: border-box;
    min-width: 0;
    cursor: pointer;
    padding: 0.45rem 0.6rem;
    border-radius: 0.35rem;
    color: var(--text-2);
    text-align: center;
    overflow-wrap: anywhere;
  }

  .seg button.on {
    background: var(--bg-light-extra);
    color: var(--text);
  }

  .seg button:hover {
    color: var(--text);
  }

  /* `all: unset` drops the native focus ring with everything else */
  .seg button:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .hint {
    font-size: 0.8em;
    color: var(--text-2);
    margin: 0;
  }

  .hint.warn {
    color: var(--text);
  }

  .mode-hint {
    font-size: 0.9em;
  }

  .future {
    margin: 0;
    font-size: 0.85em;
    color: var(--orange);
  }

  .future.all {
    color: var(--green);
  }

  .count {
    color: var(--text-2);
    font-size: 0.85em;
    font-variant-numeric: tabular-nums;
  }

  .search {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    min-height: 2.5rem;
    padding: 0 0.75rem;
    background: var(--bg-dark);
    border: 1px solid var(--border-light);
    border-radius: 0.6rem;
    color: var(--text-2);
  }

  .search:focus-within {
    border-color: var(--accent);
  }

  .host-search {
    flex: 1 1 auto;
    min-width: 0;
    background: none;
    border: 0;
    outline: none;
    color: var(--text);
    font: inherit;
    font-size: 0.9em;
  }

  .hosts {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--border-light);
    border-radius: 0.6rem;
    overflow: hidden;
    container-type: inline-size;
  }

  .host {
    display: grid;
    grid-template-columns: auto auto minmax(0, 1fr);
    align-items: center;
    column-gap: 0.6rem;
    row-gap: 0.1rem;
    min-height: 3rem;
    padding: 0.35rem 0.75rem;
    box-sizing: border-box;
    border-bottom: 1px solid var(--border-light);
  }

  .host:last-child {
    border-bottom: none;
  }

  .host.off .name {
    color: var(--text-2);
  }

  .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    background: color-mix(in srgb, var(--text-2) 45%, transparent);
  }

  .dot.online {
    background: var(--green);
  }

  .who {
    min-width: 0;
  }

  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .note {
    font-size: 0.75em;
    color: var(--text-2);
  }

  .note.denied {
    color: var(--danger);
  }

  .lan-mark {
    color: var(--yellow);
  }

  .meta {
    grid-column: 3;
    font-size: 0.75em;
    color: var(--text-2);
    font-family: var(--font-mono);
    overflow-wrap: anywhere;
  }

  .ip {
    color: var(--grey);
  }

  .ip,
  .mac {
    display: inline-block;
    max-width: 100%;
  }

  @container (min-width: 520px) {
    .host {
      grid-template-columns: auto auto minmax(0, 1fr) 8rem 9.5rem;
    }

    .meta {
      display: contents;
    }

    .sep {
      display: none;
    }

    .ip {
      grid-column: 4;
    }

    .gone {
      grid-column: 4 / 6;
    }

    .mac {
      grid-column: 5;
      color: var(--text-2);
    }
  }

  .host.policy {
    grid-template-columns: auto minmax(0, 1fr) auto;
  }

  .manual {
    border-top: 1px solid var(--border-light);
    padding-top: 0.75rem;
  }

  .manual-toggle {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    align-self: flex-start;
    border: none;
    background: transparent;
    color: var(--accent);
    font: inherit;
    font-size: 0.95em;
    cursor: pointer;
    padding: 0;
  }

  .chevron {
    display: inline-flex;
    transform: rotate(-90deg);
  }

  .chevron.open {
    transform: none;
  }

  .field {
    font-size: 0.85em;
    color: var(--text-2);
    margin-top: 0.25rem;
  }

  textarea {
    resize: vertical;
    font-family: var(--font-mono);
  }

  .error {
    font-size: 0.85em;
    color: var(--danger);
    margin: 0;
    overflow-wrap: anywhere;
  }
</style>
