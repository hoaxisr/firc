<script lang="ts">
  import { getContext } from "svelte";

  import DevicePicker from "../../../components/DevicePicker.svelte";
  import Button from "../../../components/ui/Button.svelte";
  import GenericDialog from "../../../components/ui/GenericDialog.svelte";
  import { fetchHosts, hosts } from "../../../data/hosts.svelte";
  import { interfaces } from "../../../data/interfaces.svelte";
  import { locale, t } from "../../../data/locale.svelte";
  import { fetchPolicies, policies } from "../../../data/policies.svelte";
  import { GROUPS_STORE_CONTEXT, groupTitle, type GroupsStore } from "../groups.svelte";

  import { Search, SelectOpen } from "../../../components/ui/icons";
  import { ifaceTitle } from "../../../data/iface-choices";
  import type { DeviceSelector, Group } from "../../../types";
  import {
    aggregate,
    applyBulk,
    bulkRows,
    replaceWith,
    type BulkEdits,
    type BulkMode,
    type Refusal,
  } from "../../../utils/device-bulk";
  import { coverageLabel, visibleRows } from "../../../utils/device-picker";
  import { counted } from "../../../utils/plural";

  let {
    open = $bindable(false),
    view = $bindable("edit"),
  }: { open?: boolean; view?: "edit" | "replace" } = $props();

  const store = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);

  let mode = $state<BulkMode>("keep");
  let edits = $state.raw<BulkEdits>({ policies: new Map(), macs: new Map() });
  let query = $state("");
  let nowOpen = $state(false);
  let selector = $state.raw<DeviceSelector>({ allow: [], deny: [] });
  let nothingChosen = $state(false);
  let invalid = $state(false);
  let manualOpen = $state(false);

  $effect(() => {
    if (open) {
      void fetchPolicies();
      void fetchHosts();
    }
  });

  $effect(() => {
    if (!open) {
      mode = "keep";
      edits = { policies: new Map(), macs: new Map() };
      query = "";
      nowOpen = false;
    }
  });

  let selected = $derived.by(() => {
    const ids = new Set(store.selection);
    return store.data.filter((g) => ids.has(g.id));
  });
  let selectors = $derived(selected.map((g) => g.devices));
  let n = $derived(selected.length);
  let counts = $derived(aggregate(selectors, mode, policies.list, hosts.list));
  let allRows = $derived(bulkRows(selectors, hosts.list));
  let rows = $derived(visibleRows(allRows, query));
  let results = $derived(
    selected.map((g) => ({
      group: g,
      ...applyBulk(g.devices, edits, mode, policies.list, hosts.list),
    })),
  );
  let editChanges = $derived(results.filter((r) => r.sel !== null).length);
  let replaceChanges = $derived(selected.filter((g) => replaceWith(g.devices, selector)).length);
  let changes = $derived(view === "edit" ? editChanges : replaceChanges);
  let edited = $derived(edits.policies.size + edits.macs.size);
  let refusals = $derived(
    results.flatMap((r) => r.refused.map((refusal) => refusalText(r.group, refusal))),
  );

  function next(target: boolean | undefined): boolean | undefined {
    return target === undefined ? true : target ? false : undefined;
  }

  function cycle(kind: "policies" | "macs", key: string) {
    const map = new Map(edits[kind]);
    const target = next(map.get(key));
    if (target === undefined) map.delete(key);
    else map.set(key, target);
    edits = { ...edits, [kind]: map };
  }

  function checked(target: boolean | undefined, on: number): "true" | "false" | "mixed" {
    if (target !== undefined) return String(target) as "true" | "false";
    return on === n ? "true" : on === 0 ? "false" : "mixed";
  }

  function nowText(on: number, short: boolean): string {
    if (on === n) return short ? t("on") : t("on in all");
    if (on === 0) return short ? t("off") : t("off in all");
    return t("on in {k} of {n}").replace("{k}", String(on)).replace("{n}", String(n));
  }

  function stateText(target: boolean | undefined, on: number): string {
    if (target === undefined) return nowText(on, false);
    return `${nowText(on, true)} → ${target ? t("on in all") : t("off in all")}`;
  }

  const policyLabel = (id: string) => {
    const pol = policies.list.find((p) => p.name === id);
    return pol?.description || id;
  };

  function hostName(mac: string): string {
    const row = allRows.find((r) => r.mac === mac);
    return row?.name || row?.ip || mac;
  }

  function reasonText(refusal: Extract<Refusal, { kind: "locked" }>): string {
    const note = refusal.note;
    if (note?.kind !== "policy-off") return t("off by a manual entry");
    const segment = note.segment;
    const policy =
      segment === undefined
        ? note.policy
        : t("{policy} of segment {segment}")
            .replace("{policy}", () => note.policy)
            .replace(
              "{segment}",
              () =>
                ifaceTitle(interfaces.list.find((i) => i.id === segment) ?? { id: segment }).title,
            );
    return t("off by policy {name}").replace("{name}", () => policy);
  }

  function refusalText(group: Group, refusal: Refusal): string {
    const name = groupTitle(group);
    switch (refusal.kind) {
      case "nothing-chosen":
        return t("{group} stays as it is: nothing would be on for «Only for the chosen»").replace(
          "{group}",
          () => name,
        );
      case "taken":
        return t("In {group}, policy {name} stays as it is: its name is taken by another policy")
          .replace("{group}", () => name)
          .replace("{name}", () => policyLabel(refusal.policy));
      case "locked":
        return t("In {group}, {device} stays as it is: {reason}")
          .replace("{group}", () => name)
          .replace("{device}", () => hostName(refusal.mac))
          .replace("{reason}", () => reasonText(refusal));
    }
  }

  let title = $derived(
    `${t("Devices")} · ${counted(n, locale.current, t("{n} group"), t("{n} groups (2-4)"), t("{n} groups"))}`,
  );

  let footer = $derived(
    view === "edit"
      ? counted(
          editChanges,
          locale.current,
          t("{n} group of {m} will change"),
          t("{n} groups of {m} will change (2-4)"),
          t("{n} groups of {m} will change"),
        ).replace("{m}", String(n))
      : counted(
          n,
          locale.current,
          t("Same for {n} group"),
          t("Same for {n} groups (2-4)"),
          t("Same for {n} groups"),
        ),
  );

  let applyText = $derived(
    view === "edit"
      ? t("Apply")
      : counted(
          replaceChanges,
          locale.current,
          t("Replace in {n} group"),
          t("Replace in {n} groups (2-4)"),
          t("Replace in {n} groups"),
        ),
  );

  function close() {
    open = false;
  }

  function submit() {
    if (view === "edit") {
      if (editChanges === 0) return;
      store.setSelectedDevices(
        (g) => applyBulk(g.devices, edits, mode, policies.list, hosts.list).sel,
      );
      close();
      return;
    }
    if (invalid) {
      manualOpen = true;
      return;
    }
    if (nothingChosen || replaceChanges === 0) return;
    const value = selector;
    store.setSelectedDevices((g) => replaceWith(g.devices, value));
    close();
  }
</script>

<GenericDialog
  {open}
  {title}
  maxWidth={640}
  contentClass="bulk-devices"
  on:close={close}
  on:submit={submit}
>
  <div slot="body" class="dialog-body">
    <p class="names">{selected.map(groupTitle).join(", ")}</p>
    <div class="seg two" role="group" aria-label={t("Devices")}>
      <button
        type="button"
        class="view-edit"
        class:on={view === "edit"}
        aria-pressed={view === "edit"}
        onclick={() => (view = "edit")}>{t("Edit")}</button
      >
      <button
        type="button"
        class="view-replace"
        class:on={view === "replace"}
        aria-pressed={view === "replace"}
        onclick={() => (view = "replace")}>{t("Replace")}</button
      >
    </div>

    {#if view === "edit"}
      <p class="hint">
        {t("Touch only the rows you need. Untouched ones stay as each group has them.")}
      </p>
      <section class="block">
        <div class="label">{t("Mode")}</div>
        <div class="seg three" role="group" aria-label={t("Mode")}>
          {#each [["keep", t("Keep as is")], ["all", t("For all")], ["only", t("Only for the chosen")]] as [id, label] (id)}
            <button
              type="button"
              class={`mode-${id}`}
              class:on={mode === id}
              aria-pressed={mode === id}
              onclick={() => (mode = id as BulkMode)}>{label}</button
            >
          {/each}
        </div>
      </section>

      <section class="block">
        <div class="label">{t("Policies")}</div>
        {#if policies.list.length > 0}
          <ul class="rows">
            {#each policies.list as pol (pol.name)}
              {@const target = edits.policies.get(pol.name)}
              {@const on = counts.policies.get(pol.name) ?? 0}
              <li class="row" class:edited={target !== undefined} data-policy={pol.name}>
                <button
                  type="button"
                  class="tri"
                  role="checkbox"
                  aria-checked={checked(target, on)}
                  aria-label={pol.description || pol.name}
                  onclick={() => cycle("policies", pol.name)}
                ></button>
                <span class="name">{pol.description || pol.name}</span>
                <span class="state">{stateText(target, on)}</span>
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
          {#if edited > 0}
            <span class="edited-count">{t("changed: {n}").replace("{n}", String(edited))}</span>
          {/if}
        </div>
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
        {#if rows.length > 0}
          <ul class="rows">
            {#each rows as row (row.mac)}
              {@const target = edits.macs.get(row.mac)}
              {@const on = counts.macs.get(row.mac) ?? 0}
              <li class="row mac" class:edited={target !== undefined} data-mac={row.mac}>
                <button
                  type="button"
                  class="tri"
                  role="checkbox"
                  aria-checked={checked(target, on)}
                  aria-label={row.name ? `${row.name} (${row.ip || row.mac})` : row.ip || row.mac}
                  onclick={() => cycle("macs", row.mac)}
                ></button>
                <span class="name">{row.name || row.mac}</span>
                <span class="ip">{row.unknown ? t("not on the network now") : row.ip}</span>
                <span class="state">{stateText(target, on)}</span>
              </li>
            {/each}
          </ul>
        {/if}
      </section>

      {#if refusals.length > 0}
        <ul class="refusals" role="status">
          {#each refusals as text, i (i)}<li>{text}</li>{/each}
        </ul>
      {/if}
    {/if}
    <div class="replace" class:gone={view !== "replace"}>
      <section class="block now">
        <button
          type="button"
          class="now-toggle"
          aria-expanded={nowOpen}
          onclick={() => (nowOpen = !nowOpen)}
        >
          <span class="chevron" class:open={nowOpen}><SelectOpen size={16} /></span>
          {t("The groups have different settings now; they will be the same")}
        </button>
        {#if nowOpen}
          <dl class="now-list">
            {#each selected as g (g.id)}
              <dt>{groupTitle(g)}</dt>
              <dd>{coverageLabel(g.devices, hosts.list, policies.list, t, locale.current)}</dd>
            {/each}
          </dl>
        {/if}
      </section>
      <DevicePicker
        seed={undefined}
        seedKey={open ? "bulk" : null}
        bind:selector
        bind:nothingChosen
        bind:invalid
        bind:manualOpen
      />
    </div>
  </div>

  <div slot="actions" class="bulk-actions">
    {#if view === "replace" && nothingChosen}
      <p class="hint done-hint" id="bulk-done-hint">
        {t(
          "Switch on at least one device or policy, or choose “For every device”. To make the group work for nobody, switch the group off on the main page.",
        )}
      </p>
    {:else}
      <span class="footer" role="status">{footer}</span>
    {/if}
    <Button type="button" onclick={close}>{t("Cancel")}</Button>
    <Button
      type="submit"
      disabled={changes === 0 || (view === "replace" && nothingChosen)}
      class="primary"
    >
      {applyText}
    </Button>
  </div>
</GenericDialog>

<style>
  .dialog-body {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    min-width: 0;
  }

  .names {
    margin: 0;
    font-size: 0.85em;
    color: var(--text-2);
    overflow-wrap: anywhere;
  }

  .block {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    min-width: 0;
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

  .edited-count {
    font-size: 0.85em;
    color: var(--accent);
  }

  .hint {
    font-size: 0.8em;
    color: var(--text-2);
    margin: 0;
  }

  .seg {
    display: grid;
    grid-template-columns: 1fr 1fr;
    background: var(--bg-dark);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    padding: 0.2rem;
    gap: 0.2rem;
  }

  .seg.three {
    grid-template-columns: 1fr 1fr 1fr;
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

  .seg button:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
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

  .rows {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--border-light);
    border-radius: 0.6rem;
    overflow: hidden;
  }

  .row {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    align-items: center;
    column-gap: 0.6rem;
    min-height: 3rem;
    padding: 0.35rem 0.75rem;
    box-sizing: border-box;
    border-bottom: 1px solid var(--border-light);
  }

  .row.mac {
    grid-template-columns: auto minmax(0, 1fr) auto auto;
  }

  .row:last-child {
    border-bottom: none;
  }

  .row.edited {
    background: color-mix(in oklab, var(--accent) 10%, transparent);
  }

  .replace {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    min-width: 0;
  }

  .replace.gone {
    display: none;
  }

  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .ip {
    font-family: var(--font-mono);
    font-size: 0.75em;
    color: var(--text-2);
  }

  .state {
    font-size: 0.8em;
    color: var(--text-2);
    text-align: right;
  }

  .row.edited .state {
    color: var(--accent);
  }

  .tri {
    position: relative;
    width: 32px;
    height: 18px;
    flex-shrink: 0;
    padding: 0;
    border: none;
    border-radius: 9999px;
    background: var(--bg-light-extra);
    cursor: pointer;
  }

  .tri::after {
    content: "";
    position: absolute;
    top: 2px;
    left: 2px;
    width: 14px;
    height: 14px;
    border-radius: 9999px;
    background: var(--text);
    transition: transform 0.2s ease;
  }

  .tri[aria-checked="true"] {
    background: var(--accent);
  }

  .tri[aria-checked="true"]::after {
    transform: translateX(14px);
    background: var(--bg-medium);
  }

  .tri[aria-checked="mixed"] {
    background: color-mix(in oklab, var(--accent) 40%, var(--bg-light-extra));
  }

  .tri[aria-checked="mixed"]::after {
    transform: translateX(7px);
  }

  .tri:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .refusals {
    margin: 0;
    padding: 0.6rem 0.75rem 0.6rem 1.8rem;
    border: 1px solid var(--orange);
    border-radius: 0.5rem;
    background: color-mix(in oklab, var(--orange) 10%, transparent);
    font-size: 0.85em;
    color: var(--text);
  }

  .now-toggle {
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

  .now-list {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 2fr);
    gap: 0.35rem 0.75rem;
    margin: 0;
    font-size: 0.9em;
  }

  .now-list dt {
    overflow-wrap: anywhere;
  }

  .now-list dd {
    margin: 0;
    color: var(--text-2);
  }

  .bulk-actions {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 0.75rem;
  }

  .footer {
    flex: 1 1 auto;
    min-width: 0;
    font-size: 0.9em;
    color: var(--text-2);
  }

  .done-hint {
    flex: 1 1 auto;
    min-width: 0;
    color: var(--orange);
  }
</style>
