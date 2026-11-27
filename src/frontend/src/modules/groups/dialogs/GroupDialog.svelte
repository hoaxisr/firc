<script lang="ts">
  import { createEventDispatcher, tick } from "svelte";

  import DevicesDialog from "../../../components/DevicesDialog.svelte";
  import Button from "../../../components/ui/Button.svelte";
  import GenericDialog from "../../../components/ui/GenericDialog.svelte";
  import Select from "../../../components/ui/Select.svelte";
  import Switch from "../../../components/ui/Switch.svelte";
  import { hosts } from "../../../data/hosts.svelte";
  import { interfaces } from "../../../data/interfaces.svelte";
  import { locale, t } from "../../../data/locale.svelte";
  import { policies } from "../../../data/policies.svelte";
  import { fetchResolvers, resolvers } from "../../../data/resolvers.svelte";
  import IfacePicker from "../components/IfacePicker.svelte";
  import {
    isValidListUrl,
    LISTS_MAX,
    normalizeListUrl,
    type GroupDialogPayload,
  } from "../groups.svelte";
  import { presetChoices } from "../preset-sources.svelte";

  import { Eye, Globe, Link, LoaderCircle, Type, X } from "../../../components/ui/icons";
  import { BLOCK, DNS, isSink } from "../../../data/iface-choices";
  import { RULE_TYPES, type DeviceSelector, type Group, type ListRule } from "../../../types";
  import { coverageLabel } from "../../../utils/device-picker";
  import { fetcher, HttpError } from "../../../utils/fetcher";
  import { resolverListProblem } from "../../../utils/resolver-validators";
  import { ifaceList, ifaceValue } from "../iface-list";
  import { intervalOptionsFor, parseIntervalSeconds } from "../intervals";
  import {
    isUrlText,
    loadCatalog,
    loadProvider,
    presetProviders,
    providerOn,
    searchCatalog,
    visibleSources,
    wantedFiles,
    type Catalog,
    type CatalogRow,
  } from "../list-catalog";
  import { listName } from "../list-name";
  import type { GroupLive } from "../live-state";
  import {
    autoEffectiveServers,
    firmwareServersFor,
    isSavedAutoUnchanged,
    modeOf,
    serverProblemText,
    serverSuggestions,
    submittedResolve,
    type DnsMode,
  } from "../resolve-choice";

  type DialogProps = {
    open: boolean;
    mode: "create" | "edit";
    group?: Group | null;
    serverError?: string | null;
    live?: GroupLive;
  };

  let { open, mode, group = null, serverError = null, live }: DialogProps = $props();
  const dispatch = createEventDispatcher();

  let name = $state("");
  let draft = $state<{ interface: string | string[] }>({ interface: "" });
  let selectedInterface = $derived(ifaceList(draft)[0]);
  type Row = { key: string; id?: string; url: string };
  let rows = $state<Row[]>([]);
  let rowSeq = 0;
  let url = $state("");
  let interval = $state(86400);
  let seededFor = $state<string | null>(null);

  let dnsMode = $state<DnsMode>("auto");
  let dnsServer = $state("");
  let cloudflare = $state(false);
  let fallbackOn = $state(true);
  let serverErrorShown = $state<string | null>(null); /* the daemon's, until the field is edited */

  let devicesDialogOpen = $state(false);
  let devicesTarget = $state<{ id: string; devices: DeviceSelector }>({
    id: "draft",
    devices: { allow: [], deny: [] },
  });

  let previewLoading = $state(false);
  let previewError = $state<string | null>(null);
  let previewTotal = $state(0);
  let previewByType = $state<Record<string, number>>({});
  let previewDropped = $state(0);
  let previewUnconstrained = $state(0);
  let previewRules = $state<ListRule[]>([]);
  let previewedUrl = $state<string | null>(null);
  let previewKey = $state<string | null>(null);

  let catalog = $state<Catalog | null>(null);
  let catalogError = $state<string | null>(null);
  let catalogLoading = $state(false);
  /* files of the optional providers that are on, fetched once the owner starts typing */
  let providerFiles = $state<Record<string, Catalog>>({});
  let providerFailed = $state<Record<string, string>>({});
  let providerPending = $state<string[]>([]);
  let failedNames = $derived(
    catalog
      ? presetProviders(catalog)
          .filter((p) => providerFailed[p.id] !== undefined && providerOn(presetChoices(), p))
          .map((p) => p.name)
      : [],
  );
  let catalogOpen = $state(false);
  let catalogActive = $state(-1);
  let catalogQuery = $derived(isUrlText(url) ? "" : url.trim());
  let full = $derived(rows.length >= LISTS_MAX);
  let catalogShown = $derived(!full && catalogOpen && catalogQuery !== "");
  let catalogHits = $derived(
    catalog && catalogQuery !== ""
      ? searchCatalog(
          { sources: visibleSources(catalog, providerFiles, presetChoices()) },
          catalogQuery,
        )
      : { rows: [], more: 0 },
  );
  let catalogStatus = $derived(
    !catalogShown || catalogHits.rows.length > 0
      ? ""
      : catalogLoading || providerPending.length > 0
        ? t("loading the catalog…")
        : catalogError !== null
          ? catalogError || t("Catalog unavailable")
          : failedNames.length > 0
            ? t("Catalog unavailable: {names}").replace("{names}", failedNames.join(", "))
            : t("nothing found"),
  );
  let urlInvalid = $derived(url !== "" && isUrlText(url) && !isValidListUrl(url));
  let rowUrls = $derived(rows.map((row) => normalizeListUrl(row.url)));
  let urlTaken = $derived(isValidListUrl(url) && rowUrls.includes(normalizeListUrl(url)));
  let canAdd = $derived(!full && isValidListUrl(url) && !urlTaken);

  function rowProblem(i: number): string | null {
    if (!isValidListUrl(rowUrls[i])) return t("Invalid URL");
    if (rowUrls.indexOf(rowUrls[i]) !== i) return t("List already exists");
    return null;
  }

  function addRow(target: string) {
    const next = normalizeListUrl(target);
    if (full || !isValidListUrl(next) || rowUrls.includes(next)) return false;
    rows.push({ key: `new-${rowSeq++}`, url: next });
    url = "";
    return true;
  }

  function removeRow(key: string) {
    rows = rows.filter((row) => row.key !== key);
    if (previewKey === key) resetPreview();
  }

  function askProviders(index: Catalog) {
    for (const p of wantedFiles(index, presetChoices())) {
      if (providerFiles[p.id] || providerPending.includes(p.id)) continue;
      providerPending = [...providerPending, p.id];
      providerFailed = Object.fromEntries(
        Object.entries(providerFailed).filter(([id]) => id !== p.id),
      );
      void loadProvider(p.id).then((r) => {
        providerPending = providerPending.filter((id) => id !== p.id);
        if (r.ok) providerFiles = { ...providerFiles, [p.id]: r.data };
        else providerFailed = { ...providerFailed, [p.id]: r.error };
      });
    }
  }

  function askCatalog() {
    if (catalog) return askProviders(catalog);
    if (catalogLoading) return;
    catalogLoading = true;
    catalogError = null;
    void loadCatalog().then((r) => {
      catalogLoading = false;
      if (r.ok) {
        catalog = r.data;
        askProviders(r.data);
      } else catalogError = r.error;
    });
  }

  function onUrlInput(e: Event) {
    const text = (e.currentTarget as HTMLInputElement).value;
    catalogActive = -1;
    catalogOpen = !isUrlText(text) && text.trim() !== "";
    if (catalogOpen) askCatalog();
  }

  function pickCatalog(row: CatalogRow) {
    if (!addRow(row.url)) url = row.url;
    catalogOpen = false;
    catalogActive = -1;
  }

  function onUrlKey(e: KeyboardEvent) {
    if (!catalogShown) {
      if (e.key === "Enter" && canAdd) {
        e.preventDefault();
        addRow(url);
      }
      return;
    }
    const n = catalogHits.rows.length;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (n === 0) return;
      if (e.key === "ArrowDown") catalogActive = (catalogActive + 1) % n;
      else catalogActive = catalogActive <= 0 ? n - 1 : catalogActive - 1;
      const id = `gd-url-option-${catalogActive}`;
      void tick().then(() => document.getElementById(id)?.scrollIntoView({ block: "nearest" }));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (catalogActive >= 0 && catalogActive < n) pickCatalog(catalogHits.rows[catalogActive]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      catalogOpen = false;
      catalogActive = -1;
    } else if (e.key === "Tab") {
      catalogOpen = false;
    }
  }

  function resetPreview() {
    previewLoading = false;
    previewError = null;
    previewTotal = 0;
    previewByType = {};
    previewDropped = 0;
    previewUnconstrained = 0;
    previewRules = [];
    previewedUrl = null;
    previewKey = null;
  }

  $effect(() => {
    if (!open) {
      seededFor = null;
      return;
    }
    const key = mode === "edit" ? (group?.id ?? "edit") : "create";
    if (seededFor === key) return;

    name = group?.name ?? "";
    draft = {
      interface: group ? ifaceValue(ifaceList(group)) : (interfaces.list[0]?.id ?? ""),
    };
    devicesTarget = {
      id: group?.id ?? "draft",
      devices: group?.devices ? { ...group.devices } : { allow: [], deny: [] },
    };
    rows = (group?.lists ?? []).map((list) => ({ key: list.id, id: list.id, url: list.url }));
    url = "";
    interval = group?.lists?.[0]?.interval ?? 86400;
    resetPreview();
    catalogOpen = false;
    catalogActive = -1;
    dnsMode = modeOf(group?.resolve);
    dnsServer = group?.resolve?.server ?? "";
    cloudflare = group?.cloudflare ?? false;
    fallbackOn = group?.resolve?.fallback !== false;
    serverErrorShown = serverError;
    void fetchResolvers();
    seededFor = key;
  });

  let devicesLabel = $derived(
    coverageLabel(devicesTarget.devices, hosts.list, policies.list, t, locale.current),
  );

  let isUrlValid = $derived(
    rows.every((_, i) => rowProblem(i) === null) && (url.trim() === "" || canAdd),
  );
  let isSinkChoice = $derived(isSink(selectedInterface));
  let isDnsChoice = $derived(selectedInterface === DNS);
  let firmwareServers = $derived(firmwareServersFor(resolvers.list, selectedInterface));
  let isEditingSavedAuto = $derived(isSavedAutoUnchanged(group, mode, selectedInterface, dnsMode));
  let autoServers = $derived(
    autoEffectiveServers({
      isEditingSavedAuto,
      resolver: group?.resolver,
      firmwareServers,
    }),
  );
  let serverCheck = $derived(
    isDnsChoice
      ? dnsServer.trim() === ""
        ? null
        : resolverListProblem(dnsServer.trim())
      : dnsMode === "own" && !isSinkChoice
        ? resolverListProblem(dnsServer.trim())
        : null,
  );
  let serverProblem = $derived(serverCheck?.problem ?? null);
  let problemText = $derived(serverProblemText(serverCheck, dnsServer, t));
  let dnsServerHasError = $derived(
    serverErrorShown !== null || (dnsServer !== "" && serverProblem !== null),
  );
  let dnsOptions = $derived([
    { value: "auto", label: t("Through the tunnel — automatic") },
    { value: "own", label: t("Through the tunnel — own server") },
    { value: "off", label: t("Not through the tunnel") },
  ]);
  let canSubmit = $derived(isUrlValid && serverProblem === null);

  function handleClose() {
    dispatch("close");
  }

  async function runPreview(row: Row) {
    const target = normalizeListUrl(row.url);
    if (!target) return;
    previewKey = row.key;
    previewLoading = true;
    previewError = null;
    try {
      const res = await fetcher.get<{
        rules: ListRule[];
        total?: number;
        byType?: Record<string, number>;
        dropped?: number;
        unconstrained?: number;
      }>(`/groups/list/preview?url=${encodeURIComponent(target)}`, { quiet: true });
      if (previewKey !== row.key) return;
      previewRules = res.rules ?? [];
      previewTotal = res.total ?? previewRules.length;
      previewByType = res.byType ?? {};
      previewDropped = res.dropped ?? 0;
      previewUnconstrained = res.unconstrained ?? 0;
      previewedUrl = target;
    } catch (e) {
      if (previewKey !== row.key) return;
      previewRules = [];
      previewTotal = 0;
      previewByType = {};
      previewDropped = 0;
      previewUnconstrained = 0;
      previewedUrl = null;
      let message = t("Failed to fetch rules");
      if (e instanceof HttpError) {
        try {
          const body = JSON.parse(e.message);
          if (body?.error) message = body.error;
        } catch {
          /* not JSON -- keep the generic message */
        }
      }
      previewError = message;
    } finally {
      if (previewKey === row.key) previewLoading = false;
    }
  }

  function ruleTypeLabel(type: string): string {
    return RULE_TYPES.find((rt) => rt.value === type)?.label ?? type;
  }

  let typeBreakdown = $derived.by(() =>
    Object.entries(previewByType)
      .filter(([, count]) => count > 0)
      .map(([type, count]) => `${count} ${ruleTypeLabel(type)}`)
      .join(", "),
  );

  const POSITION_KEY = "firc.groupAddPosition";

  function readPosition(): "start" | "end" {
    try {
      return localStorage.getItem(POSITION_KEY) === "start" ? "start" : "end";
    } catch {
      return "end";
    }
  }

  let position = $state<"start" | "end">(readPosition());

  function choosePosition(next: "start" | "end") {
    position = next;
    try {
      localStorage.setItem(POSITION_KEY, next);
    } catch {}
  }

  function handleSubmit() {
    if (!canSubmit) return;
    if (isDnsChoice && dnsServer.trim() === "") {
      serverErrorShown = t("A DNS only group needs a server");
      return;
    }
    if (url.trim() !== "") addRow(url);
    const payload: GroupDialogPayload = {
      name: name.trim(),
      interface: ifaceValue(ifaceList(draft)),
      devices: devicesTarget.devices,
      lists: rows.map((row) => ({
        ...(row.id ? { id: row.id } : {}),
        url: normalizeListUrl(row.url),
        interval,
      })),
      resolve: submittedResolve(selectedInterface, group?.resolve, dnsMode, dnsServer, fallbackOn),
      cloudflare: selectedInterface !== BLOCK && selectedInterface !== DNS && cloudflare,
      ...(mode === "create" ? { position } : {}),
    };
    dispatch("submit", payload);
    handleClose();
  }
</script>

{#snippet previewResult()}
  {#if previewError}
    <p class="preview-error">{previewError}</p>
  {:else if previewedUrl}
    <div class="preview-result">
      <div class="preview-counts">
        <span class="count">
          <b>{previewTotal}</b><span class="count-label">{t("total")}</span>
        </span>
        {#if typeBreakdown}
          <span class="breakdown">({typeBreakdown})</span>
        {/if}
      </div>
      {#if previewTotal === 0 && previewDropped === 0}
        <div class="preview-note">{t("This list holds nothing firc can route")}</div>
      {:else if previewDropped > 0}
        <div class="preview-note">
          {t("Lines that are not rules")}: {previewDropped}
          {#if previewTotal === 0}
            &mdash; {t("this list is in a format firc does not route")}
          {/if}
        </div>
      {/if}
      {#if previewUnconstrained > 0}
        <div class="preview-note">
          {t("Names without a protocol limit")}: {previewUnconstrained}
        </div>
      {/if}
      {#if previewRules.length > 0}
        {#if previewTotal > previewRules.length}
          <div class="preview-shown">
            {t("Showing the first {n}").replace("{n}", String(previewRules.length))}
          </div>
        {/if}
        <div class="preview-rules">
          {#each previewRules as rule (rule.id)}
            <div class="preview-rule-row">
              <span class="preview-rule-type">{ruleTypeLabel(rule.type)}</span>
              <span class="preview-rule-pattern">{rule.rule}</span>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
{/snippet}

{#snippet serverField(dns: boolean)}
  <div class="field">
    <label for="gd-dns-server">{t("Server")}</label>
    <div class="group-dialog-input-wrapper">
      <span class="icon"><Globe size={18} /></span>
      <input
        id="gd-dns-server"
        type="text"
        list="gd-dns-servers"
        placeholder={dns ? "https://dns.comss.one/dns-query, 9.9.9.9" : "9.9.9.9, 1.1.1.1"}
        bind:value={dnsServer}
        oninput={() => (serverErrorShown = null)}
        class:invalid={dnsServerHasError}
        aria-invalid={dnsServerHasError}
        aria-describedby={dnsServerHasError ? "gd-dns-server-error gd-dns-hint" : "gd-dns-hint"}
      />
      <datalist id="gd-dns-servers">
        {#each serverSuggestions(resolvers.list) as s}
          <option value={s}></option>
        {/each}
      </datalist>
    </div>
    {#if serverErrorShown}
      <span id="gd-dns-server-error" class="field-error dns-server-error">{serverErrorShown}</span>
    {:else if dnsServer !== "" && serverProblem !== null}
      <span id="gd-dns-server-error" class="field-error dns-server-error">{problemText}</span>
    {/if}
    <span id="gd-dns-hint" class="dns-hint">
      {dns
        ? t("The router asks these servers itself, not through a tunnel.")
        : t(
            "The server is asked through the tunnel, so a DNS server on the local network will not work.",
          )}
    </span>
  </div>
{/snippet}

<GenericDialog
  {open}
  title={mode === "create" ? t("New Group") : t("Group Settings")}
  on:close={handleClose}
  maxWidth={520}
>
  <div slot="body" class="group-dialog-content">
    <div class="row">
      <div class="field">
        <label for="gd-name">{t("Name")}</label>
        <div class="group-dialog-input-wrapper">
          <span class="icon"><Type size={18} /></span>
          <!-- svelte-ignore a11y_autofocus -->
          <input id="gd-name" class="group-name-input" type="text" bind:value={name} autofocus />
        </div>
      </div>
      <div class="field">
        <span class="lbl">{t("Interface")}</span>
        <IfacePicker bind:value={draft.interface} {live} closed="chain" class="interface-select" />
      </div>
    </div>

    <div class="field">
      <span class="lbl">{t("Devices")}</span>
      <button type="button" class="devices-button" onclick={() => (devicesDialogOpen = true)}>
        {devicesLabel}
      </button>
    </div>

    <div class="dns-block" id="gd-dns">
      <span class="lbl">{t("DNS")}</span>
      {#if !isDnsChoice}
        <Select
          options={dnsOptions}
          selected={dnsMode}
          onValueChange={(v: string) => (dnsMode = v as DnsMode)}
          disabled={isSinkChoice}
          ariaLabel={t("DNS")}
          class="dns-select"
        />
      {/if}
      {#if isDnsChoice}
        {@render serverField(true)}
        <div class="list-toggle">
          <Switch bind:checked={fallbackOn} aria-label={t("Fall back to the common DNS")} />
          <span class="list-toggle-label">{t("Fall back to the common DNS")}</span>
          <span class="list-toggle-hint"
            >{t("if the group's DNS does not answer, the common DNS answers")}</span
          >
        </div>
      {:else if selectedInterface === BLOCK}
        <span class="dns-blackhole-hint">{t("the daemon answers the group's names")}</span>
      {:else if isSinkChoice}
        <span class="dns-blackhole-hint">
          {t("A blackhole group has no tunnel: its names go to the common upstream.")}
        </span>
      {:else if dnsMode === "auto"}
        <span class="dns-effective">
          {autoServers.length > 0
            ? autoServers.join(", ")
            : t("the firmware has no DNS for this interface — common upstream")}
        </span>
      {:else if dnsMode === "own"}
        {@render serverField(false)}
      {/if}
    </div>

    {#if selectedInterface !== BLOCK && !isDnsChoice}
      <div class="list-toggle">
        <Switch bind:checked={cloudflare} aria-label={t("One Cloudflare address")} />
        <span class="list-toggle-label">{t("One Cloudflare address")}</span>
        <span class="list-toggle-hint"
          >{t(
            "This group's web traffic to Cloudflare sites goes through one checked Cloudflare address.",
          )}</span
        >
      </div>
    {/if}

    <div class="list-block">
      <div class="list-toggle">
        <span class="list-toggle-label">{t("Lists by URL")}</span>
        <span class="list-toggle-hint">{t("optional: without them the group is manual")}</span>
      </div>

      {#if rows.length > 0}
        <div class="gd-list-rows">
          {#each rows as row, i (row.key)}
            {@const problem = rowProblem(i)}
            <div class="gd-list-row">
              {#if problem === null}
                <span class="gd-list-name">{listName(rowUrls[i])}</span>
              {/if}
              <div class="gd-list-line">
                <div class="group-dialog-input-wrapper gd-list-field">
                  <span class="icon"><Link size={18} /></span>
                  <input
                    type="text"
                    class="gd-list-url"
                    class:invalid={problem !== null}
                    bind:value={row.url}
                    aria-label={t("List address")}
                    aria-invalid={problem !== null}
                    title={row.url}
                  />
                </div>
                <Button
                  type="button"
                  small
                  class="gd-list-preview"
                  aria-label={t("Preview")}
                  title={t("Preview")}
                  onclick={() => runPreview(row)}
                  disabled={problem !== null || (previewLoading && previewKey === row.key)}
                >
                  {#if previewLoading && previewKey === row.key}
                    <LoaderCircle class="spin" size={18} />
                  {:else}
                    <Eye size={18} />
                  {/if}
                </Button>
                <Button
                  type="button"
                  small
                  class="gd-list-remove"
                  aria-label={t("Remove list")}
                  title={t("Remove list")}
                  onclick={() => removeRow(row.key)}
                >
                  <X size={18} />
                </Button>
              </div>
              {#if problem !== null}
                <span class="field-error">{problem}</span>
              {/if}
              {#if previewKey === row.key}
                {@render previewResult()}
              {/if}
            </div>
          {/each}
        </div>
        <div class="preview-hint-line">
          <Eye size={14} /><span class="preview-hint">{t("fetches and parses, saves nothing")}</span
          >
        </div>
      {/if}

      <div class="field">
        <label for="gd-url">{t("Address or name")}</label>
        <div class="gd-list-line gd-add-line">
          <div class="group-dialog-input-wrapper gd-list-field">
            <span class="icon"><Link size={18} /></span>
            <input
              id="gd-url"
              type="text"
              role="combobox"
              autocomplete="off"
              aria-autocomplete="list"
              aria-expanded={catalogShown}
              aria-controls={catalogShown ? "gd-url-catalog" : undefined}
              aria-activedescendant={catalogShown &&
              catalogActive >= 0 &&
              catalogActive < catalogHits.rows.length
                ? `gd-url-option-${catalogActive}`
                : undefined}
              bind:value={url}
              oninput={onUrlInput}
              onkeydown={onUrlKey}
              onblur={() => (catalogOpen = false)}
              placeholder="https://example.com/list.txt"
              disabled={full}
              class:invalid={urlInvalid || urlTaken}
            />
          </div>
          <Button type="button" class="gd-list-add" onclick={() => addRow(url)} disabled={!canAdd}>
            {t("Add list")}
          </Button>
        </div>
        <span class="catalog-status" role="status">{catalogStatus}</span>
        {#if catalogShown}
          <div class="catalog-panel" id="gd-url-catalog">
            {#if catalogHits.rows.length > 0}
              <ul role="listbox" aria-label={t("Address or name")}>
                {#each catalogHits.rows as hit, i (i)}
                  <!-- svelte-ignore a11y_click_events_have_key_events -->
                  <li
                    id={`gd-url-option-${i}`}
                    role="option"
                    aria-selected={i === catalogActive}
                    class:active={i === catalogActive}
                    onpointerdown={(e) => e.preventDefault()}
                    onclick={() => pickCatalog(hit)}
                  >
                    <span class="catalog-name">{hit.name}</span>
                    <span class="catalog-badge">{hit.source}</span>
                  </li>
                {/each}
              </ul>
              {#if catalogHits.more > 0}
                <div class="catalog-note">
                  {t("{n} more").replace("{n}", String(catalogHits.more))}
                </div>
              {/if}
              {#if failedNames.length > 0}
                <div class="catalog-note catalog-error">
                  {t("Catalog unavailable: {names}").replace("{names}", failedNames.join(", "))}
                </div>
              {/if}
            {:else if catalogLoading || providerPending.length > 0}
              <div class="catalog-note">{t("loading the catalog…")}</div>
            {:else if catalogError !== null}
              <div class="catalog-note catalog-error">
                {catalogError || t("Catalog unavailable")}
              </div>
            {:else if failedNames.length > 0}
              <div class="catalog-note catalog-error">
                {t("Catalog unavailable: {names}").replace("{names}", failedNames.join(", "))}
              </div>
            {:else}
              <div class="catalog-note">{t("nothing found")}</div>
            {/if}
          </div>
        {/if}
        {#if urlInvalid}
          <span class="field-error">{t("Invalid URL")}</span>
        {:else if urlTaken}
          <span class="field-error">{t("List already exists")}</span>
        {:else if full}
          <span class="list-toggle-hint">{t("A group holds at most 16 lists")}</span>
        {/if}
      </div>

      {#if rows.length > 0 || url.trim() !== ""}
        <div class="field">
          <span class="lbl">{t("Update:")}</span>
          <Select
            options={intervalOptionsFor(interval, t)}
            selected={String(interval)}
            onValueChange={(value) => {
              const next = parseIntervalSeconds(value);
              if (next !== null) interval = next;
            }}
            class="interval-select"
            ariaLabel={t("Update:")}
          />
        </div>
      {/if}
    </div>
  </div>

  <div slot="actions" class="group-dialog-actions">
    {#if mode === "create"}
      <div class="position" title={t("Groups higher in the list are checked first")}>
        <span class="position-label">{t("Add:")}</span>
        <div class="position-seg" role="group" aria-label={t("Add:")}>
          <button
            type="button"
            data-position="start"
            aria-pressed={position === "start"}
            onclick={() => choosePosition("start")}>{t("at the start")}</button
          >
          <button
            type="button"
            data-position="end"
            aria-pressed={position === "end"}
            onclick={() => choosePosition("end")}>{t("at the end")}</button
          >
        </div>
      </div>
    {/if}
    <div class="button-container">
      <Button onclick={handleSubmit} disabled={!canSubmit} class="primary" style="width: 100%">
        {mode === "create" ? t("Create") : t("Save")}
      </Button>
    </div>
  </div>
</GenericDialog>

<DevicesDialog
  open={devicesDialogOpen}
  target={devicesTarget}
  on:close={() => (devicesDialogOpen = false)}
/>

<style>
  .catalog-status {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
  .group-dialog-content {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
    padding: 0.5rem 0 1rem;
  }

  .row {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.75rem;
  }

  @media (max-width: 700px) {
    .row {
      grid-template-columns: 1fr;
    }
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  label,
  .lbl {
    color: var(--text-2);
    font-size: 0.9rem;
  }

  .group-dialog-input-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  .icon {
    position: absolute;
    left: 0.75rem;
    color: var(--text-2);
    display: flex;
    align-items: center;
    pointer-events: none;
  }

  input,
  .devices-button,
  :global(.interface-select [data-select-trigger]),
  :global(.interval-select [data-select-trigger]),
  :global(.dns-select [data-select-trigger]) {
    background-color: var(--bg-dark-extra) !important;
    border: 1px solid var(--bg-light-extra) !important;
    color: var(--text) !important;
    padding: 0 0.75rem !important;
    height: 2.75rem !important;
    border-radius: 0.5rem !important;
    font-size: 1rem !important;
    font-family: var(--font) !important;
    outline: none !important;
    width: 100% !important;
    box-sizing: border-box !important;
    text-align: left;
  }

  :global(.interface-select),
  :global(.interval-select),
  :global(.dns-select) {
    width: 100% !important;
    max-width: 100% !important;
  }
  :global(.interface-select [data-select-trigger] > .selected),
  :global(.interval-select [data-select-trigger] > .selected),
  :global(.dns-select [data-select-trigger] > .selected) {
    width: 100%;
    justify-content: space-between;
  }
  :global(.interface-select .selected-text),
  :global(.interval-select .selected-text),
  :global(.dns-select .selected-text) {
    align-items: start;
  }
  :global(.interface-select .selected-value),
  :global(.interval-select .selected-value),
  :global(.dns-select .selected-value),
  :global(.interface-select .selected-description),
  :global(.interval-select .selected-description) {
    padding-left: 0;
  }

  #gd-dns-server::-webkit-calendar-picker-indicator {
    display: none !important;
  }

  .group-dialog-input-wrapper input {
    padding-left: 2.3rem !important;
  }

  input:focus,
  :global(.interface-select [data-select-trigger]:focus),
  :global(.interval-select [data-select-trigger]:focus),
  :global(.dns-select [data-select-trigger]:focus) {
    border-color: var(--accent) !important;
  }

  input.invalid {
    border-color: var(--red) !important;
  }

  .devices-button {
    cursor: pointer;
    color: var(--text-2) !important;
  }

  .list-block {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    padding: 0.9rem;
    border-radius: 0.6rem;
    border: 1px solid var(--bg-light-extra);
    background: var(--bg-dark-extra);
  }

  .list-toggle {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex-wrap: wrap;
  }

  .dns-block .list-toggle {
    margin-top: 0.5rem;
  }

  .list-toggle-label {
    font-size: 1rem;
    font-weight: 600;
  }

  .list-toggle-hint {
    font-size: 0.8rem;
    color: var(--text-2);
  }

  .dns-block {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .dns-block > .field {
    margin-top: 0.6rem;
  }

  .dns-effective,
  .dns-hint,
  .dns-blackhole-hint {
    font-size: 0.8rem;
    color: var(--text-2);
  }

  .gd-list-rows {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .gd-list-row {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    min-width: 0;
  }

  .gd-list-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 0.85rem;
    color: var(--text);
  }

  .gd-list-line {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    min-width: 0;
  }

  .gd-list-field {
    flex: 1 1 auto;
    min-width: 0;
  }

  .gd-list-url {
    text-overflow: ellipsis;
  }

  .gd-list-line :global(.gd-list-add) {
    flex: none;
    padding: 0.5rem 0.8rem;
    white-space: nowrap;
  }

  .gd-list-line :global(.gd-list-preview),
  .gd-list-line :global(.gd-list-remove) {
    flex: none;
  }

  @media (max-width: 700px) {
    .gd-add-line {
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    .gd-add-line .gd-list-field {
      flex-basis: 100%;
    }
  }

  .preview-hint-line {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    color: var(--text-2);
  }

  .preview-hint {
    min-width: 0;
    font-size: 0.8rem;
    line-height: 1.3;
    color: var(--text-2);
  }

  .preview-error {
    color: var(--red);
    font-size: 0.85rem;
    margin: 0;
  }

  .catalog-panel {
    box-sizing: border-box;
    padding: 0.3rem;
    background: var(--bg-dark);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
  }

  .catalog-panel ul {
    max-height: 16rem;
    overflow-y: auto;
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .catalog-panel li {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    min-width: 0;
    padding: 0.35rem 0.5rem;
    border-radius: 0.25rem;
    cursor: pointer;
  }

  .catalog-panel li:hover,
  .catalog-panel li.active {
    background: var(--bg-light-extra);
  }

  .catalog-name {
    flex: 1 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .catalog-badge {
    flex: none;
    padding: 0.05rem 0.4rem;
    border-radius: 0.3rem;
    background: var(--bg-light);
    color: var(--text-2);
    font-family: var(--font-mono);
    font-size: 0.75rem;
  }

  .catalog-note {
    padding: 0.35rem 0.5rem;
    color: var(--text-2);
    font-size: 0.85rem;
  }

  .catalog-error {
    color: var(--red);
  }

  .field-error {
    color: var(--red);
    font-size: 0.75rem;
  }

  .preview-result {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .preview-counts {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
  }

  .count b {
    font-size: 1.1rem;
  }

  .count-label {
    font-size: 0.75rem;
    color: var(--text-2);
    margin-left: 0.25rem;
  }

  .breakdown {
    font-size: 0.8rem;
    color: var(--text-2);
    font-style: italic;
  }

  .preview-note,
  .preview-shown {
    color: var(--text-2);
    font-size: 0.85rem;
  }

  .preview-rules {
    display: flex;
    flex-direction: column;
  }

  .preview-rule-row {
    display: grid;
    grid-template-columns: 110px minmax(0, 1fr);
    gap: 0.5rem;
    height: 1.9rem;
    align-items: center;
    font-size: 0.85rem;
    border-top: 1px solid var(--bg-light-extra);
  }

  .preview-rule-type {
    color: var(--text-2);
  }

  .preview-rule-pattern {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .group-dialog-actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    flex-wrap: wrap;
    width: 100%;
  }

  .position {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--text-2);
    font-size: 0.9rem;
  }

  .position-seg {
    display: flex;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    padding: 0.2rem;
    gap: 0.2rem;
  }

  .position-seg button {
    all: unset;
    cursor: pointer;
    padding: 0.42rem 0.7rem 0.38rem;
    border-radius: 0.35rem;
    color: color-mix(in srgb, var(--text-2) 75%, transparent);
    font-size: 0.92rem;
    white-space: nowrap;
  }

  .position-seg button:hover {
    color: var(--text);
  }

  .position-seg button:focus-visible {
    outline: 2px solid var(--accent, currentColor);
  }

  .position-seg button[aria-pressed="true"] {
    background: color-mix(in srgb, var(--accent, var(--text)) 16%, var(--bg-light-extra));
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--accent, var(--text)) 55%, transparent);
    color: var(--text);
  }

  @media (max-width: 700px) {
    .group-dialog-actions {
      flex-direction: column;
      align-items: stretch;
    }

    .position {
      justify-content: space-between;
    }
  }

  .button-container {
    width: 33.33%;
    min-width: 140px;
  }

  @media (max-width: 700px) {
    .button-container {
      width: 100%;
    }
  }

  :global(.spin) {
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }
</style>
