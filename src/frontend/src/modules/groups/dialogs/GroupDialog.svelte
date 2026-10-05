<script lang="ts">
  import { createEventDispatcher } from "svelte";

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
  import { isValidListUrl, normalizeListUrl, type GroupDialogPayload } from "../groups.svelte";

  import { Globe, Link, LoaderCircle, Type } from "../../../components/ui/icons";
  import { RULE_TYPES, type DeviceSelector, type Group, type ListRule } from "../../../types";
  import { coverageLabel } from "../../../utils/device-picker";
  import { fetcher, HttpError } from "../../../utils/fetcher";
  import { resolverAddrProblem } from "../../../utils/resolver-validators";
  import { intervalOptionsFor, parseIntervalSeconds } from "../intervals";
  import {
    autoEffectiveServers,
    firmwareServersFor,
    isSavedAutoUnchanged,
    modeOf,
    serverSuggestions,
    submittedResolve,
    type DnsMode,
  } from "../resolve-choice";

  type DialogProps = {
    open: boolean;
    mode: "create" | "edit";
    group?: Group | null;
    serverError?: string | null;
  };

  let { open, mode, group = null, serverError = null }: DialogProps = $props();
  const dispatch = createEventDispatcher();

  let name = $state("");
  let selectedInterface = $state("");
  let listEnabled = $state(false);
  let url = $state("");
  let interval = $state(86400);
  let seededFor = $state<string | null>(null);

  let dnsMode = $state<DnsMode>("auto");
  let dnsServer = $state("");
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

  function resetPreview() {
    previewLoading = false;
    previewError = null;
    previewTotal = 0;
    previewByType = {};
    previewDropped = 0;
    previewUnconstrained = 0;
    previewRules = [];
    previewedUrl = null;
  }

  $effect(() => {
    if (!open) {
      seededFor = null;
      return;
    }
    const key = mode === "edit" ? (group?.id ?? "edit") : "create";
    if (seededFor === key) return;

    name = group?.name ?? "";
    selectedInterface = group?.interface ?? interfaces.list[0]?.id ?? "";
    devicesTarget = {
      id: group?.id ?? "draft",
      devices: group?.devices ? { ...group.devices } : { allow: [], deny: [] },
    };
    listEnabled = Boolean(group?.list);
    url = group?.list?.url ?? "";
    interval = group?.list?.interval ?? 86400;
    resetPreview();
    dnsMode = modeOf(group?.resolve);
    dnsServer = group?.resolve?.server ?? "";
    serverErrorShown = serverError;
    void fetchResolvers();
    seededFor = key;
  });

  let devicesLabel = $derived(
    coverageLabel(devicesTarget.devices, hosts.list, policies.list, t, locale.current),
  );

  let isUrlValid = $derived(!listEnabled || isValidListUrl(url));
  let isBlackhole = $derived(selectedInterface === "blackhole");
  let firmwareServers = $derived(firmwareServersFor(resolvers.list, selectedInterface));
  let isEditingSavedAuto = $derived(isSavedAutoUnchanged(group, mode, selectedInterface, dnsMode));
  let autoServers = $derived(
    autoEffectiveServers({
      isEditingSavedAuto,
      resolver: group?.resolver,
      firmwareServers,
    }),
  );
  let serverProblem = $derived(
    dnsMode === "own" && !isBlackhole ? resolverAddrProblem(dnsServer.trim()) : null,
  );
  let serverProblemText = $derived.by(() => {
    if (serverProblem === "port") return t("The port must be between 1 and 65535");
    if (serverProblem === "sink")
      return t("This address cannot be a DNS server (0.0.0.0, 127.x, ::, ::1)");
    if (serverProblem === "mapped") return t("Write the IPv4 address itself");
    if (serverProblem === "syntax") return t("An address, address:port, or [IPv6]:port");
    return "";
  });
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

  async function runPreview() {
    const target = normalizeListUrl(url);
    if (!target) return;
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
      previewRules = res.rules ?? [];
      previewTotal = res.total ?? previewRules.length;
      previewByType = res.byType ?? {};
      previewDropped = res.dropped ?? 0;
      previewUnconstrained = res.unconstrained ?? 0;
      previewedUrl = target;
    } catch (e) {
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
      previewLoading = false;
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

  function handleSubmit() {
    if (!canSubmit) return;
    const payload: GroupDialogPayload = {
      name: name.trim(),
      interface: selectedInterface,
      devices: devicesTarget.devices,
      list: listEnabled ? { url: normalizeListUrl(url), interval } : null,
      resolve: submittedResolve(isBlackhole, group?.resolve, dnsMode, dnsServer),
    };
    dispatch("submit", payload);
    handleClose();
  }
</script>

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
        <Select
          options={interfaces.list.map((item) => ({
            value: item.id,
            label: item.id,
            description: item.name,
          }))}
          bind:selected={selectedInterface}
          class="interface-select"
        />
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
      <Select
        options={dnsOptions}
        selected={dnsMode}
        onValueChange={(v: string) => (dnsMode = v as DnsMode)}
        disabled={isBlackhole}
        ariaLabel={t("DNS")}
        class="dns-select"
      />
      {#if isBlackhole}
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
        <div class="field">
          <label for="gd-dns-server">{t("Server")}</label>
          <div class="group-dialog-input-wrapper">
            <span class="icon"><Globe size={18} /></span>
            <input
              id="gd-dns-server"
              type="text"
              list="gd-dns-servers"
              placeholder="9.9.9.9"
              bind:value={dnsServer}
              oninput={() => (serverErrorShown = null)}
              class:invalid={dnsServerHasError}
              aria-invalid={dnsServerHasError}
              aria-describedby={dnsServerHasError
                ? "gd-dns-server-error gd-dns-hint"
                : "gd-dns-hint"}
            />
            <datalist id="gd-dns-servers">
              {#each serverSuggestions(resolvers.list) as s}
                <option value={s}></option>
              {/each}
            </datalist>
          </div>
          {#if serverErrorShown}
            <span id="gd-dns-server-error" class="field-error dns-server-error"
              >{serverErrorShown}</span
            >
          {:else if dnsServer !== "" && serverProblem !== null}
            <span id="gd-dns-server-error" class="field-error dns-server-error"
              >{serverProblemText}</span
            >
          {/if}
          <span id="gd-dns-hint" class="dns-hint">
            {t(
              "The server is asked through the tunnel, so a DNS server on the local network will not work.",
            )}
          </span>
        </div>
      {/if}
    </div>

    <div class="list-block">
      <div class="list-toggle">
        <Switch bind:checked={listEnabled} aria-label={t("List by URL")} />
        <span class="list-toggle-label">{t("List by URL")}</span>
        <span class="list-toggle-hint">{t("optional: without it the group is manual")}</span>
      </div>

      {#if listEnabled}
        <div class="field">
          <label for="gd-url">{t("Address")}</label>
          <div class="group-dialog-input-wrapper">
            <span class="icon"><Link size={18} /></span>
            <input
              id="gd-url"
              type="text"
              bind:value={url}
              placeholder="https://example.com/list.txt"
              class:invalid={url !== "" && !isValidListUrl(url)}
            />
          </div>
          {#if url !== "" && !isValidListUrl(url)}
            <span class="field-error">{t("Invalid URL")}</span>
          {/if}
        </div>
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

        <div class="preview-row">
          <Button
            type="button"
            onclick={runPreview}
            disabled={!isValidListUrl(url) || previewLoading}
          >
            <div class="button-content">
              {#if previewLoading}
                <LoaderCircle class="spin" size={16} />
              {/if}
              <span>{t("Preview")}</span>
            </div>
          </Button>
          <span class="preview-hint">{t("fetches and parses, saves nothing")}</span>
        </div>

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
              <div class="preview-rules">
                {#each previewRules.slice(0, 3) as rule (rule.id)}
                  <div class="preview-rule-row">
                    <span class="preview-rule-type">{ruleTypeLabel(rule.type)}</span>
                    <span class="preview-rule-pattern">{rule.rule}</span>
                  </div>
                {/each}
              </div>
            {/if}
          </div>
        {/if}
      {/if}
    </div>

    {#if mode === "create"}
      <p class="footer-note">
        {t("The group goes to the end of the list. Drag it up to have it take names earlier.")}
      </p>
    {/if}
  </div>

  <div slot="actions" class="group-dialog-actions">
    <div class="button-container">
      <Button onclick={handleSubmit} disabled={!canSubmit} style="width: 100%">
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

  .preview-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .preview-row :global(button) {
    flex: 0 0 auto;
    padding: 0.5rem 1rem;
  }

  .preview-hint {
    flex: 1 1 auto;
    min-width: 0;
    font-size: 0.8rem;
    line-height: 1.3;
    color: var(--text-2);
  }

  .button-content {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .preview-error {
    color: var(--red);
    font-size: 0.85rem;
    margin: 0;
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

  .preview-note {
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

  .footer-note {
    margin: 0;
    font-size: 0.8rem;
    color: var(--text-2);
    line-height: 1.4;
  }

  .group-dialog-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    width: 100%;
  }

  .button-container {
    width: 33.33%;
    min-width: 140px;
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
