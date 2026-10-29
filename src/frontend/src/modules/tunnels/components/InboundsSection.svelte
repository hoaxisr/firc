<script lang="ts">
  import Button from "../../../components/ui/Button.svelte";
  import Select from "../../../components/ui/Select.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { interfaces } from "../../../data/interfaces.svelte";
  import { t } from "../../../data/locale.svelte";
  import { loadSettings, settings } from "../../settings/settings.svelte";
  import type { TunnelsStore } from "../tunnels.svelte";

  import { Add, Delete, Eye, EyeOff } from "../../../components/ui/icons";
  import { ifaceTitle } from "../../../data/iface-choices";
  import {
    inboundLook,
    inboundRefusal,
    MAX_INBOUNDS,
    nextInboundPort,
    WHOLE_GROUP,
  } from "../inbounds";
  import type { ClientTunnel } from "../tunnels-data";

  let { store, tunnel = $bindable() }: { store: TunnelsStore; tunnel: ClientTunnel } = $props();

  let shown = $state<Record<number, boolean>>({});

  $effect(() => {
    if (!settings.loaded) void loadSettings();
  });

  const link = $derived(store.link);
  const live = $derived(store.stateOf(tunnel.id));
  const saved = $derived(store.isSaved(tunnel.id));
  const rows = $derived(store.nodeRows[tunnel.key] ?? []);
  const refusal = $derived(
    inboundRefusal(
      tunnel.inbounds,
      store.data.filter((o) => o.key !== tunnel.key),
      link,
      t,
    ),
  );
  const daemonRefusal = $derived(store.refusalFor(tunnel.id));
  const inboundDaemon = $derived(daemonRefusal?.field?.startsWith("inbounds[") ?? false);
  const full = $derived(tunnel.inbounds.length >= MAX_INBOUNDS);

  function titleOf(id: string): string {
    const item = interfaces.list.find((i) => i.id === id);
    return item ? ifaceTitle(item).title : id;
  }

  const listenOptions = (current: string) =>
    [...link, ...(current && !link.includes(current) ? [current] : [])].map((id) => ({
      value: id,
      label: titleOf(id),
    }));

  const nodeOptions = (current: string) => [
    { value: WHOLE_GROUP, label: t("Whole group") },
    ...rows.map((r) => ({
      value: r.key,
      label: `${r.name} · ${r.source === "link" ? t("link") : r.source}`,
    })),
    ...(current && current !== WHOLE_GROUP && !rows.some((r) => r.key === current)
      ? [{ value: current, label: current }]
      : []),
  ];

  function add() {
    if (full) return;
    tunnel.inbounds.push({
      port: nextInboundPort(tunnel.inbounds),
      listen: link[0] ?? "",
      node: rows[0]?.key ?? "",
      user: "",
      password: "",
    });
  }

  function remove(index: number) {
    tunnel.inbounds.splice(index, 1);
    shown = {};
  }

  const flagged = $derived.by(() => {
    const m = /^inbounds\[(\d+)\]\.(\w+)$/.exec(daemonRefusal?.field ?? "");
    if (m) return { index: Number(m[1]), field: m[2] };
    return refusal ? { index: refusal.index, field: refusal.field.split(".")[1] ?? "" } : null;
  });
  const bad = (index: number, field: string) => flagged?.index === index && flagged.field === field;

  function stateOf(port: number) {
    return saved ? live?.inbounds?.find((s) => s.port === port) : undefined;
  }
</script>

<section class="sec">
  <div class="sec-h">
    <span>{t("Inbound ports")}</span>
    <span class="sp"></span>
    <Button small class="text-btn" inactive={full || link.length === 0} onclick={add}>
      <Add size={15} />{t("Add port")}
    </Button>
  </div>
  <div class="hint">
    {t(
      "SOCKS5 and HTTP CONNECT on the router's address; traffic goes only through the chosen node, or through the whole group as the tunnel spreads it",
    )}
  </div>

  {#if refusal && !inboundDaemon}
    <div class="inb-refusal" role="alert">
      <code>{refusal.field}</code>
      {refusal.text}
    </div>
  {/if}

  {#if tunnel.inbounds.length > 0}
    <div class="head">
      <span>{t("Port")}</span>
      <span>{t("Interface")}</span>
      <span>{t("Node")}</span>
      <span>{t("Login")}</span>
      <span>{t("Password")}</span>
      <span></span>
    </div>
  {/if}

  {#each tunnel.inbounds as ib, index (index)}
    {@const st = stateOf(ib.port)}
    {@const look = st ? inboundLook(st.state, ib.listen, t) : null}
    <div class="inb" data-inbound={index}>
      <div class="cell">
        <span class="lab">{t("Port")}</span>
        <input
          type="number"
          min="1"
          max="65535"
          aria-label={t("Port")}
          class:invalid={bad(index, "port")}
          aria-invalid={bad(index, "port")}
          bind:value={ib.port}
        />
      </div>
      <div class="cell">
        <span class="lab">{t("Interface")}</span>
        <Select
          ariaLabel={t("Interface")}
          options={listenOptions(ib.listen)}
          selected={ib.listen}
          onValueChange={(v: string) => (ib.listen = v)}
        />
      </div>
      <div class="cell wide">
        <span class="lab">{t("Node")}</span>
        <Select
          ariaLabel={t("Node")}
          options={nodeOptions(ib.node)}
          selected={ib.node}
          onValueChange={(v: string) => (ib.node = v)}
        />
      </div>
      <div class="cell">
        <span class="lab">{t("Login")}</span>
        <input
          type="text"
          autocomplete="off"
          maxlength="255"
          aria-label={t("Login")}
          class:invalid={bad(index, "user")}
          aria-invalid={bad(index, "user")}
          bind:value={ib.user}
        />
      </div>
      <div class="cell">
        <span class="lab">{t("Password")}</span>
        <span class="pw">
          <input
            type={shown[index] ? "text" : "password"}
            autocomplete="new-password"
            maxlength="255"
            aria-label={t("Password")}
            class:invalid={bad(index, "password")}
            aria-invalid={bad(index, "password")}
            bind:value={ib.password}
          />
          <Tooltip value={t(shown[index] ? "Hide the password" : "Show the password")}>
            <Button
              small
              aria-label={t(shown[index] ? "Hide the password" : "Show the password")}
              aria-pressed={Boolean(shown[index])}
              onclick={() => (shown[index] = !shown[index])}
            >
              {#if shown[index]}<EyeOff size={20} />{:else}<Eye size={20} />{/if}
            </Button>
          </Tooltip>
        </span>
      </div>
      <div class="cell del">
        <Tooltip value={t("Delete")}>
          <Button small onclick={() => remove(index)}>
            <Delete size={20} />
          </Button>
        </Tooltip>
      </div>
      {#if look && st}
        <span class="st {look.tone}" title={st.why}>{look.text}</span>
      {/if}
    </div>
  {/each}
</section>

<style>
  .sec-h {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 14px;
    font-weight: 600;
    font-size: 1.05rem;
    background: var(--bg-light);
  }
  .sp {
    flex: 1;
  }
  .sec-h :global(.text-btn) {
    font-size: 0.85rem;
    gap: 6px;
    border: 1px solid var(--bg-light-extra);
    background: var(--bg-light-extra);
    color: var(--text);
    padding: 0.25rem 0.6rem;
  }
  .hint {
    padding: 8px 14px;
    color: var(--text-2);
    font-size: 0.85rem;
  }
  .inb-refusal {
    color: var(--red);
    font-size: 0.9rem;
    padding: 4px 14px 8px;
  }
  .head,
  .inb {
    display: grid;
    grid-template-columns:
      6rem minmax(0, 1.5fr) minmax(0, 1.7fr) minmax(0, 1fr) minmax(0, 1.4fr)
      2.5rem;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.9rem;
  }
  .head {
    color: var(--text-2);
    font-size: 0.8rem;
    border-top: 1px solid var(--bg-light-extra);
  }
  .inb {
    border-top: 1px solid var(--bg-light-extra);
  }
  .inb input {
    box-sizing: border-box;
    min-width: 0;
    width: 100%;
    padding: 6px 10px;
    border-radius: 8px;
    background: var(--bg-light);
    border: 1px solid var(--bg-light);
    color: var(--text);
    font: inherit;
  }
  .pw {
    display: flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
  }
  .st {
    grid-column: 1 / -1;
    font-size: 0.8rem;
    color: var(--text-2);
  }
  .st.green {
    color: var(--green);
  }
  .st.red {
    color: var(--red);
  }
  .st.orange {
    color: var(--orange);
  }
  .inb input.invalid {
    border-color: var(--red);
  }
  .cell {
    min-width: 0;
  }
  .cell :global(.select-wrap),
  .inb :global([data-select-trigger]) {
    max-width: 100%;
    min-width: 0;
  }
  .lab {
    display: none;
  }
  @media (max-width: 700px) {
    .head {
      display: none;
    }
    .inb {
      grid-template-columns: repeat(2, minmax(0, 1fr)) auto;
      gap: 0.5rem 0.75rem;
      align-items: start;
    }
    .cell:nth-child(2) {
      grid-column: 2 / -1;
    }
    .lab {
      display: block;
      color: var(--text-2);
      font-size: 0.75rem;
      margin-bottom: 2px;
    }
    .cell.wide {
      grid-column: 1 / -1;
    }
    .cell.del {
      grid-column: 3;
      align-self: end;
    }
  }
</style>
