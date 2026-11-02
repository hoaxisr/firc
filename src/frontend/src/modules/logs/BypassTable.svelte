<script lang="ts">
  import { DropdownMenu } from "bits-ui";
  import { onDestroy } from "svelte";

  import Button from "../../components/ui/Button.svelte";
  import { autolist, ruleCovering, whyClass, whyLabel } from "../../data/autolist.svelte";
  import { relativeTime, rowDevices, statsDevices } from "../../data/dnsstats.svelte";
  import { groupsBridge } from "../../data/groups-bridge.svelte";
  import { hosts } from "../../data/hosts.svelte";
  import { knownGroups } from "../../data/known-groups.svelte";
  import { locale, t } from "../../data/locale.svelte";
  import { tabRequest } from "../../data/tab-request.svelte";

  import { SelectOpen, X } from "../../components/ui/icons";
  import type { AutolistAddress, Group } from "../../types";
  import { toast } from "../../utils/events";
  import { fetcher } from "../../utils/fetcher";
  import { counted } from "../../utils/plural";

  let { addresses }: { addresses: AutolistAddress[] } = $props();

  const CLOCK_MS = 30_000;

  let now = $state(Math.floor(Date.now() / 1000));
  let busy = $state<Set<string>>(new Set());

  const clock = setInterval(() => (now = Math.floor(Date.now() / 1000)), CLOCK_MS);
  onDestroy(() => clearInterval(clock));

  const devices = $derived(statsDevices(hosts.list, []));
  const store = $derived(groupsBridge.store);
  const groups = $derived<Group[]>(store?.dataLoaded ? store.data : []);

  function failures(n: number): string {
    return counted(n, locale.current, t("{n} failure"), t("{n} failures (2-4)"), t("{n} failures"));
  }

  function key(a: AutolistAddress): string {
    return `${a.address}/${a.proto}/${a.port}`;
  }

  function groupName(id: string): string {
    return knownGroups.list.find((g) => g.id === id)?.name ?? id;
  }

  function devicesOf(a: AutolistAddress) {
    return rowDevices(
      a.clients.map((address) => ({ address, queries: 1 })),
      devices,
    );
  }

  function ptrText(a: AutolistAddress): string {
    if (a.ptrState === "name") return `PTR: ${a.ptr}`;
    return a.ptrState === "pending" ? "PTR: …" : "PTR: —";
  }

  function metaText(a: AutolistAddress): string {
    const names = devicesOf(a).map((d) => d.label);
    return [`${a.proto}/${a.port}`, failures(a.fails), names.join(" · ")]
      .filter(Boolean)
      .join(" · ");
  }

  function mark(k: string, on: boolean) {
    const next = new Set(busy);
    if (on) next.add(k);
    else next.delete(k);
    busy = next;
  }

  function syncGroups() {
    const st = groupsBridge.store;
    if (st?.dataLoaded && !st.tracker.isDirty) void st.mount();
  }

  async function add(a: AutolistAddress, groupId: string) {
    const k = key(a);
    mark(k, true);
    try {
      const v6 = a.address.includes(":");
      await fetcher.post(`/groups/${groupId}/rules?save=true`, {
        type: v6 ? "subnet6" : "subnet",
        rule: `${a.address}/${v6 ? 128 : 32}`,
        enable: true,
        proto: a.proto,
        ports: String(a.port),
        comment: a.name || a.ptr || "",
      });
      toast.success(
        t("{address} added to «{group}»")
          .replace("{address}", a.address)
          .replace("{group}", groupName(groupId)),
      );
      syncGroups();
    } catch {
    } finally {
      mark(k, false);
    }
  }

  async function dismiss(a: AutolistAddress) {
    const k = key(a);
    mark(k, true);
    try {
      await autolist.dismissAddress(a);
    } catch {
    } finally {
      mark(k, false);
    }
  }
</script>

{#if addresses.length > 0}
  <h3 class="title">{t("Addresses past firc")}</h3>
  <div class="card">
    <div class="head" aria-hidden="true">
      <span>{t("Address")}</span>
      <span>{t("Name ")}</span>
      <span>{t("Port")}</span>
      <span class="num">{t("Failures")}</span>
      <span>{t("Devices")}</span>
      <span>{t("Last")}</span>
      <span></span>
    </div>
    {#each addresses as a (key(a))}
      {@const devs = devicesOf(a)}
      {@const locked = busy.has(key(a))}
      {@const covering = ruleCovering(groups, a.groups, a.address)}
      <div class="row" data-address={a.address}>
        <span class="addr">
          <span class="ip">{a.address}</span>
          <span class="ptr" title={a.ptrState === "name" ? a.ptr : undefined}>{ptrText(a)}</span>
        </span>
        <span class="nm">
          <span class="sni" title={a.name}>{a.name || "—"}</span>
          <span class="pill {whyClass(a.why)}">{whyLabel(a.why, 0, t)}</span>
          <span class="meta">{metaText(a)}</span>
        </span>
        <span class="port">{a.proto}/{a.port}</span>
        <span class="num">{a.fails}</span>
        <span class="devs">
          {#each devs.slice(0, 2) as d (d.key)}
            <span class="dev">
              <span class="dn">{d.label}</span>
              {#if d.label !== d.address}<span class="da">{d.address}</span>{/if}
            </span>
          {/each}
          {#if devs.length > 2}
            <span class="more">{t("and {n} more").replace("{n}", String(devs.length - 2))}</span>
          {/if}
        </span>
        <span class="last">{relativeTime(a.lastAt, now, t)}</span>
        <span class="act">
          {#if covering}
            <Button onclick={() => tabRequest.open("groups", covering.rule)} inactive={locked}
              >{t("To the rule")}</Button
            >
          {:else if a.groups.length > 0}
            <DropdownMenu.Root>
              <DropdownMenu.Trigger disabled={locked}>
                {#snippet child({ props })}
                  <Button {...props} class="primary"
                    >{t("To group")}<SelectOpen size={14} aria-hidden="true" /></Button
                  >
                {/snippet}
              </DropdownMenu.Trigger>
              <DropdownMenu.Portal>
                <DropdownMenu.Content
                  class="bp-menu"
                  align="end"
                  sideOffset={4}
                  collisionPadding={8}
                >
                  {#each a.groups as id (id)}
                    <DropdownMenu.Item class="bp-item" onSelect={() => void add(a, id)}>
                      {groupName(id)}
                    </DropdownMenu.Item>
                  {/each}
                </DropdownMenu.Content>
              </DropdownMenu.Portal>
            </DropdownMenu.Root>
          {/if}
          <Button
            aria-label={t("Dismiss for a day")}
            title={t("Dismiss for a day")}
            onclick={() => void dismiss(a)}
            inactive={locked}><X size={14} aria-hidden="true" /></Button
          >
        </span>
      </div>
    {/each}
  </div>
{/if}

<style>
  .title {
    margin: 1rem 0 0.5rem;
    font-size: 0.95rem;
    font-weight: 700;
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
      minmax(0, 1.5fr) minmax(0, 1.3fr) 4.5rem 3.5rem minmax(0, 1.1fr) minmax(0, 0.7fr)
      9.5rem;
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
  .addr,
  .nm,
  .devs,
  .dev {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .addr {
    line-height: 1.25;
  }
  .ip {
    font-family: var(--font-mono);
    font-weight: 700;
    overflow-wrap: anywhere;
  }
  .ptr,
  .port,
  .last,
  .more {
    color: var(--text-2);
  }
  .ptr {
    font-family: var(--font-mono);
    font-size: 0.74rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .nm {
    align-items: flex-start;
    gap: 0.2rem;
  }
  .sni {
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .meta {
    display: none;
  }
  .port {
    font-family: var(--font-mono);
    font-size: 0.8rem;
  }
  .last {
    font-size: 0.8rem;
  }
  .num {
    text-align: left;
    font-variant-numeric: tabular-nums;
  }
  .pill {
    display: inline-flex;
    max-width: 100%;
    padding: 0.1rem 0.5rem;
    border-radius: 0.4rem;
    font-size: 0.76rem;
    font-weight: 600;
    line-height: 1.3;
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
  .devs {
    gap: 0.2rem;
  }
  .dev {
    line-height: 1.2;
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
  }
  .act {
    display: flex;
    gap: 0.4rem;
    justify-content: flex-end;
  }
  .act :global(button) {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.35rem 0.7rem;
    font-size: 0.88rem;
    white-space: nowrap;
  }
  .act :global(button[aria-label]) {
    padding: 0.4rem 0.5rem;
  }
  :global(.bp-menu) {
    min-width: 10rem;
    max-width: min(20rem, 90vw);
    padding: 0.2rem;
    background: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
    z-index: 20;
  }
  :global(.bp-item[data-dropdown-menu-item]) {
    padding: 0.5rem 0.6rem;
    border-radius: 0.4rem;
    color: var(--text-2);
    cursor: pointer;
    outline: none;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  :global(.bp-item[data-dropdown-menu-item][data-highlighted]) {
    background: var(--bg-light-extra);
    color: var(--text);
  }
  @container (max-width: 760px) {
    .head {
      display: none;
    }
    .row {
      grid-template-columns: minmax(0, 1fr) auto;
      grid-template-areas:
        "addr last"
        "nm nm"
        "act act";
      gap: 0.4rem 0.6rem;
      padding: 0.7rem 0.8rem;
    }
    .addr {
      grid-area: addr;
    }
    .nm {
      grid-area: nm;
      flex-direction: row;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.2rem 0.6rem;
    }
    .port,
    .num,
    .devs {
      display: none;
    }
    .meta {
      display: inline;
      color: var(--text-2);
      font-size: 0.8rem;
    }
    .last {
      grid-area: last;
    }
    .act {
      grid-area: act;
      justify-content: flex-start;
    }
  }
</style>
