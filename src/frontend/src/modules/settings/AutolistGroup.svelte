<script lang="ts">
  import { onMount } from "svelte";

  import Select from "../../components/ui/Select.svelte";
  import { fetchInterfaces, interfaces } from "../../data/interfaces.svelte";
  import { t } from "../../data/locale.svelte";

  import { ifaceTitle, isSink } from "../../data/iface-choices";
  import { toast } from "../../utils/events";
  import { fetcher } from "../../utils/fetcher";
  import { hasGroupNamed } from "./settings";

  type Props = {
    value: string;
    onchange: (id: string) => void;
    ariaLabel: string;
    invalid?: boolean;
    required?: boolean;
    changed?: string;
  };
  let {
    value,
    onchange,
    ariaLabel,
    invalid = false,
    required = false,
    changed = "",
  }: Props = $props();

  type GroupItem = { id: string; name: string; interface?: string | string[] };

  const NEW = "new";
  const AUTOLIST_NAME = $derived(t("Autolist"));

  let groups = $state<GroupItem[]>([]);
  let loaded = $state(false);
  let creating = $state(false);
  let wantNew = $state(false);
  let iface = $state("");

  async function loadGroups() {
    try {
      const res = await fetcher.get<{ groups?: GroupItem[] }>("/groups", { quiet: true });
      groups = res?.groups ?? [];
    } catch (error) {
      console.error("Failed to load groups:", error);
    } finally {
      loaded = true;
    }
  }

  onMount(() => {
    void loadGroups();
    if (interfaces.list.length === 0) void fetchInterfaces();
  });

  const offered = $derived(groups.filter((g) => g.interface !== "block"));
  const current = $derived(groups.find((g) => g.id === value));
  const tunnels = $derived([
    ...interfaces.list.filter((i) => i.role === "tunnel"),
    ...interfaces.list.filter((i) => i.role !== "tunnel" && i.role !== "lan" && !isSink(i.id)),
  ]);

  const haveOwn = $derived(hasGroupNamed(offered, ["Autolist", AUTOLIST_NAME]));
  const options = $derived([
    ...(haveOwn
      ? []
      : [{ value: NEW, label: t("New group {name}").replace("{name}", AUTOLIST_NAME) }]),
    ...offered.map((g) => ({ value: g.id, label: g.name || g.id, description: g.id, mono: true })),
    ...(current && !offered.includes(current)
      ? [{ value, label: current.name || current.id, hidden: true }]
      : []),
    ...(value === "" || current
      ? []
      : [{ value, label: t("A group that no longer exists"), missing: true }]),
    { value: "", label: t("not chosen"), hidden: true },
  ]);
  const ifaceOptions = $derived(
    tunnels.map((i) => {
      const { title, sub } = ifaceTitle(i);
      return { value: i.id, label: title, description: sub, mono: true };
    }),
  );

  function pick(v: string) {
    if (v === NEW) {
      wantNew = true;
      return;
    }
    wantNew = false;
    onchange(v);
  }

  async function create() {
    if (iface === "" || creating) return;
    creating = true;
    try {
      const made = await fetcher.post<GroupItem>(
        "/groups?save=true",
        { name: AUTOLIST_NAME, interface: iface, enable: true, rules: [] },
        { quiet: true },
      );
      groups = [...groups, made];
      wantNew = false;
      onchange(made.id);
      toast.success(t("Group {name} created").replace("{name}", AUTOLIST_NAME));
    } catch (error) {
      toast.error(
        `${t("Request failed")}: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      creating = false;
    }
  }
</script>

<div class="autolist-group" class:invalid>
  <Select
    {options}
    selected={wantNew ? NEW : value}
    shown={wantNew ? NEW : value}
    onValueChange={pick}
    {ariaLabel}
    disabled={!loaded}
    showSelectedDescription={false}
    class="autolist-select {changed}"
  />
  {#if required}
    <span class="hint error" role="alert">
      {t("Choose a group: automatic adding will not turn on without one")}
    </span>
  {:else if !wantNew && value === "" && loaded}
    <span class="hint">{t("Not chosen: nothing is added")}</span>
  {/if}
  {#if wantNew}
    <div class="new">
      <Select
        options={ifaceOptions}
        selected={iface}
        onValueChange={(v: string) => (iface = v)}
        ariaLabel={t("Interface of the new group")}
        showSelectedDescription={false}
        class="autolist-select"
      />
      <button type="button" class="create" disabled={iface === "" || creating} onclick={create}>
        {t("Create")}
      </button>
    </div>
    <span class="hint">{t("Where the added domains will go")}</span>
  {/if}
</div>

<style>
  .autolist-group {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 6px;
    width: 100%;
    min-width: 0;
  }
  .autolist-group :global(.autolist-select) {
    width: 100%;
    min-width: 0;
    max-width: 100%;
  }
  .autolist-group :global(.autolist-select [data-select-root]) {
    width: 100%;
  }
  .autolist-group :global(.autolist-select [data-select-trigger]) {
    width: 100%;
    height: 2.25rem;
    padding: 0 10px;
    border-radius: 8px;
    background: var(--bg-light);
    border: 1px solid var(--bg-light);
    box-sizing: border-box;
  }
  .autolist-group :global(.autolist-select [data-select-trigger] > .selected) {
    width: 100%;
    justify-content: space-between;
  }
  .autolist-group :global(.autolist-select .selected-value) {
    padding-left: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .autolist-group :global(.autolist-select.changed-live [data-select-trigger]) {
    background: var(--bg-dark);
    border-color: var(--accent);
  }
  .autolist-group.invalid :global(.autolist-select [data-select-trigger]) {
    border-color: var(--danger);
  }
  .new {
    display: flex;
    gap: 8px;
    align-items: center;
    min-width: 0;
  }
  .new :global(.autolist-select) {
    flex: 1;
  }
  .hint {
    font-size: 0.8rem;
    color: var(--text-2);
    text-align: left;
  }
  .hint.error {
    color: var(--danger);
  }
  .create {
    flex: none;
    height: 2.25rem;
    padding: 0 12px;
    border-radius: 8px;
    border: 1px solid var(--accent);
    background: transparent;
    color: var(--accent);
    font: inherit;
    cursor: pointer;
  }
  .create:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
