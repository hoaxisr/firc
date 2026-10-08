<script lang="ts">
  import { onDestroy, onMount, setContext, tick } from "svelte";

  import DevicesDialog from "../../components/DevicesDialog.svelte";
  import PageControls from "../../components/layout/PageControls.svelte";
  import Placeholder from "../../components/ui/Placeholder.svelte";
  import { fetchHosts } from "../../data/hosts.svelte";
  import { t } from "../../data/locale.svelte";
  import { fetchPolicies } from "../../data/policies.svelte";
  import BulkBar from "./components/BulkBar.svelte";
  import GroupPanel from "./components/GroupPanel.svelte";
  import Search from "./components/Search.svelte";
  import GroupDialog from "./dialogs/GroupDialog.svelte";
  import ImportConfigDialog from "./dialogs/ImportConfigDialog.svelte";
  import ImportRulesDialog from "./dialogs/ImportRulesDialog.svelte";
  import {
    GROUPS_STORE_CONTEXT,
    GroupsStore,
    type GroupDialogPayload,
    type GroupDragData,
    type GroupDropSlotData,
  } from "./groups.svelte";

  import { droppable } from "../../lib/dnd";
  import { type Group, type Rule } from "../../types";
  import { toast } from "../../utils/events";
  import { groupsFromFile } from "./groups-data";

  type Props = {
    onRenderComplete?: () => void;
  };

  let { onRenderComplete }: Props = $props();

  const store = new GroupsStore({ onRenderComplete: () => onRenderComplete?.() });
  setContext(GROUPS_STORE_CONTEXT, store);

  let importRulesModal = $state<{ open: boolean; groupIndex: number | null }>({
    open: false,
    groupIndex: null,
  });

  let devicesModal = $state<{ open: boolean; groupIndex: number | null }>({
    open: false,
    groupIndex: null,
  });

  let groupDialog = $state<{ open: boolean; mode: "create" | "edit"; groupIndex: number | null }>({
    open: false,
    mode: "create",
    groupIndex: null,
  });

  let importConfigModal = $state<{ open: boolean; fileName: string }>({
    open: false,
    fileName: "",
  });

  let bulkBarHeight = $state(0);
  let bulkBarFocused = $state(false);
  let showBulkBar = $derived(store.selection.length > 0);
  let groupList = $state<HTMLDivElement>();

  function trackBulkBarFocus(event: FocusEvent) {
    bulkBarFocused = Boolean((event.target as Element | null)?.closest?.(".bulk-bar"));
  }

  let bulkBarWasShown = false;
  $effect(() => {
    const shown = showBulkBar;
    if (bulkBarWasShown && !shown && bulkBarFocused) {
      bulkBarFocused = false;
      void tick().then(() => {
        const active = document.activeElement;
        if (active && active !== document.body) return;
        const first = groupList?.querySelector<HTMLElement>(
          ".group-wrapper:not(.is-hidden) .place-number",
        );
        (first ?? groupList)?.focus();
      });
    }
    bulkBarWasShown = shown;
  });

  let importedGroups = $state<Group[]>([]);
  let isImportingConfig = $state(false);
  let isImportingRules = $state(false);
  let pendingToast = $state<string | null>(null);

  function resetImportConfigModal() {
    importConfigModal = { open: false, fileName: "" };
    importedGroups = [];
  }

  function openImportRulesModal(groupIndex: number) {
    importRulesModal = { open: true, groupIndex };
  }

  function closeImportRulesModal() {
    importRulesModal = { open: false, groupIndex: null };
  }

  function openDevicesModal(groupIndex: number) {
    devicesModal = { open: true, groupIndex };
  }

  function closeDevicesModal() {
    devicesModal = { open: false, groupIndex: null };
  }

  function openGroupDialog() {
    groupDialog = { open: true, mode: "create", groupIndex: null };
  }

  function openGroupSettings(groupIndex: number) {
    groupDialog = { open: true, mode: "edit", groupIndex };
  }

  function closeGroupDialog() {
    const closingGroupId =
      groupDialog.mode === "edit" && groupDialog.groupIndex !== null
        ? store.data[groupDialog.groupIndex]?.id
        : undefined;
    if (store.groupFieldError?.group === closingGroupId) {
      store.clearGroupFieldError();
    }
    groupDialog = { ...groupDialog, open: false };
  }

  $effect(() => {
    const fe = store.groupFieldError;
    if (!fe || groupDialog.open || !fe.field.startsWith("resolve")) return;
    const idx = store.data.findIndex((g) => g.id === fe.group);
    if (idx >= 0) openGroupSettings(idx);
  });

  async function handleGroupDialogSubmit(payload: GroupDialogPayload) {
    store.clearGroupFieldError();
    if (groupDialog.mode === "edit" && groupDialog.groupIndex !== null) {
      store.updateGroupFromDialog(groupDialog.groupIndex, payload);
    } else {
      await store.createGroupFromDialog(payload);
    }
  }

  function exportConfig() {
    const payload = store.toConfigPayload();
    if (!payload.groups.length) {
      toast.warning(t("Empty config exported"));
    }
    const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "config.firc";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  function importConfig(event: Event) {
    const input = event?.currentTarget as HTMLInputElement;
    const file = input?.files?.[0];
    if (!file) {
      toast.error(t("Choose a config file to import."));
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const groups = groupsFromFile(file.name, event.target?.result as string);
        if (!groups?.length) {
          toast.error(t("Invalid config file"));
          return;
        }

        importedGroups = groups;
        importConfigModal = {
          open: true,
          fileName: file.name,
        };
      } catch (error) {
        console.error("Error parsing CONFIG:", error);
        toast.error(t("Invalid config file"));
      }
    };
    reader.onerror = (event) => {
      console.error("Error reading file:", event.target?.error);
      toast.error(t("Invalid config file"));
    };

    reader.readAsText(file);
    input.value = "";
  }

  async function handleImportRules(event: CustomEvent<{ group_index: number; rules: Rule[] }>) {
    const { group_index, rules } = event.detail;
    if (!rules.length) return;

    isImportingRules = true;
    await tick();
    try {
      await store.addRulesToGroup(group_index, rules);
      /* The count stays outside t(): inside, the key matches no locale entry. */
      pendingToast = t("Imported rules: ") + rules.length;
    } catch (error) {
      console.error("Failed to import rules:", error);
      toast.error(t("Failed to import rules"));
    } finally {
      isImportingRules = false;
    }
  }

  async function handleImportConfig(payload: { groups: Group[]; replace: boolean }) {
    if (!payload.groups.length) return;

    isImportingConfig = true;
    await tick();
    try {
      const cloned = await store.cloneGroupsWithNewIds(payload.groups);
      if (payload.replace) {
        await store.overwriteGroups(cloned);
      } else {
        await store.addGroups(cloned);
      }
      pendingToast = `${t("Config imported")}: ${cloned.length}`;
    } catch (error) {
      console.error("Failed to import config:", error);
      toast.error(t("Failed to import config"));
    } finally {
      isImportingConfig = false;
      resetImportConfigModal();
    }
  }

  $effect(() => {
    const message = pendingToast;
    if (!message) return;
    if (isImportingConfig || isImportingRules) return;
    if (!store.isAllRendered) return;

    let cancelled = false;
    const fire = () => {
      if (cancelled) return;
      if (pendingToast !== message) return;
      toast.success(message);
      pendingToast = null;
    };

    if (typeof requestAnimationFrame === "function") {
      requestAnimationFrame(fire);
    } else {
      setTimeout(fire, 0);
    }

    return () => {
      cancelled = true;
    };
  });

  onMount(() => {
    void store.mount();
    store.startLivePolling();
    void fetchHosts();
    void fetchPolicies(true);
  });

  onDestroy(() => {
    store.destroy();
  });
</script>

<div
  class="groups-page"
  style={showBulkBar
    ? `padding-bottom: calc(${bulkBarHeight}px + 2.5rem + env(safe-area-inset-bottom))`
    : ""}
>
  <PageControls
    actionsClass="group-controls-actions"
    controlsClass="group-controls"
    addLabel={t("Add Group")}
    canSave={store.canSave}
    ready={store.canAdd}
    saveError={store.invalidRules.size > 0 ? t("Some rules are empty or invalid") : undefined}
    exportLabel={t("Export Config")}
    importLabel={t("Import Config")}
    importAccept=".firc,.mtrickle"
    onAdd={openGroupDialog}
    onExport={exportConfig}
    onImport={importConfig}
    onSave={() => store.saveChanges()}
    saveButtonId="save-changes"
    saveLabel={t("Save Changes")}
  >
    {#snippet search()}
      <Search />
    {/snippet}
  </PageControls>

  <p class="order-hint">
    {t("Order is priority: a name goes to the first group from the top that matches it")}
  </p>

  {#if store.fetchError}
    <Placeholder variant="error" minHeight="auto" subtitle={t("Check connection or try again")}>
      {t("Failed to load groups")}
    </Placeholder>
  {:else if isImportingConfig || isImportingRules || !store.isAllRendered}
    <Placeholder variant="loading" minHeight="auto">
      {t("Loading groups...")}
    </Placeholder>
  {:else if store.noVisibleGroups}
    <Placeholder variant="empty" minHeight="auto">
      {t("No matches found")}
    </Placeholder>
  {:else if store.isEmptyData}
    <Placeholder variant="empty" minHeight="auto" subtitle={t("Create a new group to get started")}>
      {t("No groups yet")}
    </Placeholder>
  {/if}

  <div
    bind:this={groupList}
    class="group-list"
    tabindex="-1"
    class:visible={store.isAllRendered && !isImportingConfig && !isImportingRules}
    style={store.isAllRendered && !isImportingConfig && !isImportingRules ? "" : "display: none;"}
    oninput={store.markDataRevision}
    onchange={store.markDataRevision}
  >
    {#each store.data.slice(0, store.renderGroupsLimit) as group, group_index (group.id)}
      {@const isVisible = !store.searchActive || store.visibilityMap.has(group_index)}

      <div
        class="group-wrapper"
        class:is-hidden={!isVisible}
        use:droppable={{
          data: { group_index, insert: "before" } as GroupDropSlotData,
          scope: "group",
          canDrop: (source: GroupDragData, target: GroupDropSlotData) =>
            source.group_index !== target.group_index,
          onDrop: (source: GroupDragData, target: GroupDropSlotData, edge) =>
            store.handleGroupSlotDrop(source, { ...target, insert: edge }),
        }}
      >
        <div class="group-wrapper-inner">
          <GroupPanel
            {group_index}
            on:importRules={() => openImportRulesModal(group_index)}
            on:devices={() => openDevicesModal(group_index)}
            on:settings={() => openGroupSettings(group_index)}
          />
        </div>
      </div>
    {/each}
  </div>
</div>

<svelte:document onfocusin={trackBulkBarFocus} />

{#if showBulkBar}
  <BulkBar bind:height={bulkBarHeight} />
{/if}

<GroupDialog
  open={groupDialog.open}
  mode={groupDialog.mode}
  group={groupDialog.mode === "edit" && groupDialog.groupIndex !== null
    ? (store.data[groupDialog.groupIndex] ?? null)
    : null}
  serverError={store.groupFieldError &&
  groupDialog.groupIndex !== null &&
  store.data[groupDialog.groupIndex]?.id === store.groupFieldError.group &&
  store.groupFieldError.field.startsWith("resolve")
    ? store.groupFieldError.error
    : null}
  on:close={closeGroupDialog}
  on:submit={(event) => handleGroupDialogSubmit(event.detail)}
/>

<ImportRulesDialog
  open={importRulesModal.open}
  group_index={importRulesModal.groupIndex}
  on:close={closeImportRulesModal}
  on:import={handleImportRules}
/>

<DevicesDialog
  open={devicesModal.open}
  target={devicesModal.groupIndex === null ? null : (store.data[devicesModal.groupIndex] ?? null)}
  on:close={closeDevicesModal}
/>

<ImportConfigDialog
  open={importConfigModal.open}
  groups={importedGroups}
  fileName={importConfigModal.fileName}
  onclose={resetImportConfigModal}
  onimport={handleImportConfig}
/>

<style>
  .order-hint {
    margin: 0 0 0.5rem;
    font-size: 0.8rem;
    color: var(--text-2);
  }

  .group-list {
    min-height: 1px;
    opacity: 0;
    outline: none;
  }

  .group-list.visible {
    opacity: 1;
  }

  .group-wrapper {
    position: relative;
    margin: 1rem 0;
    display: grid;
    grid-template-rows: 1fr;
    opacity: 1;
    transition: none;
  }

  .group-wrapper-inner {
    min-height: 0;
    overflow: hidden;
  }

  .group-wrapper.is-hidden {
    display: none;
  }
</style>
