<script lang="ts">
  import { Collapsible } from "bits-ui";
  import { createEventDispatcher, getContext, tick } from "svelte";
  import { slide } from "svelte/transition";

  import Pagination from "../../../components/Pagination.svelte";
  import Button from "../../../components/ui/Button.svelte";
  import DropdownMenu from "../../../components/ui/DropdownMenu.svelte";
  import Select from "../../../components/ui/Select.svelte";
  import Switch from "../../../components/ui/Switch.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { hosts } from "../../../data/hosts.svelte";
  import { interfaces } from "../../../data/interfaces.svelte";
  import { locale, t } from "../../../data/locale.svelte";
  import { policies } from "../../../data/policies.svelte";
  import { GROUPS_STORE_CONTEXT, type GroupsStore } from "../groups.svelte";
  import GroupDuplicateMenu from "./GroupDuplicateMenu.svelte";
  import ListHeader from "./ListHeader.svelte";
  import ListRuleRow from "./ListRuleRow.svelte";
  import LiveStatus from "./LiveStatus.svelte";
  import RuleRow from "./RuleRow.svelte";

  import {
    Add,
    Delete,
    Devices,
    Dots,
    Grip,
    GroupCollapse,
    GroupExpand,
    ImportList,
    Refresh,
    RSS,
    Settings,
    SortAsc,
    SortDesc,
    SortNeutral,
  } from "../../../components/ui/icons";
  import { draggable, droppable } from "../../../lib/dnd";
  import { type Rule } from "../../../types";
  import { defaultRule } from "../../../utils/defaults";
  import { coverageLabel } from "../../../utils/device-picker";
  import { type SortDirection } from "../../../utils/rule-sorter";
  import { fallbackCountText, resolverTag } from "../resolve-choice";

  type Props = {
    group_index: number;
  };

  let { group_index }: Props = $props();

  const store = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);
  if (!store) {
    throw new Error("GroupsStore context is missing");
  }
  const dispatch = createEventDispatcher();

  const PAGE_SIZE = 50;
  let currentPage = $state(1);

  let client_width = $state<number>(Infinity);
  let is_desktop = $derived(client_width > 668);

  let group = $derived(store.data[group_index]);
  let searchActive = $derived(store.searchActive);
  let searchQuery = $derived(store.normalizedSearch);
  let isGroupSearchMatched = $derived(group ? store.searchMatchedGroupIds.has(group.id) : false);
  let groupNameHighlightParts = $derived(
    group && isGroupSearchMatched
      ? store.getSearchHighlightParts(group.name ?? "", searchQuery)
      : undefined,
  );
  let hasGroupNameSearchHighlight = $derived(Boolean(groupNameHighlightParts));
  let visibleRuleIndices = $derived(store.visibilityMap.get(group_index));
  let effectiveOpen = $derived(group ? (store.open_state[group.id] ?? false) : false);
  let duplicateConflicts = $derived(group ? store.getDuplicateConflictsForGroup(group.id) : []);
  let deviceCount = $derived(
    group ? (group.devices?.allow.length ?? 0) + (group.devices?.deny.length ?? 0) : 0,
  );

  let devicesLabel = $derived(
    coverageLabel(group?.devices, hosts.list, policies.list, t, locale.current),
  );

  let placeNumber = $derived(group_index + 1);
  let selected = $derived(group ? store.isSelected(group.id) : false);

  let hasList = $derived(Boolean(group?.list));
  let resolverTagText = $derived(resolverTag(group?.resolver, t));
  let fallbackText = $derived(fallbackCountText(group?.resolver, t));
  let listSaved = $derived(group ? store.listSaved(group.id) : false);
  let ownRulesCount = $derived(group?.rules.length ?? 0);

  let nameMirrorWidth = $state(0);
  let nameFieldWidth = $derived(
    Math.min(420, Math.max(64, nameMirrorWidth + 20 + (duplicateConflicts.length > 0 ? 36 : 0))),
  );
  let anyList = $derived(store.data.some((g) => Boolean(g.list)));
  let listPage = $derived(group ? store.lists.pageState[group.id] : undefined);
  const LIST_PAGE_SIZE = store.lists.pageSize;

  let listMatchedCount = $derived(
    group?.list && listPage?.q === store.normalizedSearch
      ? listPage.matched
      : (group?.list?.rulesTotal ?? 0),
  );
  let listUsePagination = $derived(listMatchedCount > LIST_PAGE_SIZE);
  let listCurrentPage = $derived(Math.floor((listPage?.offset ?? 0) / LIST_PAGE_SIZE) + 1);
  let listDisplayedRules = $derived.by(() => listPage?.rules ?? []);
  let listChangedCount = $derived(group ? store.lists.ruleEdits(group.id).length : 0);

  $effect(() => {
    if (!group?.list) return;
    const state = store.lists.pageState[group.id];
    if (effectiveOpen && !state?.loaded && !state?.failed) {
      store.lists.loadRules(group.id, 0);
    }
  });

  function toggleOpen() {
    if (!group) return;
    const next = !effectiveOpen;
    if (next && group.list) {
      const state = store.lists.pageState[group.id];
      if (state?.failed) {
        store.lists.pageState[group.id] = { ...state, failed: false };
      }
    }
    store.open_state[group.id] = next;
  }

  type GroupDnD = {
    group_id: string;
    group_index: number;
    name: string;
    count: number;
  };

  function createGroupDragPreview(headerEl: HTMLElement, name: string, count: number) {
    const badge = document.createElement("div");
    badge.style.cssText =
      "position:fixed;top:-1000px;left:-1000px;pointer-events:none;z-index:2147483647;transform:translateZ(0);font:600 13px/1.2 var(--font, -apple-system, system-ui, Segoe UI, Roboto, sans-serif);color:var(--text,#e5e7eb);";

    const inner = document.createElement("div");
    inner.style.cssText =
      "display:flex;align-items:center;gap:.55rem;padding:.42rem .7rem;border-radius:.7rem;background:var(--bg-light,rgba(30,30,36,.92));border:1px solid var(--bg-light-extra,rgba(255,255,255,.12));box-shadow:0 6px 18px rgba(0,0,0,.35);backdrop-filter:saturate(120%) blur(6px);";

    const title = document.createElement("span");
    title.textContent = name || "group";
    title.style.cssText =
      "max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;";
    inner.appendChild(title);

    const cnt = document.createElement("span");
    cnt.textContent = `• ${count}`;
    cnt.style.opacity = "0.8";
    inner.appendChild(cnt);

    const gripClone = headerEl.querySelector(".group-grip")?.cloneNode(true) as HTMLElement | null;
    if (gripClone) {
      gripClone.style.cssText += "opacity:.9;display:flex;align-items:center;margin-left:.25rem;";
      inner.appendChild(gripClone);
    }

    badge.appendChild(inner);
    document.body.appendChild(badge);
    return badge;
  }

  let totalRulesCount = $derived(
    searchActive && Array.isArray(visibleRuleIndices)
      ? visibleRuleIndices.length
      : (group?.rules.length ?? 0),
  );

  let usePagination = $derived(totalRulesCount > PAGE_SIZE);

  $effect(() => {
    if (searchActive && visibleRuleIndices) {
      currentPage = 1;
    }
  });

  $effect(() => {
    const maxPage = Math.ceil(totalRulesCount / PAGE_SIZE);
    if (currentPage > maxPage && maxPage > 0) {
      currentPage = 1;
    }
  });

  let displayedRules = $derived.by(() => {
    if (!group) return [];
    let rulesToRender: { rule: Rule; originalIndex: number }[] = [];

    let sourceIndices: number[] = [];
    if (searchActive && Array.isArray(visibleRuleIndices)) {
      sourceIndices = visibleRuleIndices;
    } else {
      sourceIndices = new Array(group.rules.length);
      for (let i = 0; i < group.rules.length; i++) sourceIndices[i] = i;
    }

    let startIndex = 0;
    let endIndex = sourceIndices.length;

    if (usePagination) {
      startIndex = (currentPage - 1) * PAGE_SIZE;
      endIndex = Math.min(startIndex + PAGE_SIZE, sourceIndices.length);
    }

    for (let i = startIndex; i < endIndex; i++) {
      const idx = sourceIndices[i];
      if (group.rules[idx]) {
        rulesToRender.push({ rule: group.rules[idx], originalIndex: idx });
      }
    }
    return rulesToRender;
  });

  let reportedFinished = false;
  $effect(() => {
    if (searchActive) return;
    if (!reportedFinished && (totalRulesCount === 0 || displayedRules.length > 0)) {
      reportedFinished = true;
      store.handleGroupFinished();
    }
  });

  let sorted = $state(false);
  let sortDirection = $state<SortDirection>("asc");
  let initialOrderIds = $state<string[] | null>(null);

  function handleSort() {
    if (!group) return;
    if (!initialOrderIds) {
      initialOrderIds = group.rules.map((rule) => rule.id);
    }

    if (sorted && sortDirection === "desc") {
      sorted = false;
      sortDirection = "asc";

      if (initialOrderIds) {
        store.restoreGroupRulesOrder(group_index, initialOrderIds);
      }
      return;
    }

    if (sorted) {
      sortDirection = "desc";
    } else {
      sorted = true;
      sortDirection = "asc";
    }

    store.sortGroupRules(group_index, sortDirection);
  }

  function findRulePosition(ruleId: string) {
    if (!group) return -1;
    if (searchActive && Array.isArray(visibleRuleIndices)) {
      const visibleIndex = visibleRuleIndices.findIndex((idx) => group.rules[idx]?.id === ruleId);
      if (visibleIndex >= 0) return visibleIndex;
    }
    return group.rules.findIndex((rule) => rule.id === ruleId);
  }

  function handleDuplicateConflictClick(groupId: string, ruleId: string) {
    const highlighted = store.highlightRuleTemporarily(ruleId);
    if (!highlighted) return;
    store.requestDuplicateRuleFocus(groupId, ruleId);
  }

  $effect(() => {
    if (!group) return;
    const request = store.duplicateFocusRequest;
    if (!request || request.groupId !== group.id) return;

    void (async () => {
      const rulePosition = findRulePosition(request.ruleId);
      if (rulePosition >= 0) {
        currentPage = Math.floor(rulePosition / PAGE_SIZE) + 1;
      }

      store.open_state[group.id] = true;

      await tick();

      if (typeof window !== "undefined") {
        requestAnimationFrame(() => {
          const row = document.querySelector<HTMLElement>(
            `.rule[data-group-uuid="${group.id}"][data-uuid="${request.ruleId}"]`,
          );
          if (row) {
            const rect = row.getBoundingClientRect();
            const inView = rect.top >= 0 && rect.bottom <= window.innerHeight;
            if (!inView) {
              row.scrollIntoView({ behavior: "smooth", block: "center" });
            }
          } else {
            const targetGroup = document.querySelector<HTMLElement>(
              `.group[data-uuid="${group.id}"]`,
            );
            if (targetGroup) {
              const rect = targetGroup.getBoundingClientRect();
              const inView = rect.top >= 0 && rect.bottom <= window.innerHeight;
              if (!inView) {
                targetGroup.scrollIntoView({ behavior: "smooth", block: "center" });
              }
            }
          }
        });
      }

      store.consumeDuplicateRuleFocus(request.groupId, request.ruleId, request.nonce);
    })();
  });

  $effect(() => {
    group?.rules.length;
    if (!sorted) {
      initialOrderIds = null;
    }
  });
</script>

<svelte:window bind:innerWidth={client_width} />

{#if group}
  <div
    class="group"
    class:selected
    role="listitem"
    data-uuid={group.id}
    use:draggable={{
      data: {
        group_id: group.id,
        group_index,
        name: group.name,
        count: group.rules.length,
      } as GroupDnD,
      scope: "group",
      handle: ".group-grip",
      effects: { effectAllowed: "move", dropEffect: "move" },
      dragImage: (node) =>
        createGroupDragPreview(
          (node.querySelector(".group-header") ?? node) as HTMLElement,
          group.name,
          group.rules.length,
        ),
    }}
  >
    <Collapsible.Root open={effectiveOpen} onOpenChange={toggleOpen}>
      <div
        class="group-header"
        data-group-index={group_index}
        use:droppable={{
          data: { rule_id: "", rule_index: 0, group_id: group.id, group_index },
          scope: "rule",
          canDrop: (src) => src.group_id === group.id,
        }}
      >
        <div class="group-left">
          <div class="group-grip" title={t("Drag Group")}>
            <Grip />
          </div>

          <button
            type="button"
            class="place-number"
            class:selected
            aria-pressed={selected}
            aria-label={(selected ? t("Deselect group {name}") : t("Select group {name}")).replace(
              "{name}",
              group.name || String(placeNumber),
            )}
            onclick={() => store.toggleSelected(group.id)}>{placeNumber}</button
          >

          <LiveStatus {group} />

          <div class="group-name-wrap">
            <div class="group-name-row">
              <div class="group-name-field" style={`width: ${nameFieldWidth}px`}>
                <input
                  type="text"
                  placeholder={t("group name...")}
                  class="group-name"
                  class:search-text-hidden={hasGroupNameSearchHighlight}
                  class:has-warning={duplicateConflicts.length > 0}
                  bind:value={group.name}
                />
                {#if hasGroupNameSearchHighlight && groupNameHighlightParts}
                  <div
                    class="search-highlight-overlay group-name-search-overlay"
                    class:has-warning={duplicateConflicts.length > 0}
                    aria-hidden="true"
                  >
                    {#each groupNameHighlightParts as part}
                      {#if part.matched}
                        <mark>{part.text}</mark>
                      {:else}
                        {part.text}
                      {/if}
                    {/each}
                  </div>
                {/if}
                <span class="name-mirror" aria-hidden="true" bind:offsetWidth={nameMirrorWidth}
                  >{group.name || t("group name...")}</span
                >
                {#if duplicateConflicts.length > 0}
                  <GroupDuplicateMenu
                    conflicts={duplicateConflicts}
                    isRuleHighlighted={store.isRuleHighlighted}
                    onConflictClick={handleDuplicateConflictClick}
                  />
                {/if}
              </div>
              {#if hasList}
                <span class="list-badge"><RSS size={12} />{t("list")}</span>
              {/if}
              {#if resolverTagText}
                <span class="resolver-badge" title={resolverTagText}>{resolverTagText}</span>
              {/if}
              {#if fallbackText}
                <span
                  class="fallback-badge"
                  title={t(
                    "Queries sent to the common upstream instead of the group's DNS since the daemon started",
                  )}>{fallbackText}</span
                >
              {/if}
            </div>
            {#if group.list}
              <ListHeader {group} />
            {/if}
          </div>
        </div>

        <div class="group-actions">
          <Select
            options={interfaces.list.map((item) => ({
              value: item.id,
              label: item.id,
              description: item.name,
            }))}
            bind:selected={group.interface}
            class="iface-select"
          />

          <Tooltip value={t(group.enable ? "Disable Group" : "Enable Group")}>
            <Switch class="enable-group" bind:checked={group.enable} />
          </Tooltip>

          {#if hasList}
            <Tooltip value={t(listSaved ? "Sync List" : "Save the group to sync its list")}>
              <Button
                small
                inactive={!listSaved}
                aria-disabled={!listSaved}
                onclick={() => store.lists.requestSync(group.id)}
              >
                <Refresh size={20} />
              </Button>
            </Tooltip>
          {:else if anyList && is_desktop}
            <span class="sync-slot" aria-hidden="true"></span>
          {/if}

          {#if is_desktop}
            <Tooltip value={t("Delete Group")}>
              <Button small onclick={() => store.deleteGroup(group_index)}>
                <Delete size={20} />
              </Button>
            </Tooltip>
            <Tooltip value={t("Add Rule")}>
              <Button
                small
                onclick={() => {
                  store.addRuleToGroup(group_index, defaultRule(), true);
                  store.open_state[group.id] = true;
                }}
              >
                <Add size={20} />
              </Button>
            </Tooltip>
            <Tooltip value={devicesLabel}>
              <Button small onclick={() => dispatch("devices")}>
                <span class="devices-icon" class:scoped={deviceCount > 0}>
                  <Devices size={20} />
                </span>
              </Button>
            </Tooltip>
            <Tooltip value={t("Import Rule List")}>
              <Button small onclick={() => dispatch("importRules")}>
                <ImportList size={20} />
              </Button>
            </Tooltip>
            <Tooltip value={t("Group Settings")}>
              <Button small aria-label={t("Group Settings")} onclick={() => dispatch("settings")}>
                <Settings size={20} />
              </Button>
            </Tooltip>
          {:else}
            <DropdownMenu>
              {#snippet trigger()}
                <Dots size={20} />
              {/snippet}
              {#snippet item1()}
                <Button
                  general
                  onclick={() => {
                    store.addRuleToGroup(group_index, defaultRule(), true);
                    store.open_state[group.id] = true;
                  }}
                >
                  <div class="dd-icon"><Add size={20} /></div>
                  <div class="dd-label">{t("Add Rule")}</div>
                </Button>
              {/snippet}
              {#snippet item2()}
                <Button general onclick={() => dispatch("importRules")}>
                  <div class="dd-icon"><ImportList size={20} /></div>
                  <div class="dd-label">{t("Import Rule List")}</div>
                </Button>
              {/snippet}
              {#snippet item5()}
                <Button general onclick={() => dispatch("devices")}>
                  <div class="dd-icon">
                    <span class="devices-icon" class:scoped={deviceCount > 0}>
                      <Devices size={20} />
                    </span>
                  </div>
                  <div class="dd-label">{devicesLabel}</div>
                </Button>
              {/snippet}
              {#snippet item4()}
                <Button general onclick={() => store.deleteGroup(group_index)}>
                  <div class="dd-icon"><Delete size={20} /></div>
                  <div class="dd-label">{t("Delete Group")}</div>
                </Button>
              {/snippet}
              {#snippet item6()}
                <Button general onclick={() => dispatch("settings")}>
                  <div class="dd-icon"><Settings size={20} /></div>
                  <div class="dd-label">{t("Group Settings")}</div>
                </Button>
              {/snippet}
            </DropdownMenu>
          {/if}

          <Tooltip value={t(effectiveOpen ? "Collapse Group" : "Expand Group")}>
            <Collapsible.Trigger>
              {#if effectiveOpen}
                <GroupCollapse size={20} />
              {:else}
                <GroupExpand size={20} />
              {/if}
            </Collapsible.Trigger>
          </Tooltip>
        </div>
      </div>

      <Collapsible.Content>
        <div transition:slide={searchActive ? { duration: 0 } : {}}>
          {#if hasList}
            <div class="rules-section-header">
              <h3>{t("Custom rules")}</h3>
              <span class="rules-section-hint">
                {ownRulesCount} · {t("checked together with the list, same owner")}
              </span>
            </div>
          {/if}
          {#if totalRulesCount > 0}
            <div class="group-rules-header">
              <div class="group-rules-header-column total">
                #{totalRulesCount}
              </div>
              <div class="group-rules-header-column">{t("Type")}</div>
              <!-- svelte-ignore a11y_click_events_have_key_events -->
              <!-- svelte-ignore a11y_no_static_element_interactions -->
              <div class="group-rules-header-column clickable" onclick={handleSort}>
                {t("Pattern")}
                <div class="sort-icon">
                  {#if sorted && sortDirection === "desc"}
                    <SortAsc size={16} />
                  {:else if sorted}
                    <SortDesc size={16} />
                  {:else}
                    <SortNeutral size={16} />
                  {/if}
                </div>
              </div>
              <div class="group-rules-header-column enabled">{t("Enabled")}</div>
            </div>
          {/if}
          <div class="group-rules">
            {#if totalRulesCount > 0}
              {#each displayedRules as { rule, originalIndex }, i (rule.id)}
                <RuleRow
                  key={rule.id}
                  bind:rule={group.rules[originalIndex]}
                  rule_index={originalIndex}
                  {group_index}
                  rule_id={rule.id}
                  group_id={group.id}
                  isDuplicate={store.isRuleDuplicate(rule.id)}
                  isHighlighted={store.isRuleHighlighted(rule.id)}
                  style={i % 2 ? "" : "background-color: var(--bg-light)"}
                />
              {/each}
            {/if}
          </div>
          {#if usePagination}
            <Pagination
              totalItems={totalRulesCount}
              pageSize={PAGE_SIZE}
              {currentPage}
              onPageChange={(p) => (currentPage = p)}
            />
          {/if}

          {#if hasList && group.list}
            <div class="rules-section-header list-section-header">
              <h3>{t("From the list")}</h3>
              <span class="rules-section-hint">
                {listMatchedCount} · {listChangedCount}
                {t("changed by hand")}
              </span>
            </div>
            {#if listMatchedCount > 0}
              <div class="list-rules-header">
                <div class="list-rules-header-column"></div>
                <div class="list-rules-header-column">{t("Type")}</div>
                <div class="list-rules-header-column pattern">{t("Pattern")}</div>
                <div class="list-rules-header-column">{t("Enabled")}</div>
              </div>
            {/if}
            <div class="list-rules">
              {#each listDisplayedRules as rule, i (rule.id)}
                <ListRuleRow
                  key={rule.id}
                  bind:rule={listDisplayedRules[i]}
                  rule_index={(listPage?.offset ?? 0) + i}
                  group_id={group.id}
                  style={i % 2 ? "" : "background-color: var(--bg-light)"}
                />
              {/each}
            </div>
            {#if listUsePagination}
              <Pagination
                totalItems={listMatchedCount}
                pageSize={LIST_PAGE_SIZE}
                currentPage={listCurrentPage}
                onPageChange={(p) => store.lists.loadRules(group.id, (p - 1) * LIST_PAGE_SIZE)}
              />
            {/if}
          {/if}
        </div>
      </Collapsible.Content>
    </Collapsible.Root>
  </div>
{/if}

<style>
  .group {
    & {
      background-color: var(--bg-medium);
      border-radius: 0.5rem;
      border: 1px solid var(--bg-light-extra);
      transition:
        transform 0.12s ease,
        opacity 0.12s ease,
        box-shadow 0.12s ease;
    }
  }

  .group-header {
    & {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.5rem;
      border-radius: 0.5rem;
      background-color: var(--bg-light);
      position: relative;
    }

    &:global(.dragover) {
      outline: 1px solid var(--accent);
      box-shadow: inset 0 0 5px 0 var(--accent);
    }
  }

  .group-left {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    flex: 1 1 auto;
    min-width: 0;
  }

  .group-grip {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: var(--text-2);
    cursor: grab;
    user-select: none;
    -webkit-user-select: none;
    -webkit-user-drag: none;
  }
  .group-grip:hover {
    color: var(--text);
  }

  .group-name {
    & {
      border: none;
      background-color: transparent;
      font-size: 1.3rem;
      font-weight: 600;
      font-family: var(--font);
      color: var(--text);
      border-bottom: 1px solid transparent;
      position: relative;
      top: 0.1rem;
      min-width: 0;
      width: 100%;
      box-sizing: border-box;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    &.has-warning {
      padding-right: 2.2rem;
    }

    &:focus-visible {
      outline: none;
      border-bottom: 1px solid var(--accent);
    }
  }

  .group.selected {
    border-color: var(--accent);
  }

  .place-number {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    min-width: 1.75rem;
    height: 1.75rem;
    padding: 0 0.3rem;
    box-sizing: border-box;
    border: 1.5px solid transparent;
    border-radius: 0.35rem;
    background: transparent;
    font: 600 0.85rem var(--font);
    color: var(--text-2);
    cursor: pointer;
    transition:
      background-color 0.1s ease-in-out,
      border-color 0.1s ease-in-out,
      color 0.1s ease-in-out;
  }

  .place-number:hover,
  .place-number:focus-visible {
    border-color: var(--text-2);
    outline: none;
  }

  .place-number.selected {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--bg-dark-extra);
  }

  .place-number.selected:focus-visible {
    box-shadow:
      0 0 0 2px var(--bg-light),
      0 0 0 3.5px var(--text-2);
  }

  .group-name-wrap {
    display: flex;
    flex-direction: column;
    position: relative;
    align-items: stretch;
    margin-left: 0.4rem;
    min-width: 0;
    flex: 1 1 auto;
    gap: 0.15rem;
  }

  .group-name-row {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    min-width: 0;
  }

  .list-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    flex-shrink: 0;
    height: 1.35rem;
    padding: 0 0.5rem;
    border-radius: 0.7rem;
    background: color-mix(in oklab, var(--accent) 22%, transparent);
    color: var(--accent);
    font-size: 0.75rem;
    font-weight: 600;
  }

  .resolver-badge,
  .fallback-badge {
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
    max-width: 22rem;
    height: 1.35rem;
    padding: 0 0.5rem;
    border-radius: 0.7rem;
    font-size: 0.75rem;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    background: color-mix(in oklab, var(--text-2) 16%, transparent);
    color: var(--text-2);
  }

  .fallback-badge {
    background: color-mix(in oklab, var(--red) 18%, transparent);
    color: var(--red);
  }

  .group-name-wrap :global([data-dropdown-menu-trigger]) {
    position: absolute;
    right: 0;
    top: 0;
    bottom: 0;
    display: flex;
    align-items: center;
    z-index: 2;
  }

  .group-name-field {
    position: relative;
    flex: 0 1 auto;
    min-width: 4rem;
  }

  .name-mirror {
    position: absolute;
    top: 0;
    left: 0;
    visibility: hidden;
    white-space: pre;
    pointer-events: none;
    font-size: 1.3rem;
    font-weight: 600;
    font-family: var(--font);
    padding: 0;
    margin: 0;
    border: 0;
  }

  .search-highlight-overlay {
    position: absolute;
    inset: 0;
    width: 100%;
    pointer-events: none;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: pre;
    color: var(--text);
    padding: 0;
    margin: 0;
    box-sizing: border-box;
  }

  .search-highlight-overlay.has-warning {
    padding-right: 2.2rem;
  }

  .group-name-search-overlay {
    transform: translateY(0.1rem);
    font: 600 1.3rem var(--font);
  }

  .search-highlight-overlay mark {
    background: color-mix(in oklab, var(--yellow) 34%, transparent);
    box-shadow:
      inset 0 0 0 1px color-mix(in oklab, var(--yellow) 62%, transparent),
      0 1px 0 color-mix(in oklab, var(--yellow) 30%, transparent);
    color: inherit;
    border-radius: 0.22rem;
  }

  .group-name.search-text-hidden {
    color: transparent;
    -webkit-text-fill-color: transparent;
    caret-color: var(--text);
  }

  .group-name.search-text-hidden:focus,
  .group-name.search-text-hidden:focus-visible {
    color: var(--text);
    -webkit-text-fill-color: var(--text);
  }

  .group-name:focus + .search-highlight-overlay,
  .group-name:focus-visible + .search-highlight-overlay {
    display: none;
  }

  .group-actions {
    & {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.2rem;
    }
    &:global([data-switch-root]) {
      margin: 0 0.3rem;
    }
  }

  /* A small Button's box: 20px icon, 0.4rem padding and a 1px border a side. */
  .sync-slot {
    flex: 0 0 auto;
    width: calc(20px + 0.8rem + 2px);
  }

  @media (min-width: 701px) {
    .group-actions :global(.iface-select) {
      display: flex;
      justify-content: flex-end;
      width: 9.5rem;
      flex: 0 0 auto;
    }
  }

  .rules-section-header {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.6rem 0.1rem 0.2rem;
  }

  .rules-section-header h3 {
    margin: 0;
    font-size: 0.95rem;
    font-weight: 600;
  }

  .rules-section-hint {
    font-size: 0.8rem;
    color: var(--text-2);
  }

  .list-section-header {
    margin-top: 0.4rem;
    border-top: 1px solid var(--bg-light-extra);
  }

  .list-rules-header {
    display: grid;
    grid-template-columns: 2.5rem 1fr 5.5fr 0.6fr;
    gap: 0.5rem;
    font-size: 0.9rem;
    color: var(--text-2);
    padding-bottom: 0.2rem;
    border-bottom: 1px solid var(--bg-light-extra);
  }

  .list-rules-header-column {
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .list-rules-header-column.pattern {
    justify-content: flex-start;
  }

  .group-rules-header {
    display: grid;
    grid-template-columns: minmax(1.1rem, max-content) 1fr 4fr 1fr;
    gap: 0.5rem;
    padding-inline: 0.1rem;
    justify-content: center;
    align-items: center;

    font-size: 0.9rem;
    color: var(--text-2);
    padding-top: 0.6rem;
    padding-bottom: 0.2rem;
    border-bottom: 1px solid var(--bg-light-extra);
  }

  .group-rules-header-column {
    & {
      display: flex;
      align-items: center;
      justify-content: center;
    }

    &.total {
      justify-content: start;
      margin-left: 0.5rem;
      white-space: nowrap;
    }

    &.enabled {
      justify-content: end;
      padding-right: 2rem;
    }

    &.total :global(svg) {
      position: relative;
      top: -1px;
    }
  }

  .clickable {
    cursor: pointer;
    user-select: none;
    transition: color 0.12s ease;
  }

  .clickable:hover {
    color: var(--text);
  }

  .sort-icon {
    margin-left: 0.4rem;
    display: flex;
    align-items: center;
    color: var(--text-2);
  }

  :global {
    [data-collapsible-trigger] {
      & {
        color: var(--text-2);
        background-color: transparent;
        border: 1px solid transparent;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 0.4rem;
        border-radius: 0.5rem;
        cursor: pointer;
      }

      &:hover {
        background-color: var(--bg-dark);
        color: var(--text);
        border: 1px solid var(--bg-light-extra);
      }
    }
  }

  @media (max-width: 700px) {
    .group-header {
      display: flex;
      flex-direction: column;
      align-items: start;
      justify-content: center;
      padding: 0.4rem 0.5rem;
    }

    .group-left {
      flex: none;
      width: 100%;
    }

    .group-name-wrap {
      width: 100%;
    }

    .group-name-row {
      flex-wrap: wrap;
      row-gap: 0.25rem;
    }

    .group-name-field {
      max-width: 100%;
    }

    .resolver-badge,
    .fallback-badge {
      max-width: 100%;
    }

    .group-grip {
      display: none;
    }

    .group-actions {
      width: 100%;
      justify-content: stretch;
      gap: 0.25rem;
    }

    :global(.group-actions > *:nth-child(1)) {
      margin-right: auto;
      width: 150px;
      min-width: 140px;
      flex: 1 1 auto;
    }

    :global(.group-actions > *:nth-child(2)) {
      margin-left: auto;
    }

    .group-rules-header {
      height: 1px;
      & .group-rules-header-column {
        display: none;
      }
    }

    .list-rules-header {
      height: 1px;
      overflow: hidden;
      & .list-rules-header-column {
        display: none;
      }
    }
  }
  .clickable {
    cursor: pointer;
    user-select: none;
    transition: color 0.12s ease;
  }
  .clickable:hover {
    color: var(--text);
  }

  .sort-icon {
    margin-left: 0.4rem;
    display: flex;
    align-items: center;
    color: var(--text-2);
  }
</style>
