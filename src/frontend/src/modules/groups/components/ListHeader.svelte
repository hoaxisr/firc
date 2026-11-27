<script lang="ts">
  import { getContext } from "svelte";

  import Button from "../../../components/ui/Button.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { t } from "../../../data/locale.svelte";
  import { GROUPS_STORE_CONTEXT, normalizeListUrl, type GroupsStore } from "../groups.svelte";
  import { listKey, syncProgressLabel } from "../lists.svelte";

  import { CloudSync, Link, Refresh } from "../../../components/ui/icons";
  import type { Group, GroupList } from "../../../types";
  import { listName } from "../list-name";

  type Props = { group: Group; list: GroupList };
  let { group, list }: Props = $props();

  const store = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);
  if (!store) {
    throw new Error("GroupsStore context is missing");
  }

  const lastUpdateDateFormatter = new Intl.DateTimeFormat("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  });
  const lastUpdateTimeFormatter = new Intl.DateTimeFormat("ru-RU", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  function formatTime(timestamp: number | undefined | null) {
    if (!timestamp) return t("Never updated");
    const date = new Date(timestamp * 1000);
    return `${lastUpdateDateFormatter.format(date)} ${lastUpdateTimeFormatter.format(date)}`;
  }

  let urlError = $derived(store.hasListUrlError(group.id, list.id));
  let syncProgress = $derived(store.lists.syncProgress[listKey(group.id, list.id)]);
  let syncError = $derived(list.sync?.state === "error" ? (list.sync.error ?? "") : "");

  let listCount = $derived(list.rulesTotal ?? 0);
  let several = $derived((group.lists?.length ?? 0) > 1);
  let saved = $derived(store.listSaved(group.id, list.id));
</script>

<div class="list-header">
  <div class="url-line">
    <span class="icon-wrap"><Link size={14} /></span>
    {#if several}
      <span class="list-name" title={list.url}>{listName(list.url ?? "")}</span>
    {/if}
    <input
      type="url"
      class="list-url-input"
      class:invalid={urlError}
      value={list.url}
      oninput={(e) =>
        store.setListUrl(group.id, list.id, (e.currentTarget as HTMLInputElement).value)}
      onblur={() => store.setListUrl(group.id, list.id, normalizeListUrl(list.url ?? ""))}
      placeholder="https://example.com/list.txt"
      aria-label={t("URL")}
      title={list.url}
    />
    {#if several}
      <Tooltip value={t(saved ? "Sync this list" : "Save the group to sync its list")}>
        <Button
          small
          class="list-sync"
          inactive={!saved}
          aria-disabled={!saved}
          onclick={() => store.lists.syncList(group.id, list.id)}
        >
          <Refresh size={16} />
        </Button>
      </Tooltip>
    {/if}
  </div>
  {#if urlError}
    <span class="url-error">{store.listUrlErrorMessage(group.id, list.id)}</span>
  {/if}
  <div class="update-line">
    <div class="update-line-row">
      <span class="icon-wrap"><CloudSync size={14} /></span>
      <span class="update-text">{formatTime(list.sync?.lastCheck || list.lastUpdate)}</span>
      <span class="update-counts">
        {listCount}
        {t("from the list")}
      </span>
      {#if syncError && !syncProgress}
        <span class="update-error">
          <span class="sync-error" title={syncError}>{syncError}</span>
        </span>
      {/if}
    </div>
  </div>
  {#if syncProgress}
    <div class="sync-progress">
      {#if syncProgress.stage === "fetch"}
        {#if syncProgress.total > 0}
          <progress max={syncProgress.total} value={syncProgress.bytes}></progress>
        {:else}
          <progress></progress>
        {/if}
      {/if}
      <span class="sync-progress-text">{syncProgressLabel(syncProgress)}</span>
    </div>
  {/if}
</div>

<style>
  .list-header {
    font-size: 0.8rem;
    color: var(--text-2);
    margin-left: 0.4rem;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.2rem;
    min-width: 0;
    width: 100%;
    max-width: 100%;
    overflow: hidden;
  }

  .url-line {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    min-width: 0;
    width: 100%;
    max-width: 100%;
    overflow: hidden;
  }

  .list-name {
    flex: none;
    max-width: 70%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text);
  }

  .list-url-input {
    min-width: 0;
    width: 100%;
    border: none;
    border-bottom: 1px solid transparent;
    background: transparent;
    color: var(--text-2);
    font: inherit;
    line-height: 1.3;
    padding: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .list-url-input:focus {
    text-overflow: clip;
  }

  .list-url-input:focus-visible {
    outline: none;
    color: var(--text);
    border-bottom-color: var(--accent);
  }

  .list-url-input.invalid {
    color: var(--red);
    border-bottom-color: var(--red);
  }

  .url-error {
    color: var(--red);
    font-size: 0.75rem;
  }

  .update-line {
    width: 100%;
    max-width: 100%;
    overflow: hidden;
  }

  .update-line-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    row-gap: 0.3rem;
    margin-left: -0.9rem;
  }

  .update-line-row > * {
    margin-left: 0.9rem;
  }

  .icon-wrap {
    display: flex;
    align-items: center;
    opacity: 0.7;
  }

  .update-counts,
  .update-error {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    min-width: 0;
  }

  .update-counts::before,
  .update-error::before {
    content: "•";
    position: absolute;
    right: calc(100% + 0.25rem);
    opacity: 0.5;
  }

  .sync-error {
    color: var(--red);
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sync-progress {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    width: 100%;
    max-width: 100%;
  }

  .sync-progress progress {
    width: 12rem;
    max-width: 100%;
    height: 0.35rem;
    accent-color: var(--accent);
  }

  .sync-progress-text {
    color: var(--text-2);
  }

  .url-line :global(.list-sync) {
    flex: none;
    padding: 0.15rem;
  }

  @media (max-width: 700px) {
    .list-header {
      max-width: 100%;
    }

    .url-line {
      max-width: 100%;
    }

    .list-url-input {
      max-width: 100%;
    }
  }
</style>
