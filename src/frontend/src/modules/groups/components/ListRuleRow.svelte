<script lang="ts">
  import { getContext, tick } from "svelte";

  import Select from "../../../components/ui/Select.svelte";
  import Switch from "../../../components/ui/Switch.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { t } from "../../../data/locale.svelte";
  import { GROUPS_STORE_CONTEXT, type GroupsStore } from "../groups.svelte";

  import { TriangleAlert } from "../../../components/ui/icons";
  import { RULE_TYPES, type ListRule } from "../../../types";
  import { VALIDATOP_MAP } from "../../../utils/rule-validators";

  type Props = {
    rule: ListRule;
    rule_index: number;
    group_id: string;
    [key: string]: any;
  };

  let { rule = $bindable(), rule_index, group_id, ...rest }: Props = $props();
  const store = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);
  if (!store) {
    throw new Error("GroupsStore context is missing");
  }

  function isPatternUnroutable() {
    return (
      rule.rule.length === 0 || (VALIDATOP_MAP[rule.type] && !VALIDATOP_MAP[rule.type](rule.rule))
    );
  }

  let isDuplicate = $derived(store.isRuleDuplicate(rule.id));
  let isHighlighted = $derived(store.isRuleHighlighted(rule.id));

  let baseline = $derived(store.lists.baselineOf(group_id, rule.id));
  let isChanged = $derived(
    Boolean(baseline) && (rule.type !== baseline!.type || rule.enable !== baseline!.enable),
  );

  async function handleTypeChange(value: string) {
    rule.type = value;
    store.markDataRevision();
    await tick();
  }
</script>

<div
  class="list-rule"
  data-index={rule_index}
  data-group-id={group_id}
  data-uuid={rule.id}
  data-group-uuid={group_id}
  data-duplicate-highlighted={isHighlighted ? "true" : undefined}
  {...rest}
>
  <div class="list-rule-row">
    <div class="list-rule-number">{rule_index + 1}</div>
    <div class="list-rule-type">
      <div class="label">{t("Type")}</div>
      <Select
        options={RULE_TYPES}
        bind:selected={rule.type}
        onValueChange={handleTypeChange}
        disabled={Boolean(rule.proto || rule.ports)}
      />
    </div>
    <div class="list-rule-pattern">
      <div class="label">{t("Pattern")}</div>
      <div class="list-rule-value pattern-value" class:unroutable={isPatternUnroutable()}>
        {rule.rule}
      </div>
      {#if rule.proto || rule.ports}
        <span class="list-rule-spec">{[rule.proto, rule.ports].filter(Boolean).join(" ")}</span>
      {/if}
      {#if isDuplicate}
        <Tooltip value={t("Duplicate rule")}>
          <span class="duplicate-indicator"><TriangleAlert size={18} /></span>
        </Tooltip>
      {/if}
      {#if isChanged}
        <span class="changed-tag">{t("changed")}</span>
      {/if}
    </div>
    <div class="list-rule-actions">
      <Tooltip value={t(rule.enable ? "Disable Rule" : "Enable Rule")}>
        <Switch bind:checked={rule.enable} />
      </Tooltip>
    </div>
  </div>
</div>

<style>
  .list-rule {
    display: block;
  }

  .list-rule-row {
    display: grid;
    grid-template-columns: 2.5rem 1fr 5.5fr 0.6fr;
    gap: 0.5rem;
    padding: 0.1rem 0;
    background: inherit;
    border-radius: inherit;
  }

  .list-rule-number {
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.9rem;
    color: var(--text-2);
  }

  .list-rule-type {
    grid-column: 2;
  }
  .list-rule-pattern {
    grid-column: 3;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .list-rule-actions {
    grid-column: 4;
  }

  .list-rule-value {
    border: none;
    background-color: transparent;
    font-size: 1rem;
    font-family: var(--font);
    color: var(--text);
    border-bottom: 1px solid transparent;
    min-width: 0;
    padding: 2px 0;
    min-height: 1.5rem;
    display: flex;
    align-items: center;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    flex: 1 1 auto;
  }

  .duplicate-indicator {
    display: inline-flex;
    flex-shrink: 0;
    color: var(--yellow);
    cursor: help;
  }

  .list-rule[data-duplicate-highlighted="true"] .list-rule-row {
    background-color: color-mix(in oklab, var(--yellow) 10%, transparent);
    box-shadow: inset 0 0 0 1px color-mix(in oklab, var(--yellow) 56%, transparent);
  }

  .list-rule-spec {
    color: var(--text-2);
    font-size: 0.9rem;
    white-space: nowrap;
  }

  .changed-tag {
    flex-shrink: 0;
    font-size: 0.7rem;
    color: var(--yellow, #ffd37a);
    border: 1px solid color-mix(in oklab, var(--yellow, #ffd37a) 45%, transparent);
    border-radius: 0.35rem;
    padding: 0.05rem 0.35rem;
  }

  .list-rule-type,
  .list-rule-pattern,
  .list-rule-actions {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0 0.5rem;
    min-width: 0;
  }

  .list-rule-type {
    justify-content: flex-start;
  }

  .list-rule-actions {
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .pattern-value.unroutable {
    border-bottom: 1px solid var(--red);
  }

  .label {
    font-size: 0.9rem;
    color: var(--text-2);
    width: 3.2rem;
    text-align: right;
    padding-right: 0.2rem;
    display: none;
  }

  @media (max-width: 700px) {
    .list-rule-row {
      grid-template-columns: minmax(0, 1fr) auto;
      column-gap: 0.4rem;
      row-gap: 0.35rem;
      padding: 0.5rem 0.35rem 0.45rem;
      align-items: start;
    }

    .list-rule-number {
      display: none;
    }

    .list-rule-type,
    .list-rule-pattern,
    .list-rule-actions {
      grid-column: auto;
    }

    .label {
      display: block;
    }

    .list-rule-type,
    .list-rule-pattern {
      display: grid;
      grid-template-columns: 3.2rem minmax(0, 1fr);
      align-items: center;
      gap: 0.35rem;
      padding: 0.05rem 0;
      grid-column: 1;
    }

    .list-rule-pattern .label,
    .list-rule-type .label {
      justify-self: end;
      text-align: right;
      position: static;
    }

    .list-rule-type :global([data-select-trigger]) {
      justify-content: flex-start;
    }

    .list-rule-actions {
      grid-column: 2;
      grid-row: 1 / span 2;
      display: flex;
      flex-direction: row;
      gap: 0.35rem;
      justify-content: center;
      align-items: center;
      align-self: stretch;
    }
  }
</style>
