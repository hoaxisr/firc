<script module lang="ts">
  let asked = false;

  function askOnce() {
    if (asked) return;
    asked = true;
    void autolist.ensure();
    if (!hosts.loaded) void fetchHosts();
  }
</script>

<script lang="ts">
  import { getContext, tick } from "svelte";

  import Button from "../../../components/ui/Button.svelte";
  import Select from "../../../components/ui/Select.svelte";
  import Switch from "../../../components/ui/Switch.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { autolist } from "../../../data/autolist.svelte";
  import { fetchHosts, hosts } from "../../../data/hosts.svelte";
  import { locale, t } from "../../../data/locale.svelte";
  import {
    GROUPS_STORE_CONTEXT,
    RULE_SEARCH_MATCH_COMMENT,
    RULE_SEARCH_MATCH_PATTERN,
    type GroupsStore,
  } from "../groups.svelte";
  import RuleComment from "./RuleComment.svelte";
  import RulePorts from "./RulePorts.svelte";

  import { Delete, Grip, TriangleAlert } from "../../../components/ui/icons";
  import { draggable, droppable, type Chip, type Edge } from "../../../lib/dnd";
  import { RULE_TYPES, ruleTakesPorts, type Rule } from "../../../types";
  import { autolistTip } from "../../../utils/autolist-tip";
  import { isValidPorts, VALIDATOP_MAP } from "../../../utils/rule-validators";
  import { deviceNames } from "../../logs/journal";

  type Props = {
    rule: Rule;
    rule_index: number;
    group_index: number;
    rule_id: string;
    group_id: string;
    isHighlighted?: boolean;
    [key: string]: any;
  };

  let {
    rule = $bindable(),
    rule_index,
    group_index,
    rule_id,
    group_id,
    isHighlighted = false,
    ...rest
  }: Props = $props();

  const store = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);
  if (!store) {
    throw new Error("GroupsStore context is missing");
  }

  const autoRule = $derived(Boolean(rule.autolist));
  const autoOff = $derived(autoRule && !rule.enable);
  const autoTip = $derived(
    autoRule
      ? autolistTip(
          rule.rule,
          autolist.data?.candidates ?? [],
          deviceNames(hosts.list),
          t,
          locale.current,
        )
      : "",
  );

  $effect(() => {
    if (autoRule) askOnce();
  });

  let overlap = $derived(store.ruleOverlap(rule.id));

  let input: HTMLInputElement;

  function applyPatternClass() {
    if (!input) return;
    /* !! matters: classList.toggle(name, undefined) toggles instead of setting. */
    const bad = !!(
      rule.rule.length === 0 ||
      (VALIDATOP_MAP[rule.type] && !VALIDATOP_MAP[rule.type](rule.rule))
    );
    input.classList.toggle("invalid", bad);
  }

  $effect(() => {
    void rule.rule;
    void rule.type;
    void portsInvalid;
    applyPatternClass();
  });

  function patternValidation() {
    applyPatternClass();
    store.markDataRevision();
  }

  function typeValidation() {
    if (!takesPorts) {
      rule.proto = undefined;
      rule.ports = undefined;
    }
    patternValidation();
  }

  const takesPorts = $derived(ruleTakesPorts(rule.type));
  const showsPorts = $derived(takesPorts || Boolean(rule.proto) || Boolean(rule.ports));
  const protoInvalid = $derived(Boolean(rule.proto) && !takesPorts);
  const portsInvalid = $derived(
    Boolean(rule.ports) && (!takesPorts || !rule.proto || !isValidPorts(rule.ports ?? "")),
  );

  function setProtoPorts(proto: Rule["proto"], ports: string | undefined) {
    rule.proto = proto;
    rule.ports = ports;
    store.markDataRevision();
    if (!showsPorts) void tick().then(() => input?.focus());
  }

  function setComment(value: string | undefined) {
    rule.comment = value;
    store.markDataRevision();
  }

  type DnDTransferData = {
    rule_id: string;
    group_id: string;
    rule_index: number;
    group_index: number;
  };

  const searchQuery = $derived(store.normalizedSearch);
  const ruleSearchMatchMask = $derived(store.searchRuleMatchMaskById.get(rule_id) ?? 0);
  const patternHighlightParts = $derived(
    ruleSearchMatchMask & RULE_SEARCH_MATCH_PATTERN
      ? store.getSearchHighlightParts(rule.rule ?? "", searchQuery)
      : undefined,
  );
  const hasPatternSearchHighlight = $derived(Boolean(patternHighlightParts));

  let overlay = $state<HTMLDivElement>();

  $effect(() => {
    void patternHighlightParts;
    const box = overlay;
    if (!box) return;
    const align = () => {
      const mark = box.querySelector("mark");
      const end = mark ? mark.offsetLeft + mark.offsetWidth : 0;
      box.scrollLeft =
        mark && end > box.clientWidth ? end - box.clientWidth + box.clientWidth / 4 : 0;
    };
    const observer = new ResizeObserver(align);
    observer.observe(box);
    void tick().then(align);
    return () => observer.disconnect();
  });

  function handlerDrop(source: DnDTransferData, target: DnDTransferData, edge: Edge) {
    if (source.rule_id === target.rule_id && source.group_id === target.group_id) {
      return;
    }

    store.changeRuleIndex(
      source.group_index,
      source.rule_index,
      target.group_index,
      target.rule_index,
      target.rule_id,
      edge,
    );
  }

  function ruleChip(): Chip {
    const type = RULE_TYPES.find((item) => item.value === rule.type)?.label ?? rule.type;
    return { grip: true, parts: [{ text: type, muted: true }, rule.rule || "…"] };
  }
</script>

<div
  class="rule no-native-dnd"
  data-index={rule_index}
  data-group-index={group_index}
  data-uuid={rule_id}
  data-group-uuid={group_id}
  data-duplicate-highlighted={isHighlighted ? "true" : undefined}
  {...rest}
  use:draggable={{
    data: { rule_id, rule_index, group_id, group_index } as DnDTransferData,
    scope: "rule",
    handle: ".grip",
    chip: ruleChip,
  }}
  use:droppable={{
    data: { rule_id, rule_index, group_id, group_index } as DnDTransferData,
    scope: "rule",
    canDrop: (src, tgt) => src.rule_id !== tgt.rule_id || src.group_id !== tgt.group_id,
    onDrop: handlerDrop,
  }}
>
  <div class="rule-row" class:autolist-off={autoOff} role="presentation">
    <div class="grip" data-index={rule_index} data-group-index={group_index} title={t("Drag Rule")}>
      <Grip />
    </div>
    <div class="type">
      <div class="label">{t("Type")}</div>
      <Select options={RULE_TYPES} bind:selected={rule.type} onValueChange={typeValidation} />
    </div>
    <div class="pattern">
      <div class="label">{t("Pattern")}</div>
      <div class="pattern-fields" class:with-ports={showsPorts} class:with-badge={autoRule}>
        <div class="search-highlight-field">
          <input
            type="text"
            placeholder={t("rule pattern...")}
            class="table-input pattern-input"
            class:search-text-hidden={hasPatternSearchHighlight}
            bind:value={rule.rule}
            bind:this={input}
            oninput={patternValidation}
            onfocusout={patternValidation}
          />
          {#if hasPatternSearchHighlight && patternHighlightParts}
            <div class="search-highlight-overlay" aria-hidden="true" bind:this={overlay}>
              {#each patternHighlightParts as part}
                {#if part.matched}
                  <mark>{part.text}</mark>
                {:else}
                  {part.text}
                {/if}
              {/each}
            </div>
          {/if}
        </div>
        {#if autoRule}
          <Tooltip value={autoTip}>
            <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
            <span class="autolist-badge" role="note" class:off={autoOff} tabindex="0">
              {autoOff ? t("auto · off by recheck") : t("auto")}
            </span>
          </Tooltip>
        {/if}
        {#if showsPorts}
          <RulePorts
            proto={rule.proto}
            ports={rule.ports}
            invalid={protoInvalid || portsInvalid}
            onchange={setProtoPorts}
          />
        {/if}
      </div>
    </div>
    <div class="actions">
      <RuleComment
        comment={rule.comment}
        matched={Boolean(ruleSearchMatchMask & RULE_SEARCH_MATCH_COMMENT)}
        onchange={setComment}
      />
      <div class="duplicate-indicator-slot" class:is-empty={!overlap}>
        {#if overlap}
          <Tooltip value={store.overlapText(overlap)}>
            <div class="duplicate-indicator" data-overlap={overlap.kind}>
              <TriangleAlert size={18} />
            </div>
          </Tooltip>
        {/if}
      </div>
      <Tooltip value={t(rule.enable ? "Disable Rule" : "Enable Rule")}>
        <Switch bind:checked={rule.enable} onCheckedChange={store.markDataRevision} />
      </Tooltip>
      <Tooltip value={t("Delete Rule")}>
        <Button
          small
          onclick={() => store.deleteRuleFromGroup(group_index, rule_index)}
          data-index={rule_index}
          data-group-index={group_index}
        >
          <Delete size={20} />
        </Button>
      </Tooltip>
    </div>
  </div>
</div>

<style>
  .rule {
    display: block;
  }

  .rule-row {
    display: grid;
    grid-template-columns: 1.1rem minmax(8rem, 1fr) minmax(0, 4fr) 10rem;
    gap: 0.5rem;
    padding: 0.1rem;
    background: inherit;
    border-radius: inherit;
  }

  .rule[data-duplicate-highlighted="true"] .rule-row {
    background-color: color-mix(in oklab, var(--yellow) 10%, transparent);
    box-shadow:
      inset 0 0 0 1px color-mix(in oklab, var(--yellow) 56%, transparent),
      0 0 0 1px color-mix(in oklab, var(--yellow) 24%, transparent),
      0 12px 28px -24px color-mix(in oklab, var(--yellow) 56%, transparent);
    animation: duplicate-focus-apple 2.2s cubic-bezier(0.22, 1, 0.36, 1) both;
  }

  .autolist-badge {
    flex: none;
    padding: 0.05rem 0.45rem;
    border-radius: 0.4rem;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
    cursor: help;
    color: var(--accent);
    background: color-mix(in oklab, var(--accent) 16%, transparent);
  }
  .autolist-badge:focus-visible {
    outline: 1px solid var(--accent);
  }
  .autolist-badge.off {
    color: var(--text-2);
    background: color-mix(in oklab, var(--text-2) 16%, transparent);
  }
  .rule-row.autolist-off {
    opacity: 0.55;
  }

  .search-highlight-field {
    position: relative;
    width: 100%;
    min-width: 0;
  }

  .pattern-fields {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    width: 100%;
    min-width: 0;
  }

  .pattern-fields > .search-highlight-field {
    flex: 1 1 6rem;
  }

  .pattern-fields.with-badge:not(.with-ports) > .search-highlight-field {
    flex: 0 1 19rem;
  }

  .pattern-fields.with-ports > .search-highlight-field {
    flex: 0 1 19rem;
  }

  .pattern-fields > :global(.rule-ports) {
    flex-shrink: 0;
    max-width: 60%;
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
    font-size: 1rem;
    font-family: var(--font);
  }

  .search-highlight-overlay mark {
    background: color-mix(in oklab, var(--yellow) 34%, transparent);
    box-shadow:
      inset 0 0 0 1px color-mix(in oklab, var(--yellow) 62%, transparent),
      0 1px 0 color-mix(in oklab, var(--yellow) 30%, transparent);
    color: inherit;
    border-radius: 0.22rem;
  }

  .table-input.search-text-hidden {
    color: transparent;
    -webkit-text-fill-color: transparent;
    caret-color: var(--text);
  }

  .table-input.search-text-hidden:focus,
  .table-input.search-text-hidden:focus-visible {
    color: var(--text);
    -webkit-text-fill-color: var(--text);
  }

  .table-input:focus + .search-highlight-overlay,
  .table-input:focus-visible + .search-highlight-overlay {
    display: none;
  }

  @keyframes duplicate-focus-apple {
    0% {
      background-color: color-mix(in oklab, var(--yellow) 2%, transparent);
      box-shadow:
        inset 0 0 0 0 color-mix(in oklab, var(--yellow) 68%, transparent),
        0 0 0 0 color-mix(in oklab, var(--yellow) 22%, transparent),
        0 0 0 0 color-mix(in oklab, var(--yellow) 58%, transparent);
    }
    18% {
      background-color: color-mix(in oklab, var(--yellow) 15%, transparent);
      box-shadow:
        inset 0 0 0 1px color-mix(in oklab, var(--yellow) 66%, transparent),
        0 0 0 1px color-mix(in oklab, var(--yellow) 30%, transparent),
        0 16px 34px -20px color-mix(in oklab, var(--yellow) 62%, transparent);
    }
    48% {
      background-color: color-mix(in oklab, var(--yellow) 10%, transparent);
      box-shadow:
        inset 0 0 0 1px color-mix(in oklab, var(--yellow) 56%, transparent),
        0 0 0 1px color-mix(in oklab, var(--yellow) 24%, transparent),
        0 12px 28px -24px color-mix(in oklab, var(--yellow) 56%, transparent);
    }
    78% {
      background-color: color-mix(in oklab, var(--yellow) 7%, transparent);
      box-shadow:
        inset 0 0 0 1px color-mix(in oklab, var(--yellow) 48%, transparent),
        0 0 0 1px color-mix(in oklab, var(--yellow) 16%, transparent),
        0 8px 16px -24px color-mix(in oklab, var(--yellow) 40%, transparent);
    }
    100% {
      background-color: color-mix(in oklab, var(--yellow) 0%, transparent);
      box-shadow:
        inset 0 0 0 0 color-mix(in oklab, var(--yellow) 0%, transparent),
        0 0 0 0 color-mix(in oklab, var(--yellow) 0%, transparent),
        0 0 0 0 color-mix(in oklab, var(--yellow) 0%, transparent);
    }
  }

  .table-input {
    border: none;
    background-color: transparent;
    font-size: 1rem;
    font-family: var(--font);
    color: var(--text);
    border-bottom: 1px solid transparent;
    width: 100%;
    padding: 0;
    margin: 0;
  }
  .table-input:focus-visible {
    outline: none;
    border-bottom: 1px solid var(--accent);
  }

  .type,
  .pattern {
    display: flex;
    align-items: center;
    justify-content: flex-start;
    padding: 0.1rem;
  }

  .actions {
    display: flex;
    align-items: center;
    justify-content: end;
    gap: 0.5rem;
  }

  .duplicate-indicator-slot {
    flex: 0 0 1.9rem;
    width: 1.9rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .duplicate-indicator-slot.is-empty {
    pointer-events: none;
  }

  .grip {
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: grab;
    color: var(--text-2);
    position: relative;
    left: 0.1rem;
    -webkit-user-drag: none;
    user-select: none;
    -webkit-user-select: none;
    -webkit-touch-callout: none;
    touch-action: none;
  }
  .grip:hover {
    color: var(--text);
  }

  .duplicate-indicator[data-overlap="split"] {
    color: var(--grey-dark);
  }

  .duplicate-indicator {
    color: var(--yellow);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0.4rem;
    border-radius: 8px;
    cursor: help;
    transition:
      background-color 0.12s ease,
      box-shadow 0.12s ease;
  }

  :global(.pattern-input.invalid),
  :global(.pattern-input.invalid:focus-visible) {
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
    .rule-row {
      display: grid;
      grid-template-columns: auto minmax(0, 1fr) auto;
      column-gap: 0.25rem;
      row-gap: 0.35rem;
      padding: 0.5rem 0.25rem 0.45rem;
      align-items: start;
    }
    .label {
      display: block;
      width: auto;
      padding-right: 0;
      white-space: nowrap;
    }
    .type,
    .pattern {
      display: grid;
      grid-template-columns: 3.5rem minmax(0, 1fr);
      align-items: center;
      gap: 0.25rem;
      padding: 0.05rem 0;
      grid-column: 2;
    }
    .pattern {
      grid-column: 2 / 4;
    }
    .pattern .label,
    .type .label {
      justify-self: end;
      text-align: right;
      position: static;
    }
    .pattern .table-input {
      width: 100%;
      min-width: 0;
    }
    .pattern-fields {
      flex-wrap: wrap;
      row-gap: 0.25rem;
    }
    .pattern .label {
      align-self: start;
    }
    .pattern-fields > .search-highlight-field,
    .pattern-fields.with-badge:not(.with-ports) > .search-highlight-field,
    .pattern-fields.with-ports > .search-highlight-field {
      flex: 1 0 100%;
    }
    .pattern-fields > :global(.rule-ports) {
      flex-shrink: 0;
      max-width: calc(100vw - 9rem);
    }
    .type :global([data-select-trigger]) {
      justify-content: flex-start;
      max-width: 100%;
    }
    .type :global(.select-wrap),
    .type :global([data-select-root]) {
      min-width: 0;
      max-width: 100%;
    }
    .duplicate-indicator-slot.is-empty {
      display: none;
    }
    .rule-row {
      position: relative;
    }
    .duplicate-indicator-slot:not(.is-empty) {
      position: absolute;
      right: 0.25rem;
      bottom: 0.45rem;
      height: 1.6rem;
    }
    .rule-row:has(.duplicate-indicator-slot:not(.is-empty)) .pattern {
      padding-right: 2rem;
    }
    .grip {
      grid-column: 1;
      grid-row: 1 / span 2;
      align-self: stretch;
      left: 0;
      padding: 0 0.3rem;
    }
    .actions {
      grid-column: 3;
      grid-row: 1;
      display: flex;
      flex-direction: row;
      gap: 0.2rem;
      justify-content: center;
      align-items: center;
      align-self: center;
    }
  }
</style>
