<script lang="ts">
  import { getContext } from "svelte";

  import Button from "../../../components/ui/Button.svelte";
  import Select from "../../../components/ui/Select.svelte";
  import Switch from "../../../components/ui/Switch.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { t } from "../../../data/locale.svelte";
  import {
    GROUPS_STORE_CONTEXT,
    RULE_SEARCH_MATCH_PATTERN,
    type GroupsStore,
  } from "../groups.svelte";

  import { Delete, Grip, TriangleAlert } from "../../../components/ui/icons";
  import { dnd_state, draggable, droppable } from "../../../lib/dnd";
  import { RULE_TYPES, ruleTakesPorts, type Rule } from "../../../types";
  import { isValidPorts, VALIDATOP_MAP } from "../../../utils/rule-validators";

  type Props = {
    rule: Rule;
    rule_index: number;
    group_index: number;
    rule_id: string;
    group_id: string;
    isDuplicate?: boolean;
    isHighlighted?: boolean;
    [key: string]: any;
  };

  let {
    rule = $bindable(),
    rule_index,
    group_index,
    rule_id,
    group_id,
    isDuplicate = false,
    isHighlighted = false,
    ...rest
  }: Props = $props();

  const store = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);
  if (!store) {
    throw new Error("GroupsStore context is missing");
  }

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
    store.checkRulesValidityState();
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
  const protoOptions = $derived([
    { value: "", label: t("Any") },
    { value: "tcp", label: "TCP" },
    { value: "udp", label: "UDP" },
  ]);

  const showsPorts = $derived(takesPorts || Boolean(rule.proto) || Boolean(rule.ports));
  const portsDisabled = $derived(!rule.proto && !rule.ports);
  const protoInvalid = $derived(Boolean(rule.proto) && !takesPorts);
  const portsInvalid = $derived(
    Boolean(rule.ports) && (!takesPorts || !rule.proto || !isValidPorts(rule.ports ?? "")),
  );

  function setProto(value: string) {
    rule.proto = value === "tcp" || value === "udp" ? value : undefined;
    if (!rule.proto) rule.ports = undefined;
    store.markDataRevision();
  }

  function setPorts(value: string) {
    rule.ports = value === "" ? undefined : value;
    store.markDataRevision();
  }

  type DnDTransferData = {
    rule_id: string;
    group_id: string;
    rule_index: number;
    group_index: number;
    drop_position?: "before" | "after";
  };

  let dropEdge = $state<"before" | "after">("before");

  const dropData = $derived<DnDTransferData>({
    rule_id,
    group_id,
    rule_index,
    group_index,
    drop_position: dropEdge,
  });

  const searchQuery = $derived(store.normalizedSearch);
  const ruleSearchMatchMask = $derived(store.searchRuleMatchMaskById.get(rule_id) ?? 0);
  const patternHighlightParts = $derived(
    ruleSearchMatchMask & RULE_SEARCH_MATCH_PATTERN
      ? store.getSearchHighlightParts(rule.rule ?? "", searchQuery)
      : undefined,
  );
  const hasPatternSearchHighlight = $derived(Boolean(patternHighlightParts));

  function applyDropEdge(after: boolean) {
    dropEdge = after ? "after" : "before";
  }

  function updateDropIntent(event: DragEvent) {
    if (dnd_state.source_scope !== "rule") return;
    const target = event.currentTarget as HTMLElement | null;
    if (!target) return;
    const rect = target.getBoundingClientRect();
    const after = event.clientY - rect.top > rect.height / 2;
    applyDropEdge(after);
  }

  function resetDropIntent(delay = false) {
    const reset = () => {
      dropEdge = "before";
    };
    if (delay) {
      setTimeout(reset, 0);
    } else {
      reset();
    }
  }

  $effect(() => {
    void rule_id;
    void group_id;
    dropEdge = "before";
  });

  function handlerDrop(source: DnDTransferData, target: DnDTransferData) {
    if (source.rule_id === target.rule_id && source.group_id === target.group_id) {
      return;
    }

    store.changeRuleIndex(
      source.group_index,
      source.rule_index,
      target.group_index,
      target.rule_index,
      target.rule_id,
      target.drop_position ?? (target.rule_id ? "before" : "after"),
    );
  }

  function createRuleDragPreview(rowEl: HTMLElement, title: string) {
    const badge = document.createElement("div");
    badge.style.cssText =
      "position:fixed;top:-1000px;left:-1000px;pointer-events:none;z-index:2147483647;transform:translateZ(0);font:600 13px/1.2 var(--font, -apple-system, system-ui, Segoe UI, Roboto, sans-serif);color:var(--text,#e5e7eb);";
    const inner = document.createElement("div");
    inner.style.cssText =
      "display:flex;align-items:center;gap:.5rem;padding:.35rem .6rem;border-radius:.6rem;background:var(--bg-light,rgba(30,30,36,.92));border:1px solid var(--bg-light-extra,rgba(255,255,255,.12));box-shadow:0 6px 18px rgba(0,0,0,.35);backdrop-filter:saturate(120%) blur(6px);";

    const gripClone = rowEl.querySelector(".grip")?.cloneNode(true) as HTMLElement | null;
    if (gripClone) {
      gripClone.style.cssText += "opacity:.85;display:flex;align-items:center;";
      inner.appendChild(gripClone);
    } else {
      const dots = document.createElement("span");
      dots.textContent = "⋮⋮";
      (dots.style as any).letterSpacing = "2px";
      dots.style.opacity = "0.85";
      inner.appendChild(dots);
    }

    const label = document.createElement("span");
    label.textContent = title || "rule";
    label.style.cssText =
      "max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;";
    inner.appendChild(label);

    badge.appendChild(inner);
    document.body.appendChild(badge);
    return badge;
  }
</script>

<div
  class="rule no-native-dnd"
  data-index={rule_index}
  data-group-index={group_index}
  data-uuid={rule_id}
  data-group-uuid={group_id}
  data-drop-edge={dropEdge}
  data-duplicate-highlighted={isHighlighted ? "true" : undefined}
  {...rest}
  use:draggable={{
    data: { rule_id, rule_index, group_id, group_index } as DnDTransferData,
    scope: "rule",
    handle: ".grip",
    effects: { effectAllowed: "move", dropEffect: "move" },
    dragImage: (node) =>
      createRuleDragPreview((node.querySelector(".rule-row") ?? node) as HTMLElement, rule.rule),
  }}
  use:droppable={{
    data: dropData,
    scope: "rule",
    canDrop: (src, tgt) => src.rule_id !== tgt.rule_id || src.group_id !== tgt.group_id,
    dropEffect: "move",
    onDrop: handlerDrop,
  }}
>
  <div
    class="rule-row"
    role="presentation"
    ondragenter={updateDropIntent}
    ondragover={updateDropIntent}
    ondragleave={() => resetDropIntent()}
    ondrop={() => resetDropIntent(true)}
  >
    <div class="grip" data-index={rule_index} data-group-index={group_index} title={t("Drag Rule")}>
      <Grip />
    </div>
    <div class="type">
      <div class="label">{t("Type")}</div>
      <Select options={RULE_TYPES} bind:selected={rule.type} onValueChange={typeValidation} />
    </div>
    <div class="pattern">
      <div class="label">{t("Pattern")}</div>
      <div class="pattern-fields">
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
            <div class="search-highlight-overlay" aria-hidden="true">
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
        {#if showsPorts}
          <span class="proto" class:invalid={protoInvalid}>
            <Select
              options={protoOptions}
              selected={rule.proto ?? ""}
              onValueChange={setProto}
              ariaLabel={t("Protocol")}
            />
          </span>
          <input
            type="text"
            placeholder={t("ports, e.g. 53,1000-2000")}
            aria-label={t("Ports")}
            class="table-input ports-input"
            class:invalid={portsInvalid}
            disabled={portsDisabled}
            value={rule.ports ?? ""}
            oninput={(event) => setPorts(event.currentTarget.value)}
          />
        {/if}
      </div>
    </div>
    <div class="actions">
      <div class="duplicate-indicator-slot" class:is-empty={!isDuplicate}>
        {#if isDuplicate}
          <Tooltip value={t("Duplicate rule")}>
            <div class="duplicate-indicator">
              <TriangleAlert size={18} />
            </div>
          </Tooltip>
        {/if}
      </div>
      <Tooltip value={t(rule.enable ? "Disable Rule" : "Enable Rule")}>
        <Switch bind:checked={rule.enable} />
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
    grid-template-columns: 1.1rem 1fr 4fr 1fr;
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

  .ports-input {
    flex: 0 1 11rem;
    width: auto;
    min-width: 0;
  }

  .ports-input:disabled {
    color: var(--text-2);
    cursor: not-allowed;
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

  .rule:global(.dragover) {
    outline: 1px solid var(--accent);
    box-shadow: inset 0 0 0 2px color-mix(in oklab, var(--accent) 50%, transparent);
    border-radius: 10px;
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
    justify-content: center;
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
  }
  .grip:hover {
    color: var(--text);
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

  .ports-input.invalid,
  .ports-input.invalid:focus-visible {
    border-bottom: 1px solid var(--red);
  }

  .proto {
    display: contents;
  }

  .proto.invalid :global([data-select-trigger]) {
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

  :global(html.dnd-possible),
  :global(html.dnd-possible *) {
    user-select: none;
    -webkit-user-select: none;
  }

  :global(html.dnd-dragging),
  :global(html.dnd-dragging *) {
    user-select: none;
    -webkit-user-select: none;
    cursor: grabbing !important;
  }

  @media (max-width: 700px) {
    .rule-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      column-gap: 0.4rem;
      row-gap: 0.35rem;
      padding: 0.5rem 0.35rem 0.45rem;
      align-items: start;
    }
    .label {
      display: block;
    }
    .type,
    .pattern {
      display: grid;
      grid-template-columns: 3.2rem minmax(0, 1fr);
      align-items: center;
      gap: 0.35rem;
      padding: 0.05rem 0;
      grid-column: 1;
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
    .pattern-fields > .search-highlight-field {
      flex: 1 0 100%;
    }
    .pattern .ports-input {
      flex: 1 1 7rem;
      width: auto;
    }
    .type :global([data-select-trigger]) {
      justify-content: flex-start;
    }
    .grip {
      display: none;
    }
    .actions {
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
