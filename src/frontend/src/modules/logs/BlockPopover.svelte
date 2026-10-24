<script lang="ts">
  import { Popover, RadioGroup } from "bits-ui";

  import Button from "../../components/ui/Button.svelte";
  import { blockTargets, ownerAbove, type BlockScope } from "../../data/dnsstats.svelte";
  import { t } from "../../data/locale.svelte";

  import { Ban } from "../../components/ui/icons";
  import type { Group } from "../../types";

  let {
    name,
    device,
    groups,
    ownerId,
    onadd,
  }: {
    name: string;
    device: { label: string; entry: string } | null;
    groups: Group[];
    ownerId: string | null;
    onadd: (scope: BlockScope, targetId: string | null) => void;
  } = $props();

  let open = $state(false);
  let scope = $state<BlockScope>("all");
  let picked = $state("");

  const candidates = $derived(
    blockTargets(groups, scope === "device" && device ? device.entry : null),
  );
  const target = $derived(
    candidates.length === 0 ? null : (candidates.find((g) => g.id === picked) ?? candidates[0]),
  );
  const warnOwner = $derived(ownerAbove(groups, ownerId, target?.id ?? null));
  const created = $derived(
    scope === "device" && device
      ? t("Blocking · {device}").replace("{device}", device.label)
      : t("Blocking"),
  );

  function add() {
    onadd(scope === "device" && device ? "device" : "all", target?.id ?? null);
    open = false;
  }

  $effect(() => {
    if (!open) {
      scope = "all";
      picked = "";
    }
  });
</script>

<Popover.Root bind:open>
  <Popover.Trigger class="bp-trigger"
    ><Ban size={14} aria-hidden="true" />{t("Block")}</Popover.Trigger
  >
  <Popover.Portal>
    <Popover.Content
      class="bp-editor"
      side="bottom"
      align="end"
      sideOffset={6}
      collisionPadding={8}
    >
      <div class="bp-head">{t("Block")} <b>{name}</b></div>

      {#if device}
        <RadioGroup.Root
          class="bp-choices"
          orientation="vertical"
          aria-label={t("For whom")}
          value={scope}
          onValueChange={(v) => {
            scope = v === "device" ? "device" : "all";
            picked = "";
          }}
        >
          {#each [{ v: "all", l: t("for everyone") }, { v: "device", l: t("only for {device}").replace("{device}", device.label) }] as c (c.v)}
            <RadioGroup.Item class="bp-choice" value={c.v}>
              {#snippet children({ checked })}
                <span class="bp-dot" class:on={checked}></span>
                <span class="bp-label">{c.l}</span>
              {/snippet}
            </RadioGroup.Item>
          {/each}
        </RadioGroup.Root>
        <div class="bp-sep"></div>
      {/if}

      {#if candidates.length === 1}
        <div class="bp-line">
          {t("into the group «{group}»").replace("{group}", candidates[0].name)}
        </div>
      {:else if candidates.length > 1}
        <div class="bp-title">{t("Into the group")}</div>
        <RadioGroup.Root
          class="bp-choices"
          orientation="vertical"
          aria-label={t("Into the group")}
          value={target?.id ?? ""}
          onValueChange={(v) => (picked = v)}
        >
          {#each candidates as g (g.id)}
            <RadioGroup.Item class="bp-choice" value={g.id}>
              {#snippet children({ checked })}
                <span class="bp-dot" class:on={checked}></span>
                <span class="bp-text">
                  <span class="bp-label">{g.name}</span>
                  <span class="bp-hint"
                    >{t("rules: {n}").replace("{n}", String(g.rules.length))}</span
                  >
                </span>
              {/snippet}
            </RadioGroup.Item>
          {/each}
        </RadioGroup.Root>
      {:else}
        <div class="bp-line">
          {t("a group «{group}» will be created").replace("{group}", created)}
          <span class="bp-hint">(0.0.0.0)</span>
        </div>
      {/if}

      {#if warnOwner}
        <div class="bp-warn">
          {t(
            "«{group}» above owns this name now — the block will not work while it is above",
          ).replace("{group}", warnOwner.name)}
        </div>
      {/if}

      <div class="bp-foot">
        <Button small onclick={() => (open = false)}>{t("Cancel")}</Button>
        <Button small class="primary" onclick={add}>{t("Add")}</Button>
      </div>
    </Popover.Content>
  </Popover.Portal>
</Popover.Root>

<style>
  :global(.bp-trigger) {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.3rem 0.55rem;
    border-radius: 0.4rem;
    border: 1px solid var(--bg-light-extra);
    background: transparent;
    color: var(--text-2);
    font: 400 0.8rem var(--font);
    white-space: nowrap;
    cursor: pointer;
  }
  :global(.bp-trigger:hover),
  :global(.bp-trigger[data-state="open"]) {
    color: var(--red);
    border-color: color-mix(in srgb, var(--red) 45%, transparent);
    background: color-mix(in srgb, var(--red) 8%, transparent);
  }
  :global(.bp-trigger:focus-visible) {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  :global(.bp-editor) {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    width: 20rem;
    max-width: calc(100vw - 1rem);
    box-sizing: border-box;
    padding: 0.6rem 0.75rem;
    background-color: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
    color: var(--text);
    z-index: 30;
    outline: none;
  }
  .bp-head {
    font-size: 0.9rem;
    overflow-wrap: anywhere;
    margin-bottom: 0.2rem;
  }
  .bp-title {
    color: var(--text-2);
    font-size: 0.75rem;
  }
  .bp-line {
    font-size: 0.86rem;
    color: var(--text);
    padding: 0.1rem 0;
  }
  .bp-sep {
    height: 1px;
    background: var(--bg-light-extra);
    margin: 0.2rem 0;
  }
  :global(.bp-choices) {
    display: flex;
    flex-direction: column;
  }
  :global(.bp-choice) {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.3rem 0.2rem;
    border: none;
    border-radius: 0.3rem;
    background: transparent;
    color: var(--text);
    font-family: var(--font);
    font-size: 0.88rem;
    text-align: left;
    cursor: pointer;
  }
  :global(.bp-choice:hover),
  :global(.bp-choice:focus-visible) {
    background: var(--bg-light);
    outline: none;
  }
  .bp-dot {
    flex: none;
    width: 12px;
    height: 12px;
    margin-top: 3px;
    box-sizing: border-box;
    border-radius: 50%;
    border: 2px solid var(--text-2);
  }
  .bp-dot.on {
    border-color: var(--accent);
    background: radial-gradient(var(--accent) 45%, transparent 50%);
  }
  .bp-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .bp-hint {
    color: var(--text-2);
    font-size: 0.76rem;
    line-height: 1.3;
  }
  .bp-warn {
    color: var(--orange);
    font-size: 0.78rem;
    line-height: 1.35;
    padding-top: 0.2rem;
  }
  .bp-foot {
    display: flex;
    justify-content: flex-end;
    gap: 0.4rem;
    margin-top: 0.4rem;
    padding-top: 0.5rem;
    border-top: 1px solid var(--bg-light-extra);
  }
  .bp-foot :global(button) {
    font-size: 0.85rem;
    padding: 0.35rem 0.8rem;
  }
</style>
