import { BLOCK } from "../../data/iface-choices";
import { configFrom, DEFAULT_RESOLVE, syncIdle, type Group, type Rule } from "../../types";
import { randomId } from "../../utils/random-id";
import { cleanComment } from "../../utils/rule-comment";
import { sortRules, type SortDirection } from "../../utils/rule-sorter";

export type YieldToMain = () => Promise<void>;

export function groupsFromFile(fileName: string, text: string): Group[] {
  const foreign = fileName.toLowerCase().endsWith(".mtrickle");
  const raw = JSON.parse(text);
  for (const group of Array.isArray(raw?.groups) ? raw.groups : []) {
    for (const rule of Array.isArray(group?.rules) ? group.rules : []) {
      if (!rule || typeof rule !== "object") continue;
      const comment = cleanComment(foreign ? rule.name : rule.comment);
      if (comment === undefined || (foreign && comment === rule.rule)) delete rule.comment;
      else rule.comment = comment;
    }
  }
  const groups = configFrom(raw).groups ?? [];
  return foreign ? groups.reverse() : groups;
}

export function cloneGroupWithNewIds(group: Group): Group {
  return {
    ...group,
    id: randomId(),
    resolve: { ...(group.resolve ?? DEFAULT_RESOLVE()) },
    resolver: undefined,
    rules: group.rules.map((rule) => ({
      ...rule,
      id: randomId(),
    })),
    list: group.list
      ? {
          url: group.list.url,
          interval: group.list.interval,
          lastUpdate: 0,
          rulesTotal: 0,
          sync: syncIdle(),
        }
      : group.list,
  };
}

export async function cloneGroupsWithNewIds(
  groups: Group[],
  yieldToMain?: YieldToMain,
  chunkSize = 20,
) {
  const cloned: Group[] = [];
  const now =
    typeof performance !== "undefined" && typeof performance.now === "function"
      ? () => performance.now()
      : () => Date.now();
  let lastYieldAt = now();
  const maybeYield = async (force = false) => {
    if (!yieldToMain) return;
    if (force || now() - lastYieldAt > 8) {
      await yieldToMain();
      lastYieldAt = now();
    }
  };

  for (let i = 0; i < groups.length; i += chunkSize) {
    const end = Math.min(i + chunkSize, groups.length);
    for (let index = i; index < end; index++) {
      const source = groups[index];
      const clonedRules: Rule[] = [];

      for (let ruleIndex = 0; ruleIndex < source.rules.length; ruleIndex++) {
        clonedRules.push({
          ...source.rules[ruleIndex],
          id: randomId(),
        });
        if (ruleIndex < source.rules.length - 1) {
          await maybeYield();
        }
      }

      cloned.push({
        ...source,
        id: randomId(),
        resolve: { ...(source.resolve ?? DEFAULT_RESOLVE()) },
        resolver: undefined,
        rules: clonedRules,
      });

      if (index < groups.length - 1) {
        await maybeYield();
      }
    }
    if (end < groups.length) {
      await maybeYield(true);
    }
  }

  return cloned;
}

export async function prependGroups(
  target: Group[],
  openState: Record<string, boolean>,
  groups: Group[],
  yieldToMain?: YieldToMain,
  chunkSize = 25,
) {
  for (let end = groups.length; end > 0; end -= chunkSize) {
    const start = Math.max(0, end - chunkSize);
    const chunk = groups.slice(start, end);

    target.unshift(...chunk);
    for (let i = 0; i < chunk.length; i++) {
      openState[chunk[i].id] = true;
    }

    if (yieldToMain && start > 0) {
      await yieldToMain();
    }
  }
}

export async function prependRules(
  group: Group,
  rules: Rule[],
  yieldToMain?: YieldToMain,
  chunkSize = 300,
) {
  for (let end = rules.length; end > 0; end -= chunkSize) {
    const start = Math.max(0, end - chunkSize);
    const chunk = rules.slice(start, end);

    group.rules.unshift(...chunk);

    if (yieldToMain && start > 0) {
      await yieldToMain();
    }
  }
}

export function sortGroupRules(group: Group, direction: SortDirection) {
  const sorted = sortRules(group.rules, direction);
  group.rules.splice(0, group.rules.length, ...sorted);
}

export function restoreGroupRulesOrder(group: Group, ruleIds: string[]) {
  const ruleMap = new Map(group.rules.map((rule) => [rule.id, rule]));
  const orderedRules = ruleIds
    .map((id) => ruleMap.get(id))
    .filter((rule): rule is Rule => Boolean(rule));

  if (!orderedRules.length) return false;

  const orderedRuleIds = new Set(orderedRules.map((rule) => rule.id));
  const remainingRules = group.rules.filter((rule) => !orderedRuleIds.has(rule.id));

  group.rules.splice(0, group.rules.length, ...orderedRules, ...remainingRules);
  return true;
}

export function withoutStaleBlock<T extends { interface: string | string[]; block?: unknown }>(
  group: T,
): T {
  if (group.interface === BLOCK) return group;
  const { block: _block, ...rest } = group;
  return rest as T;
}

export function toConfigPayload(groups: Group[]) {
  return { groups: structuredClone(groups).map(withoutStaleBlock) };
}
