import { persistedState } from "../../utils/persisted-state.svelte";

import type { PresetChoices, PresetProvider } from "./list-catalog";

// Only what the owner chose is kept: a provider never touched follows its default, so a new one arrives with it.
const stored = persistedState<PresetChoices>("preset_sources", {});

/** The owner's choices; anything unreadable in storage counts as no choice at all. */
export function presetChoices(): PresetChoices {
  const c = stored.current;
  return c !== null && typeof c === "object" && !Array.isArray(c) ? c : {};
}

export function setProviderOn(p: PresetProvider, on: boolean) {
  stored.current = { ...presetChoices(), [p.id]: on };
}
