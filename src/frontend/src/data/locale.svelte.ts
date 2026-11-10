import { persistedState } from "../utils/persisted-state.svelte";

import ru from "../locales/ru.json" with { type: "json" };
import { browserLocale } from "../utils/browser-locale";

export const locales: Record<string, Record<string, string>> = { en: {}, ru };

export const locale = persistedState<string>("locale", browserLocale(globalThis.navigator));
const translation = $derived(locales[locale.state.value]);

export function t(key: string) {
  return translation[key] ?? key;
}
