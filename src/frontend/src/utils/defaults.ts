import { interfaces } from "../data/interfaces.svelte";

import { DEFAULT_RESOLVE, type Group, type Rule } from "../types";
import { randomId } from "./random-id";

export { randomId };

export function defaultGroup(): Group {
  return {
    enable: true,
    id: randomId(),
    interface: interfaces.list.at(0)?.id ?? "",
    name: "",
    devices: { allow: [], deny: [] },
    cloudflare: false,
    resolve: DEFAULT_RESOLVE(),
    rules: [],
    lists: [],
  };
}

export function defaultRule(): Rule {
  return {
    enable: true,
    id: randomId(),
    rule: "",
    type: "namespace",
  };
}
