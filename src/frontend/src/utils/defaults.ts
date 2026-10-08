import { groupInterfaces } from "../data/interfaces.svelte";

import { DEFAULT_RESOLVE, type Group, type Rule } from "../types";
import { randomId } from "./random-id";

export { randomId };

export function defaultGroup(): Group {
  return {
    enable: true,
    id: randomId(),
    interface: groupInterfaces().at(0)?.id ?? "",
    name: "",
    devices: { allow: [], deny: [] },
    resolve: DEFAULT_RESOLVE(),
    rules: [],
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
