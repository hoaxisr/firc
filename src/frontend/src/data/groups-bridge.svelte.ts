import type { GroupsStore } from "../modules/groups/groups.svelte";

export const groupsBridge = $state<{ store: GroupsStore | null }>({ store: null });
