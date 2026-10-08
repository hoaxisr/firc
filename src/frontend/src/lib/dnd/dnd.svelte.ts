export type DnDState = {
  is_dragging: boolean;
  source: any;
  target: any;
  source_scope: string;
};

export const dnd_state = $state<DnDState>({
  is_dragging: false,
  source: null,
  target: null,
  source_scope: "",
});
