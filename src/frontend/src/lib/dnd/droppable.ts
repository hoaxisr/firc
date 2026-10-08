export type Edge = "before" | "after";

export type DroppableOptions<T> = {
  data: T;
  scope: string;
  canDrop?: (source: any, target: T) => boolean;
  onDrop?: (source: any, target: T, edge: Edge) => void;
  edge?: Edge;
};

export type DropTarget = {
  node: HTMLElement;
  options: DroppableOptions<any>;
};

const targets = new Set<DropTarget>();
let onGone: ((target: DropTarget) => void) | null = null;

export function dropTargets(scope: string): DropTarget[] {
  const out: DropTarget[] = [];
  for (const target of targets) if (target.options.scope === scope) out.push(target);
  return out;
}

export function whenTargetGone(fn: ((target: DropTarget) => void) | null) {
  onGone = fn;
}

export function droppable<T>(node: HTMLElement, options: DroppableOptions<T>) {
  const target: DropTarget = { node, options };
  targets.add(target);
  node.dataset.droppable = options.scope;

  return {
    update(next: DroppableOptions<T>) {
      target.options = next;
      node.dataset.droppable = next.scope;
    },
    destroy() {
      targets.delete(target);
      delete node.dataset.droppable;
      onGone?.(target);
    },
  };
}
