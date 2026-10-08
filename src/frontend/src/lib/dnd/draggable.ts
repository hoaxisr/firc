import { dnd_state } from "./dnd.svelte";

import { dropTargets, whenTargetGone, type DropTarget, type Edge } from "./droppable";

export type ChipPart = string | { text: string; muted?: boolean };

export type Chip = { grip?: boolean; parts: ChipPart[] };

export type DraggableOptions<S> = {
  data: S;
  scope: string;
  handle: string;
  chip?: () => Chip;
  onDrop?: (source: S, target: any, edge: Edge) => void;
};

const THRESHOLD = 4;
const EDGE_ZONE = 60;
const MAX_SCROLL = 18;
const MAX_SLOT = 120;
const SLOT_CLOSE_MS = 200;

type Drag = {
  node: HTMLElement;
  handle: Element;
  options: () => DraggableOptions<any>;
  pointerId: number;
  x0: number;
  y0: number;
  x: number;
  y: number;
  started: boolean;
  target: DropTarget | null;
  edge: Edge;
  slot: HTMLElement | null;
  chip: HTMLElement | null;
  slotHeight: number;
  slotRadius: string;
  raf: number;
};

let drag: Drag | null = null;

const reducedMotion = () =>
  typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

function inside(r: DOMRect, x: number, y: number) {
  return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
}

function visibleRect(el: Element): DOMRect | null {
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0 ? r : null;
}

function buildChip(d: Drag): HTMLElement {
  const chip = document.createElement("div");
  chip.className = "dnd-chip";
  chip.setAttribute("aria-hidden", "true");
  const spec = d.options().chip?.() ?? { parts: [] };
  if (spec.grip) {
    const grip = document.createElement("span");
    grip.className = "dnd-chip-grip";
    const svg = d.handle.querySelector("svg");
    if (svg) grip.appendChild(svg.cloneNode(true));
    else grip.textContent = "⋮⋮";
    chip.appendChild(grip);
  }
  for (const part of spec.parts) {
    const span = document.createElement("span");
    const muted = typeof part !== "string" && part.muted;
    span.className = muted ? "dnd-chip-muted" : "dnd-chip-text";
    span.textContent = typeof part === "string" ? part : part.text;
    chip.appendChild(span);
  }
  document.body.appendChild(chip);
  return chip;
}

function placeChip(d: Drag) {
  if (!d.chip) return;
  const left = Math.max(4, Math.min(d.x - 14, window.innerWidth - d.chip.offsetWidth - 8));
  d.chip.style.transform = `translate(${left}px, ${d.y}px) translateY(-50%) rotate(-1.5deg)`;
}

function closeSlot(slot: HTMLElement) {
  slot.classList.add("dnd-slot-closing");
  if (reducedMotion()) {
    slot.remove();
    return;
  }
  slot.style.height = "0px";
  slot.style.marginTop = "0px";
  slot.style.marginBottom = "0px";
  window.setTimeout(() => slot.remove(), SLOT_CLOSE_MS);
}

function liveNeighbour(el: Element, dir: "previousElementSibling" | "nextElementSibling") {
  let n = el[dir];
  while (n && n.classList.contains("dnd-slot-closing")) n = n[dir];
  return n;
}

function openSlot(d: Drag, target: DropTarget, edge: Edge) {
  if (d.slot) {
    const settled =
      edge === "after"
        ? liveNeighbour(d.slot, "previousElementSibling") === target.node
        : liveNeighbour(d.slot, "nextElementSibling") === target.node;
    if (settled) return;
    closeSlot(d.slot);
  }
  const slot = document.createElement("div");
  slot.className = "dnd-slot";
  slot.setAttribute("aria-hidden", "true");
  slot.style.borderRadius = d.slotRadius;
  const css = getComputedStyle(target.node);
  const height = `${d.slotHeight}px`;
  if (edge === "after") target.node.after(slot);
  else target.node.before(slot);
  if (reducedMotion()) {
    slot.style.height = height;
    slot.style.marginTop = css.marginTop;
    slot.style.marginBottom = css.marginBottom;
  } else {
    slot.style.height = "0px";
    slot.style.marginTop = "0px";
    slot.style.marginBottom = "0px";
    void slot.offsetHeight;
    slot.style.height = height;
    slot.style.marginTop = css.marginTop;
    slot.style.marginBottom = css.marginBottom;
  }
  d.slot = slot;
}

function setTarget(d: Drag, target: DropTarget | null, edge: Edge) {
  d.target = target;
  d.edge = edge;
  dnd_state.target = target ? target.options.data : null;
  if (target) openSlot(d, target, edge);
  else if (d.slot) {
    closeSlot(d.slot);
    d.slot = null;
  }
}

function hitTest(d: Drag) {
  const options = d.options();
  const candidates = dropTargets(options.scope);
  let union: { top: number; bottom: number; left: number; right: number } | null = null;
  for (const target of candidates) {
    const r = visibleRect(target.node);
    if (!r) continue;
    union = union
      ? {
          top: Math.min(union.top, r.top),
          bottom: Math.max(union.bottom, r.bottom),
          left: Math.min(union.left, r.left),
          right: Math.max(union.right, r.right),
        }
      : { top: r.top, bottom: r.bottom, left: r.left, right: r.right };
    if (!inside(r, d.x, d.y)) continue;
    const allowed = target.options.canDrop?.(options.data, target.options.data) ?? true;
    if (!allowed) {
      setTarget(d, null, "before");
      return;
    }
    const edge = target.options.edge ?? (d.y > r.top + r.height / 2 ? "after" : "before");
    setTarget(d, target, edge);
    return;
  }
  if (d.target && d.slot) {
    const s = d.slot.getBoundingClientRect();
    const inSlot = inside(s, d.x, d.y);
    const inUnion =
      union !== null &&
      d.x >= union.left &&
      d.x <= union.right &&
      d.y >= Math.min(union.top, s.top) &&
      d.y <= Math.max(union.bottom, s.bottom);
    if (inSlot || inUnion) return;
  }
  setTarget(d, null, "before");
}

function autoScroll() {
  const d = drag;
  if (!d || !d.started) return;
  const h = window.innerHeight;
  let dy = 0;
  if (d.y < EDGE_ZONE) dy = -Math.ceil(MAX_SCROLL * Math.min(1, (EDGE_ZONE - d.y) / EDGE_ZONE));
  else if (d.y > h - EDGE_ZONE)
    dy = Math.ceil(MAX_SCROLL * Math.min(1, (d.y - (h - EDGE_ZONE)) / EDGE_ZONE));
  if (dy !== 0) {
    const before = window.scrollY;
    window.scrollBy(0, dy);
    if (window.scrollY !== before) hitTest(d);
  }
  d.raf = requestAnimationFrame(autoScroll);
}

function blockSelect(e: Event) {
  e.preventDefault();
}

function begin(d: Drag) {
  d.started = true;
  const options = d.options();
  const box = d.node.getBoundingClientRect();
  d.slotHeight = Math.round(Math.min(box.height, MAX_SLOT));
  const radius = getComputedStyle(d.node).borderRadius;
  d.slotRadius = radius && radius !== "0px" ? radius : "8px";

  dnd_state.is_dragging = true;
  dnd_state.source = options.data;
  dnd_state.source_scope = options.scope;
  dnd_state.target = null;

  const html = document.documentElement;
  html.classList.add("dnd-dragging");
  html.dataset.dndScope = options.scope;
  d.node.classList.add("dnd-origin");
  d.node.setAttribute("aria-grabbed", "true");
  window.getSelection()?.removeAllRanges();
  window.addEventListener("selectstart", blockSelect, true);

  d.chip = buildChip(d);
  placeChip(d);
  d.raf = requestAnimationFrame(autoScroll);
}

function finish(d: Drag) {
  drag = null;
  cancelAnimationFrame(d.raf);
  window.removeEventListener("pointermove", onMove, true);
  window.removeEventListener("pointerup", onUp, true);
  window.removeEventListener("pointercancel", onCancel, true);
  window.removeEventListener("keydown", onKey, true);
  window.removeEventListener("selectstart", blockSelect, true);
  d.handle.removeEventListener("lostpointercapture", onLost);
  try {
    if (d.handle.hasPointerCapture(d.pointerId)) d.handle.releasePointerCapture(d.pointerId);
  } catch {}
  if (!d.started) return;

  document.querySelectorAll(".dnd-slot").forEach((el) => el.remove());
  d.chip?.remove();
  d.node.classList.remove("dnd-origin");
  d.node.removeAttribute("aria-grabbed");
  const html = document.documentElement;
  html.classList.remove("dnd-dragging");
  delete html.dataset.dndScope;

  dnd_state.is_dragging = false;
  dnd_state.source = null;
  dnd_state.target = null;
  dnd_state.source_scope = "";

  const swallow = (e: Event) => {
    e.stopPropagation();
    e.preventDefault();
  };
  window.addEventListener("click", swallow, true);
  window.setTimeout(() => window.removeEventListener("click", swallow, true), 0);
}

function onMove(e: PointerEvent) {
  const d = drag;
  if (!d || e.pointerId !== d.pointerId) return;
  d.x = e.clientX;
  d.y = e.clientY;
  if (!d.started) {
    if (Math.hypot(d.x - d.x0, d.y - d.y0) < THRESHOLD) return;
    begin(d);
  }
  e.preventDefault();
  placeChip(d);
  hitTest(d);
}

function onUp(e: PointerEvent) {
  const d = drag;
  if (!d || e.pointerId !== d.pointerId) return;
  if (!d.started) {
    finish(d);
    return;
  }
  d.x = e.clientX;
  d.y = e.clientY;
  hitTest(d);
  const { target, edge } = d;
  const options = d.options();
  finish(d);
  if (!target) return;
  if (!(target.options.canDrop?.(options.data, target.options.data) ?? true)) return;
  const drop = target.options.onDrop ?? options.onDrop;
  drop?.(options.data, target.options.data, edge);
}

function onCancel(e: PointerEvent) {
  if (drag && e.pointerId === drag.pointerId) finish(drag);
}

function onLost(e: Event) {
  if (drag && (e as PointerEvent).pointerId === drag.pointerId) finish(drag);
}

function onKey(e: KeyboardEvent) {
  if (!drag || e.key !== "Escape") return;
  if (drag.started) {
    e.preventDefault();
    e.stopPropagation();
  }
  finish(drag);
}

whenTargetGone((target) => {
  if (drag?.started && drag.target === target) setTarget(drag, null, "before");
});

export function draggable<S>(node: HTMLElement, options: DraggableOptions<S>) {
  function onDown(e: PointerEvent) {
    if (drag || !e.isPrimary || e.button !== 0) return;
    const handle = (e.target as Element | null)?.closest?.(options.handle);
    if (!handle || !node.contains(handle)) return;
    e.preventDefault();
    drag = {
      node,
      handle,
      options: () => options,
      pointerId: e.pointerId,
      x0: e.clientX,
      y0: e.clientY,
      x: e.clientX,
      y: e.clientY,
      started: false,
      target: null,
      edge: "before",
      slot: null,
      chip: null,
      slotHeight: 0,
      slotRadius: "",
      raf: 0,
    };
    try {
      handle.setPointerCapture(e.pointerId);
    } catch {}
    window.addEventListener("pointermove", onMove, true);
    window.addEventListener("pointerup", onUp, true);
    window.addEventListener("pointercancel", onCancel, true);
    window.addEventListener("keydown", onKey, true);
    handle.addEventListener("lostpointercapture", onLost);
  }

  node.addEventListener("pointerdown", onDown);

  return {
    update(next: DraggableOptions<S>) {
      options = next;
    },
    destroy() {
      node.removeEventListener("pointerdown", onDown);
      if (drag?.node === node) finish(drag);
    },
  };
}
