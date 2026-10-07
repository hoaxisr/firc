import { fetchInterfaces } from "../../data/interfaces.svelte";
import { t } from "../../data/locale.svelte";

import type { Tunnel, TunnelPreview, TunnelProbeRow, TunnelsRes, TunnelState } from "../../types";
import { overlay, toast } from "../../utils/events";
import { fetcher, HttpError } from "../../utils/fetcher";
import { restartingDevices } from "./tunnel-editor";
import {
  defaultTunnel,
  fieldRefusal,
  MAX_TUNNELS,
  normalizeTunnel,
  plain,
  probeRefusal,
  savedNotApplied,
  withKey,
  type ClientTunnel,
  type TunnelFieldError,
} from "./tunnels-data";

const STATE_POLL_MS = 2000 as const;
const STATE_TIMEOUT_MS = 4000 as const;

export class TunnelsStore {
  data = $state<ClientTunnel[]>([]);
  #baseline = "[]";
  loaded = $state(false);
  fetchError = $state(false);
  saving = $state(false);
  fieldError = $state<TunnelFieldError | null>(null);
  states = $state<TunnelState[]>([]);
  polling = $state(false);

  #dispose: (() => void) | null = null;
  #active = false;
  #timer: ReturnType<typeof setInterval> | null = null;
  #seq = 0;
  #taken = 0;
  #pollFailing = false;

  constructor() {
    this.#dispose = $effect.root(() => {
      $effect(() => {
        if (typeof window === "undefined" || !this.canSave) return;
        const guard = (event: BeforeUnloadEvent) => event.preventDefault();
        window.addEventListener("beforeunload", guard);
        return () => window.removeEventListener("beforeunload", guard);
      });
    });
  }

  get dirty() {
    return JSON.stringify(plain($state.snapshot(this.data) as Tunnel[])) !== this.#baseline;
  }

  get canSave() {
    return this.dirty && !this.saving;
  }

  #adopt(tunnels: Tunnel[]) {
    const normalized = tunnels.map(normalizeTunnel);
    this.#baseline = JSON.stringify(normalized);
    const keys = new Map(this.data.map((tn) => [tn.id, tn.key]));
    this.data = normalized.map((tn) => {
      const key = keys.get(tn.id);
      return key ? { ...tn, key } : withKey(tn);
    });
  }

  get restarting(): string[] {
    return restartingDevices(
      JSON.parse(this.#baseline) as Tunnel[],
      plain($state.snapshot(this.data) as Tunnel[]),
    );
  }

  isSaved(id: string): boolean {
    return (JSON.parse(this.#baseline) as Tunnel[]).some((tn) => tn.id === id);
  }

  get canAdd() {
    return this.data.length < MAX_TUNNELS;
  }

  refusalFor(id: string): TunnelFieldError | null {
    return this.fieldError && this.fieldError.tunnel === id ? this.fieldError : null;
  }

  get looseRefusal(): TunnelFieldError | null {
    const e = this.fieldError;
    return e && !this.data.some((tn) => tn.id === e.tunnel) ? e : null;
  }

  stateOf(id: string): TunnelState | undefined {
    return this.states.find((s) => s.id === id);
  }

  async load(): Promise<void> {
    try {
      const answer = await fetcher.get<TunnelsRes>("/tunnels", { quiet: true });
      this.#adopt(answer?.tunnels ?? []);
      this.loaded = true;
      this.fetchError = false;
    } catch (error) {
      this.fetchError = true;
      console.error("Failed to load tunnels:", error instanceof Error ? error.name : "error");
    }
  }

  addTunnel() {
    if (!this.canAdd) return;
    const taken = [
      ...(JSON.parse(this.#baseline) as Tunnel[]),
      ...($state.snapshot(this.data) as Tunnel[]),
    ];
    this.data.push(withKey(defaultTunnel(taken)));
  }

  removeTunnel(id: string) {
    const index = this.data.findIndex((tunnel) => tunnel.id === id);
    if (index >= 0) this.data.splice(index, 1);
  }

  async saveChanges(): Promise<void> {
    if (!this.canSave) return;
    this.saving = true;
    this.fieldError = null;
    overlay.show(t("saving changes..."));
    try {
      const body = { tunnels: plain($state.snapshot(this.data) as Tunnel[]) };
      const answer = await fetcher.put<TunnelsRes>("/tunnels", body);
      this.#adopt(answer?.tunnels ?? body.tunnels);
      toast.success(t("Saved"));
      void fetchInterfaces();
      void this.pollState();
    } catch (error) {
      this.fieldError = fieldRefusal(error);
      if (savedNotApplied(error)) await this.load();
    } finally {
      overlay.hide();
      this.saving = false;
    }
  }

  async refresh(id: string): Promise<void> {
    try {
      const answer = await fetcher.post<{ queued?: boolean }>(
        `/tunnels/${encodeURIComponent(id)}/refresh`,
        {},
      );
      if (answer?.queued) toast.success(t("Subscriptions are being refreshed"));
      else toast.info(t("No subscriptions to refresh"));
      void this.pollState();
    } catch {
      return;
    }
  }

  async restart(id: string): Promise<void> {
    try {
      await fetcher.post(`/tunnels/${encodeURIComponent(id)}/restart`, {}, { quiet: true });
      toast.success(t("Restart requested"));
      void this.pollState();
    } catch (error) {
      if (error instanceof HttpError && error.status === 409) {
        toast.warning(t("The tunnel is not running, nothing to restart"));
      } else {
        toast.error(t("Request failed"));
      }
    }
  }

  async preview(tunnel: Tunnel, signal?: AbortSignal): Promise<TunnelPreview> {
    return await fetcher<TunnelPreview>("/tunnels/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tunnel: plain([tunnel])[0] }),
      quiet: true,
      signal,
    });
  }

  async probe(tunnel: Tunnel): Promise<TunnelProbeRow[] | null> {
    try {
      const answer = await fetcher.post<{ nodes?: TunnelProbeRow[] }>(
        "/tunnels/probe",
        { tunnel: plain([tunnel])[0] },
        { quiet: true },
      );
      return answer?.nodes ?? [];
    } catch (error) {
      toast.error(probeRefusal(error, t));
      return null;
    }
  }

  pollState = async (): Promise<void> => {
    const seq = ++this.#seq;
    try {
      const answer = await fetcher.get<{ tunnels?: TunnelState[] }>("/tunnels/state", {
        quiet: true,
        signal: AbortSignal.timeout(STATE_TIMEOUT_MS),
      });
      if (seq <= this.#taken) return;
      this.#taken = seq;
      this.states = answer?.tunnels ?? [];
      if (this.#pollFailing) console.info("Tunnel state polls answer again");
      this.#pollFailing = false;
    } catch (error) {
      if (!this.#pollFailing) {
        console.error(
          "Failed to poll tunnel state:",
          error instanceof Error ? error.name : "error",
        );
      }
      this.#pollFailing = true;
    }
  };

  onVisibility = () => {
    if (!this.#active) return;
    if (document.visibilityState === "visible") {
      void this.pollState();
      this.#arm();
    } else {
      this.#disarm();
    }
  };

  #arm() {
    this.#disarm();
    this.#timer = setInterval(() => void this.pollState(), STATE_POLL_MS);
    this.polling = true;
  }

  #disarm() {
    if (this.#timer !== null) clearInterval(this.#timer);
    this.#timer = null;
    this.polling = false;
  }

  async setActive(active: boolean): Promise<void> {
    if (active === this.#active) return;
    this.#active = active;
    if (typeof document === "undefined") return;
    if (!active) {
      document.removeEventListener("visibilitychange", this.onVisibility);
      this.#disarm();
      return;
    }
    document.addEventListener("visibilitychange", this.onVisibility);
    if (document.visibilityState === "visible") this.#arm();
    const first = document.visibilityState === "visible" ? this.pollState() : Promise.resolve();
    if (!this.loaded && !this.dirty) await this.load();
    await first;
  }

  handleSaveShortcut = (event: KeyboardEvent) => {
    if (!this.#active) return;
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s" && this.canSave) {
      event.preventDefault();
      void this.saveChanges();
    }
  };

  destroy() {
    this.#active = false;
    this.#disarm();
    if (typeof document !== "undefined") {
      document.removeEventListener("visibilitychange", this.onVisibility);
    }
    this.#dispose?.();
    this.#dispose = null;
  }
}
