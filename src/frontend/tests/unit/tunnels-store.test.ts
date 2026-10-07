import assert from "node:assert";
import { afterEach, describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const store0 = new Map<string, string>();
const memoryStorage = {
  getItem: (k: string) => (store0.has(k) ? store0.get(k)! : null),
  setItem: (k: string, v: string) => void store0.set(k, String(v)),
  removeItem: (k: string) => void store0.delete(k),
  clear: () => store0.clear(),
  key: (i: number) => Array.from(store0.keys())[i] ?? null,
  get length() {
    return store0.size;
  },
};
Object.defineProperty(globalThis, "localStorage", {
  value: memoryStorage,
  configurable: true,
  writable: true,
});
const { TunnelsStore } = await import("../../src/modules/tunnels/tunnels.svelte");
const { fieldRefusal, probeRefusal } = await import("../../src/modules/tunnels/tunnels-data");
const { HttpError } = await import("../../src/utils/fetcher");

type Handler = unknown | ((init?: any) => unknown);

function installFetchStub(handlers: Record<string, Handler>) {
  const requests: { path: string; method?: string; body?: any }[] = [];
  const original = globalThis.fetch;
  (globalThis as any).fetch = async (input: unknown, init?: { method?: string; body?: string }) => {
    const path = String(input)
      .replace(/^https?:\/\/[^/]+/, "")
      .replace(/^\/api\/v1/, "");
    const body = init?.body !== undefined ? JSON.parse(init.body) : undefined;
    requests.push({ path, method: init?.method, body });
    if (!(path in handlers)) throw new Error(`unstubbed fetch: ${path}`);
    const h = handlers[path];
    const r: any = await (typeof h === "function" ? (h as any)(body) : h);
    if (r && typeof r === "object" && "__status" in r) {
      return {
        ok: false,
        status: r.__status,
        body: true,
        statusText: "error",
        text: async () => JSON.stringify(r.__body),
        json: async () => structuredClone(r.__body),
      };
    }
    return { ok: true, status: 200, json: async () => structuredClone(r) };
  };
  return {
    requests,
    restore: () => {
      (globalThis as any).fetch = original;
    },
  };
}

const events: any[] = [];
(globalThis as any).window = {
  dispatchEvent: (e: any) => (events.push(e), true),
  addEventListener: () => {},
  removeEventListener: () => {},
};
if (!("CustomEvent" in globalThis)) {
  (globalThis as any).CustomEvent = class {
    detail: unknown;
    constructor(
      public type: string,
      init?: { detail?: unknown },
    ) {
      this.detail = init?.detail;
    }
  };
}

const tunnel = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  device: "tunvless0",
  enable: true,
  active: 1,
  by: "connection",
  interval: 60,
  silence: 20,
  filter: "",
  order: [],
  exclude: [],
  sources: [
    {
      id: "0000000a",
      kind: "link",
      link: "vless://00000000-0000-4000-8000-000000000001@a.example.invalid:443?security=none#A",
    },
  ],
  uplink: { kind: "auto", ref: "" },
  advanced: { ca: "", insecure: false, timeout: 8 },
  ...extra,
});

const stateOf = (id: string, status = "up") => ({
  id,
  device: "tunvless0",
  status,
  since: 1,
  backoffS: 0,
  lastExit: 0,
  uplinkOk: true,
  active: [],
  groups: [],
  nodes: [],
  subscriptions: [],
  rxBps: 0,
  txBps: 0,
});

const stubs: { restore: () => void }[] = [];
afterEach(() => {
  for (const s of stubs.splice(0)) s.restore();
  events.length = 0;
});
const stub = (handlers: Record<string, Handler>) => {
  const s = installFetchStub(handlers);
  stubs.push(s);
  return s;
};

describe("TunnelsStore load and dirty", () => {
  // Catches a loaded set that already reads dirty, which would arm the save button and the unload guard.
  it("a fresh load is clean", async () => {
    stub({ "/tunnels": { tunnels: [tunnel("main")] } });
    const store = new TunnelsStore();
    await store.load();
    assert.strictEqual(store.loaded, true);
    assert.strictEqual(store.data.length, 1);
    assert.strictEqual(store.canSave, false);
  });

  // Catches an edit that never reaches the tracker, the save button staying dead.
  it("editing a field makes the set savable, and undoing it makes it clean again", async () => {
    stub({ "/tunnels": { tunnels: [tunnel("main")] } });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].interval = 90;
    assert.strictEqual(store.canSave, true);
    store.data[0].interval = 60;
    assert.strictEqual(store.canSave, false);
  });

  // Catches a description edit missing from dirty tracking, or a tunnel without one reading dirty on load.
  it("a description edit is a change and a missing one loads as empty", async () => {
    const bare = tunnel("main") as Record<string, unknown>;
    delete bare.description;
    stub({ "/tunnels": { tunnels: [bare] } });
    const store = new TunnelsStore();
    await store.load();
    assert.strictEqual(store.data[0].description, "");
    assert.strictEqual(store.canSave, false);
    store.data[0].description = "PRAW-1";
    assert.strictEqual(store.canSave, true);
    store.data[0].description = "";
    assert.strictEqual(store.canSave, false);
  });

  // Catches an edit in a source, or a swap of two, not marking the set dirty.
  it("a source edit and a source swap are both changes", async () => {
    const two = tunnel("main", {
      sources: [
        { id: "0000000a", kind: "link", link: "vless://a" },
        { id: "0000000b", kind: "link", link: "vless://b" },
      ],
    });
    stub({ "/tunnels": { tunnels: [two] } });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].sources[0].link = "vless://changed";
    assert.strictEqual(store.canSave, true);
    store.data[0].sources[0].link = "vless://a";
    assert.strictEqual(store.canSave, false);
    store.data[0].sources.reverse();
    assert.strictEqual(store.canSave, true);
  });

  // Catches a reorder of the node order list passing as unchanged.
  it("reordering the order list is a change", async () => {
    stub({ "/tunnels": { tunnels: [tunnel("main", { order: ["a:1", "a:2"] })] } });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].order.reverse();
    assert.strictEqual(store.canSave, true);
  });

  // Catches nested edits (uplink, advanced) the old tracker could not see.
  it("an uplink edit and an advanced edit are changes", async () => {
    stub({ "/tunnels": { tunnels: [tunnel("main")] } });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].uplink.kind = "iface";
    assert.strictEqual(store.canSave, true);
    store.data[0].uplink.kind = "auto";
    assert.strictEqual(store.canSave, false);
    store.data[0].advanced.timeout = 9;
    assert.strictEqual(store.canSave, true);
    store.data[0].advanced.timeout = 8;
    assert.strictEqual(store.canSave, false);
  });

  // Catches a rename of the tunnel id passing as unchanged.
  it("renaming a tunnel is a change, and renaming it back is clean", async () => {
    stub({ "/tunnels": { tunnels: [tunnel("main")] } });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].id = "other";
    assert.strictEqual(store.canSave, true);
    store.data[0].id = "main";
    assert.strictEqual(store.canSave, false);
  });

  // Catches an equal array assigned over order staying dirty forever.
  it("reassigning order to an equal array is clean", async () => {
    stub({ "/tunnels": { tunnels: [tunnel("main", { order: ["a:1", "a:2"] })] } });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].order = ["a:2"];
    assert.strictEqual(store.canSave, true);
    store.data[0].order = ["a:1", "a:2"];
    assert.strictEqual(store.canSave, false);
  });

  // Catches client keys leaking into the request, or two tunnels sharing a key.
  it("gives each tunnel its own key and never sends it", async () => {
    const s = stub({
      "/tunnels": (body: any) =>
        body ?? { tunnels: [tunnel("a"), tunnel("b", { device: "tunvless1" })] },
      "/system/interfaces": { interfaces: [] },
      "/tunnels/state": { tunnels: [] },
    });
    const store = new TunnelsStore();
    await store.load();
    assert.notStrictEqual(store.data[0].key, store.data[1].key);
    store.data[0].id = "c";
    await store.saveChanges();
    const put = s.requests.find((r) => r.method === "PUT")!;
    assert.ok(!("key" in put.body.tunnels[0]));
  });

  // Catches a new source sent with a client-made id instead of letting the daemon derive it.
  it("a source added then saved goes out without an id; a kept one keeps its own", async () => {
    const s = stub({
      "/tunnels": (body: any) => body ?? { tunnels: [tunnel("main")] },
      "/system/interfaces": { interfaces: [] },
      "/tunnels/state": { tunnels: [] },
    });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].sources.push({ kind: "link", link: "vless://new" } as any);
    assert.strictEqual(store.canSave, true);
    await store.saveChanges();
    const sent = s.requests.find((r) => r.method === "PUT")!.body.tunnels[0].sources;
    assert.strictEqual(sent[0].id, "0000000a");
    assert.ok(!("id" in sent[1]));
  });

  // Catches a written-but-unapplied save leaving the page off the file, or an unwritten one wiping the edits.
  it("re-reads the set only when the daemon wrote it but did not apply it", async () => {
    let gets = 0;
    let answer: { __status: number; __body: { error: string } } = {
      __status: 500,
      __body: { error: "saved, but not applied" },
    };
    const s = stub({
      "/tunnels": (body: any) => {
        if (body) return answer;
        gets++;
        return { tunnels: [tunnel("main", { interval: 90 })] };
      },
    });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].interval = 70;
    await store.saveChanges();
    assert.strictEqual(gets, 2);
    assert.strictEqual(store.data[0].interval, 90);
    answer = { __status: 500, __body: { error: "tunnels.yaml not written" } };
    store.data[0].interval = 70;
    await store.saveChanges();
    assert.strictEqual(gets, 2);
    assert.strictEqual(store.data[0].interval, 70);
    answer = { __status: 400, __body: { error: "saved, but not applied" } };
    await store.saveChanges();
    assert.strictEqual(gets, 2);
    assert.strictEqual(store.data[0].interval, 70);
    void s;
  });

  // Catches a 503 (tunnels not running) toasting or leaving the page half loaded.
  it("a failed load is quiet and marks the failure", async () => {
    stub({ "/tunnels": { __status: 503, __body: { error: "tunnels are not running" } } });
    const store = new TunnelsStore();
    await store.load();
    assert.strictEqual(store.loaded, false);
    assert.strictEqual(store.fetchError, true);
    assert.strictEqual(events.length, 0);
  });

  // Catches an added tunnel with no device or id clash: two tunnels on one device.
  it("a new tunnel takes the first free device and a free id", async () => {
    stub({ "/tunnels": { tunnels: [tunnel("tunnel1", { device: "tunvless0" })] } });
    const store = new TunnelsStore();
    await store.load();
    store.addTunnel();
    assert.strictEqual(store.data.length, 2);
    assert.strictEqual(store.data[1].device, "tunvless1");
    assert.notStrictEqual(store.data[1].id, "tunnel1");
    assert.strictEqual(store.canSave, true);
  });
});

describe("TunnelsStore.saveChanges", () => {
  // Catches a save that sends client-only state or omits the whole set.
  it("PUTs the whole set and comes back clean with the answer", async () => {
    const s = stub({
      "/tunnels": (body: any) =>
        body ? { tunnels: body.tunnels, restarted: ["tunvless0"] } : { tunnels: [tunnel("main")] },
      "/system/interfaces": { interfaces: [{ id: "tunvless0" }] },
      "/tunnels/state": { tunnels: [stateOf("main")] },
    });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].interval = 90;
    await store.saveChanges();
    const put = s.requests.find((r) => r.method === "PUT");
    assert.strictEqual(put!.path, "/tunnels");
    assert.strictEqual(put!.body.tunnels.length, 1);
    assert.strictEqual(put!.body.tunnels[0].interval, 90);
    assert.strictEqual(store.canSave, false);
    assert.strictEqual(store.data[0].interval, 90);
  });

  // Catches new devices not reaching the group pickers after a save.
  it("re-reads the interfaces after a save", async () => {
    const s = stub({
      "/tunnels": (body: any) => (body ? body : { tunnels: [tunnel("main")] }),
      "/system/interfaces": { interfaces: [] },
      "/tunnels/state": { tunnels: [] },
    });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].active = 2;
    await store.saveChanges();
    assert.ok(s.requests.some((r) => r.path === "/system/interfaces"));
  });

  // Catches a rejected save losing the edits, or the error not naming the tunnel and field.
  it("a 400 keeps the edits and names the tunnel and the field", async () => {
    stub({
      "/tunnels": (body: any) =>
        body
          ? {
              __status: 400,
              __body: {
                error: "url must be http or https",
                field: "sources[0].url",
                tunnel: "main",
              },
            }
          : { tunnels: [tunnel("main")] },
    });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].interval = 90;
    await store.saveChanges();
    assert.deepStrictEqual(store.fieldError, {
      tunnel: "main",
      field: "sources[0].url",
      error: "url must be http or https",
    });
    assert.strictEqual(store.canSave, true);
    assert.strictEqual(store.data[0].interval, 90);
  });

  // Catches the error from the previous refusal surviving the next attempt.
  it("clears the field error when the next save goes through", async () => {
    let refuse = true;
    stub({
      "/tunnels": (body: any) =>
        !body
          ? { tunnels: [tunnel("main")] }
          : refuse
            ? { __status: 400, __body: { error: "no", field: "interval", tunnel: "main" } }
            : body,
      "/system/interfaces": { interfaces: [] },
      "/tunnels/state": { tunnels: [] },
    });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].interval = 90;
    await store.saveChanges();
    assert.ok(store.fieldError);
    refuse = false;
    await store.saveChanges();
    assert.strictEqual(store.fieldError, null);
  });

  // Catches a save of an unchanged set hitting the daemon and restarting nothing useful.
  it("does nothing when nothing changed", async () => {
    const s = stub({ "/tunnels": { tunnels: [tunnel("main")] } });
    const store = new TunnelsStore();
    await store.load();
    await store.saveChanges();
    assert.strictEqual(s.requests.filter((r) => r.method === "PUT").length, 0);
  });
});

describe("TunnelsStore lookups by daemon id", () => {
  // Catches a view looking a state or a refusal up by the client key instead of the tunnel id.
  it("finds the state and the refusal of a tunnel whose key differs from its id", async () => {
    stub({
      "/tunnels": (body: any) =>
        body
          ? { __status: 400, __body: { error: "bad", field: "active", tunnel: "t0" } }
          : { tunnels: [tunnel("t0")] },
      "/tunnels/state": { tunnels: [stateOf("t0", "up")] },
    });
    const store = new TunnelsStore();
    await store.load();
    await store.pollState();
    const row = store.data[0];
    assert.notStrictEqual(row.key, "t0");
    assert.strictEqual(store.stateOf(row.id)?.status, "up");
    assert.strictEqual(store.stateOf(row.key), undefined);
    row.active = 3;
    await store.saveChanges();
    assert.strictEqual(store.refusalFor(row.id)?.field, "active");
    assert.strictEqual(store.refusalFor(row.key), null);
    assert.strictEqual(store.looseRefusal, null);
  });

  // Catches a refusal naming no tunnel on the page showing nowhere.
  it("shows a refusal of the whole set as a loose one", async () => {
    stub({
      "/tunnels": (body: any) =>
        body
          ? { __status: 400, __body: { error: "at most 8", field: null, tunnel: null } }
          : { tunnels: [tunnel("t0")] },
    });
    const store = new TunnelsStore();
    await store.load();
    store.data[0].active = 3;
    await store.saveChanges();
    assert.strictEqual(store.looseRefusal?.error, "at most 8");
  });
});

describe("fieldRefusal", () => {
  // Catches a null tunnel or field turned into the string "null", or a non-400 treated as a refusal.
  it("reads the daemon's 400 body and nothing else", async () => {
    const { HttpError } = await import("../../src/utils/fetcher");
    assert.deepStrictEqual(
      fieldRefusal(new HttpError('{"error":"too many","field":null,"tunnel":null}', 400)),
      { tunnel: "", field: "", error: "too many" },
    );
    assert.strictEqual(fieldRefusal(new HttpError('{"error":"x"}', 500)), null);
    assert.strictEqual(fieldRefusal(new Error("network")), null);
  });
});

describe("TunnelsStore state polling", () => {
  // Catches polling that runs while the tab is hidden: a request every two seconds nobody sees.
  it("polls only while active and visible", async () => {
    const s = stub({
      "/tunnels": { tunnels: [tunnel("main")] },
      "/tunnels/state": { tunnels: [stateOf("main")] },
    });
    (globalThis as any).document = {
      visibilityState: "visible",
      addEventListener() {},
      removeEventListener() {},
    };
    try {
      const store = new TunnelsStore();
      const polls = () => s.requests.filter((r) => r.path === "/tunnels/state").length;
      assert.strictEqual(store.polling, false);
      assert.strictEqual(polls(), 0);
      await store.setActive(true);
      assert.strictEqual(store.polling, true);
      const first = polls();
      assert.ok(first >= 1);
      await store.setActive(false);
      assert.strictEqual(store.polling, false);
      assert.strictEqual(polls(), first);
    } finally {
      delete (globalThis as any).document;
    }
  });

  // Catches the poll surviving the document going to the background.
  it("stops when the document is hidden and resumes when it shows", async () => {
    stub({
      "/tunnels": { tunnels: [tunnel("main")] },
      "/tunnels/state": { tunnels: [stateOf("main")] },
    });
    const doc: any = {
      visibilityState: "visible",
      addEventListener() {},
      removeEventListener() {},
    };
    (globalThis as any).document = doc;
    try {
      const store = new TunnelsStore();
      await store.setActive(true);
      assert.strictEqual(store.polling, true);
      doc.visibilityState = "hidden";
      store.onVisibility();
      assert.strictEqual(store.polling, false);
      doc.visibilityState = "visible";
      store.onVisibility();
      assert.strictEqual(store.polling, true);
      await store.setActive(false);
    } finally {
      delete (globalThis as any).document;
    }
  });

  // Catches a hidden tab polling the moment it is activated.
  it("does not poll on activation while the document is hidden", async () => {
    const s = stub({
      "/tunnels": { tunnels: [tunnel("main")] },
      "/tunnels/state": { tunnels: [] },
    });
    (globalThis as any).document = {
      visibilityState: "hidden",
      addEventListener() {},
      removeEventListener() {},
    };
    try {
      const store = new TunnelsStore();
      await store.setActive(true);
      assert.strictEqual(store.polling, false);
      assert.strictEqual(s.requests.filter((r) => r.path === "/tunnels/state").length, 0);
      await store.setActive(false);
    } finally {
      delete (globalThis as any).document;
    }
  });

  // Catches a slow older answer overwriting a newer one: states jumping backwards.
  it("keeps the newest answer when an older one lands late", async () => {
    let release: (v: unknown) => void = () => {};
    let n = 0;
    stub({
      "/tunnels/state": () => {
        n++;
        if (n === 1) return new Promise((r) => (release = r));
        return { tunnels: [stateOf("main", "up")] };
      },
    });
    const store = new TunnelsStore();
    const slow = store.pollState();
    const fast = store.pollState();
    await fast;
    assert.strictEqual(store.stateOf("main")?.status, "up");
    release({ tunnels: [stateOf("main", "off")] });
    await slow;
    assert.strictEqual(store.stateOf("main")?.status, "up");
  });

  // Catches a failing poll toasting every two seconds.
  it("a failing poll is quiet", async () => {
    stub({ "/tunnels/state": { __status: 503, __body: { error: "off" } } });
    const store = new TunnelsStore();
    await store.pollState();
    assert.strictEqual(events.length, 0);
  });
});

describe("TunnelsStore editor actions", () => {
  // Catches the restart note fed from the draft alone, naming tunnels nobody touched or missing the edited one.
  it("names only the saved tunnel whose run changed", async () => {
    stub({
      "/tunnels": {
        tunnels: [tunnel("a", { device: "tunvless0" }), tunnel("b", { device: "tunvless1" })],
      },
    });
    const store = new TunnelsStore();
    await store.load();
    assert.deepStrictEqual(store.restarting, []);
    store.data[1].silence = 5;
    store.addTunnel();
    assert.deepStrictEqual(store.restarting, ["tunvless1"]);
    assert.strictEqual(store.isSaved("b"), true);
    assert.strictEqual(store.isSaved(store.data[2].id), false);
  });

  // Catches a draft probe sent with the client key, or a busy probe shown as a generic failure.
  it("probes the draft without its key and names a busy probe", async () => {
    const s = stub({
      "/tunnels": { tunnels: [tunnel("a")] },
      "/tunnels/probe": { __status: 409, __body: { error: "a probe is already running" } },
    });
    const store = new TunnelsStore();
    await store.load();
    const answer = await store.probe(store.data[0]);
    assert.strictEqual(answer, null);
    const sent = s.requests.find((r) => r.path === "/tunnels/probe")?.body;
    assert.strictEqual(sent.tunnel.id, "a");
    assert.strictEqual("key" in sent.tunnel, false);
    assert.strictEqual(events.at(-1)?.detail.content, "A check is already running");
  });

  // Catches "save first" read as a busy probe, telling the user to wait for something that never ends.
  it("tells a save-first refusal from a busy probe", () => {
    const t = (key: string) => key;
    assert.strictEqual(
      probeRefusal(new HttpError(JSON.stringify({ error: "save first" }), 409), t),
      "Save the tunnel and let it start: it is checked through its own uplink",
    );
    assert.strictEqual(
      probeRefusal(new HttpError(JSON.stringify({ error: "a probe is already running" }), 409), t),
      "A check is already running",
    );
  });
});

describe("TunnelsStore keys and new tunnels", () => {
  // Catches a new tunnel reusing a just-deleted saved tunnel's id or device, so it shows the old daemon tunnel's state.
  it("a tunnel added after deleting a saved one takes neither its id nor its device", async () => {
    stub({ "/tunnels": { tunnels: [tunnel("tunnel1", { device: "tunvless0" })] } });
    const store = new TunnelsStore();
    await store.load();
    store.removeTunnel("tunnel1");
    store.addTunnel();
    assert.notStrictEqual(store.data[0].id, "tunnel1");
    assert.notStrictEqual(store.data[0].device, "tunvless0");
    assert.strictEqual(store.isSaved(store.data[0].id), false);
  });

  // Catches a save handing every tunnel a fresh key, remounting the cards and losing open panels and probe results.
  it("keeps each tunnel's client key across a save", async () => {
    stub({
      "/tunnels": (body: any) => (body ? { tunnels: body.tunnels } : { tunnels: [tunnel("main")] }),
      "/system/interfaces": { interfaces: [] },
      "/tunnels/state": { tunnels: [] },
    });
    const store = new TunnelsStore();
    await store.load();
    const key = store.data[0].key;
    store.data[0].interval = 90;
    await store.saveChanges();
    assert.strictEqual(store.data[0].key, key);
  });
});

describe("an aborted preview", () => {
  // Catches every superseded preview logged as a fetch error while the user types a filter.
  it("is not logged", async () => {
    stub({
      "/tunnels/preview": () => {
        throw new DOMException("aborted", "AbortError");
      },
    });
    const logged: unknown[] = [];
    const original = console.error;
    console.error = (...args: unknown[]) => void logged.push(args);
    try {
      const store = new TunnelsStore();
      await assert.rejects(store.preview(tunnel("a") as any));
    } finally {
      console.error = original;
    }
    assert.deepStrictEqual(logged, []);
  });
});
