<script lang="ts">
  import Switch from "../../../components/ui/Switch.svelte";
  import { t } from "../../../data/locale.svelte";
  import type { TunnelsStore } from "../tunnels.svelte";

  import { deviceProblem } from "../tunnel-editor";
  import type { ClientTunnel } from "../tunnels-data";

  let { store, tunnel = $bindable() }: { store: TunnelsStore; tunnel: ClientTunnel } = $props();

  const timeoutBad = $derived(
    !Number.isInteger(tunnel.advanced.timeout) ||
      tunnel.advanced.timeout < 1 ||
      tunnel.advanced.timeout > 600,
  );
  const deviceBad = $derived(deviceProblem(tunnel.device, store.data, tunnel.id, t));
</script>

<div class="row">
  <div class="label">
    <div class="name">{t("Connect timeout")}</div>
    <div class="hint">{t("How long to wait for a node to answer a new connection")}</div>
  </div>
  <div class="controls">
    <input
      type="number"
      min="1"
      max="600"
      aria-label={t("Connect timeout")}
      class:invalid={timeoutBad}
      aria-invalid={timeoutBad}
      bind:value={tunnel.advanced.timeout}
    />
    <span class="unit">{t("s")}</span>
  </div>
</div>
<div class="row">
  <div class="label">
    <div class="name">{t("Certificate check")}</div>
    <div class="hint">{t("Off only for a server with a self-signed certificate you trust")}</div>
  </div>
  <div class="controls">
    <Switch
      aria-label={t("Certificate check")}
      checked={!tunnel.advanced.insecure}
      onCheckedChange={(v: boolean) => (tunnel.advanced.insecure = !v)}
    />
  </div>
</div>
<div class="row">
  <div class="label">
    <div class="name">{t("Own CA")}</div>
    <div class="hint">
      {t("Path to a CA certificate file on the router; empty for the system ones")}
    </div>
  </div>
  <div class="controls">
    <input
      type="text"
      class="wide"
      aria-label={t("Own CA")}
      placeholder="/opt/etc/ssl/ca.pem"
      bind:value={tunnel.advanced.ca}
    />
  </div>
</div>
<div class="row">
  <div class="label">
    <div class="name">{t("Device name")}</div>
    <div class="hint" class:bad={Boolean(deviceBad)}>
      {deviceBad ?? t("The interface groups choose; tunvless0 to tunvless99")}
    </div>
  </div>
  <div class="controls">
    <input
      type="text"
      class="wide"
      aria-label={t("Device name")}
      class:invalid={Boolean(deviceBad)}
      aria-invalid={Boolean(deviceBad)}
      bind:value={tunnel.device}
    />
  </div>
</div>
