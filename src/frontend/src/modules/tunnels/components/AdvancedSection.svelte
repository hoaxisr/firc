<script lang="ts">
  import Select from "../../../components/ui/Select.svelte";
  import Switch from "../../../components/ui/Switch.svelte";
  import { interfaces } from "../../../data/interfaces.svelte";
  import { t } from "../../../data/locale.svelte";
  import type { TunnelsStore } from "../tunnels.svelte";

  import { skippedLabels } from "../tunnel-editor";
  import type { ClientTunnel } from "../tunnels-data";

  let { store, tunnel = $bindable() }: { store: TunnelsStore; tunnel: ClientTunnel } = $props();

  const timeoutBad = $derived(
    !Number.isInteger(tunnel.advanced.timeout) ||
      tunnel.advanced.timeout < 1 ||
      tunnel.advanced.timeout > 600,
  );
  const tcpPort = $derived(store.stateOf(tunnel.id)?.tcpPort ?? 0);
  const tcpSkipped = $derived(
    skippedLabels(store.stateOf(tunnel.id)?.tcpSkipped ?? [], interfaces.list),
  );
  const fingerprintOptions = $derived([
    { value: "", label: t("From the link") },
    { value: "chrome", label: "Chrome" },
    { value: "firefox", label: "Firefox" },
  ]);
  const tcpOff = $derived(store.stateOf(tunnel.id)?.tcpOff ?? "");
  const offText = $derived(
    tcpOff === "acl"
      ? t(
          "Not working now: an access list cannot be read or judged, TCP goes through the TUN. Details in the journal",
        )
      : tcpOff === "kernel"
        ? t("Not working now: the kernel lacks REDIRECT or addrtype, TCP goes through the TUN")
        : tcpOff === "refused"
          ? t(
              "Not working now: the kernel refused the redirect rule, TCP goes through the TUN. Details in the journal",
            )
          : t("Not working now: TCP goes through the TUN. Details in the journal"),
  );
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
    <div class="name">{t("TCP through the kernel")}</div>
    <div class="hint">
      {t(
        "Faster for TCP: the kernel accepts the connection and hands it to tunvless without TUN. IPv4 only; UDP and IPv6 go as before",
      )}
    </div>
    {#if tunnel.advanced.kernelTcp && tcpOff !== ""}
      <div class="hint bad">{offText}</div>
    {:else}
      {#if tunnel.advanced.kernelTcp && tcpPort > 0}
        <div class="hint">
          {t("Now: tunvless listens on port {port}").replace("{port}", String(tcpPort))}
        </div>
      {/if}
      {#if tunnel.advanced.kernelTcp && tcpSkipped.length > 0}
        <div class="hint">
          {t("Not used for: {names} (access list denies)").replace(
            "{names}",
            tcpSkipped.join(", "),
          )}
        </div>
      {/if}
    {/if}
  </div>
  <div class="controls">
    <Switch
      aria-label={t("TCP through the kernel")}
      checked={tunnel.advanced.kernelTcp}
      onCheckedChange={(v: boolean) => (tunnel.advanced.kernelTcp = v)}
    />
  </div>
</div>
<div class="row">
  <div class="label">
    <div class="name">{t("ClientHello fingerprint")}</div>
    <div class="hint">
      {t("Which browser's TLS ClientHello the connection imitates; empty takes it from the link")}
    </div>
    {#if tunnel.advanced.fingerprint === "firefox"}
      <div class="hint">
        {t(
          "Firefox lists AES first: a server with AES hardware picks it, which can slow connections without Vision on a router without AES",
        )}
      </div>
    {/if}
  </div>
  <div class="controls">
    <span class="field">
      <Select
        ariaLabel={t("ClientHello fingerprint")}
        options={fingerprintOptions}
        selected={tunnel.advanced.fingerprint}
        onValueChange={(v: string) =>
          (tunnel.advanced.fingerprint = v as typeof tunnel.advanced.fingerprint)}
      />
    </span>
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
