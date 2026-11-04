<script lang="ts">
  import { dnsProxy, snoozeDnsWarning } from "../data/dns-proxy.svelte";
  import { t } from "../data/locale.svelte";
  import { tabRequest } from "../data/tab-request.svelte";
  import { settings } from "../modules/settings/settings.svelte";
  import Button from "./ui/Button.svelte";
  import GenericDialog from "./ui/GenericDialog.svelte";

  import { dnsWarning, warningShown } from "../modules/settings/dns-proxy";

  const proxy = $derived(dnsProxy.state);
  const open = $derived(warningShown(proxy, dnsProxy.snoozedUntil, dnsProxy.now, settings.overlay));
  const text = $derived(proxy && !proxy.listening ? dnsWarning(proxy, t) : null);

  function toSettings() {
    snoozeDnsWarning();
    tabRequest.open("settings");
  }
</script>

{#if text && proxy}
  <GenericDialog
    {open}
    title={t("DNS is not working")}
    maxWidth={560}
    contentClass="dns-warning"
    on:close={snoozeDnsWarning}
  >
    <div slot="body" class="body" data-testid="dns-warning">
      <p class="taken">{text.taken}</p>
      <p>{text.effect}</p>
      <p><strong>{t("What to do")}:</strong> {text.todo}</p>
      <p class="muted">{text.after}</p>
      {#if proxy.error}
        <pre>{proxy.error}</pre>
      {/if}
    </div>
    <div slot="actions" class="actions">
      <Button type="button" onclick={snoozeDnsWarning}>{t("Hide for a minute")}</Button>
      <Button type="button" class="primary" onclick={toSettings}>{t("Open Settings")}</Button>
    </div>
  </GenericDialog>
{/if}

<style>
  .body {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    min-width: 0;
  }

  p {
    margin: 0;
    line-height: 1.45;
  }

  .taken {
    font-weight: 600;
    color: var(--red);
  }

  .muted {
    font-size: 0.85em;
    color: var(--text-2);
  }

  pre {
    margin: 0;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    background: var(--bg-dark-extra);
    font: 0.8rem/1.45 var(--font-mono);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .actions {
    display: flex;
    width: 100%;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 0.75rem;
  }

  @media (max-width: 500px) {
    .actions {
      flex-direction: column-reverse;
      align-items: stretch;
    }
  }
</style>
