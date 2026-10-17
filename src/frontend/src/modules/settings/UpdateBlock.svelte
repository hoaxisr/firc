<script lang="ts">
  import Button from "../../components/ui/Button.svelte";
  import { t } from "../../data/locale.svelte";
  import { checkUpdate, installUpdate, update } from "./update.svelte";

  import { CloudDownload, Refresh } from "../../components/ui/icons";
  import {
    landed,
    offered,
    progressPercent,
    reasonText,
    resultCurrent,
    running,
    runningText,
  } from "./update";

  const res = $derived(update.res);
  const check = $derived(res?.check ?? null);
  const latest = $derived(check?.latest ?? null);
  const canOffer = $derived(offered(res));
  const busy = $derived(update.checking || update.installing || running(res));
  const percent = $derived(progressPercent(res));
  const stateText = $derived(runningText(res?.state ?? "installing", latest?.version ?? "", t));
  const result = $derived(res !== null && resultCurrent(res) ? res.result : null);
  const done = $derived(res !== null && landed(res));

  const date = (iso: string) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString();
  };
</script>

{#if res}
  <section class="panel" data-testid="update-block">
    <div class="head">
      <span class="installed">
        {t("Installed")}
        <b>{res.installed.version}</b>
        {#if res.installed.target}({res.installed.target}){/if}
      </span>
      <div class="action">
        <Button small general inactive={busy} onclick={() => void checkUpdate()}>
          <span class="check"><Refresh size={16} />{t("Check")}</span>
        </Button>
        {#if canOffer}
          <Button small general inactive={busy} onclick={() => void installUpdate()}>
            <span class="check"><CloudDownload size={16} />{t("Install")}</span>
          </Button>
        {/if}
      </div>
    </div>

    {#if update.checking}
      <div class="line muted">{t("Checking...")}</div>
    {:else if check?.newer && latest}
      <div class="line newer">
        {t("{version} from {date}")
          .replace("{version}", () => latest.version)
          .replace("{date}", () => date(latest.publishedAt))}
      </div>
      {#if latest.notes}
        <pre class="notes">{latest.notes}</pre>
      {/if}
    {:else if check && !check.error}
      <div class="line muted">
        {t("Up to date, checked {n} min ago").replace("{n}", String(Math.floor(check.ageS / 60)))}
      </div>
    {/if}

    {#if update.checkError}
      <div class="line error" data-testid="update-error">{update.checkError}</div>
    {:else if check?.error && !update.checking}
      <div class="line error" data-testid="update-error">
        {t("The last check failed")}: {check.error}
      </div>
    {/if}

    {#if running(res)}
      <div class="progress" data-testid="update-progress">
        <span class="line">{stateText}</span>
        {#if percent !== null}
          <div
            class="bar"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent}
            aria-label={t("Download")}
          >
            <div class="fill" style:width="{percent}%"></div>
          </div>
          <span class="line muted">{percent} %</span>
        {/if}
      </div>
    {:else if res.state === "failed" && res.error}
      <div class="line error" data-testid="update-install-error">
        {t("The install failed")}: {res.error}
      </div>
    {:else if result}
      <div class="line" class:muted={done} class:error={!done} data-testid="update-result">
        {(done
          ? t("{version} installed, opkg exit {code}")
          : t("{version} not installed, opkg exit {code}, see logread")
        )
          .replace("{version}", () => result.version)
          .replace("{code}", String(result.opkgExit))}
      </div>
    {/if}

    {#if !res.canInstall}
      <div class="line muted">{reasonText(res.reason, t)}</div>
    {/if}
  </section>
{/if}

<style>
  .panel {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px 12px;
    background: var(--bg-medium);
    border: 1px solid var(--bg-light-extra);
    border-radius: 8px;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .action {
    flex: 0 0 auto;
    display: flex;
    gap: 8px;
  }
  .progress {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .bar {
    flex: 1;
    height: 6px;
    border-radius: 3px;
    background: var(--bg-light-extra);
    overflow: hidden;
  }
  .fill {
    height: 100%;
    background: var(--accent);
    transition: width 0.3s;
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .line {
    font-size: 0.9rem;
  }
  .muted {
    color: var(--text-2);
  }
  .newer {
    color: var(--accent);
    font-weight: 600;
  }
  .error {
    color: var(--red);
  }
  .notes {
    margin: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font-family: inherit;
    font-size: 0.9rem;
    color: var(--text);
  }
</style>
