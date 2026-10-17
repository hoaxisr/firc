<script lang="ts">
  import { Popover } from "bits-ui";

  import { t } from "../../data/locale.svelte";
  import { checkUpdate, installUpdate, update } from "./update.svelte";

  import { Refresh } from "../../components/ui/icons";
  import {
    hasNewer,
    reasonText,
    releaseLinkText,
    releaseUrl,
    running,
    runningText,
    updateStatus,
  } from "./update";

  let { version }: { version: string } = $props();

  const res = $derived(update.res);
  const status = $derived(res ? updateStatus(res, update) : null);
  const failed = $derived(
    status?.kind === "install-failed" ||
      status?.kind === "not-installed" ||
      status?.kind === "check-failed",
  );
  const dot = $derived(failed ? "failed" : hasNewer(res) ? "newer" : null);
  const busy = $derived(update.checking || update.installing || running(res));
  const action = $derived(status?.kind === "newer" && status.offered);
  const look = $derived(busy ? "busy" : action ? "action" : failed ? "failed" : "idle");
</script>

<Popover.Root>
  <Popover.Trigger class="version-button" aria-label={`${t("Updates")}: ${version}`}>
    <span class="version-text" title={`${t("build")}: ${version}`}>{version}</span>
    {#if dot}
      <span
        class="update-dot"
        data-testid="update-dot"
        data-tone={dot}
        title={dot === "failed" ? t("The last update failed") : t("A newer release is available")}
      ></span>
    {/if}
  </Popover.Trigger>
  <Popover.Portal>
    <Popover.Content class="update-popover" align="start" sideOffset={6} collisionPadding={8}>
      {#if res && status}
        <button
          type="button"
          class="status"
          class:primary={look === "busy" || look === "action"}
          class:failed={look === "failed"}
          data-testid="update-status"
          data-state={look}
          aria-busy={busy}
          disabled={look !== "action"}
          onclick={() => void installUpdate()}
        >
          {#if status.kind === "running"}
            <span class="title">{runningText(status.state, status.version, t)}</span>
            {#if status.percent !== null}
              <span
                class="bar"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={status.percent}
                aria-label={t("Download")}
                ><span class="fill" style:width="{status.percent}%"></span></span
              >
              <span class="sub">{status.percent} %</span>
            {:else}
              <span class="pulse" aria-hidden="true"></span>
            {/if}
          {:else if status.kind === "checking"}
            <span class="title">{t("Checking...")}</span>
            <span class="pulse" aria-hidden="true"></span>
          {:else if status.kind === "install-failed"}
            <span class="title">{t("The install failed")}</span>
            <span class="sub">{status.error}</span>
          {:else if status.kind === "not-installed"}
            <span class="title">{t("The install failed")}</span>
            <span class="sub">
              {t("{version} not installed, opkg exit {code}, see logread")
                .replace("{version}", () => status.version)
                .replace("{code}", String(status.code))}
            </span>
          {:else if status.kind === "check-failed"}
            <span class="title">{t("Check failed")}</span>
            <span class="sub">{status.error}</span>
          {:else if status.kind === "newer"}
            <span class="title"
              >{t("Install {version}").replace("{version}", () => status.version)}</span
            >
            {#if !status.offered}<span class="sub">{reasonText(res.reason, t)}</span>{/if}
          {:else if status.kind === "up-to-date"}
            <span class="title">{t("Latest version")}</span>
            <span class="sub">
              {t("checked {n} min ago").replace("{n}", String(status.minutes))}
            </span>
          {:else}
            <span class="title">{t("Not checked yet")}</span>
          {/if}
        </button>
        <div class="row">
          <a href={releaseUrl(res)} target="_blank" rel="noopener noreferrer">
            {releaseLinkText(res, t)}
          </a>
          <button
            type="button"
            class="check"
            disabled={busy}
            data-testid="update-check"
            onclick={() => void checkUpdate()}
          >
            <Refresh size={14} />{t("Check")}
          </button>
        </div>
      {:else}
        <div class="row">{t("No answer from the daemon")}</div>
      {/if}
    </Popover.Content>
  </Popover.Portal>
</Popover.Root>

<style>
  :global(.version-button) {
    all: unset;
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    min-width: 0;
    max-width: 100%;
    padding: 0.2rem 0.35rem;
    border-radius: 0.4rem;
    cursor: pointer;
  }
  :global(.version-button:hover),
  :global(.version-button:focus-visible) {
    background: var(--bg-light);
  }
  .version-text {
    display: block;
    min-width: 0;
    font-size: smaller;
    color: var(--text-2);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .update-dot {
    flex: none;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent);
  }
  .update-dot[data-tone="failed"] {
    background: var(--danger);
  }
  :global(.update-popover) {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    box-sizing: border-box;
    width: min(20rem, calc(100vw - 1rem));
    padding: 0.7rem;
    background: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.6rem;
    box-shadow: var(--shadow-popover);
    color: var(--text);
    z-index: 30;
    outline: none;
  }
  .status {
    all: unset;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.2rem;
    width: 100%;
    padding: 0.75rem 0.6rem;
    border-radius: 0.5rem;
    border: 1px solid var(--bg-light-extra);
    background: var(--bg-medium);
    color: var(--text-2);
    text-align: center;
  }
  .status.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--bg-dark-extra);
    cursor: pointer;
  }
  .status[data-state="busy"] {
    cursor: progress;
  }
  .bar,
  .pulse {
    display: block;
    width: 70%;
    height: 4px;
    margin-top: 0.25rem;
    border-radius: 2px;
    background: color-mix(in srgb, var(--bg-dark-extra) 30%, transparent);
    overflow: hidden;
  }
  .fill {
    display: block;
    height: 100%;
    background: var(--bg-dark-extra);
  }
  .pulse::after {
    content: "";
    display: block;
    width: 35%;
    height: 100%;
    background: var(--bg-dark-extra);
    animation: pulse-slide 1.2s ease-in-out infinite;
  }
  @keyframes pulse-slide {
    from {
      transform: translateX(-100%);
    }
    to {
      transform: translateX(290%);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .pulse::after {
      animation: none;
      width: 100%;
      opacity: 0.6;
    }
  }
  .status.failed .title {
    color: var(--danger);
  }
  .title {
    font-size: 1.05rem;
    font-weight: 600;
  }
  .sub {
    max-width: 100%;
    font-size: 0.8rem;
    color: var(--text-2);
    overflow-wrap: anywhere;
  }
  .status.primary .sub {
    color: inherit;
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.6rem;
    font-size: 0.85rem;
  }
  .row a {
    min-width: 0;
    color: var(--accent);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .check {
    all: unset;
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    flex: none;
    padding: 0.3rem 0.55rem;
    border-radius: 0.4rem;
    background: var(--bg-light);
    color: var(--text);
    cursor: pointer;
  }
  .check:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
