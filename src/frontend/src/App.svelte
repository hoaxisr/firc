<script lang="ts">
  import "./app.css";

  import AuthPage from "./components/AuthPage.svelte";
  import AppLayout from "./components/layout/AppLayout.svelte";
  import { token } from "./data/auth.svelte";
  import { fetchInterfaces } from "./data/interfaces.svelte";
  import TooltipLayer from "./lib/tooltip/TooltipLayer.svelte";

  $effect(() => {
    if (token.current) {
      fetchInterfaces();
    }
  });
</script>

{#if !token.current}
  <AuthPage />
{:else}
  <AppLayout />
{/if}

<TooltipLayer />
