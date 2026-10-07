<script lang="ts">
  import Select from "../../../components/ui/Select.svelte";
  import { interfaces } from "../../../data/interfaces.svelte";
  import { t } from "../../../data/locale.svelte";

  import type { Tunnel } from "../../../types";
  import { parseUplink, uplinkOptions, uplinkValue } from "../tunnel-editor";
  import type { ClientTunnel } from "../tunnels-data";

  let { tunnel = $bindable(), tunnels }: { tunnel: ClientTunnel; tunnels: Tunnel[] } = $props();

  const options = $derived(uplinkOptions(tunnel, tunnels, interfaces.list, t));
</script>

<Select
  ariaLabel={t("Way out to the internet")}
  {options}
  selected={uplinkValue(tunnel.uplink)}
  onValueChange={(v: string) => (tunnel.uplink = parseUplink(v))}
/>
