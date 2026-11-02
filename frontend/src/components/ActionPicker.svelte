<script lang="ts">
  import type { Action } from "../lib/types";
  import { targets } from "../lib/store.svelte";

  let { value = $bindable(), compact = false }: { value: Action; compact?: boolean } = $props();
  const list = $derived(targets());

  function pick(t: Action["type"]) {
    if (t === "proxy") value = { type: "proxy", target: value.target && list.some((x) => x.id === value.target) ? value.target : list[0]?.id };
    else value = { type: t };
  }
</script>

<div class="ap" class:compact>
  <div class="seg">
    <button type="button" class:on={value.type === "direct"} onclick={() => pick("direct")}>Direct</button>
    <button type="button" class:on={value.type === "proxy"} onclick={() => pick("proxy")} disabled={!list.length} title={list.length ? "" : "Add a proxy first"}>Proxy</button>
    <button type="button" class:on={value.type === "block"} onclick={() => pick("block")}>Block</button>
  </div>
  {#if value.type === "proxy"}
    <select class="input" bind:value={value.target}>
      {#each list.filter((t) => t.kind === "proxy") as t}<option value={t.id}>{t.label} — {t.sub}</option>{/each}
      {#if list.some((t) => t.kind === "chain")}
        <optgroup label="Chains & groups">
          {#each list.filter((t) => t.kind === "chain") as t}<option value={t.id}>{t.label} — {t.sub}</option>{/each}
        </optgroup>
      {/if}
    </select>
  {/if}
</div>

<style>
  .ap { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .ap select { flex: 1; min-width: 200px; }
  .compact select { min-width: 160px; height: 30px; }
</style>
