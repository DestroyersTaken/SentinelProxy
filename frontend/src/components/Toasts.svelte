<script lang="ts">
  import { app } from "../lib/store.svelte";
  import Icon from "./Icon.svelte";
  const icons: Record<string, string> = { ok: "check", error: "alert", warn: "alert", info: "info" };
</script>

<div class="ts">
  {#each app.toasts as t (t.id)}
    <div class="t {t.kind}"><Icon name={icons[t.kind]} /><span>{t.msg}</span></div>
  {/each}
</div>

<style>
  .ts { position: fixed; right: 18px; bottom: 18px; display: flex; flex-direction: column; gap: 8px; z-index: 100; max-width: 420px; }
  .t { display: flex; gap: 10px; align-items: flex-start; padding: 11px 14px; border-radius: 11px; background: var(--surface-2); border: 1px solid var(--border-2); box-shadow: var(--shadow); white-space: pre-line; animation: in .18s; }
  .t.ok :global(svg) { color: var(--green); }
  .t.error { border-color: var(--red); }
  .t.error :global(svg) { color: var(--red); }
  .t.warn :global(svg) { color: var(--amber); }
  .t.info :global(svg) { color: var(--accent); }
  @keyframes in { from { opacity: 0; transform: translateY(8px) } }
</style>
