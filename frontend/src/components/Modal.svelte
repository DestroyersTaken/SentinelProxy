<script lang="ts">
  import type { Snippet } from "svelte";
  import Icon from "./Icon.svelte";
  let { title, width = 560, onclose, children, footer, subtitle = "" }: { title: string; width?: number; onclose: () => void; children: Snippet; footer?: Snippet; subtitle?: string } = $props();
  function key(e: KeyboardEvent) { if (e.key === "Escape") onclose(); }
</script>

<svelte:window onkeydown={key} />
<div class="ov" role="presentation" onmousedown={(e) => { if (e.target === e.currentTarget) onclose(); }}>
  <div class="m" style="width:min({width}px, calc(100vw - 40px))" role="dialog" aria-modal="true" aria-label={title}>
    <div class="h">
      <div class="col" style="gap:2px">
        <h2>{title}</h2>
        {#if subtitle}<div class="muted" style="font-size:12.5px">{subtitle}</div>{/if}
      </div>
      <span class="spacer"></span>
      <button class="btn ghost icon" onclick={onclose} aria-label="Close"><Icon name="x" /></button>
    </div>
    <div class="b">{@render children()}</div>
    {#if footer}<div class="f">{@render footer()}</div>{/if}
  </div>
</div>

<style>
  .ov { position: fixed; inset: 0; background: rgba(5, 7, 12, .55); backdrop-filter: blur(3px); display: flex; align-items: center; justify-content: center; z-index: 50; animation: fade .12s; }
  .m { background: var(--surface); border: 1px solid var(--border-2); border-radius: 16px; box-shadow: var(--shadow); max-height: calc(100vh - 60px); display: flex; flex-direction: column; animation: pop .14s; }
  .h { display: flex; align-items: center; padding: 16px 18px 10px; }
  h2 { margin: 0; font-size: 16px; font-weight: 650; }
  .b { padding: 6px 18px 16px; overflow: auto; }
  .f { display: flex; gap: 8px; justify-content: flex-end; padding: 12px 18px; border-top: 1px solid var(--border); }
  @keyframes fade { from { opacity: 0 } }
  @keyframes pop { from { opacity: 0; transform: translateY(6px) scale(.985) } }
</style>
