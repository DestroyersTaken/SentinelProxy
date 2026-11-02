<script lang="ts">
  let { checked = $bindable(), disabled = false, onchange, label = "" }: { checked?: boolean; disabled?: boolean; onchange?: (v: boolean) => void; label?: string } = $props();
</script>

<button type="button" class="tg" class:on={!!checked} {disabled} role="switch" aria-checked={!!checked} aria-label={label}
  onclick={(e) => { e.stopPropagation(); checked = !checked; onchange?.(checked); }}>
  <span></span>
</button>

<style>
  .tg { width: 34px; height: 20px; border-radius: 20px; border: 0; background: var(--surface-3); position: relative; cursor: pointer; flex: none; transition: background .15s; padding: 0; outline: 1px solid var(--border-2); }
  .tg span { position: absolute; top: 3px; left: 3px; width: 14px; height: 14px; border-radius: 50%; background: var(--muted); transition: transform .15s, background .15s; }
  .tg.on { background: var(--accent); outline-color: transparent; }
  .tg.on span { transform: translateX(14px); background: #fff; }
  .tg:disabled { opacity: .5; cursor: default; }
</style>
