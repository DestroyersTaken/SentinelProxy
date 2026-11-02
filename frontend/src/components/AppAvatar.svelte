<script lang="ts">
  import { appLabel, hue } from "../lib/format";
  let { name, size = 26 }: { name: string; size?: number } = $props();
  const label = $derived(appLabel(name));
  const h = $derived(hue(label.toLowerCase()));
</script>

<span class="av" style="width:{size}px;height:{size}px;font-size:{size * 0.42}px;background:hsl({h} 55% 45% / .22);color:hsl({h} 75% 70%)">{label.slice(0, 2)}</span>

<style>
  .av { display: inline-flex; align-items: center; justify-content: center; border-radius: 8px; font-weight: 700; text-transform: uppercase; flex: none; letter-spacing: -.02em; }
  :global([data-theme="light"]) .av { filter: saturate(1.2) brightness(.8); }
</style>
