<script lang="ts">
  import Icon from "./Icon.svelte";
  let { type, label = "" }: { type: string; label?: string } = $props();
  const icon = $derived(type === "proxy" ? "shield" : type === "block" ? "ban" : "arrowRight");
  const text = $derived(label || (type === "proxy" ? "Proxy" : type === "block" ? "Block" : "Direct"));
</script>

<span class="badge {type}" title={text}><Icon name={icon} size={12} stroke={2.2} /><span class="ellipsis">{text}</span></span>
