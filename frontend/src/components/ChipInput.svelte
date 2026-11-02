<script lang="ts">
  import { call } from "../lib/api";
  import Icon from "./Icon.svelte";

  let { values = $bindable(), placeholder = "", kind = "text", suggestions = [], mono = true }:
    { values?: string[]; placeholder?: string; kind?: "app" | "host" | "port" | "text"; suggestions?: string[]; mono?: boolean } = $props();

  let text = $state("");
  let input: HTMLInputElement;
  let errors = $state<Record<string, string>>({});
  let open = $state(false);

  const list = $derived(values ?? []);
  const filtered = $derived(
    text.length === 0 ? [] :
    suggestions.filter((s) => s.toLowerCase().includes(text.toLowerCase()) && !list.includes(s)).slice(0, 8)
  );

  async function check(v: string) {
    if (kind !== "host" && kind !== "port") return;
    const r = await call<string>("ValidatePattern", kind, v).catch(() => "");
    if (r && !r.startsWith("ok:")) errors = { ...errors, [v]: r };
    else if (r.startsWith("ok:")) errors = { ...errors, [v]: "" , ["~" + v]: r.slice(3) };
  }

  function add(raw: string) {
    const parts = raw.split(/[;,\n\r]+/).map((s) => s.trim().replace(/^"|"$/g, "")).filter(Boolean);
    const next = [...list];
    for (const p of parts) {
      if (!next.some((x) => x.toLowerCase() === p.toLowerCase())) { next.push(p); check(p); }
    }
    values = next;
    text = "";
  }

  function remove(i: number) { values = list.filter((_, j) => j !== i); }

  function key(e: KeyboardEvent) {
    if (e.key === "Enter" || e.key === "," || e.key === ";" || (e.key === "Tab" && text.trim())) {
      if (text.trim()) { e.preventDefault(); add(filtered.length && e.key === "Tab" ? filtered[0] : text); }
    } else if (e.key === "Backspace" && !text && list.length) {
      remove(list.length - 1);
    }
  }

  $effect(() => { for (const v of list) if (!(v in errors)) check(v); });
</script>

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div class="ci" onclick={() => input?.focus()}>
  {#each list as v, i (v)}
    <span class="chip" class:bad={errors[v]} class:mono title={errors[v] || errors["~" + v] || v}>
      {#if errors[v]}<Icon name="alert" size={12} />{/if}
      <span class="ellipsis">{v}</span>
      <button type="button" onclick={(e) => { e.stopPropagation(); remove(i); }} aria-label="Remove {v}"><Icon name="x" size={12} stroke={2.4} /></button>
    </span>
  {/each}
  <input bind:this={input} bind:value={text} onkeydown={key} placeholder={list.length ? "" : placeholder}
    onpaste={(e) => { const t = e.clipboardData?.getData("text") ?? ""; if (/[;,\n]/.test(t)) { e.preventDefault(); add(t); } }}
    onfocus={() => (open = true)} onblur={() => { setTimeout(() => (open = false), 150); if (text.trim()) add(text); }} />
  {#if open && filtered.length}
    <div class="sug">
      {#each filtered as s}
        <button type="button" onmousedown={(e) => { e.preventDefault(); add(s); }}>{s}</button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .ci { position: relative; display: flex; flex-wrap: wrap; gap: 5px; align-items: center; min-height: 36px; padding: 4px 6px; border: 1px solid var(--border-2); border-radius: 8px; background: var(--bg-2); cursor: text; }
  .ci:focus-within { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-bg); }
  input { flex: 1; min-width: 120px; border: 0; outline: 0; background: transparent; height: 26px; padding: 0 4px; }
  .chip { display: inline-flex; align-items: center; gap: 4px; height: 24px; padding: 0 4px 0 8px; border-radius: 6px; background: var(--surface-3); max-width: 100%; font-size: 12.5px; }
  .chip.mono { font-family: var(--mono); font-size: 12px; }
  .chip.bad { background: var(--red-bg); color: var(--red); }
  .chip button { border: 0; background: transparent; padding: 2px; border-radius: 4px; display: flex; cursor: pointer; color: var(--muted); }
  .chip button:hover { background: var(--border-2); color: var(--text); }
  .sug { position: absolute; left: 0; right: 0; top: calc(100% + 4px); background: var(--surface-2); border: 1px solid var(--border-2); border-radius: 9px; box-shadow: var(--shadow); z-index: 20; padding: 4px; max-height: 240px; overflow: auto; }
  .sug button { display: block; width: 100%; text-align: left; border: 0; background: transparent; padding: 6px 9px; border-radius: 6px; cursor: pointer; font-family: var(--mono); font-size: 12.5px; }
  .sug button:hover { background: var(--accent-bg); }
</style>
