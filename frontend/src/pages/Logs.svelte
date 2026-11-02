<script lang="ts">
  import { call } from "../lib/api";
  import { toast } from "../lib/store.svelte";
  import type { LogEntry } from "../lib/types";
  import Icon from "../components/Icon.svelte";
  import Toggle from "../components/Toggle.svelte";

  let logs = $state<LogEntry[]>([]);
  let level = $state("all");
  let kind = $state("all");
  let q = $state("");
  let follow = $state(true);
  let box: HTMLDivElement;
  let last = 0;

  async function load() {
    try {
      const fresh = await call<LogEntry[]>("GetLogs", last, 2000);
      if (fresh.length) {
        last = fresh[fresh.length - 1].seq;
        logs = [...logs, ...fresh].slice(-5000);
        if (follow) requestAnimationFrame(() => box && (box.scrollTop = box.scrollHeight));
      }
    } catch {}
  }
  $effect(() => { load(); const t = setInterval(load, 1000); return () => clearInterval(t); });

  const shown = $derived(logs.filter((l) => {
    if (level === "warn" && l.level !== "warn" && l.level !== "error") return false;
    if (level === "error" && l.level !== "error") return false;
    if (kind === "conn" && l.kind !== "conn") return false;
    if (kind === "events" && l.kind === "conn") return false;
    return !q || l.msg.toLowerCase().includes(q.toLowerCase());
  }));

  function time(t: string) { const d = new Date(t); return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0"); }
  async function clear() { await call("ClearLogs"); logs = []; }
  function copy() { navigator.clipboard?.writeText(shown.map((l) => `${l.time} [${l.level}] ${l.msg}`).join("\n")); toast(`Copied ${shown.length} lines`, "ok", 1800); }
</script>

<div class="page">
  <div class="page-h">
    <h1>Logs</h1>
    <div class="seg">{#each [["all", "All"], ["conn", "Connections"], ["events", "Events"]] as [k, l]}<button class:on={kind === k} onclick={() => (kind = k)}>{l}</button>{/each}</div>
    <div class="seg">{#each [["all", "Any level"], ["warn", "Warnings"], ["error", "Errors"]] as [k, l]}<button class:on={level === k} onclick={() => (level = k)}>{l}</button>{/each}</div>
    <span class="spacer"></span>
    <div class="search" style="width:240px"><Icon name="search" size={14} /><input class="input" placeholder="Search logs…" bind:value={q} /></div>
    <label class="row muted" style="font-size:12.5px"><Toggle bind:checked={follow} label="Follow" />Follow</label>
    <button class="btn" onclick={copy}><Icon name="copy" size={14} />Copy</button>
    <button class="btn" onclick={clear}><Icon name="trash" size={14} />Clear</button>
  </div>
  <div class="page-b" style="display:flex">
    <div class="card box" bind:this={box} onscroll={() => { if (box) follow = box.scrollHeight - box.scrollTop - box.clientHeight < 30; }}>
      {#each shown as l (l.seq)}
        <div class="ln {l.level}"><span class="tm">{time(l.time)}</span><span class="lv">{l.level}</span><span class="msg">{l.msg}</span></div>
      {:else}
        <div class="empty"><Icon name="logs" size={26} /><h4>Nothing logged{q ? " matches" : " yet"}</h4></div>
      {/each}
    </div>
  </div>
</div>

<style>
  .box { flex: 1; overflow: auto; padding: 8px 0; font-family: var(--mono); font-size: 12.3px; user-select: text; }
  .ln { display: flex; gap: 12px; padding: 2px 14px; line-height: 1.55; }
  .ln:hover { background: var(--surface-2); }
  .tm { color: var(--faint); flex: none; }
  .lv { width: 44px; flex: none; text-transform: uppercase; font-size: 11px; color: var(--muted); padding-top: 1px; }
  .msg { white-space: pre-wrap; overflow-wrap: anywhere; }
  .warn .lv, .warn .msg { color: var(--amber); }
  .error .lv, .error .msg { color: var(--red); }
  .debug .msg { color: var(--muted); }
</style>
