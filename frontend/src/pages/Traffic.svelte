<script lang="ts">
  import { call } from "../lib/api";
  import { toast } from "../lib/store.svelte";
  import { bytes, speed, num, appLabel, ago } from "../lib/format";
  import type { AppStat, HostStat, RouteStat } from "../lib/types";
  import Icon from "../components/Icon.svelte";
  import AppAvatar from "../components/AppAvatar.svelte";
  import QuickRule from "../components/QuickRule.svelte";

  let tab = $state("apps");
  let apps = $state<AppStat[]>([]);
  let hosts = $state<HostStat[]>([]);
  let routes = $state<RouteStat[]>([]);
  let sort = $state<"total" | "speed" | "conns" | "name">("total");
  let quick = $state<null | { app: string; host: string; scope: string }>(null);

  async function load() {
    try { [apps, hosts, routes] = await Promise.all([call<AppStat[]>("GetApps"), call<HostStat[]>("GetTopHosts", 200), call<RouteStat[]>("GetRoutes")]); } catch {}
  }
  $effect(() => { load(); const t = setInterval(load, 1500); return () => clearInterval(t); });

  const sortedApps = $derived([...apps].sort((a, b) =>
    sort === "name" ? a.name.localeCompare(b.name) : sort === "speed" ? b.speedUp + b.speedDown - (a.speedUp + a.speedDown) : sort === "conns" ? b.conns - a.conns : b.up + b.down - (a.up + a.down)));
  const totalAll = $derived(apps.reduce((s, a) => s + a.up + a.down, 0) || 1);

  async function reset() { await call("ResetStats"); toast("Statistics reset", "ok"); load(); }
</script>

<div class="page">
  <div class="page-h">
    <h1>Traffic</h1>
    <div class="seg">
      <button class:on={tab === "apps"} onclick={() => (tab = "apps")}>Applications</button>
      <button class:on={tab === "hosts"} onclick={() => (tab = "hosts")}>Destinations</button>
      <button class:on={tab === "routes"} onclick={() => (tab = "routes")}>Proxies</button>
    </div>
    <span class="spacer"></span>
    {#if tab === "apps"}
      <span class="muted">Sort</span>
      <select class="input" style="width:150px" bind:value={sort}>
        <option value="total">Total data</option><option value="speed">Current speed</option><option value="conns">Connections</option><option value="name">Name</option>
      </select>
    {/if}
    <button class="btn" onclick={reset}><Icon name="refresh" size={14} />Reset statistics</button>
  </div>
  <div class="page-b">
    <div class="card" style="overflow:hidden">
      {#if tab === "apps"}
        <table class="t">
          <thead><tr><th>Application</th><th class="num">Open</th><th class="num">Connections</th><th class="num">Proxied</th><th class="num">Blocked</th><th class="num">↓ Down</th><th class="num">↑ Up</th><th class="num">Speed</th><th style="width:16%">Share</th><th class="num">Last seen</th><th></th></tr></thead>
          <tbody>
            {#each sortedApps as a (a.name)}
              <tr>
                <td><div class="row"><AppAvatar name={a.name} size={24} /><div class="col" style="gap:0;min-width:0"><strong class="ellipsis">{appLabel(a.name)}</strong><span class="muted ellipsis" style="font-size:11.5px;max-width:320px" title={a.path}>{a.path}</span></div></div></td>
                <td class="num">{a.active}</td>
                <td class="num">{num(a.conns)}</td>
                <td class="num">{num(a.proxied)}</td>
                <td class="num" style:color={a.blocked ? "var(--red)" : ""}>{num(a.blocked)}</td>
                <td class="num mono">{bytes(a.down)}</td>
                <td class="num mono">{bytes(a.up)}</td>
                <td class="num mono muted">{a.speedUp + a.speedDown ? speed(a.speedUp + a.speedDown) : ""}</td>
                <td><div class="share"><span style="width:{((a.up + a.down) / totalAll) * 100}%"></span></div></td>
                <td class="num muted">{ago(a.lastSeen)}</td>
                <td>{#if a.name !== "Unknown"}<button class="btn sm" onclick={() => (quick = { app: a.name, host: "", scope: "app" })}>Rule…</button>{/if}</td>
              </tr>
            {:else}
              <tr><td colspan="11"><div class="empty"><Icon name="bar" size={26} /><h4>No traffic yet</h4></div></td></tr>
            {/each}
          </tbody>
        </table>
      {:else if tab === "hosts"}
        <table class="t">
          <thead><tr><th>Destination</th><th class="num">Connections</th><th class="num">↓ Down</th><th class="num">↑ Up</th><th class="num">Total</th><th></th></tr></thead>
          <tbody>
            {#each hosts as h (h.host)}
              <tr><td class="mono">{h.host}</td><td class="num">{num(h.conns)}</td><td class="num mono">{bytes(h.down)}</td><td class="num mono">{bytes(h.up)}</td><td class="num mono">{bytes(h.up + h.down)}</td>
                <td><button class="btn sm" onclick={() => (quick = { app: "", host: h.host, scope: /^[\d.:]+$/.test(h.host) ? "host" : "domain" })}>Rule…</button></td></tr>
            {:else}
              <tr><td colspan="6"><div class="empty"><Icon name="globe" size={26} /><h4>No destinations yet</h4></div></td></tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <table class="t">
          <thead><tr><th>Proxy / chain</th><th class="num">Open</th><th class="num">Connections</th><th class="num">Errors</th><th class="num">↓ Down</th><th class="num">↑ Up</th></tr></thead>
          <tbody>
            {#each routes as r (r.name)}
              <tr><td><div class="row"><Icon name="shield" size={14} /><strong>{r.name}</strong></div></td><td class="num">{r.active}</td><td class="num">{num(r.conns)}</td><td class="num" style:color={r.errors ? "var(--red)" : ""}>{num(r.errors)}</td><td class="num mono">{bytes(r.down)}</td><td class="num mono">{bytes(r.up)}</td></tr>
            {:else}
              <tr><td colspan="6"><div class="empty"><Icon name="shield" size={26} /><h4>Nothing has used a proxy yet</h4></div></td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </div>
</div>

{#if quick}<QuickRule appName={quick.app} host={quick.host} initial={quick.scope} onclose={() => (quick = null)} />{/if}

<style>
  .share { height: 6px; border-radius: 4px; background: var(--surface-3); overflow: hidden; }
  .share span { display: block; height: 100%; background: var(--accent); }
</style>
