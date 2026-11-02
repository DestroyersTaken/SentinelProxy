<script lang="ts">
  import { call } from "../lib/api";
  import { app, toast } from "../lib/store.svelte";
  import { bytes, speed, duration, appLabel, clock } from "../lib/format";
  import type { Conn, Action } from "../lib/types";
  import Icon from "../components/Icon.svelte";
  import AppAvatar from "../components/AppAvatar.svelte";
  import ActionBadge from "../components/ActionBadge.svelte";
  import Toggle from "../components/Toggle.svelte";
  import QuickRule from "../components/QuickRule.svelte";

  let conns = $state<Conn[]>([]);
  let q = $state("");
  let filter = $state("all");
  let net = $state("all");
  let showClosed = $state(true);
  let paused = $state(false);
  let sel = $state<Conn | null>(null);
  let quick = $state<null | { app: string; host: string; scope: string; action?: Action }>(null);
  let now = $state(Date.now());

  async function load() {
    if (paused) return;
    try { conns = await call<Conn[]>("GetConnections", showClosed); now = Date.now(); } catch {}
    if (sel) sel = conns.find((c) => c.id === sel!.id) ?? sel;
  }
  $effect(() => { showClosed; load(); const t = setInterval(load, 1000); return () => clearInterval(t); });

  const shown = $derived.by(() => {
    const ql = q.trim().toLowerCase();
    return conns.filter((c) => {
      if (filter === "proxy" && c.action !== "proxy") return false;
      if (filter === "direct" && c.action !== "direct") return false;
      if (filter === "block" && c.state !== "blocked") return false;
      if (filter === "failed" && c.state !== "failed") return false;
      if (filter === "active" && c.end) return false;
      if (net !== "all" && c.network !== net) return false;
      if (!ql) return true;
      return [c.app, c.host, c.dst, c.rule, c.route, c.path].some((x) => x?.toLowerCase().includes(ql));
    });
  });
  const counts = $derived({
    all: conns.length,
    active: conns.filter((c) => !c.end).length,
    proxy: conns.filter((c) => c.action === "proxy").length,
    direct: conns.filter((c) => c.action === "direct").length,
    block: conns.filter((c) => c.state === "blocked").length,
    failed: conns.filter((c) => c.state === "failed").length,
  });

  function stateBadge(c: Conn) {
    if (c.state === "blocked") return { k: "block", t: "Blocked" };
    if (c.state === "failed") return { k: "block", t: "Failed" };
    if (c.end) return { k: "", t: "Closed" };
    if (c.state === "connecting") return { k: "warn", t: "Connecting" };
    return { k: "ok", t: c.inbound === "bypass" ? "Open (bypass)" : "Open" };
  }

  function hostOf(c: Conn) { return c.host || (c.dst || "").replace(/:\d+$/, "").replace(/^\[|\]$/g, ""); }

  async function kill(c: Conn) {
    await call("KillConnection", c.id);
    toast("Connection closed", "ok", 1600);
    load();
  }
  async function killApp(name: string) {
    const n = await call<number>("KillApp", name);
    toast(`Closed ${n} connection(s) of ${appLabel(name)}`, "ok");
    load();
  }
  const sourceText: Record<string, string> = { tls: "from TLS SNI", http: "from HTTP Host", fakeip: "via fake-IP DNS", dns: "from DNS (best guess)", request: "requested by the app" };
</script>

<div class="page">
  <div class="page-h">
    <h1>Connections</h1>
    <span class="sub">{counts.active} open · {counts.all} listed</span>
    <span class="spacer"></span>
    <div class="search" style="width:280px">
      <Icon name="search" size={14} />
      <input class="input" placeholder="Filter by app, host, IP, rule…" bind:value={q} />
    </div>
    <button class="btn" class:primary={paused} onclick={() => (paused = !paused)} title="Freeze the list to inspect it">
      <Icon name={paused ? "play" : "pause"} size={14} />{paused ? "Resume" : "Pause"}
    </button>
  </div>
  <div class="bar">
    <div class="seg">
      {#each [["all", "All"], ["active", "Open"], ["proxy", "Proxied"], ["direct", "Direct"], ["block", "Blocked"], ["failed", "Failed"]] as [k, l]}
        <button class:on={filter === k} onclick={() => (filter = k)}>{l} <span class="c">{counts[k as keyof typeof counts]}</span></button>
      {/each}
    </div>
    <div class="seg">
      {#each [["all", "TCP + UDP"], ["tcp", "TCP"], ["udp", "UDP"]] as [k, l]}<button class:on={net === k} onclick={() => (net = k)}>{l}</button>{/each}
    </div>
    <span class="spacer"></span>
    <label class="row muted" style="font-size:12.5px"><Toggle bind:checked={showClosed} label="Show closed" />Show closed</label>
    <button class="btn sm ghost" onclick={async () => { await call("ClearClosed"); load(); }}><Icon name="trash" size={13} />Clear closed</button>
  </div>

  <div class="wrap">
    <div class="tbl">
      {#if shown.length === 0}
        <div class="empty">
          <Icon name="activity" size={28} />
          <h4>{conns.length ? "Nothing matches the filter" : "No connections yet"}</h4>
          <span>{app.state?.running ? "Open a website or an app and it shows up here instantly." : "Turn proxying on to start routing and monitoring traffic."}</span>
        </div>
      {:else}
        <table class="t" class:narrow={!!sel}>
          <thead><tr>
            <th style="width:15%">App</th><th>Destination</th><th style="width:15%">Route</th><th class="opt" style="width:13%">Rule</th>
            <th class="num" style="width:84px">↓ Down</th><th class="num opt" style="width:72px">↑ Up</th><th class="num opt" style="width:88px">Speed</th><th class="num" style="width:62px">Time</th><th style="width:104px">State</th>
          </tr></thead>
          <tbody>
            {#each shown.slice(0, 600) as c (c.id)}
              {@const sb = stateBadge(c)}
              <tr class:sel={sel?.id === c.id} class:closed={!!c.end} onclick={() => (sel = c)}>
                <td><div class="row" style="min-width:0"><AppAvatar name={c.app} size={22} /><span class="ellipsis" title={c.path || c.app}>{appLabel(c.app)}</span>{#if c.network === "udp"}<span class="badge info sm">UDP</span>{/if}</div></td>
                <td><div class="col" style="gap:0;min-width:0">
                  <span class="ellipsis mono dst" title={c.host}>{hostOf(c)}<span class="muted">:{c.port}</span></span>
                  {#if c.host && c.dst}<span class="ellipsis muted ip">{c.dst}</span>{:else if c.host && c.action === "proxy" && c.state !== "blocked"}<span class="ellipsis muted ip">resolved by proxy</span>{/if}
                </div></td>
                <td><ActionBadge type={c.state === "blocked" ? "block" : c.action || "direct"} label={c.action === "proxy" ? (c.hops?.join(" → ") || c.route) : ""} /></td>
                <td class="opt"><span class="ellipsis muted" style="display:block" title={c.rule}>{c.rule}</span></td>
                <td class="num mono">{bytes(c.down)}</td>
                <td class="num mono opt">{bytes(c.up)}</td>
                <td class="num mono muted opt">{c.end ? "" : c.speedDown + c.speedUp ? speed(c.speedDown + c.speedUp) : ""}</td>
                <td class="num mono muted">{duration((c.end || now) - c.start)}</td>
                <td><span class="badge {sb.k}">{sb.t}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if shown.length > 600}<div class="muted" style="padding:10px">Showing the newest 600 of {shown.length}. Narrow the filter to see more.</div>{/if}
      {/if}
    </div>

    {#if sel}
      {@const c = sel}
      <div class="drawer">
        <div class="row" style="padding:14px 14px 6px">
          <AppAvatar name={c.app} size={34} />
          <div class="col" style="gap:0;min-width:0;flex:1">
            <strong class="ellipsis">{appLabel(c.app)}</strong>
            <span class="muted ellipsis" style="font-size:12px" title={c.path}>{c.path || (c.pid ? "PID " + c.pid : "unknown process")}</span>
          </div>
          <button class="btn ghost icon sm" onclick={() => (sel = null)}><Icon name="x" size={14} /></button>
        </div>
        <div class="dl">
          <div><span>Destination</span><strong class="mono">{hostOf(c)}:{c.port}</strong></div>
          {#if c.host}<div><span>Hostname</span><span>{sourceText[c.hostSource] ?? c.hostSource}</span></div>{/if}
          <div><span>IP address</span><span class="mono">{c.dst || "resolved by the proxy"}</span></div>
          <div><span>Protocol</span><span>{c.network.toUpperCase()} · {c.inbound === "local-proxy" ? "via local proxy" : c.inbound === "bypass" ? "direct, bypassing the relay" : "captured"}</span></div>
          <div><span>Route</span><span><ActionBadge type={c.state === "blocked" ? "block" : c.action} label={c.action === "proxy" ? c.route : ""} /></span></div>
          {#if c.hops?.length}<div><span>Path</span><span class="mono">you → {c.hops.join(" → ")} → site</span></div>{/if}
          <div><span>Rule</span><span>{c.rule}</span></div>
          <div><span>Started</span><span>{clock(c.start)}{#if c.end} · lasted {duration(c.end - c.start)}{/if}</span></div>
          <div><span>Traffic</span><span class="mono">↓ {bytes(c.down)} · ↑ {bytes(c.up)}</span></div>
          {#if c.error}<div class="err"><span>Error</span><span>{c.error}</span></div>{/if}
        </div>
        <div class="acts">
          <div class="lbl">Make a rule</div>
          <button class="btn" onclick={() => (quick = { app: c.app, host: hostOf(c), scope: "app" })}><Icon name="shield" size={14} />Route this app…</button>
          <button class="btn" onclick={() => (quick = { app: c.app, host: hostOf(c), scope: c.host ? "domain" : "host" })}><Icon name="globe" size={14} />Route this site…</button>
          <button class="btn danger" onclick={() => (quick = { app: c.app, host: hostOf(c), scope: c.host ? "domain" : "host", action: { type: "block" } })}><Icon name="ban" size={14} />Block this site…</button>
          {#if !c.end}
            <div class="lbl">Connection</div>
            <button class="btn" onclick={() => kill(c)}><Icon name="x" size={14} />Close connection</button>
            {#if c.app}<button class="btn" onclick={() => killApp(c.app)}><Icon name="x" size={14} />Close all of {appLabel(c.app)}</button>{/if}
          {/if}
          <button class="btn ghost" onclick={() => { navigator.clipboard?.writeText(`${c.app} → ${hostOf(c)}:${c.port} (${c.dst}) via ${c.route || c.action} rule "${c.rule}"`); toast("Copied", "ok", 1500); }}><Icon name="copy" size={14} />Copy details</button>
        </div>
      </div>
    {/if}
  </div>
</div>

{#if quick}
  <QuickRule appName={quick.app} host={quick.host} initial={quick.scope} action={quick.action} onclose={() => (quick = null)} />
{/if}

<style>
  .bar { display: flex; align-items: center; gap: 10px; padding: 0 24px 12px; flex-wrap: wrap; }
  .seg .c { color: var(--faint); font-size: 11.5px; margin-left: 3px; font-variant-numeric: tabular-nums; }
  .wrap { flex: 1; min-height: 0; display: flex; gap: 12px; padding: 0 24px 20px; }
  .tbl { flex: 1; min-width: 0; overflow: auto; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); }
  table { table-layout: fixed; }
  table.narrow :global(.opt) { display: none; }
  tr { cursor: pointer; }
  tr.closed td { opacity: .55; }
  td { font-size: 12.8px; }
  .dst { font-size: 12.5px; color: var(--text); }
  .ip { font-size: 11.5px; font-family: var(--mono); }
  .badge.sm { height: 18px; font-size: 10.5px; padding: 0 5px; }
  .drawer { width: 340px; flex: none; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: auto; animation: slide .15s; }
  .dl { padding: 6px 14px 10px; display: flex; flex-direction: column; }
  .dl > div { display: grid; grid-template-columns: 92px 1fr; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 12.5px; align-items: center; }
  .dl > div > span:first-child { color: var(--muted); }
  .dl > div > *:last-child { min-width: 0; overflow-wrap: anywhere; }
  .dl .err span:last-child { color: var(--red); }
  .acts { display: flex; flex-direction: column; gap: 6px; padding: 4px 14px 16px; }
  .acts .lbl { font-size: 11.5px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; margin-top: 8px; }
  .acts .btn { justify-content: flex-start; }
  @keyframes slide { from { opacity: 0; transform: translateX(10px) } }
</style>
