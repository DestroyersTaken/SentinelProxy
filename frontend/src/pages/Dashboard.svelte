<script lang="ts">
  import { app, go, setRunning, toast, refreshHealth } from "../lib/store.svelte";
  import { call } from "../lib/api";
  import { bytes, speed, num, appLabel } from "../lib/format";
  import type { AppStat, HostStat, RouteStat, LogEntry, CheckResult } from "../lib/types";
  import Icon from "../components/Icon.svelte";
  import SpeedChart from "../components/SpeedChart.svelte";
  import AppAvatar from "../components/AppAvatar.svelte";

  let apps = $state<AppStat[]>([]);
  let hosts = $state<HostStat[]>([]);
  let routes = $state<RouteStat[]>([]);
  let events = $state<LogEntry[]>([]);
  let checking = $state(false);
  let span = $state(120);

  async function load() {
    try {
      [apps, hosts, routes] = await Promise.all([call<AppStat[]>("GetApps"), call<HostStat[]>("GetTopHosts", 8), call<RouteStat[]>("GetRoutes")]);
      const logs = await call<LogEntry[]>("GetLogs", 0, 200);
      events = logs.filter((l) => l.kind !== "conn").slice(-6).reverse();
    } catch {}
  }
  $effect(() => { load(); const t = setInterval(load, 2000); return () => clearInterval(t); });

  const s = $derived(app.summary);
  const st = $derived(app.state);
  const p = $derived(app.profile);
  const routed = $derived.by(() => {
    const t = (s?.proxied ?? 0) + (s?.direct ?? 0) + (s?.blocked ?? 0);
    return { t, p: t ? (s!.proxied / t) * 100 : 0, d: t ? (s!.direct / t) * 100 : 0, b: t ? (s!.blocked / t) * 100 : 0 };
  });
  const maxApp = $derived(Math.max(1, ...apps.slice(0, 7).map((a) => a.up + a.down)));
  const maxHost = $derived(Math.max(1, ...hosts.map((h) => h.up + h.down)));
  const proxyList = $derived((p?.proxies ?? []).slice(0, 7));

  async function checkAll() {
    checking = true;
    try {
      const r = await call<Record<string, CheckResult>>("CheckAll");
      const ok = Object.values(r).filter((x) => x.ok).length;
      toast(`${ok} of ${Object.keys(r).length} proxies working`, ok === Object.keys(r).length ? "ok" : "warn");
      await refreshHealth();
    } catch (e: any) { toast(e.message, "error"); }
    checking = false;
  }

  function copyLocal() {
    if (st?.localProxy.detail) { navigator.clipboard?.writeText(st.localProxy.detail); toast("Copied " + st.localProxy.detail, "ok", 2000); }
  }
</script>

<div class="page">
  <div class="page-h">
    <h1>Dashboard</h1>
    <span class="sub">Profile “{st?.profile}”</span>
  </div>
  <div class="page-b">
    {#if p && p.proxies.length === 0}
      <div class="card onboard">
        <div class="col" style="gap:4px">
          <h3 style="margin:0">Get started in three steps</h3>
          <span class="muted">SentinelProxy sends each app's traffic where your rules say: through a proxy, directly, or nowhere.</span>
        </div>
        <div class="steps">
          <button class="step" onclick={() => go("proxies", { add: true })}><span class="n">1</span><span><strong>Add a proxy</strong><br /><span class="muted">or paste a list of them</span></span></button>
          <button class="step" onclick={() => go("rules", { add: true })}><span class="n">2</span><span><strong>Create a rule</strong><br /><span class="muted">pick an app or a website</span></span></button>
          <button class="step" onclick={() => setRunning(true)}><span class="n">3</span><span><strong>Turn proxying on</strong><br /><span class="muted">watch it on Connections</span></span></button>
          <button class="step alt" onclick={() => go("import")}><span class="n"><Icon name="upload" size={15} /></span><span><strong>Coming from Proxifier?</strong><br /><span class="muted">import your .ppx profile</span></span></button>
        </div>
      </div>
    {/if}

    <div class="kpis">
      <div class="card kpi">
        <div class="kl"><span class="sw" style="background:var(--down)"></span>Download</div>
        <div class="kv">{speed(s?.speedDown)}</div>
        <div class="ks">{bytes(s?.totalDown)} total</div>
      </div>
      <div class="card kpi">
        <div class="kl"><span class="sw" style="background:var(--up)"></span>Upload</div>
        <div class="kv">{speed(s?.speedUp)}</div>
        <div class="ks">{bytes(s?.totalUp)} total</div>
      </div>
      <div class="card kpi">
        <div class="kl"><Icon name="activity" size={14} />Active connections</div>
        <div class="kv">{num(s?.active)}</div>
        <div class="ks">{s?.activeTcp ?? 0} TCP · {s?.activeUdp ?? 0} UDP · {num(s?.totalConns)} total</div>
      </div>
      <div class="card kpi">
        <div class="kl"><Icon name="shield" size={14} />Routing</div>
        <div class="bar3">
          <span style="width:{routed.p}%;background:var(--accent)"></span>
          <span style="width:{routed.d}%;background:var(--teal)"></span>
          <span style="width:{routed.b}%;background:var(--red)"></span>
        </div>
        <div class="ks legend">
          <span><i style="background:var(--accent)"></i>{num(s?.proxied)} proxied</span>
          <span><i style="background:var(--teal)"></i>{num(s?.direct)} direct</span>
          <span><i style="background:var(--red)"></i>{num(s?.blocked)} blocked</span>
        </div>
      </div>
    </div>

    <div class="g2">
      <div class="card">
        <div class="card-h">
          <h3>Live traffic</h3>
          <span class="spacer"></span>
          <div class="seg">
            <button class:on={span === 60} onclick={() => (span = 60)}>1m</button>
            <button class:on={span === 120} onclick={() => (span = 120)}>2m</button>
            <button class:on={span === 300} onclick={() => (span = 300)}>5m</button>
          </div>
        </div>
        <div class="card-b"><SpeedChart points={s?.history ?? []} {span} height={210} /></div>
      </div>

      <div class="card">
        <div class="card-h"><h3>Status</h3></div>
        <div class="card-b col" style="gap:10px">
          <div class="srow">
            <span class="dot {st?.capture.active ? 'up' : st?.capture.enabled && st?.running ? 'down' : 'unknown'}"></span>
            <div class="col" style="gap:0;min-width:0">
              <strong>System-wide capture</strong>
              <span class="muted ellipsis" title={st?.capture.error || st?.captureHint}>
                {#if st?.capture.active}Every app is captured ({st.capture.detail}){:else if !st?.capture.enabled}Off: only apps using the local proxy{:else if st?.capture.error}{st.capture.error}{:else if !st?.captureReady}{st?.captureHint}{:else}Starts when proxying is on{/if}
              </span>
            </div>
          </div>
          <div class="srow">
            <span class="dot {st?.localProxy.active ? 'up' : 'unknown'}"></span>
            <div class="col" style="gap:0;min-width:0">
              <strong>Local proxy</strong>
              <span class="muted ellipsis">{#if st?.localProxy.active}SOCKS5 / HTTP on <span class="mono">{st.localProxy.detail}</span>{:else if st?.localProxy.error}{st.localProxy.error}{:else if st?.localProxy.enabled}Starts when proxying is on{:else}Off{/if}</span>
            </div>
            {#if st?.localProxy.active}<button class="btn sm icon ghost" title="Copy address" onclick={copyLocal}><Icon name="copy" size={14} /></button>{/if}
          </div>
          <div class="hr"></div>
          <div class="row"><strong>Proxies</strong><span class="spacer"></span>
            {#if proxyList.length}<button class="btn sm" onclick={checkAll} disabled={checking}><Icon name="zap" size={13} />{checking ? "Checking…" : "Check all"}</button>{/if}
          </div>
          {#each proxyList as px}
            {@const h = app.health[px.id]}
            <div class="srow tight">
              <span class="dot {h?.state ?? 'unknown'}"></span>
              <span class="ellipsis" style="flex:1">{px.name || px.host}</span>
              <span class="muted mono">{h?.state === "up" ? h.latencyMs + " ms" : h?.state === "down" ? "down" : "—"}</span>
            </div>
          {:else}
            <span class="muted">No proxies yet.</span>
          {/each}
        </div>
      </div>
    </div>

    <div class="g3">
      <div class="card">
        <div class="card-h"><h3>Top apps</h3><span class="spacer"></span><button class="btn sm ghost" onclick={() => go("traffic")}>All<Icon name="chevronRight" size={13} /></button></div>
        <div class="card-b col" style="gap:9px">
          {#each apps.slice(0, 7) as a}
            <div class="bl">
              <AppAvatar name={a.name} size={24} />
              <div class="col" style="gap:3px;flex:1;min-width:0">
                <div class="row"><span class="ellipsis" style="flex:1" title={a.path}>{appLabel(a.name)}</span><span class="muted mono">{bytes(a.up + a.down)}</span></div>
                <div class="meter"><span style="width:{((a.up + a.down) / maxApp) * 100}%"></span></div>
              </div>
            </div>
          {:else}
            <span class="muted">No traffic yet.</span>
          {/each}
        </div>
      </div>
      <div class="card">
        <div class="card-h"><h3>Top destinations</h3></div>
        <div class="card-b col" style="gap:9px">
          {#each hosts as h}
            <div class="col" style="gap:3px">
              <div class="row"><span class="ellipsis mono" style="flex:1">{h.host}</span><span class="muted mono">{bytes(h.up + h.down)}</span></div>
              <div class="meter teal"><span style="width:{((h.up + h.down) / maxHost) * 100}%"></span></div>
            </div>
          {:else}
            <span class="muted">No traffic yet.</span>
          {/each}
        </div>
      </div>
      <div class="card">
        <div class="card-h"><h3>Proxy usage</h3></div>
        <div class="card-b col" style="gap:8px">
          {#each routes.slice(0, 6) as r}
            <div class="row">
              <Icon name="shield" size={14} />
              <span class="ellipsis" style="flex:1">{r.name}</span>
              <span class="muted mono" title="active / total connections">{r.active}/{r.conns}</span>
              <span class="mono" style="width:76px;text-align:right">{bytes(r.up + r.down)}</span>
            </div>
          {:else}
            <span class="muted">Nothing went through a proxy yet.</span>
          {/each}
          {#if events.length}
            <div class="hr"></div>
            <strong style="font-size:12.5px">Recent events</strong>
            {#each events as e}
              <div class="ev {e.level}"><span class="ellipsis" title={e.msg}>{e.msg}</span></div>
            {/each}
          {/if}
        </div>
      </div>
    </div>
  </div>
</div>

<style>
  .onboard { padding: 16px; margin-bottom: 14px; display: flex; flex-direction: column; gap: 14px; background: linear-gradient(135deg, var(--accent-bg), transparent 60%), var(--surface); }
  .steps { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
  .step { display: flex; gap: 11px; align-items: center; padding: 12px; border-radius: 11px; border: 1px solid var(--border-2); background: var(--surface-2); cursor: pointer; text-align: left; line-height: 1.35; }
  .step:hover { border-color: var(--accent); }
  .step .n { width: 28px; height: 28px; flex: none; border-radius: 50%; background: var(--accent); color: #fff; display: flex; align-items: center; justify-content: center; font-weight: 700; }
  .step.alt .n { background: var(--surface-3); color: var(--text); }
  .kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 12px; }
  .kpi { padding: 14px 16px; display: flex; flex-direction: column; gap: 4px; }
  .kl { display: flex; align-items: center; gap: 7px; color: var(--muted); font-size: 12.5px; font-weight: 500; }
  .kv { font-size: 24px; font-weight: 650; letter-spacing: -.02em; font-variant-numeric: tabular-nums; }
  .ks { color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }
  .sw { width: 9px; height: 9px; border-radius: 3px; display: inline-block; }
  .bar3 { display: flex; height: 10px; border-radius: 6px; overflow: hidden; background: var(--surface-3); margin: 10px 0 6px; }
  .bar3 span { display: block; height: 100%; transition: width .4s; }
  .legend { display: flex; gap: 10px; flex-wrap: wrap; }
  .legend i { display: inline-block; width: 7px; height: 7px; border-radius: 2px; margin-right: 4px; }
  .g2 { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: 12px; margin-bottom: 12px; }
  .g3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
  .srow { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .srow.tight { font-size: 12.5px; }
  .hr { height: 1px; background: var(--border); }
  .bl { display: flex; align-items: center; gap: 10px; }
  .meter { height: 5px; border-radius: 4px; background: var(--surface-3); overflow: hidden; }
  .meter span { display: block; height: 100%; background: var(--accent); border-radius: 4px; transition: width .4s; }
  .meter.teal span { background: var(--teal); }
  .ev { font-size: 12px; color: var(--text-2); display: flex; }
  .ev.warn { color: var(--amber); }
  .ev.error { color: var(--red); }
  @media (max-width: 1180px) { .steps, .kpis { grid-template-columns: repeat(2, 1fr); } .g3 { grid-template-columns: 1fr 1fr; } }
</style>
