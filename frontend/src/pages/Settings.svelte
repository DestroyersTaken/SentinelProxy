<script lang="ts">
  import { app, mutate, toast, applyTheme } from "../lib/store.svelte";
  import { call } from "../lib/api";
  import type { Settings, AppSettings, State } from "../lib/types";
  import Toggle from "../components/Toggle.svelte";
  import ChipInput from "../components/ChipInput.svelte";
  import Icon from "../components/Icon.svelte";

  let s = $state<Settings>(JSON.parse(JSON.stringify(app.profile!.settings)));
  let a = $state<AppSettings>(JSON.parse(JSON.stringify(app.state!.app)));
  const dirty = $derived(JSON.stringify(s) !== JSON.stringify(app.profile!.settings));
  const st = $derived(app.state!);
  const isWin = $derived(st.os === "windows");

  async function save() {
    const v = $state.snapshot(s) as Settings;
    if (await mutate((p) => (p.settings = v), "Settings saved")) s = JSON.parse(JSON.stringify(app.profile!.settings));
  }
  function revert() { s = JSON.parse(JSON.stringify(app.profile!.settings)); }
  async function saveApp() {
    try { app.state = await call<State>("SaveAppSettings", $state.snapshot(a)); applyTheme(a.theme); } catch (e: any) { toast(e.message, "error"); }
  }
</script>

<div class="page">
  <div class="page-h">
    <h1>Settings</h1>
    <span class="sub">Profile settings apply to “{st.profile}”. App preferences apply everywhere.</span>
  </div>
  <div class="page-b">
    <div class="grid">
      <section class="card">
        <div class="card-h"><Icon name="zap" /><h3>Traffic capture</h3></div>
        <div class="card-b col" style="gap:2px">
          <div class="opt"><div><strong>Capture all apps automatically</strong><span>Route every program by your rules, no per-app proxy settings needed. {isWin ? "Uses the WinDivert driver; needs administrator rights." : st.os === "linux" ? "Uses nftables; needs root. TCP only on Linux." : "Not available on this system."}</span>
            {#if !st.captureReady && st.captureHint}<span class="warn"><Icon name="alert" size={12} /> {st.captureHint}</span>{/if}
            {#if st.canElevate}<button class="btn sm" style="align-self:flex-start;margin-top:6px" onclick={() => call("RestartAsAdmin").catch((e) => toast(e.message, "error"))}><Icon name="shield" size={13} />Restart as administrator</button>{/if}</div><Toggle bind:checked={s.intercept} /></div>
          <div class="opt" class:dim={!s.intercept}><div><strong>Capture UDP</strong><span>Games, voice chat, QUIC/HTTP3. UDP goes through SOCKS5 proxies only.</span></div><Toggle bind:checked={s.interceptUdp} disabled={!s.intercept} /></div>
          <div class="opt" class:dim={!s.intercept}><div><strong>Capture IPv6</strong><span>Also route IPv6 connections.</span></div><Toggle bind:checked={s.interceptIpv6} disabled={!s.intercept} /></div>
          <div class="opt"><div><strong>When a proxy can't carry UDP</strong><span>HTTP proxies and chains only carry TCP. Blocking makes apps such as browsers fall back to TCP, so nothing leaks around the proxy.</span></div>
            <div class="seg"><button class:on={s.udpFallback === "block"} onclick={() => (s.udpFallback = "block")}>Block</button><button class:on={s.udpFallback === "direct"} onclick={() => (s.udpFallback = "direct")}>Send direct</button></div></div>
          <div class="opt"><div><strong>Detect hostnames</strong><span>Read the site name from HTTPS (SNI) and HTTP requests, so domain rules work even when apps connect by IP, and proxies get the real hostname.</span></div><Toggle bind:checked={s.sniff} /></div>
          <div class="opt" class:dim={!s.intercept}><div><strong>Relay direct connections too</strong><span>Full byte counts and hostnames for direct traffic. Off: direct traffic bypasses SentinelProxy entirely (fastest).</span></div><Toggle bind:checked={s.relayDirect} disabled={!s.intercept} /></div>
        </div>
      </section>

      <section class="card">
        <div class="card-h"><Icon name="globe" /><h3>Name resolution (DNS)</h3></div>
        <div class="card-b col" style="gap:10px">
          <div class="radios">
            <button class:on={s.dns.mode === "auto"} onclick={() => (s.dns.mode = "auto")}><strong>Smart (recommended)</strong><span>Your normal DNS keeps working. Proxied connections send the hostname to the proxy, which resolves it.</span></button>
            <button class:on={s.dns.mode === "fakeip"} onclick={() => (s.dns.mode = "fakeip")} disabled={!isWin} title={isWin ? "" : "Windows only"}><strong>Through proxy, leak-proof</strong><span>Answers DNS with placeholder addresses so every hostname is resolved by the proxy and no DNS query leaks. {isWin ? "" : "(Windows only)"}</span></button>
            <button class:on={s.dns.mode === "local"} onclick={() => (s.dns.mode = "local")}><strong>Always local</strong><span>Resolve everything on this computer and give proxies IP addresses only.</span></button>
          </div>
          {#if s.dns.mode === "fakeip"}
            <label class="field">Never fake these names <span class="hint">resolved by your normal DNS</span><ChipInput bind:values={s.dns.exclusions} kind="host" placeholder="*.local, intranet.corp" /></label>
            <div class="grid2">
              <label class="field">DNS servers SentinelProxy uses itself<ChipInput bind:values={s.dns.upstreams} placeholder="1.1.1.1, 8.8.8.8" /></label>
              <label class="field">Placeholder range<input class="input mono" bind:value={s.dns.fakeIpRange} /></label>
            </div>
          {/if}
        </div>
      </section>

      <section class="card">
        <div class="card-h"><Icon name="server" /><h3>Local proxy server</h3></div>
        <div class="card-b col" style="gap:2px">
          <div class="opt"><div><strong>Run a local SOCKS5 / HTTP proxy</strong><span>For apps you point at a proxy yourself, phones and consoles on your network, or when capture isn't available. Same rules apply.</span></div><Toggle bind:checked={s.localProxy} /></div>
          <div class="grid2" class:dim={!s.localProxy} style="padding:8px 0">
            <label class="field">Listen address <span class="hint">use 0.0.0.0:2080 to share on your LAN</span><input class="input mono" bind:value={s.localProxyListen} disabled={!s.localProxy} /></label>
            <div class="grid2">
              <label class="field">Username<input class="input" bind:value={s.localProxyUser} placeholder="none" disabled={!s.localProxy} /></label>
              <label class="field">Password<input class="input" type="password" bind:value={s.localProxyPassword} disabled={!s.localProxy} /></label>
            </div>
          </div>
          {#if st.sysProxySupported}
            <div class="opt" class:dim={!s.localProxy}><div><strong>Set as the Windows system proxy</strong><span>Browsers and apps that follow Windows proxy settings use SentinelProxy. Restored when you turn it off.</span></div><Toggle bind:checked={s.systemProxy} disabled={!s.localProxy} /></div>
          {/if}
        </div>
      </section>

      <section class="card">
        <div class="card-h"><Icon name="activity" /><h3>Proxy health</h3></div>
        <div class="card-b col" style="gap:10px">
          <div class="opt"><div><strong>Check group members in the background</strong><span>Keeps failover and fastest groups up to date.</span></div><Toggle bind:checked={s.healthCheck} /></div>
          <div class="grid2">
            <label class="field">Check every (seconds)<input class="input" type="number" min="15" bind:value={s.healthCheckIntervalSec} /></label>
            <label class="field">Connect timeout (seconds)<input class="input" type="number" min="2" max="120" bind:value={s.connectTimeoutSec} /></label>
          </div>
          <label class="field">Test URL<input class="input mono" bind:value={s.checkUrl} /></label>
        </div>
      </section>

      <section class="card">
        <div class="card-h"><Icon name="logs" /><h3>Logging</h3></div>
        <div class="card-b col" style="gap:10px">
          <div class="opt"><div><strong>Log every connection</strong><span>One line per connection in Logs. Turn off for very busy machines.</span></div><Toggle bind:checked={s.logConnections} /></div>
          <label class="field">Level
            <div class="seg">{#each ["debug", "info", "warn", "error"] as l}<button class:on={s.logLevel === l} onclick={() => (s.logLevel = l)}>{l}</button>{/each}</div>
          </label>
          <span class="hint">Log file: <span class="mono">{st.dataDir}/logs/sentinelproxy.log</span></span>
        </div>
      </section>

      <section class="card">
        <div class="card-h"><Icon name="settings" /><h3>App</h3><span class="hint">saved immediately</span></div>
        <div class="card-b col" style="gap:2px">
          <div class="opt"><div><strong>Turn proxying on at launch</strong></div><Toggle bind:checked={a.startEnabled} onchange={saveApp} /></div>
          <div class="opt"><div><strong>Start minimized to the tray</strong></div><Toggle bind:checked={a.startMinimized} onchange={saveApp} /></div>
          <div class="opt"><div><strong>Closing the window keeps it running in the tray</strong></div><Toggle bind:checked={a.closeToTray} onchange={saveApp} /></div>
          <div class="opt"><div><strong>Theme</strong></div>
            <div class="seg">{#each [["system", "System"], ["dark", "Dark"], ["light", "Light"]] as [k, l]}<button class:on={a.theme === k} onclick={() => { a.theme = k; saveApp(); }}>{l}</button>{/each}</div></div>
          <span class="hint" style="padding-top:8px">Data folder: <span class="mono">{st.dataDir}</span> · version {st.version} · {st.os}</span>
        </div>
      </section>
    </div>
  </div>
  {#if dirty}
    <div class="savebar">
      <Icon name="info" size={15} /><span>You have unsaved changes.</span><span class="spacer"></span>
      <button class="btn ghost" onclick={revert}>Discard</button>
      <button class="btn primary" onclick={save}><Icon name="check" size={14} />Save settings</button>
    </div>
  {/if}
</div>

<style>
  .grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 12px; align-items: start; padding-bottom: 60px; }
  .opt { display: flex; align-items: center; gap: 16px; padding: 10px 0; border-bottom: 1px solid var(--border); }
  .opt:last-child { border-bottom: 0; }
  .opt > div:first-child { flex: 1; display: flex; flex-direction: column; gap: 2px; }
  .opt span { color: var(--muted); font-size: 12.3px; line-height: 1.4; }
  .opt .warn { color: var(--amber); }
  .dim { opacity: .5; }
  .radios { display: flex; flex-direction: column; gap: 8px; }
  .radios button { display: flex; flex-direction: column; gap: 3px; align-items: flex-start; text-align: left; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border-2); background: var(--surface-2); cursor: pointer; }
  .radios button span { color: var(--muted); font-size: 12.3px; }
  .radios button.on { border-color: var(--accent); background: var(--accent-bg); }
  .radios button:disabled { opacity: .5; cursor: default; }
  .savebar { position: absolute; left: 50%; transform: translateX(-50%); bottom: 18px; display: flex; align-items: center; gap: 10px; padding: 10px 12px 10px 16px; border-radius: 12px; background: var(--surface-2); border: 1px solid var(--accent); box-shadow: var(--shadow); width: min(640px, 90%); animation: up .18s; }
  .page { position: relative; }
  @keyframes up { from { opacity: 0; transform: translate(-50%, 8px) } }
  @media (max-width: 1150px) { .grid { grid-template-columns: 1fr; } }
</style>
