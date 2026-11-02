<script lang="ts">
  import { onMount } from "svelte";
  import { app, init, setRunning, toast, refreshState, refreshProfile } from "./lib/store.svelte";
  import { call } from "./lib/api";
  import { speed } from "./lib/format";
  import type { State } from "./lib/types";
  import Icon from "./components/Icon.svelte";
  import Toasts from "./components/Toasts.svelte";
  import Modal from "./components/Modal.svelte";
  import Dashboard from "./pages/Dashboard.svelte";
  import Connections from "./pages/Connections.svelte";
  import Proxies from "./pages/Proxies.svelte";
  import Rules from "./pages/Rules.svelte";
  import Traffic from "./pages/Traffic.svelte";
  import Logs from "./pages/Logs.svelte";
  import ImportExport from "./pages/ImportExport.svelte";
  import Settings from "./pages/Settings.svelte";

  onMount(init);

  const nav = [
    { id: "dashboard", label: "Dashboard", icon: "dashboard" },
    { id: "connections", label: "Connections", icon: "activity" },
    { id: "proxies", label: "Proxies", icon: "server" },
    { id: "rules", label: "Rules", icon: "rules" },
    { id: "traffic", label: "Traffic", icon: "bar" },
    { id: "logs", label: "Logs", icon: "logs" },
    { id: "import", label: "Import / Export", icon: "file" },
    { id: "settings", label: "Settings", icon: "settings" },
  ];

  const count = (id: string) => {
    if (id === "connections") return app.summary?.active ?? 0;
    if (id === "proxies") return (app.profile?.proxies.length ?? 0) + (app.profile?.chains.length ?? 0);
    if (id === "rules") return app.profile?.rules.length ?? 0;
    return 0;
  };

  let profMenu = $state(false);
  let profDialog = $state<null | { mode: "new" | "rename" | "delete"; name: string; copy: boolean }>(null);
  let busy = $state(false);

  async function toggle() {
    if (!app.state || busy) return;
    busy = true;
    try { await setRunning(!app.state.running); } catch (e: any) { toast(e.message, "error"); }
    busy = false;
  }

  async function elevate() {
    try { await call("RestartAsAdmin"); } catch (e: any) { toast(e.message, "error"); }
  }

  async function switchTo(name: string) {
    profMenu = false;
    try { app.state = await call<State>("SwitchProfile", name); await refreshProfile(); toast(`Switched to “${name}”`, "ok"); }
    catch (e: any) { toast(e.message, "error"); }
  }

  async function profAction() {
    if (!profDialog) return;
    try {
      if (profDialog.mode === "new") app.state = await call<State>("CreateProfile", profDialog.name, profDialog.copy);
      else if (profDialog.mode === "rename") app.state = await call<State>("RenameProfile", profDialog.name);
      else app.state = await call<State>("DeleteProfile", profDialog.name);
      await refreshProfile();
      profDialog = null;
    } catch (e: any) { toast(e.message, "error"); }
  }

  const statusChips = $derived.by(() => {
    const s = app.state;
    if (!s) return [];
    const out: { label: string; kind: string; title: string }[] = [];
    if (s.capture.enabled) {
      if (s.capture.active) out.push({ label: `Capture · ${s.capture.detail}`, kind: "ok", title: "All apps are captured automatically" });
      else if (s.running) out.push({ label: "Capture unavailable", kind: "warn", title: s.capture.error || s.captureHint || "" });
      else if (!s.captureReady) out.push({ label: "Capture needs setup", kind: "warn", title: s.captureHint || "" });
    }
    if (s.localProxy.enabled && s.localProxy.active) out.push({ label: `Local proxy · ${s.localProxy.detail}`, kind: "info", title: "Point apps at this SOCKS5/HTTP address" });
    if (s.localProxy.error) out.push({ label: "Local proxy error", kind: "warn", title: s.localProxy.error });
    if (s.systemProxy.active) out.push({ label: "System proxy set", kind: "info", title: "Windows proxy settings point at SentinelProxy" });
    return out;
  });
</script>

{#if !app.ready}
  <div class="boot">
    <img src="/logo.svg" alt="" width="56" height="56" />
    {#if app.error}
      <h3>Could not reach the SentinelProxy service</h3>
      <p class="muted">{app.error}</p>
      <button class="btn" onclick={() => location.reload()}><Icon name="refresh" />Retry</button>
    {:else}
      <p class="muted">Starting…</p>
    {/if}
  </div>
{:else}
  <div class="shell">
    <aside>
      <div class="brand">
        <img src="/logo.svg" alt="" width="28" height="28" />
        <div class="col" style="gap:0">
          <strong>SentinelProxy</strong>
          <span class="muted" style="font-size:11.5px">v{app.state?.version}</span>
        </div>
      </div>
      <nav>
        {#each nav as n}
          <button class:on={app.page === n.id} onclick={() => (app.page = n.id)}>
            <Icon name={n.icon} size={17} />
            <span>{n.label}</span>
            {#if count(n.id)}<span class="cnt">{count(n.id)}</span>{/if}
          </button>
        {/each}
      </nav>
      <div class="spacer"></div>
      <div class="mini">
        <div class="row"><span class="arrow down">↓</span><span class="mono">{speed(app.summary?.speedDown)}</span></div>
        <div class="row"><span class="arrow up">↑</span><span class="mono">{speed(app.summary?.speedUp)}</span></div>
      </div>
    </aside>

    <main>
      <header>
        <button class="power" class:on={app.state?.running} onclick={toggle} disabled={busy} title="Turn proxying on or off">
          <span class="knob"><Icon name="power" size={15} stroke={2.4} /></span>
          <span class="col" style="gap:0;align-items:flex-start">
            <strong>{app.state?.running ? "Proxying on" : "Proxying off"}</strong>
            <span class="sub">{app.state?.running ? "Rules are being applied" : "Traffic is not touched"}</span>
          </span>
        </button>
        <div class="chips">
          {#each statusChips as c}<span class="badge {c.kind}" title={c.title}>{c.label}</span>{/each}
          {#if app.state?.canElevate && app.state.capture.enabled && !app.state.capture.active}
            <button class="btn sm" onclick={elevate} title="System-wide capture needs administrator rights"><Icon name="shield" size={13} />Restart as administrator</button>
          {/if}
        </div>
        <span class="spacer"></span>
        <div class="prof">
          <button class="btn" onclick={() => (profMenu = !profMenu)}>
            <Icon name="layers" /><span class="ellipsis" style="max-width:180px">{app.state?.profile}</span><Icon name="chevronDown" size={14} />
          </button>
          {#if profMenu}
            <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
            <div class="scrim" onclick={() => (profMenu = false)}></div>
            <div class="menu">
              <div class="mh">Profiles</div>
              {#each app.state?.profiles ?? [] as p}
                <button onclick={() => switchTo(p)}>
                  <span class="ck">{#if p === app.state?.profile}<Icon name="check" size={14} />{/if}</span>
                  <span class="ellipsis">{p}</span>
                  {#if p !== app.state?.profile}
                    <span class="spacer"></span>
                    <span role="button" tabindex="-1" class="del" title="Delete" onclick={(e) => { e.stopPropagation(); profMenu = false; profDialog = { mode: "delete", name: p, copy: false }; }} onkeydown={() => {}}><Icon name="trash" size={13} /></span>
                  {/if}
                </button>
              {/each}
              <div class="sep"></div>
              <button onclick={() => { profMenu = false; profDialog = { mode: "new", name: "", copy: false }; }}><span class="ck"><Icon name="plus" size={14} /></span>New profile…</button>
              <button onclick={() => { profMenu = false; profDialog = { mode: "new", name: (app.state?.profile ?? "") + " copy", copy: true }; }}><span class="ck"><Icon name="copy" size={14} /></span>Duplicate current…</button>
              <button onclick={() => { profMenu = false; profDialog = { mode: "rename", name: app.state?.profile ?? "", copy: false }; }}><span class="ck"><Icon name="edit" size={14} /></span>Rename current…</button>
            </div>
          {/if}
        </div>
      </header>
      <section class="content">
        {#key app.page}
          {#if app.page === "dashboard"}<Dashboard />
          {:else if app.page === "connections"}<Connections />
          {:else if app.page === "proxies"}<Proxies />
          {:else if app.page === "rules"}<Rules />
          {:else if app.page === "traffic"}<Traffic />
          {:else if app.page === "logs"}<Logs />
          {:else if app.page === "import"}<ImportExport />
          {:else if app.page === "settings"}<Settings />
          {/if}
        {/key}
      </section>
    </main>
  </div>
{/if}

{#if profDialog}
  <Modal title={profDialog.mode === "new" ? (profDialog.copy ? "Duplicate profile" : "New profile") : profDialog.mode === "rename" ? "Rename profile" : "Delete profile"} width={420} onclose={() => (profDialog = null)}>
    {#if profDialog.mode === "delete"}
      <p>Delete the profile <strong>{profDialog.name}</strong>? Its proxies and rules are removed for good. Export it first if you might need it again.</p>
    {:else}
      <label class="field">Name
        <!-- svelte-ignore a11y_autofocus -->
        <input class="input" bind:value={profDialog.name} autofocus onkeydown={(e) => e.key === "Enter" && profAction()} />
      </label>
      {#if profDialog.mode === "new" && !profDialog.copy}<p class="hint">Starts with the Localhost & LAN rule and default settings.</p>{/if}
    {/if}
    {#snippet footer()}
      <button class="btn ghost" onclick={() => (profDialog = null)}>Cancel</button>
      <button class="btn {profDialog?.mode === 'delete' ? 'danger' : 'primary'}" onclick={profAction}>{profDialog?.mode === "delete" ? "Delete" : profDialog?.mode === "rename" ? "Rename" : "Create"}</button>
    {/snippet}
  </Modal>
{/if}

<Toasts />

<style>
  .boot { height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; }
  .shell { display: flex; height: 100%; }
  aside { width: 226px; flex: none; background: var(--bg-2); border-right: 1px solid var(--border); display: flex; flex-direction: column; padding: 14px 12px; }
  .brand { display: flex; align-items: center; gap: 10px; padding: 4px 8px 16px; }
  .brand strong { font-size: 14.5px; letter-spacing: -.01em; }
  nav { display: flex; flex-direction: column; gap: 2px; }
  nav button { display: flex; align-items: center; gap: 11px; height: 36px; padding: 0 10px; border: 0; border-radius: 9px; background: transparent; color: var(--text-2); cursor: pointer; font-weight: 500; text-align: left; }
  nav button:hover { background: var(--surface); color: var(--text); }
  nav button.on { background: var(--accent-bg); color: var(--text); }
  nav button.on :global(svg) { color: var(--accent); }
  .cnt { margin-left: auto; font-size: 11.5px; padding: 0 7px; border-radius: 10px; background: var(--surface-3); color: var(--muted); font-variant-numeric: tabular-nums; }
  .mini { padding: 10px; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); display: flex; flex-direction: column; gap: 3px; font-size: 12.5px; }
  .arrow { font-weight: 700; width: 12px; }
  .arrow.down { color: var(--down); }
  .arrow.up { color: var(--up); }
  main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  header { display: flex; align-items: center; gap: 14px; padding: 12px 24px; border-bottom: 1px solid var(--border); min-height: 64px; }
  .power { display: flex; align-items: center; gap: 11px; padding: 6px 16px 6px 6px; border-radius: 40px; border: 1px solid var(--border-2); background: var(--surface); cursor: pointer; transition: all .15s; }
  .power .knob { width: 34px; height: 34px; border-radius: 50%; display: flex; align-items: center; justify-content: center; background: var(--surface-3); color: var(--muted); transition: all .15s; }
  .power strong { font-size: 13.5px; }
  .power .sub { font-size: 11.5px; color: var(--muted); }
  .power.on { border-color: color-mix(in srgb, var(--green) 45%, transparent); background: var(--green-bg); }
  .power.on .knob { background: var(--green); color: #06120c; box-shadow: 0 0 0 4px var(--green-bg), 0 0 18px color-mix(in srgb, var(--green) 50%, transparent); }
  .chips { display: flex; gap: 6px; flex-wrap: wrap; min-width: 0; }
  .prof { position: relative; }
  .scrim { position: fixed; inset: 0; z-index: 30; }
  .menu { position: absolute; right: 0; top: calc(100% + 6px); width: 260px; background: var(--surface-2); border: 1px solid var(--border-2); border-radius: 12px; box-shadow: var(--shadow); padding: 6px; z-index: 31; }
  .menu .mh { font-size: 11.5px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); padding: 6px 10px 4px; font-weight: 600; }
  .menu button { display: flex; align-items: center; gap: 6px; width: 100%; border: 0; background: transparent; padding: 7px 8px; border-radius: 7px; cursor: pointer; text-align: left; }
  .menu button:hover { background: var(--surface-3); }
  .menu .ck { width: 18px; display: inline-flex; color: var(--accent); }
  .menu .del { color: var(--muted); padding: 2px; border-radius: 4px; display: flex; }
  .menu .del:hover { color: var(--red); }
  .menu .sep { height: 1px; background: var(--border); margin: 5px 4px; }
  .content { flex: 1; min-height: 0; }
</style>
