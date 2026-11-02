<script lang="ts">
  import { app, mutate, toast, uid, actionText, targets } from "../lib/store.svelte";
  import { call } from "../lib/api";
  import { num } from "../lib/format";
  import type { Rule, Action, TestResult, Process } from "../lib/types";
  import Icon from "../components/Icon.svelte";
  import Modal from "../components/Modal.svelte";
  import Toggle from "../components/Toggle.svelte";
  import ChipInput from "../components/ChipInput.svelte";
  import ActionPicker from "../components/ActionPicker.svelte";
  import ActionBadge from "../components/ActionBadge.svelte";

  const p = $derived(app.profile!);
  let edit = $state<Rule | null>(null);
  let isNew = $state(false);
  let tmplMenu = $state(false);
  let help = $state(false);
  let procs = $state<string[]>([]);
  let dragFrom = $state<number | null>(null);
  let dragOver = $state<number | null>(null);
  let tester = $state(false);
  let test = $state({ app: "chrome.exe", host: "www.google.com", port: 443, protocol: "tcp" });
  let testRes = $state<TestResult | null>(null);
  let q = $state("");

  $effect(() => {
    if (app.focus?.page === "rules" && app.focus.data?.add) { app.focus = null; newRule(); }
  });

  async function loadProcs() {
    try { procs = (await call<Process[]>("ListProcesses")).map((x) => x.name); } catch {}
  }

  const firstProxy = (): Action => (targets().length ? { type: "proxy", target: targets()[0].id } : { type: "direct" });

  const templates: { name: string; desc: string; make: () => Partial<Rule> }[] = [
    { name: "Browsers through a proxy", desc: "Chrome, Edge, Firefox, Brave, Opera", make: () => ({ name: "Browsers", apps: ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"], action: firstProxy() }) },
    { name: "One app through a proxy", desc: "Pick any program", make: () => ({ name: "", apps: [], action: firstProxy() }) },
    { name: "Websites through a proxy", desc: "e.g. a streaming service", make: () => ({ name: "Sites", hosts: [".netflix.com", ".nflxvideo.net"], action: firstProxy() }) },
    { name: "Game (TCP + UDP)", desc: "Route a game, including voice and matchmaking", make: () => ({ name: "Game", apps: ["game.exe"], action: firstProxy() }) },
    { name: "Block telemetry & ads", desc: "Common tracking domains", make: () => ({ name: "Block trackers", hosts: ["keyword:telemetry", ".doubleclick.net", ".googlesyndication.com", ".app-measurement.com", "vortex.data.microsoft.com"], action: { type: "block" } }) },
    { name: "Keep something direct", desc: "Bypass the proxy for a site or app", make: () => ({ name: "Direct", hosts: [], action: { type: "direct" } }) },
  ];

  function newRule(t?: (typeof templates)[number]) {
    tmplMenu = false;
    const base = t?.make() ?? { name: "", action: firstProxy() };
    edit = { id: uid(), name: "", enabled: true, apps: [], hosts: [], ports: [], protocol: "", action: { type: "direct" }, ...base } as Rule;
    isNew = true;
    loadProcs();
  }
  function editRule(r: Rule) { edit = JSON.parse(JSON.stringify(r)); isNew = false; loadProcs(); }

  function autoName(r: Rule) {
    const parts: string[] = [];
    if (r.apps?.length) parts.push(r.apps.slice(0, 2).join(", ") + (r.apps.length > 2 ? ` +${r.apps.length - 2}` : ""));
    if (r.hosts?.length) parts.push(r.hosts.slice(0, 2).join(", ") + (r.hosts.length > 2 ? ` +${r.hosts.length - 2}` : ""));
    if (r.ports?.length) parts.push("port " + r.ports.join(", "));
    return parts.join(" · ") || "Everything";
  }

  async function saveRule() {
    if (!edit) return;
    const r = $state.snapshot(edit) as Rule;
    if (!r.name.trim()) r.name = autoName(r);
    if (r.action.type === "proxy" && !r.action.target) { toast("Choose a proxy for this rule", "warn"); return; }
    const ok = await mutate((pr) => {
      const i = pr.rules.findIndex((x) => x.id === r.id);
      if (i >= 0) pr.rules[i] = r;
      else pr.rules.unshift(r);
    }, isNew ? "Rule added at the top" : "Rule saved");
    if (ok) edit = null;
  }

  function toggleRule(r: Rule, on: boolean) { mutate((pr) => { const x = pr.rules.find((y) => y.id === r.id); if (x) x.enabled = on; }); }
  function del(r: Rule) { mutate((pr) => { pr.rules = pr.rules.filter((x) => x.id !== r.id); }, `Deleted “${r.name}”`); }
  function dup(r: Rule) {
    mutate((pr) => { const i = pr.rules.findIndex((x) => x.id === r.id); pr.rules.splice(i + 1, 0, { ...JSON.parse(JSON.stringify(r)), id: uid(), name: r.name + " copy" }); }, "Duplicated");
  }
  function move(from: number, to: number) {
    if (from === to || to < 0 || to >= p.rules.length) return;
    mutate((pr) => { const [x] = pr.rules.splice(from, 1); pr.rules.splice(to, 0, x); });
  }
  function setDefault(a: Action) { mutate((pr) => (pr.defaultAction = a), "Default rule updated"); }
  let defAction = $state<Action>({ type: "direct" });
  $effect(() => { defAction = JSON.parse(JSON.stringify(p.defaultAction)); });
  $effect(() => {
    const a = defAction;
    if (a.type !== p.defaultAction.type || a.target !== p.defaultAction.target) setDefault($state.snapshot(a) as Action);
  });

  async function runTest() {
    try { testRes = await call<TestResult>("TestRule", test, null); } catch (e: any) { toast(e.message, "error"); }
  }

  const shown = $derived(p.rules.map((r, i) => ({ r, i })).filter(({ r }) => {
    const ql = q.toLowerCase().trim();
    if (!ql) return true;
    return [r.name, ...(r.apps ?? []), ...(r.hosts ?? []), ...(r.ports ?? []), actionText(r.action)].some((x) => x.toLowerCase().includes(ql));
  }));
  const yn = (v: string) => (v === "yes" ? "✓" : v === "no" ? "✗" : v === "unknown" ? "?" : "·");
</script>

<div class="page">
  <div class="page-h">
    <h1>Rules</h1>
    <span class="sub">Checked from top to bottom; the first rule that matches wins.</span>
    <span class="spacer"></span>
    <div class="search" style="width:220px"><Icon name="search" size={14} /><input class="input" placeholder="Find a rule…" bind:value={q} /></div>
    <button class="btn" class:primary={tester} onclick={() => { tester = !tester; if (tester) { loadProcs(); runTest(); } }}><Icon name="flask" size={14} />Test</button>
    <div class="tm">
      <button class="btn primary" onclick={() => (tmplMenu = !tmplMenu)}><Icon name="plus" size={14} />New rule<Icon name="chevronDown" size={13} /></button>
      {#if tmplMenu}
        <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
        <div class="scrim" onclick={() => (tmplMenu = false)}></div>
        <div class="menu">
          <button onclick={() => newRule()}><Icon name="plus" size={15} /><span><strong>Blank rule</strong><br /><span class="muted">Start from scratch</span></span></button>
          <div class="sep"></div>
          {#each templates as t}
            <button onclick={() => newRule(t)}><Icon name="wand" size={15} /><span><strong>{t.name}</strong><br /><span class="muted">{t.desc}</span></span></button>
          {/each}
        </div>
      {/if}
    </div>
  </div>
  <div class="page-b">
    {#if tester}
      <div class="card tester">
        <div class="row" style="gap:10px;flex-wrap:wrap">
          <strong>What happens if…</strong>
          <div style="width:190px"><input class="input mono" list="procs" bind:value={test.app} placeholder="app.exe" oninput={runTest} /></div>
          <span class="muted">connects to</span>
          <div style="flex:1;min-width:200px"><input class="input mono" bind:value={test.host} placeholder="host or IP" oninput={runTest} /></div>
          <span class="muted">port</span>
          <div style="width:90px"><input class="input mono" type="number" bind:value={test.port} oninput={runTest} /></div>
          <div class="seg">{#each ["tcp", "udp"] as pr}<button class:on={test.protocol === pr} onclick={() => { test.protocol = pr; runTest(); }}>{pr.toUpperCase()}</button>{/each}</div>
        </div>
        {#if testRes}
          <div class="verdict">
            <ActionBadge type={testRes.decision.action.type} label={testRes.label} />
            <span>matched by <strong>{testRes.decision.ruleName}</strong>{testRes.decision.index >= 0 ? ` (rule #${testRes.decision.index + 1})` : ""}</span>
          </div>
          <div class="trace">
            {#each testRes.steps as st, i}
              <div class="ts" class:hit={st.matched} class:off={!st.enabled}>
                <span class="muted mono">#{i + 1}</span><span class="ellipsis" style="flex:1">{st.ruleName}</span>
                {#if st.error}<span class="badge block">{st.error}</span>{:else}
                  <span title="Apps">App {yn(st.apps)}</span><span title="Hosts">Host {yn(st.hosts)}</span><span title="Ports">Port {yn(st.ports)}</span><span title="Protocol">Proto {yn(st.protocol)}</span>
                {/if}
                {#if !st.enabled}<span class="badge">off</span>{/if}
                {#if st.matched}<span class="badge ok">match</span>{/if}
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

    <div class="card list">
      {#each shown as { r, i } (r.id)}
        <div class="rule" class:off={!r.enabled} class:over={dragOver === i && dragFrom !== i} draggable={!q} role="listitem"
          ondragstart={() => (dragFrom = i)} ondragover={(e) => { e.preventDefault(); dragOver = i; }} ondragleave={() => (dragOver = null)}
          ondrop={() => { if (dragFrom !== null) move(dragFrom, i); dragFrom = dragOver = null; }} ondragend={() => (dragFrom = dragOver = null)}
          ondblclick={() => editRule(r)}>
          <span class="grip" title="Drag to reorder"><Icon name="drag" size={15} /></span>
          <span class="idx mono">{i + 1}</span>
          <Toggle checked={r.enabled} onchange={(v) => toggleRule(r, v)} label="Enabled" />
          <div class="col" style="gap:4px;min-width:0;flex:1">
            <strong class="ellipsis">{r.name}</strong>
            <div class="conds">
              {#if r.apps?.length}<span class="cond"><Icon name="app" size={12} />{r.apps.slice(0, 3).join(", ")}{r.apps.length > 3 ? ` +${r.apps.length - 3}` : ""}</span>{/if}
              {#if r.hosts?.length}<span class="cond"><Icon name="globe" size={12} />{r.hosts.slice(0, 3).join(", ")}{r.hosts.length > 3 ? ` +${r.hosts.length - 3}` : ""}</span>{/if}
              {#if r.ports?.length}<span class="cond">port {r.ports.join(", ")}</span>{/if}
              {#if r.protocol}<span class="cond">{r.protocol.toUpperCase()} only</span>{/if}
              {#if !r.apps?.length && !r.hosts?.length && !r.ports?.length && !r.protocol}<span class="cond">everything</span>{/if}
            </div>
          </div>
          <span class="hits mono" title="Connections matched since the rule was loaded">{num(app.hits[r.id] ?? 0)} hits</span>
          <div class="act"><ActionBadge type={r.action.type} label={actionText(r.action)} /></div>
          <div class="row" style="gap:2px">
            <button class="btn sm icon ghost" title="Move up" disabled={i === 0} onclick={() => move(i, i - 1)}><Icon name="up" size={13} /></button>
            <button class="btn sm icon ghost" title="Move down" disabled={i === p.rules.length - 1} onclick={() => move(i, i + 1)}><Icon name="down" size={13} /></button>
            <button class="btn sm icon ghost" title="Edit" onclick={() => editRule(r)}><Icon name="edit" size={14} /></button>
            <button class="btn sm icon ghost" title="Duplicate" onclick={() => dup(r)}><Icon name="copy" size={14} /></button>
            <button class="btn sm icon ghost" title="Delete" onclick={() => del(r)}><Icon name="trash" size={14} /></button>
          </div>
        </div>
      {:else}
        <div class="empty"><Icon name="rules" size={26} /><h4>{q ? "No rule matches" : "No rules"}</h4><span>Everything uses the default rule below.</span></div>
      {/each}
      <div class="rule def">
        <span class="grip"></span>
        <span class="idx"><Icon name="lock" size={13} /></span>
        <div class="col" style="gap:2px;flex:1;min-width:0">
          <strong>Default</strong>
          <span class="muted" style="font-size:12px">Everything no rule above matched</span>
        </div>
        <span class="hits mono">{num(app.hits[""] ?? 0)} hits</span>
        <ActionPicker bind:value={defAction} compact />
      </div>
    </div>
  </div>
</div>

<datalist id="procs">{#each procs as pr}<option value={pr}></option>{/each}</datalist>

{#if edit}
  <Modal title={isNew ? "New rule" : "Edit rule"} width={660} onclose={() => (edit = null)}>
    <div class="col" style="gap:14px">
      <div class="row" style="gap:12px">
        <label class="field" style="flex:1">Name<input class="input" bind:value={edit.name} placeholder={autoName(edit)} /></label>
        <label class="field">Enabled<div style="height:34px;display:flex;align-items:center"><Toggle bind:checked={edit.enabled} label="Enabled" /></div></label>
      </div>
      <label class="field">Applications <span class="hint">Program names or paths. Wildcards: <code>steam*</code>, <code>C:\Games\*</code>. Empty = any app.</span>
        <ChipInput bind:values={edit.apps} kind="app" placeholder="chrome.exe, discord*, C:\Games\*" suggestions={procs} />
      </label>
      <label class="field">
        <span class="row">Destinations <span class="hint">Empty = anywhere.</span><span class="spacer"></span><button type="button" class="btn sm ghost" onclick={() => (help = !help)}><Icon name="info" size={13} />Syntax</button></span>
        <ChipInput bind:values={edit.hosts} kind="host" placeholder="*.google.com, .netflix.com, 10.0.0.0/8, keyword:ads" />
      </label>
      {#if help}
        <div class="help">
          <div><code>example.com</code><span>exactly this host</span></div>
          <div><code>*.example.com</code><span>any subdomain (not example.com itself)</span></div>
          <div><code>.example.com</code><span>example.com and every subdomain</span></div>
          <div><code>*cdn*</code><span>wildcards anywhere (<code>*</code> and <code>?</code>)</span></div>
          <div><code>keyword:ads</code><span>hostname contains "ads"</span></div>
          <div><code>re:^api\d+\.</code><span>regular expression</span></div>
          <div><code>10.0.0.0/8</code><span>IP network (IPv4 or IPv6)</span></div>
          <div><code>192.168.1.10-192.168.1.50</code><span>IP range</span></div>
          <div><code>192.168.*.*</code><span>IP wildcard</span></div>
          <p class="hint" style="grid-column:1/-1;margin:4px 0 0">Hostnames are detected even when an app connects by IP (from HTTPS/HTTP requests and DNS), so domain rules work for browsers and most apps.</p>
        </div>
      {/if}
      <div class="row" style="gap:12px;align-items:flex-start">
        <label class="field" style="flex:1">Ports <span class="hint">e.g. 443, 8000-9000. Empty = any.</span>
          <ChipInput bind:values={edit.ports} kind="port" placeholder="80, 443" />
        </label>
        <label class="field">Protocol
          <div class="seg">{#each [["", "Any"], ["tcp", "TCP"], ["udp", "UDP"]] as [k, l]}<button type="button" class:on={(edit.protocol ?? "") === k} onclick={() => (edit!.protocol = k as any)}>{l}</button>{/each}</div>
        </label>
      </div>
      <label class="field">Action<ActionPicker bind:value={edit.action} /></label>
      <div class="preview">
        <Icon name="info" size={14} />
        <span>When <strong>{edit.apps?.length ? edit.apps.join(", ") : "any app"}</strong> connects to <strong>{edit.hosts?.length ? edit.hosts.join(", ") : "anywhere"}</strong>{edit.ports?.length ? ` on port ${edit.ports.join(", ")}` : ""}{edit.protocol ? ` over ${edit.protocol.toUpperCase()}` : ""}, <strong>{edit.action.type === "block" ? "block it" : edit.action.type === "direct" ? "connect directly" : "send it through " + actionText(edit.action)}</strong>.</span>
      </div>
    </div>
    {#snippet footer()}
      <button class="btn ghost" onclick={() => (edit = null)}>Cancel</button>
      <button class="btn primary" onclick={saveRule}>{isNew ? "Add rule" : "Save"}</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .tm { position: relative; }
  .scrim { position: fixed; inset: 0; z-index: 30; }
  .menu { position: absolute; right: 0; top: calc(100% + 6px); width: 300px; background: var(--surface-2); border: 1px solid var(--border-2); border-radius: 12px; box-shadow: var(--shadow); padding: 6px; z-index: 31; }
  .menu button { display: flex; gap: 10px; align-items: flex-start; width: 100%; text-align: left; border: 0; background: transparent; padding: 8px 10px; border-radius: 8px; cursor: pointer; line-height: 1.35; }
  .menu button :global(svg) { margin-top: 2px; color: var(--accent); }
  .menu button:hover { background: var(--surface-3); }
  .menu .muted { font-size: 12px; }
  .menu .sep { height: 1px; background: var(--border); margin: 4px; }
  .list { overflow: hidden; }
  .rule { display: flex; align-items: center; gap: 12px; padding: 10px 14px; border-bottom: 1px solid var(--border); background: var(--surface); }
  .rule:hover { background: var(--surface-2); }
  .rule.off > :not(.grip):not(:global(.tg)):not(.row) { opacity: .5; }
  .rule.over { box-shadow: inset 0 2px 0 var(--accent); }
  .rule.def { background: var(--bg-2); border-bottom: 0; }
  .grip { color: var(--faint); cursor: grab; width: 15px; display: flex; }
  .idx { width: 22px; color: var(--muted); font-size: 12px; text-align: center; display: flex; justify-content: center; }
  .conds { display: flex; gap: 6px; flex-wrap: wrap; }
  .cond { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text-2); background: var(--surface-3); padding: 1px 8px; border-radius: 6px; font-family: var(--mono); max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hits { font-size: 12px; color: var(--muted); width: 80px; text-align: right; }
  .act { width: 170px; display: flex; justify-content: flex-end; }
  .tester { padding: 14px 16px; margin-bottom: 12px; display: flex; flex-direction: column; gap: 12px; }
  .verdict { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 10px; background: var(--surface-2); }
  .trace { display: flex; flex-direction: column; max-height: 220px; overflow: auto; }
  .ts { display: flex; gap: 12px; align-items: center; padding: 5px 4px; font-size: 12.5px; border-bottom: 1px dashed var(--border); }
  .ts span[title] { color: var(--muted); width: 54px; font-family: var(--mono); font-size: 11.5px; }
  .ts.hit { background: var(--green-bg); border-radius: 6px; }
  .ts.off { opacity: .5; }
  .help { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 16px; padding: 12px; border-radius: 10px; background: var(--surface-2); font-size: 12.5px; }
  .help div { display: flex; gap: 8px; align-items: baseline; }
  .help code { color: var(--accent-2); white-space: nowrap; }
  .help span { color: var(--muted); }
  .preview { display: flex; gap: 10px; align-items: flex-start; padding: 11px 13px; border-radius: 10px; background: var(--accent-bg); color: var(--text-2); line-height: 1.5; }
  .preview :global(svg) { margin-top: 3px; color: var(--accent); }
</style>
