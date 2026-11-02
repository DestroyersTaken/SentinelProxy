<script lang="ts">
  import { app, mutate, toast, uid, refreshHealth, refreshProfile, targetLabel, go } from "../lib/store.svelte";
  import { call } from "../lib/api";
  import { proxyTypeLabel, modeInfo, ago } from "../lib/format";
  import type { Proxy, Chain, CheckResult, ImportPreview, MergeSummary, ProxyType } from "../lib/types";
  import Icon from "../components/Icon.svelte";
  import Modal from "../components/Modal.svelte";
  import Toggle from "../components/Toggle.svelte";

  const p = $derived(app.profile!);
  let edit = $state<Proxy | null>(null);
  let isNew = $state(false);
  let showPass = $state(false);
  let uri = $state("");
  let chainEdit = $state<Chain | null>(null);
  let chainNew = $state(false);
  let addMember = $state("");
  let result = $state<{ name: string; r: CheckResult } | null>(null);
  let checking = $state<Record<string, boolean>>({});
  let paste = $state<string | null>(null);
  let del = $state<{ kind: "proxy" | "chain"; id: string; name: string; uses: string[] } | null>(null);

  $effect(() => {
    if (app.focus?.page === "proxies" && app.focus.data?.add) { app.focus = null; newProxy(); }
  });

  function newProxy() {
    edit = { id: uid(), name: "", type: "socks5", host: "", port: 1080, username: "", password: "", localDns: false, tlsInsecure: false, tlsServerName: "", notes: "" };
    isNew = true; uri = ""; showPass = false;
  }
  function editProxy(px: Proxy) { edit = JSON.parse(JSON.stringify(px)); isNew = false; uri = ""; showPass = false; }

  const defaults: Record<string, number> = { socks5: 1080, socks4: 1080, socks4a: 1080, http: 8080, https: 443 };
  function setType(t: ProxyType) {
    if (!edit) return;
    if (!edit.port || Object.values(defaults).includes(edit.port)) edit.port = defaults[t];
    edit.type = t;
  }

  function parseURI(s: string) {
    if (!edit) return;
    s = s.trim();
    if (!s) return;
    try {
      let t: ProxyType | null = null;
      let rest = s;
      const m = s.match(/^(\w+):\/\//);
      if (m) {
        const map: Record<string, ProxyType> = { socks5: "socks5", socks5h: "socks5", socks: "socks5", socks4: "socks4", socks4a: "socks4a", http: "http", https: "https" };
        t = map[m[1].toLowerCase()] ?? null;
        const u = new URL(s.replace(/^\w+:/, "http:"));
        edit.host = u.hostname.replace(/^\[|\]$/g, "");
        edit.port = Number(u.port) || defaults[t ?? "socks5"];
        edit.username = decodeURIComponent(u.username);
        edit.password = decodeURIComponent(u.password);
        if (u.hash) edit.name = decodeURIComponent(u.hash.slice(1));
        if (t) edit.type = t;
        return;
      }
      let cred = "";
      if (rest.includes("@")) { [cred, rest] = [rest.slice(0, rest.lastIndexOf("@")), rest.slice(rest.lastIndexOf("@") + 1)]; }
      const parts = rest.split(":");
      edit.host = parts[0];
      edit.port = Number(parts[1]) || edit.port;
      if (parts.length >= 4) { edit.username = parts[2]; edit.password = parts.slice(3).join(":"); }
      if (cred) { const i = cred.indexOf(":"); edit.username = i < 0 ? cred : cred.slice(0, i); edit.password = i < 0 ? "" : cred.slice(i + 1); }
    } catch { toast("Could not read that address", "warn"); }
  }

  async function saveProxy(thenCheck = false) {
    if (!edit) return;
    const px = $state.snapshot(edit) as Proxy;
    if (!px.host.trim()) { toast("Enter the proxy's host or IP", "warn"); return; }
    const ok = await mutate((pr) => {
      const i = pr.proxies.findIndex((x) => x.id === px.id);
      if (i >= 0) pr.proxies[i] = px; else pr.proxies.push(px);
    }, isNew ? "Proxy added" : "Proxy saved");
    if (ok) { edit = null; if (thenCheck) check(px.id, px.name || px.host); }
  }

  async function check(id: string, name: string) {
    checking = { ...checking, [id]: true };
    try {
      const r = await call<CheckResult>("CheckProxy", id);
      result = { name, r };
      await refreshHealth();
    } catch (e: any) { toast(e.message, "error"); }
    checking = { ...checking, [id]: false };
  }

  function uses(id: string): string[] {
    const out: string[] = [];
    for (const r of p.rules) if (r.action.type === "proxy" && r.action.target === id) out.push(`rule “${r.name}”`);
    for (const c of p.chains) if (c.members.includes(id)) out.push(`chain “${c.name}”`);
    if (p.defaultAction.type === "proxy" && p.defaultAction.target === id) out.push("the default rule");
    return out;
  }

  async function doDelete() {
    if (!del) return;
    const { id, kind } = del;
    await mutate((pr) => {
      if (kind === "proxy") pr.proxies = pr.proxies.filter((x) => x.id !== id);
      else pr.chains = pr.chains.filter((x) => x.id !== id);
      for (const c of pr.chains) c.members = c.members.filter((m) => m !== id);
      pr.chains = pr.chains.filter((c) => c.members.length > 0);
      const valid = new Set([...pr.proxies.map((x) => x.id), ...pr.chains.map((x) => x.id)]);
      for (const r of pr.rules) if (r.action.type === "proxy" && !valid.has(r.action.target!)) { r.action = { type: "direct" }; r.enabled = false; }
      if (pr.defaultAction.type === "proxy" && !valid.has(pr.defaultAction.target!)) pr.defaultAction = { type: "direct" };
    }, `${del.name} deleted`);
    del = null;
  }

  function duplicate(px: Proxy) {
    mutate((pr) => pr.proxies.push({ ...JSON.parse(JSON.stringify(px)), id: uid(), name: (px.name || px.host) + " copy" }), "Duplicated");
  }

  function newChain() {
    chainEdit = { id: uid(), name: "", mode: "failover", members: [] };
    chainNew = true; addMember = "";
  }
  function editChain(c: Chain) { chainEdit = JSON.parse(JSON.stringify(c)); chainNew = false; addMember = ""; }
  const memberOptions = $derived.by(() => {
    if (!chainEdit) return [];
    const list = p.proxies.map((x) => ({ id: x.id, label: x.name || `${x.host}:${x.port}`, kind: "proxy" }));
    if (chainEdit.mode !== "chain") for (const c of p.chains) if (c.id !== chainEdit.id) list.push({ id: c.id, label: c.name, kind: "chain" });
    return list.filter((x) => chainEdit!.mode === "chain" || !chainEdit!.members.includes(x.id));
  });
  function move(i: number, d: number) {
    if (!chainEdit) return;
    const m = chainEdit.members;
    const j = i + d;
    if (j < 0 || j >= m.length) return;
    [m[i], m[j]] = [m[j], m[i]];
  }
  async function saveChain() {
    if (!chainEdit) return;
    const c = $state.snapshot(chainEdit) as Chain;
    if (!c.name.trim()) { toast("Give the chain a name", "warn"); return; }
    if (c.members.length === 0) { toast("Add at least one proxy", "warn"); return; }
    if (c.mode === "chain") c.members = c.members.filter((m) => p.proxies.some((x) => x.id === m));
    const ok = await mutate((pr) => {
      const i = pr.chains.findIndex((x) => x.id === c.id);
      if (i >= 0) pr.chains[i] = c; else pr.chains.push(c);
    }, chainNew ? "Created" : "Saved");
    if (ok) chainEdit = null;
  }

  async function addPasted() {
    if (!paste?.trim()) return;
    try {
      const pv = await call<ImportPreview>("PreviewImport", "", paste, false, "");
      const r = await call<{ summary: MergeSummary; save: { ok: boolean } }>("ApplyImport", pv.token, { replace: false, proxies: true, chains: true, rules: false, rulesOnTop: false, settings: false, default: false }, "");
      if (r.save.ok) {
        await refreshProfile();
        toast(`Added ${r.summary.proxiesAdded} proxies${r.summary.proxiesSame ? ` (${r.summary.proxiesSame} already existed)` : ""}${pv.warnings.length ? "\n" + pv.warnings.join("\n") : ""}`, "ok", 6000);
        paste = null;
      }
    } catch (e: any) { toast(e.message, "error"); }
  }

  async function checkAll() {
    for (const px of p.proxies) checking = { ...checking, [px.id]: true };
    try {
      const r = await call<Record<string, CheckResult>>("CheckAll");
      const ok = Object.values(r).filter((x) => x.ok).length;
      toast(`${ok} of ${Object.keys(r).length} proxies working`, ok === Object.keys(r).length ? "ok" : "warn");
      await refreshHealth();
    } catch (e: any) { toast(e.message, "error"); }
    checking = {};
  }

  function memberLabel(id: string) { return targetLabel(id, p); }
</script>

<div class="page">
  <div class="page-h">
    <h1>Proxies</h1>
    <span class="sub">{p.proxies.length} proxies · {p.chains.length} chains & groups</span>
    <span class="spacer"></span>
    {#if p.proxies.length}<button class="btn" onclick={checkAll}><Icon name="zap" size={14} />Check all</button>{/if}
    <button class="btn" onclick={() => (paste = "")}><Icon name="clipboard" size={14} />Paste list</button>
    <button class="btn primary" onclick={newProxy}><Icon name="plus" size={14} />Add proxy</button>
  </div>
  <div class="page-b">
    <div class="card">
      {#if p.proxies.length === 0}
        <div class="empty">
          <Icon name="server" size={28} />
          <h4>No proxies yet</h4>
          <span>Add a SOCKS5, HTTP or HTTPS proxy, paste a whole list, or <button class="link" onclick={() => go("import")}>import from Proxifier, Clash or a file</button>.</span>
          <div class="row" style="margin-top:6px"><button class="btn primary" onclick={newProxy}><Icon name="plus" size={14} />Add proxy</button><button class="btn" onclick={() => (paste = "")}>Paste list</button></div>
        </div>
      {:else}
        <table class="t">
          <thead><tr><th style="width:28px"></th><th>Name</th><th>Type</th><th>Address</th><th class="num">Latency</th><th>Last check</th><th>Used by</th><th style="width:150px"></th></tr></thead>
          <tbody>
            {#each p.proxies as px (px.id)}
              {@const h = app.health[px.id]}
              {@const u = uses(px.id)}
              <tr ondblclick={() => editProxy(px)}>
                <td><span class="dot {h?.state ?? 'unknown'}" title={h?.lastError || h?.state || "not checked yet"}></span></td>
                <td><strong>{px.name || px.host}</strong>{#if px.username}<span class="lock" title="Uses a username and password"><Icon name="lock" size={12} /></span>{/if}</td>
                <td><span class="badge">{proxyTypeLabel[px.type]}</span></td>
                <td class="mono">{px.host}:{px.port}</td>
                <td class="num mono">{h?.state === "up" ? `${h.latencyMs} ms` : h?.state === "down" ? "—" : ""}</td>
                <td class="muted" title={h?.lastError}>{h?.lastCheck && !h.lastCheck.startsWith("0001") ? ago(h.lastCheck) : "never"}{#if h?.state === "down"} · <span style="color:var(--red)">failed</span>{/if}</td>
                <td class="muted">{u.length ? `${u.length} rule${u.length > 1 ? "s/chains" : ""}` : "unused"}</td>
                <td><div class="row" style="justify-content:flex-end;gap:4px">
                  <button class="btn sm" onclick={() => check(px.id, px.name || px.host)} disabled={checking[px.id]}><Icon name="zap" size={13} />{checking[px.id] ? "…" : "Check"}</button>
                  <button class="btn sm icon ghost" title="Edit" onclick={() => editProxy(px)}><Icon name="edit" size={14} /></button>
                  <button class="btn sm icon ghost" title="Duplicate" onclick={() => duplicate(px)}><Icon name="copy" size={14} /></button>
                  <button class="btn sm icon ghost" title="Delete" onclick={() => (del = { kind: "proxy", id: px.id, name: px.name || px.host, uses: u })}><Icon name="trash" size={14} /></button>
                </div></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>

    <div class="sec">
      <div class="col" style="gap:2px">
        <h2>Chains & groups</h2>
        <span class="muted">Chain proxies one after another, or group them for automatic failover and load balancing.</span>
      </div>
      <span class="spacer"></span>
      <button class="btn" onclick={newChain} disabled={!p.proxies.length}><Icon name="plus" size={14} />New chain or group</button>
    </div>
    <div class="chains">
      {#each p.chains as c (c.id)}
        {@const h = app.health[c.id]}
        <div class="card chain">
          <div class="row">
            <span class="badge {c.mode === 'chain' ? 'proxy' : 'info'}">{modeInfo[c.mode]?.label}</span>
            <strong class="ellipsis" style="flex:1">{c.name}</strong>
            {#if h}<span class="dot {h.state}" title={h.lastError || ""}></span>{/if}
          </div>
          <div class="flow" class:list={c.mode !== "chain"}>
            {#if c.mode === "chain"}<span class="node you">You</span>{/if}
            {#each c.members as m, i}
              {#if c.mode === "chain"}<Icon name="arrowRight" size={13} />{/if}
              <span class="node"><span class="dot {app.health[m]?.state ?? 'unknown'}"></span>{#if c.mode !== "chain"}<span class="muted">{i + 1}.</span>{/if}{memberLabel(m)}</span>
            {/each}
            {#if c.mode === "chain"}<Icon name="arrowRight" size={13} /><span class="node you">Site</span>{/if}
          </div>
          <div class="row" style="justify-content:flex-end;gap:4px">
            <button class="btn sm" onclick={() => check(c.id, c.name)} disabled={checking[c.id]}><Icon name="zap" size={13} />{checking[c.id] ? "…" : "Check"}</button>
            <button class="btn sm icon ghost" onclick={() => editChain(c)} title="Edit"><Icon name="edit" size={14} /></button>
            <button class="btn sm icon ghost" onclick={() => (del = { kind: "chain", id: c.id, name: c.name, uses: uses(c.id) })} title="Delete"><Icon name="trash" size={14} /></button>
          </div>
        </div>
      {:else}
        <div class="card empty" style="grid-column:1/-1;padding:28px">
          <span>Examples: a <strong>Failover</strong> group that keeps you online when one proxy dies, a <strong>Fastest</strong> group that always picks the quickest server, or a <strong>Chain</strong> that hops through two proxies for extra privacy.</span>
        </div>
      {/each}
    </div>
  </div>
</div>

{#if edit}
  <Modal title={isNew ? "Add proxy" : "Edit proxy"} width={560} onclose={() => (edit = null)}>
    <div class="col" style="gap:14px">
      {#if isNew}
        <label class="field">Quick fill <span class="hint">Paste socks5://user:pass@host:port, host:port:user:pass or user:pass@host:port</span>
          <input class="input mono" placeholder="socks5://user:pass@1.2.3.4:1080" bind:value={uri} oninput={() => parseURI(uri)} />
        </label>
      {/if}
      <div class="col" style="gap:6px">
        <span class="flabel">Type</span>
        <div class="seg">
          {#each ["socks5", "http", "https", "socks4a", "socks4"] as t}
            <button type="button" class:on={edit.type === t} onclick={() => setType(t as ProxyType)}>{proxyTypeLabel[t]}</button>
          {/each}
        </div>
        <span class="hint">{edit.type === "socks5" ? "Recommended. Supports TCP and UDP, hostnames and passwords." : edit.type === "http" ? "HTTP proxy using CONNECT (what Proxifier calls an HTTPS proxy). TCP only." : edit.type === "https" ? "HTTP CONNECT over an encrypted TLS connection to the proxy." : edit.type === "socks4a" ? "SOCKS4 with hostname support. No passwords, TCP only." : "Legacy SOCKS4: IPv4 only, no passwords."}</span>
      </div>
      <div class="hp">
        <label class="field">Host or IP<input class="input mono" bind:value={edit.host} placeholder="proxy.example.com" /></label>
        <label class="field">Port<input class="input mono" type="number" min="1" max="65535" bind:value={edit.port} /></label>
      </div>
      {#if edit.type !== "socks4" && edit.type !== "socks4a"}
        <div class="grid2">
          <label class="field">Username <span class="hint">optional</span><input class="input" bind:value={edit.username} autocomplete="off" /></label>
          <label class="field">Password
            <div class="pw"><input class="input" type={showPass ? "text" : "password"} bind:value={edit.password} autocomplete="off" />
              <button type="button" class="btn ghost icon sm" onclick={() => (showPass = !showPass)} title={showPass ? "Hide" : "Show"}><Icon name={showPass ? "eyeOff" : "eye"} size={14} /></button></div>
          </label>
        </div>
      {/if}
      <label class="field">Name <span class="hint">optional, shown in rules and logs</span><input class="input" bind:value={edit.name} placeholder={edit.host || "My proxy"} /></label>
      <details>
        <summary>Advanced</summary>
        <div class="col" style="gap:12px;padding-top:10px">
          <label class="row"><Toggle bind:checked={edit.localDns} label="Resolve locally" /><span>Resolve hostnames on this computer <span class="hint">(by default the proxy resolves them, which avoids DNS leaks)</span></span></label>
          {#if edit.type === "https"}
            <label class="field">TLS server name <span class="hint">if it differs from the host</span><input class="input mono" bind:value={edit.tlsServerName} /></label>
            <label class="row"><Toggle bind:checked={edit.tlsInsecure} label="Skip verification" /><span>Don't verify the proxy's certificate <span class="hint">(self-signed)</span></span></label>
          {/if}
          <label class="field">Notes<input class="input" bind:value={edit.notes} /></label>
        </div>
      </details>
    </div>
    {#snippet footer()}
      <button class="btn ghost" onclick={() => (edit = null)}>Cancel</button>
      <button class="btn" onclick={() => saveProxy(true)}>Save & check</button>
      <button class="btn primary" onclick={() => saveProxy(false)}>Save</button>
    {/snippet}
  </Modal>
{/if}

{#if chainEdit}
  <Modal title={chainNew ? "New chain or group" : "Edit " + chainEdit.name} width={620} onclose={() => (chainEdit = null)}>
    <div class="col" style="gap:14px">
      <label class="field">Name<input class="input" bind:value={chainEdit.name} placeholder="e.g. Always online" /></label>
      <div class="modes">
        {#each Object.entries(modeInfo) as [k, v]}
          <button type="button" class:on={chainEdit.mode === k} onclick={() => (chainEdit!.mode = k as any)}><strong>{v.label}</strong><span>{v.desc}</span></button>
        {/each}
      </div>
      <div class="col" style="gap:6px">
        <span class="flabel">{chainEdit.mode === "chain" ? "Hops, in order" : "Members, in order of preference"}</span>
        {#each chainEdit.members as m, i}
          <div class="mem">
            <span class="muted mono">{i + 1}</span>
            <span class="dot {app.health[m]?.state ?? 'unknown'}"></span>
            <span class="ellipsis" style="flex:1">{memberLabel(m)}</span>
            <button class="btn sm icon ghost" onclick={() => move(i, -1)} disabled={i === 0} title="Move up"><Icon name="up" size={13} /></button>
            <button class="btn sm icon ghost" onclick={() => move(i, 1)} disabled={i === chainEdit.members.length - 1} title="Move down"><Icon name="down" size={13} /></button>
            <button class="btn sm icon ghost" onclick={() => (chainEdit!.members = chainEdit!.members.filter((_, j) => j !== i))} title="Remove"><Icon name="x" size={13} /></button>
          </div>
        {/each}
        <div class="row">
          <select class="input" bind:value={addMember}>
            <option value="">Add a {chainEdit.mode === "chain" ? "hop" : "member"}…</option>
            {#each memberOptions as o}<option value={o.id}>{o.kind === "chain" ? "⛓ " : ""}{o.label}</option>{/each}
          </select>
          <button class="btn" disabled={!addMember} onclick={() => { chainEdit!.members.push(addMember); addMember = ""; }}><Icon name="plus" size={14} />Add</button>
        </div>
      </div>
    </div>
    {#snippet footer()}
      <button class="btn ghost" onclick={() => (chainEdit = null)}>Cancel</button>
      <button class="btn primary" onclick={saveChain}>Save</button>
    {/snippet}
  </Modal>
{/if}

{#if result}
  <Modal title={`${result.r.ok ? "Working" : "Not working"}: ${result.name}`} width={520} onclose={() => (result = null)}>
    <div class="col" style="gap:4px">
      {#each result.r.stages as st}
        <div class="stage" class:bad={!st.ok}>
          <span class="si"><Icon name={st.ok ? "check" : "x"} size={14} stroke={2.6} /></span>
          <div class="col" style="gap:0;flex:1;min-width:0"><strong>{st.name}</strong>{#if st.detail}<span class="muted" style="overflow-wrap:anywhere">{st.detail}</span>{/if}</div>
          <span class="mono muted">{st.ms} ms</span>
        </div>
      {/each}
      {#if result.r.ok}
        <div class="sum">
          <div><span class="muted">Latency</span><strong>{result.r.latencyMs} ms</strong></div>
          <div><span class="muted">Exit IP</span><strong class="mono">{result.r.exitIp || "unknown"}</strong></div>
          <div><span class="muted">UDP</span><strong>{result.r.udp === "ok" ? "Works" : result.r.udp === "unsupported" ? "Not supported" : result.r.udp === "failed" ? "Failed" : "Not tested"}</strong></div>
        </div>
      {/if}
    </div>
    {#snippet footer()}<button class="btn primary" onclick={() => (result = null)}>Done</button>{/snippet}
  </Modal>
{/if}

{#if paste !== null}
  <Modal title="Paste proxies" subtitle="One per line, in any common notation. Duplicates are skipped." width={600} onclose={() => (paste = null)}>
    <textarea class="input" rows="10" bind:value={paste} placeholder={"socks5://user:pass@1.2.3.4:1080#Home\nhttp://5.6.7.8:3128\n9.9.9.9:1080:user:pass\nuser:pass@10.0.0.1:1080"}></textarea>
    {#snippet footer()}
      <button class="btn ghost" onclick={() => (paste = null)}>Cancel</button>
      <button class="btn primary" onclick={addPasted}>Add proxies</button>
    {/snippet}
  </Modal>
{/if}

{#if del}
  <Modal title="Delete {del.name}?" width={460} onclose={() => (del = null)}>
    {#if del.uses.length}
      <p>It is used by {del.uses.join(", ")}. Those rules will switch to <strong>Direct</strong> and be disabled, and it will be removed from chains.</p>
    {:else}
      <p>This can't be undone.</p>
    {/if}
    {#snippet footer()}
      <button class="btn ghost" onclick={() => (del = null)}>Cancel</button>
      <button class="btn danger" onclick={doDelete}>Delete</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .lock { margin-left: 6px; color: var(--muted); vertical-align: -1px; }
  .link { border: 0; background: none; color: var(--accent-2); cursor: pointer; padding: 0; }
  .sec { display: flex; align-items: flex-end; gap: 12px; margin: 26px 0 12px; }
  .sec h2 { margin: 0; font-size: 15px; }
  .chains { display: grid; grid-template-columns: repeat(auto-fill, minmax(330px, 1fr)); gap: 12px; }
  .chain { padding: 14px; display: flex; flex-direction: column; gap: 12px; }
  .flow { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; color: var(--muted); }
  .flow.list { flex-direction: column; align-items: stretch; gap: 4px; }
  .node { display: inline-flex; align-items: center; gap: 6px; padding: 4px 9px; border-radius: 7px; background: var(--surface-2); border: 1px solid var(--border); color: var(--text); font-size: 12.5px; }
  .node.you { background: transparent; border-style: dashed; color: var(--muted); }
  .flabel { font-size: 12.5px; font-weight: 500; color: var(--text-2); }
  .hp { display: grid; grid-template-columns: 1fr 120px; gap: 12px; }
  .pw { display: flex; gap: 6px; align-items: center; }
  details summary { cursor: pointer; color: var(--text-2); font-weight: 500; }
  .modes { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 8px; }
  .modes button { display: flex; flex-direction: column; align-items: flex-start; gap: 3px; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border-2); background: var(--surface-2); cursor: pointer; text-align: left; }
  .modes button span { font-size: 12px; color: var(--muted); line-height: 1.35; }
  .modes button.on { border-color: var(--accent); background: var(--accent-bg); }
  .mem { display: flex; align-items: center; gap: 8px; padding: 6px 8px; border-radius: 8px; background: var(--surface-2); border: 1px solid var(--border); }
  .stage { display: flex; gap: 10px; align-items: center; padding: 9px 0; border-bottom: 1px solid var(--border); }
  .si { width: 22px; height: 22px; border-radius: 50%; display: flex; align-items: center; justify-content: center; background: var(--green-bg); color: var(--green); flex: none; }
  .stage.bad .si { background: var(--red-bg); color: var(--red); }
  .stage.bad strong { color: var(--red); }
  .sum { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-top: 12px; }
  .sum > div { display: flex; flex-direction: column; gap: 2px; padding: 10px; border-radius: 9px; background: var(--surface-2); }
</style>
