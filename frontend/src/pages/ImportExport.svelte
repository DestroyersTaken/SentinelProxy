<script lang="ts">
  import { call } from "../lib/api";
  import { app, toast, refreshProfile, refreshState, normalizeProfile } from "../lib/store.svelte";
  import { proxyTypeLabel, modeInfo } from "../lib/format";
  import type { Format, ImportPreview, MergeOptions, MergeSummary, SaveResult } from "../lib/types";
  import Icon from "../components/Icon.svelte";
  import ActionBadge from "../components/ActionBadge.svelte";

  let formats = $state<Format[]>([]);
  let format = $state("");
  let mode = $state<"file" | "paste">("file");
  let text = $state("");
  let fileName = $state("");
  let preview = $state<ImportPreview | null>(null);
  let dest = $state<"merge" | "replace" | "new">("merge");
  let newName = $state("");
  let opts = $state<MergeOptions>({ replace: false, proxies: true, chains: true, rules: true, rulesOnTop: false, settings: false, default: false });
  let drag = $state(false);
  let busy = $state(false);
  let exportWarn = $state<{ name: string; warnings: string[] } | null>(null);
  let hasDialog = $state(false);
  let fileInput = $state<HTMLInputElement>();

  $effect(() => {
    call<Format[]>("GetFormats").then((f) => (formats = f));
    call<boolean>("HasSaveDialog").then((v) => (hasDialog = v)).catch(() => {});
  });

  function b64(buf: ArrayBuffer) {
    let s = "";
    const b = new Uint8Array(buf);
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
    return btoa(s);
  }

  async function readFile(f: File) {
    fileName = f.name;
    const buf = await f.arrayBuffer();
    await doPreview(b64(buf), true);
  }

  async function doPreview(content: string, isB64: boolean) {
    busy = true;
    try {
      preview = await call<ImportPreview>("PreviewImport", fileName, content, isB64, format);
      normalizeProfile(preview.profile);
      const pr = preview.profile;
      opts = { replace: false, proxies: pr.proxies.length > 0, chains: pr.chains.length > 0, rules: pr.rules.length > 0, rulesOnTop: false, settings: false, default: false };
      dest = "merge";
      newName = (fileName.replace(/\.[^.]+$/, "") || preview.formatName) + " (imported)";
    } catch (e: any) { toast(e.message, "error", 6000); preview = null; }
    busy = false;
  }

  async function apply() {
    if (!preview) return;
    busy = true;
    try {
      const o = { ...opts, replace: dest === "replace" };
      if (dest === "new") { o.default = preview.hasDefault; o.settings = preview.hasSettings && opts.settings; }
      const r = await call<{ summary: MergeSummary; save: SaveResult }>("ApplyImport", preview.token, o, dest === "new" ? newName : "");
      if (!r.save.ok) {
        toast(r.save.error || (r.save.problems ?? []).map((x) => x.message).join("\n"), "error", 7000);
      } else {
        await Promise.all([refreshProfile(), refreshState()]);
        const s = r.summary;
        toast(`Imported ${s.proxiesAdded} proxies${s.proxiesSame ? ` (${s.proxiesSame} already existed)` : ""}, ${s.chainsAdded} chains and ${s.rulesAdded} rules` + (s.warnings.length ? "\n" + s.warnings.join("\n") : ""), "ok", 7000);
        preview = null; text = ""; fileName = "";
      }
    } catch (e: any) { toast(e.message, "error"); }
    busy = false;
  }

  async function doExport(f: Format) {
    try {
      const r = await call<{ fileName: string; content: string; warnings: string[]; savedTo?: string }>("Export", f.id, hasDialog);
      if (!r.savedTo) {
        const blob = new Blob([r.content], { type: "application/octet-stream" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = r.fileName;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      }
      toast(r.savedTo ? `Saved to ${r.savedTo}` : `Downloaded ${r.fileName}`, "ok");
      exportWarn = r.warnings.length ? { name: f.name, warnings: r.warnings } : null;
    } catch (e: any) { if (e.message !== "cancelled") toast(e.message, "error"); }
  }

  async function copyExport(f: Format) {
    try {
      const r = await call<{ content: string; warnings: string[] }>("Export", f.id, false);
      await navigator.clipboard.writeText(r.content);
      toast(`${f.name} copied to the clipboard`, "ok");
      exportWarn = r.warnings.length ? { name: f.name, warnings: r.warnings } : null;
    } catch (e: any) { toast(e.message, "error"); }
  }

  const imp = $derived(formats.filter((f) => f.import));
  const exp = $derived(formats.filter((f) => f.export));
  const pv = $derived(preview?.profile);
  const label = (id?: string) => {
    if (!pv || !id) return "?";
    if (id.startsWith("name:")) return id.slice(5) + " (by name)";
    return pv.proxies.find((x) => x.id === id)?.name || pv.proxies.find((x) => x.id === id)?.host || pv.chains.find((x) => x.id === id)?.name || "?";
  };
</script>

<div class="page">
  <div class="page-h">
    <h1>Import / Export</h1>
    <span class="sub">Move proxies and rules between SentinelProxy, Proxifier, ProxyBridge, Clash, sing-box and more.</span>
  </div>
  <div class="page-b">
    <div class="cols">
      <div class="card">
        <div class="card-h"><Icon name="upload" /><h3>Import</h3><span class="spacer"></span>
          <div class="seg"><button class:on={mode === "file"} onclick={() => (mode = "file")}>File</button><button class:on={mode === "paste"} onclick={() => (mode = "paste")}>Paste</button></div>
        </div>
        <div class="card-b col" style="gap:12px">
          <label class="field">Format
            <select class="input" bind:value={format}>
              <option value="">Detect automatically</option>
              {#each imp as f}<option value={f.id}>{f.name} ({f.ext})</option>{/each}
            </select>
          </label>
          {#if mode === "file"}
            <button class="drop" class:drag onclick={() => fileInput?.click()}
              ondragover={(e) => { e.preventDefault(); drag = true; }} ondragleave={() => (drag = false)}
              ondrop={(e) => { e.preventDefault(); drag = false; const f = e.dataTransfer?.files?.[0]; if (f) readFile(f); }}>
              <Icon name="upload" size={26} />
              <strong>{busy ? "Reading…" : fileName || "Drop a file here or click to choose"}</strong>
              <span class="muted">.ppx · .json · .yaml · .txt · .csv</span>
            </button>
            <input type="file" bind:this={fileInput} hidden accept=".ppx,.json,.yaml,.yml,.txt,.csv,.xml,.conf" onchange={(e) => { const f = (e.currentTarget as HTMLInputElement).files?.[0]; if (f) readFile(f); (e.currentTarget as HTMLInputElement).value = ""; }} />
          {:else}
            <textarea class="input" rows="9" bind:value={text} placeholder={"Paste a Proxifier profile, Clash YAML, sing-box JSON, ProxyBridge rules or a list of proxies…"}></textarea>
            <button class="btn" disabled={!text.trim() || busy} onclick={() => { fileName = ""; doPreview(text, false); }}><Icon name="search" size={14} />Read</button>
          {/if}
          <div class="fmts">
            {#each imp as f}<div><strong>{f.name}</strong><span class="muted">{f.hint}</span></div>{/each}
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-h"><Icon name="download" /><h3>Export “{app.state?.profile}”</h3></div>
        <div class="card-b col" style="gap:8px">
          {#each exp as f}
            <div class="ex">
              <div class="col" style="gap:1px;flex:1;min-width:0"><strong>{f.name} <span class="muted mono" style="font-weight:400">{f.ext}</span></strong><span class="muted ellipsis" style="font-size:12px" title={f.hint}>{f.hint}</span></div>
              <button class="btn sm ghost icon" title="Copy to clipboard" onclick={() => copyExport(f)}><Icon name="copy" size={14} /></button>
              <button class="btn sm" onclick={() => doExport(f)}><Icon name="download" size={13} />Export</button>
            </div>
          {/each}
          {#if exportWarn}
            <div class="warns"><strong>{exportWarn.name}: some things could not be expressed</strong>{#each exportWarn.warnings as w}<div>• {w}</div>{/each}</div>
          {/if}
          <p class="hint" style="margin:6px 0 0">Passwords are included in exports. Keep exported files private.</p>
        </div>
      </div>
    </div>

    {#if preview && pv}
      <div class="card pv">
        <div class="card-h">
          <Icon name="file" /><h3>{preview.formatName}{fileName ? ` · ${fileName}` : ""}</h3>
          <span class="spacer"></span>
          <span class="badge">{pv.proxies.length} proxies</span><span class="badge">{pv.chains.length} chains</span><span class="badge">{pv.rules.length} rules</span>
          {#if preview.hasDefault}<span class="badge">default: {preview.defaultText}</span>{/if}
        </div>
        <div class="card-b col" style="gap:14px">
          {#if preview.warnings.length}
            <div class="warns">{#each preview.warnings as w}<div><Icon name="alert" size={13} /> {w}</div>{/each}</div>
          {/if}
          <div class="lists">
            {#if pv.proxies.length}
              <div class="lst"><div class="lh">Proxies</div>
                {#each pv.proxies.slice(0, 50) as x}<div class="li"><span class="badge">{proxyTypeLabel[x.type]}</span><span class="ellipsis">{x.name || x.host}</span><span class="muted mono ellipsis">{x.host}:{x.port}</span>{#if x.username}<Icon name="lock" size={12} />{/if}</div>{/each}
                {#if pv.proxies.length > 50}<div class="muted">… and {pv.proxies.length - 50} more</div>{/if}
              </div>
            {/if}
            {#if pv.chains.length}
              <div class="lst"><div class="lh">Chains & groups</div>
                {#each pv.chains as c}<div class="li"><span class="badge info">{modeInfo[c.mode]?.label}</span><span class="ellipsis">{c.name}</span><span class="muted">{c.members.length} members</span></div>{/each}
              </div>
            {/if}
            {#if pv.rules.length}
              <div class="lst wide"><div class="lh">Rules</div>
                {#each pv.rules.slice(0, 60) as r}
                  <div class="li"><span class="ellipsis" style="flex:1" class:muted={!r.enabled}>{r.name}{r.enabled ? "" : " (off)"}</span>
                    <span class="muted mono ellipsis" style="max-width:40%">{[...(r.apps ?? []), ...(r.hosts ?? []), ...(r.ports ?? []).map((x) => ":" + x)].slice(0, 4).join(", ")}</span>
                    <ActionBadge type={r.action.type} label={r.action.type === "proxy" ? label(r.action.target) : ""} /></div>
                {/each}
                {#if pv.rules.length > 60}<div class="muted">… and {pv.rules.length - 60} more</div>{/if}
              </div>
            {/if}
          </div>
          <div class="hr"></div>
          <div class="row" style="gap:16px;align-items:flex-start;flex-wrap:wrap">
            <div class="col" style="gap:6px">
              <span class="lbl">Where</span>
              <div class="seg">
                <button class:on={dest === "merge"} onclick={() => (dest = "merge")}>Add to “{app.state?.profile}”</button>
                <button class:on={dest === "replace"} onclick={() => (dest = "replace")}>Replace its contents</button>
                <button class:on={dest === "new"} onclick={() => (dest = "new")}>New profile</button>
              </div>
              {#if dest === "new"}<input class="input" bind:value={newName} placeholder="Profile name" />{/if}
              {#if dest === "replace"}<span class="hint" style="color:var(--amber)">The current proxies, chains and rules are removed first.</span>{/if}
            </div>
            <div class="col" style="gap:6px">
              <span class="lbl">Include</span>
              <div class="checks">
                <label><input type="checkbox" bind:checked={opts.proxies} disabled={!pv.proxies.length} />Proxies</label>
                <label><input type="checkbox" bind:checked={opts.chains} disabled={!pv.chains.length} />Chains</label>
                <label><input type="checkbox" bind:checked={opts.rules} disabled={!pv.rules.length} />Rules</label>
                {#if preview.hasDefault && dest !== "new"}<label><input type="checkbox" bind:checked={opts.default} />Default action ({preview.defaultText})</label>{/if}
                {#if preview.hasSettings}<label><input type="checkbox" bind:checked={opts.settings} />Settings</label>{/if}
                {#if opts.rules && dest === "merge"}<label><input type="checkbox" bind:checked={opts.rulesOnTop} />Put imported rules first</label>{/if}
              </div>
            </div>
            <span class="spacer"></span>
            <div class="row" style="align-self:flex-end">
              <button class="btn ghost" onclick={() => (preview = null)}>Cancel</button>
              <button class="btn primary" onclick={apply} disabled={busy}><Icon name="check" size={14} />Import</button>
            </div>
          </div>
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .cols { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr); gap: 12px; align-items: start; }
  .drop { display: flex; flex-direction: column; align-items: center; gap: 6px; padding: 26px; border: 1.5px dashed var(--border-2); border-radius: 12px; background: var(--bg-2); cursor: pointer; color: var(--text-2); }
  .drop:hover, .drop.drag { border-color: var(--accent); background: var(--accent-bg); }
  .fmts { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 14px; font-size: 12px; }
  .fmts div { display: flex; flex-direction: column; }
  .ex { display: flex; align-items: center; gap: 8px; padding: 9px 10px; border-radius: 9px; background: var(--surface-2); border: 1px solid var(--border); }
  .warns { padding: 10px 12px; border-radius: 9px; background: var(--amber-bg); color: var(--amber); font-size: 12.5px; display: flex; flex-direction: column; gap: 3px; }
  .warns :global(svg) { vertical-align: -2px; }
  .pv { margin-top: 12px; border-color: var(--accent); }
  .lists { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 12px; }
  .lst { display: flex; flex-direction: column; gap: 4px; max-height: 260px; overflow: auto; padding: 10px; border-radius: 10px; background: var(--surface-2); }
  .lst.wide { grid-column: 1 / -1; }
  .lh { font-size: 11.5px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; margin-bottom: 2px; }
  .li { display: flex; gap: 8px; align-items: center; font-size: 12.5px; min-width: 0; }
  .lbl { font-size: 12.5px; font-weight: 600; color: var(--text-2); }
  .checks { display: flex; flex-wrap: wrap; gap: 6px 14px; }
  .checks label { display: flex; gap: 6px; align-items: center; cursor: pointer; }
  .hr { height: 1px; background: var(--border); }
  input[type="checkbox"] { accent-color: var(--accent); width: 15px; height: 15px; }
</style>
