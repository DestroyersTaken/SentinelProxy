<script lang="ts">
  import type { Action, SaveResult } from "../lib/types";
  import { call } from "../lib/api";
  import { app, refreshProfile, toast, targets } from "../lib/store.svelte";
  import { appLabel } from "../lib/format";
  import Modal from "./Modal.svelte";
  import ActionPicker from "./ActionPicker.svelte";

  let { appName = "", host = "", initial = "app", action: initialAction, onclose }:
    { appName?: string; host?: string; initial?: string; action?: Action; onclose: () => void } = $props();

  let scope = $state(initial);
  let action = $state<Action>(initialAction ?? (targets().length ? { type: "proxy", target: targets()[0].id } : { type: "direct" }));
  const isIP = $derived(/^[\d.]+$|:/.test(host));

  async function create() {
    try {
      const r = await call<SaveResult>("AddQuickRule", { app: appName, host, scope, action });
      if (!r.ok) { toast(r.error || (r.problems ?? []).map((p) => p.message).join("\n"), "error"); return; }
      app.state = r.state;
      await refreshProfile();
      toast("Rule added at the top of the list. New connections use it right away.", "ok");
      onclose();
    } catch (e: any) { toast(e.message, "error"); }
  }
</script>

<Modal title="Create a rule" subtitle="It is added at the top, so it wins over other rules." width={520} {onclose}>
  <div class="col" style="gap:14px">
    <div class="col" style="gap:6px">
      <span class="lbl">Match</span>
      <div class="opts">
        {#if appName}<button class:on={scope === "app"} onclick={() => (scope = "app")}><strong>{appLabel(appName)}</strong><span>all of its traffic</span></button>{/if}
        {#if host}<button class:on={scope === "host"} onclick={() => (scope = "host")}><strong class="mono">{host}</strong><span>from any app</span></button>{/if}
        {#if host && !isIP}<button class:on={scope === "domain"} onclick={() => (scope = "domain")}><strong class="mono">*.{host.split(".").slice(-2).join(".")}</strong><span>the whole site, any app</span></button>{/if}
        {#if appName && host}<button class:on={scope === "app+host"} onclick={() => (scope = "app+host")}><strong>{appLabel(appName)} → <span class="mono">{host}</span></strong><span>only this app to this host</span></button>{/if}
      </div>
    </div>
    <div class="col" style="gap:6px">
      <span class="lbl">Then</span>
      <ActionPicker bind:value={action} />
    </div>
  </div>
  {#snippet footer()}
    <button class="btn ghost" onclick={onclose}>Cancel</button>
    <button class="btn primary" onclick={create}>Add rule</button>
  {/snippet}
</Modal>

<style>
  .lbl { font-size: 12.5px; font-weight: 600; color: var(--text-2); }
  .opts { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .opts button { display: flex; flex-direction: column; gap: 2px; align-items: flex-start; text-align: left; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border-2); background: var(--surface-2); cursor: pointer; min-width: 0; }
  .opts button strong { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .opts button span { color: var(--muted); font-size: 12px; }
  .opts button.on { border-color: var(--accent); background: var(--accent-bg); }
</style>
