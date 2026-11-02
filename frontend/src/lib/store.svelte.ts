import { call, on } from "./api";
import type { Action, Health, Profile, SaveResult, State, Summary } from "./types";

export interface Toast { id: number; msg: string; kind: "ok" | "error" | "info" | "warn" }

export const app = $state({
  ready: false,
  error: "",
  state: null as State | null,
  profile: null as Profile | null,
  summary: null as Summary | null,
  health: {} as Record<string, Health>,
  hits: {} as Record<string, number>,
  page: "dashboard",
  toasts: [] as Toast[],
  // Set by pages that want to jump elsewhere with context.
  focus: null as null | { page: string; data: any },
});

let toastSeq = 0;
export function toast(msg: string, kind: Toast["kind"] = "info", ms = 3800) {
  const id = ++toastSeq;
  app.toasts.push({ id, msg, kind });
  setTimeout(() => { app.toasts = app.toasts.filter((t) => t.id !== id); }, ms);
}

export function applyTheme(theme: string) {
  const dark = theme === "dark" || (theme !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

export async function refreshState() {
  app.state = await call<State>("GetState");
  applyTheme(app.state.app.theme);
}

/** Go encodes empty lists as null; the UI always wants arrays. */
export function normalizeProfile(p: Profile): Profile {
  p.proxies ??= [];
  p.chains ??= [];
  p.rules ??= [];
  for (const c of p.chains) c.members ??= [];
  for (const r of p.rules) { r.apps ??= []; r.hosts ??= []; r.ports ??= []; r.protocol ??= ""; }
  for (const x of p.proxies) { x.localDns ??= false; x.tlsInsecure ??= false; x.username ??= ""; x.password ??= ""; }
  p.settings.dns.upstreams ??= [];
  p.settings.dns.exclusions ??= [];
  return p;
}

export async function refreshProfile() {
  app.profile = normalizeProfile(await call<Profile>("GetProfile"));
}

export async function refreshHealth() {
  try {
    app.health = await call<Record<string, Health>>("GetHealth");
    app.hits = await call<Record<string, number>>("GetRuleHits");
  } catch {}
}

export async function init() {
  try {
    await Promise.all([refreshState(), refreshProfile(), refreshHealth()]);
    app.summary = await call<Summary>("GetSummary");
    app.ready = true;
  } catch (e: any) {
    app.error = e.message;
    return;
  }
  on<Summary>("tick", (s) => { app.summary = s; });
  on<State>("state", (s) => { app.state = s; applyTheme(s.app.theme); });
  // Server mode has no event push when the socket drops; poll as a fallback.
  setInterval(async () => {
    try { app.summary = await call<Summary>("GetSummary"); } catch {}
  }, 2000);
  setInterval(refreshHealth, 4000);
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => app.state && applyTheme(app.state.app.theme));
}

/** Clones the profile, lets fn modify it and saves. Returns true on success. */
export async function mutate(fn: (p: Profile) => void, okMsg?: string): Promise<boolean> {
  if (!app.profile) return false;
  const p: Profile = JSON.parse(JSON.stringify(app.profile));
  fn(p);
  return save(p, okMsg);
}

export async function save(p: Profile, okMsg?: string): Promise<boolean> {
  try {
    const r = await call<SaveResult>("SaveProfile", p);
    if (!r.ok) {
      const msg = r.error || (r.problems ?? []).map((x) => x.message).join("\n") || "Could not save";
      toast(msg, "error", 6000);
      return false;
    }
    app.state = r.state;
    await refreshProfile();
    if (okMsg) toast(okMsg, "ok");
    return true;
  } catch (e: any) {
    toast(e.message, "error", 6000);
    return false;
  }
}

export async function setRunning(on: boolean) {
  app.state = await call<State>("SetRunning", on);
  const s = app.state;
  if (on && s.capture.enabled && !s.capture.active && s.capture.error) toast(s.capture.error, "warn", 7000);
}

export interface Target { id: string; label: string; kind: "proxy" | "chain"; sub: string }

export function targets(p: Profile | null = app.profile): Target[] {
  if (!p) return [];
  return [
    ...p.proxies.map((x) => ({ id: x.id, label: x.name || `${x.host}:${x.port}`, kind: "proxy" as const, sub: `${x.type.toUpperCase()} ${x.host}:${x.port}` })),
    ...p.chains.map((c) => ({ id: c.id, label: c.name, kind: "chain" as const, sub: `${c.mode} · ${c.members.length} members` })),
  ];
}

export function targetLabel(id: string | undefined, p: Profile | null = app.profile): string {
  if (!id || !p) return "?";
  const px = p.proxies.find((x) => x.id === id);
  if (px) return px.name || `${px.host}:${px.port}`;
  const c = p.chains.find((x) => x.id === id);
  return c ? c.name : "missing";
}

export function actionText(a: Action, p: Profile | null = app.profile): string {
  if (a.type === "direct") return "Direct";
  if (a.type === "block") return "Block";
  return targetLabel(a.target, p);
}

export function uid(): string {
  return Math.random().toString(16).slice(2, 14);
}

export function go(page: string, data?: any) {
  app.focus = data !== undefined ? { page, data } : null;
  app.page = page;
}
