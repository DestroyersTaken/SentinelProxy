export function bytes(n: number | undefined): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${u[i]}`;
}

export function speed(n: number | undefined): string {
  if (!n) return "0 B/s";
  return bytes(n) + "/s";
}

/** Bits per second, the way connection speeds are usually quoted. */
export function bits(n: number | undefined): string {
  const b = (n ?? 0) * 8;
  if (b < 1000) return `${b.toFixed(0)} bps`;
  const u = ["Kbps", "Mbps", "Gbps"];
  let v = b / 1000;
  let i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}

export function duration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export function clock(t: string | number): string {
  const d = new Date(t);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function ago(t: string | number): string {
  const d = typeof t === "number" ? t * (t < 1e12 ? 1000 : 1) : Date.parse(t);
  if (!d || d < 0) return "never";
  return duration(Date.now() - d) + " ago";
}

export function num(n: number | undefined): string {
  return (n ?? 0).toLocaleString();
}

/** A stable hue for an app name, used for avatars. */
export function hue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h % 360;
}

export function appLabel(name: string): string {
  if (!name) return "Unknown";
  return name.replace(/\.exe$/i, "");
}

export const proxyTypeLabel: Record<string, string> = {
  socks5: "SOCKS5", socks4: "SOCKS4", socks4a: "SOCKS4a", http: "HTTP", https: "HTTPS",
};

export const modeInfo: Record<string, { label: string; desc: string }> = {
  chain: { label: "Chain", desc: "Connect through every proxy in order: you → 1 → 2 → … → site." },
  failover: { label: "Failover", desc: "Use the first working proxy; switch to the next one automatically when it fails." },
  fastest: { label: "Fastest", desc: "Use the proxy with the lowest measured latency; fall back to the others on failure." },
  roundrobin: { label: "Round robin", desc: "Spread connections evenly across all working proxies." },
  random: { label: "Random", desc: "Pick a random working proxy for each connection." },
};
