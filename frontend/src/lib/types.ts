export type ProxyType = "socks5" | "socks4" | "socks4a" | "http" | "https";
export type ChainMode = "chain" | "failover" | "roundrobin" | "fastest" | "random";
export type ActionType = "direct" | "proxy" | "block";

export interface Proxy {
  id: string; name: string; type: ProxyType; host: string; port: number;
  username?: string; password?: string; tlsServerName?: string; tlsInsecure?: boolean;
  localDns?: boolean; tags?: string[]; notes?: string;
}
export interface Chain { id: string; name: string; mode: ChainMode; members: string[]; notes?: string }
export interface Action { type: ActionType; target?: string }
export interface Rule {
  id: string; name: string; enabled: boolean; apps?: string[]; hosts?: string[]; ports?: string[];
  protocol?: "" | "tcp" | "udp"; action: Action; notes?: string;
}
export interface DNSSettings { mode: "auto" | "local" | "fakeip"; fakeIpRange: string; upstreams: string[]; exclusions: string[] }
export interface Settings {
  intercept: boolean; interceptUdp: boolean; interceptIpv6: boolean; udpFallback: "block" | "direct";
  sniff: boolean; relayDirect: boolean; localProxy: boolean; localProxyListen: string;
  localProxyUser?: string; localProxyPassword?: string; systemProxy: boolean; connectTimeoutSec: number;
  healthCheck: boolean; healthCheckIntervalSec: number; checkUrl: string; dns: DNSSettings;
  logConnections: boolean; logLevel: string;
}
export interface Profile {
  version: number; name: string; proxies: Proxy[]; chains: Chain[]; rules: Rule[];
  defaultAction: Action; settings: Settings;
}
export interface Component { enabled: boolean; active: boolean; detail: string; error?: string }
export interface AppSettings { startEnabled: boolean; startMinimized: boolean; closeToTray: boolean; theme: string; notifications: boolean }
export interface State {
  running: boolean; version: string; os: string; profile: string; profiles: string[];
  capture: Component; captureReady: boolean; captureHint?: string; localProxy: Component;
  systemProxy: Component; sysProxySupported: boolean; elevated: boolean; canElevate: boolean; dataDir: string; app: AppSettings;
}
export interface Point { t: number; up: number; down: number }
export interface CaptureStats { packets: number; redirected: number; bypassed: number; dnsFaked: number; flows: number; errors: number; lastError?: string }
export interface Summary {
  speedUp: number; speedDown: number; totalUp: number; totalDown: number; active: number; activeTcp: number; activeUdp: number;
  totalConns: number; proxied: number; direct: number; blocked: number; failed: number; history: Point[]; since: number;
  capture?: CaptureStats; running: boolean; dnsCache: number; udpSessions: number;
}
export interface Conn {
  id: number; network: string; inbound: string; app: string; pid: number; path: string; src: string; dst: string;
  host: string; hostSource: string; port: number; rule: string; ruleId: string; action: string; route: string;
  hops: string[] | null; state: string; error?: string; start: number; end?: number; up: number; down: number; speedUp: number; speedDown: number;
}
export interface AppStat { name: string; path: string; up: number; down: number; conns: number; active: number; blocked: number; proxied: number; speedUp: number; speedDown: number; lastSeen: number }
export interface RouteStat { name: string; up: number; down: number; conns: number; active: number; errors: number }
export interface HostStat { host: string; up: number; down: number; conns: number }
export interface Health { id: string; state: "unknown" | "up" | "down"; latencyMs: number; lastCheck: string; lastError?: string; failures: number }
export interface Stage { name: string; ok: boolean; ms: number; detail?: string }
export interface CheckResult { id: string; ok: boolean; latencyMs: number; exitIp?: string; udp: string; stages: Stage[]; error?: string; path?: string[] }
export interface LogEntry { seq: number; time: string; level: string; kind: string; msg: string }
export interface Problem { kind: string; id?: string; message: string }
export interface SaveResult { ok: boolean; problems: Problem[] | null; error?: string; state: State }
export interface Step { ruleId: string; ruleName: string; enabled: boolean; apps: string; hosts: string; ports: string; protocol: string; matched: boolean; error?: string }
export interface Decision { action: Action; ruleId: string; ruleName: string; index: number }
export interface TestResult { decision: Decision; label: string; steps: Step[] }
export interface Format { id: string; name: string; ext: string; import: boolean; export: boolean; scope: string; hint: string }
export interface ImportPreview { token: string; format: string; formatName: string; warnings: string[]; profile: Profile; hasSettings: boolean; hasDefault: boolean; defaultText: string }
export interface MergeOptions { replace: boolean; proxies: boolean; chains: boolean; rules: boolean; rulesOnTop: boolean; settings: boolean; default: boolean }
export interface MergeSummary { proxiesAdded: number; proxiesSame: number; chainsAdded: number; rulesAdded: number; warnings: string[] }
export interface Process { pid: number; name: string; path: string }
