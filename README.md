<p align="center"><img src="frontend/public/logo.svg" width="72" alt=""></p>

<h1 align="center">SentinelProxy</h1>

<p align="center">Send any app's traffic through SOCKS5 / HTTP / HTTPS proxies by rules (per app, per site, per port), and watch every connection live.<br>A modern, open alternative to Proxifier.</p>

![Dashboard](docs/screenshots/dashboard.png)

## Why

Proxifier works, but its UI is dated, it can't import other tools' configs, and it has no failover or health checks. ProxyBridge is open source, but it only routes by process and IP, and gives you little insight into what's happening. SentinelProxy aims to do everything Proxifier does, and more:

| | Proxifier | ProxyBridge | **SentinelProxy** |
|---|:-:|:-:|:-:|
| Capture every app without configuring it | ✓ | ✓ | ✓ (WinDivert) |
| Rules by app, host, IP range, port | ✓ | ✓ | ✓ plus regex, keywords, `.domain` suffixes |
| Hostname rules even when apps connect by IP | DNS hooks | ✗ | ✓ TLS SNI + HTTP Host + DNS learning |
| SOCKS5 / SOCKS4 / HTTP proxies | ✓ | SOCKS5, HTTP | ✓ plus SOCKS4a and **HTTPS (TLS to proxy)** |
| UDP through SOCKS5 | ✓ | ✓ | ✓ |
| Proxy chains | ✓ | ✗ | ✓ |
| Failover / load balancing | basic | ✗ | ✓ failover, **fastest**, round robin, random, with background health checks |
| DNS through proxy | ✓ | ✗ | ✓ hostname passthrough, or leak-proof fake-IP mode |
| Live connections, per-app traffic | ✓ | log only | ✓ live speeds, details panel, close connections |
| One-click rule from a connection | ✗ | ✗ | ✓ |
| Rule tester ("what happens if…") | ✗ | ✗ | ✓ with per-rule trace |
| Proxy checker | ✓ | ✗ | ✓ latency, exit IP, UDP test |
| Import / export | own format | own JSON | **Proxifier .ppx, ProxyBridge, Clash/Mihomo, sing-box, FoxyProxy, proxy lists, CSV** |
| Local SOCKS5/HTTP proxy port (for phones, consoles, the LAN) | ✗ | ✗ | ✓ with optional auth |
| Profiles | ✓ | ✗ | ✓ |
| Price | paid | free | free |

## Features

**Routing**
- Rules are checked top to bottom, and the first match wins. Each rule can match on applications (`chrome.exe`, `steam*`, `C:\Games\*`), destinations, ports (`443`, `8000-9000`) and protocol (TCP/UDP). Actions are **Direct**, **Proxy** (a proxy, chain or group) or **Block**.
- Destination syntax: `example.com`, `*.example.com`, `.example.com` (the domain and all its subdomains), `*cdn*`, `keyword:ads`, `re:^api\d+\.`, `10.0.0.0/8`, `192.168.1.10-192.168.1.50`, `192.168.*.*`, IPv6.
- **Smart hostname detection.** Most apps connect by IP after a DNS lookup. SentinelProxy reads the real hostname from the TLS ClientHello (SNI) or the HTTP `Host` header, and learns it from DNS responses, so `*.netflix.com → US proxy` just works. Proxies receive the hostname rather than the IP, so the remote end resolves it, with no DNS leak and the right CDN for the exit location.
- The engine only waits for a hostname when it could change the decision. A connection that is direct no matter what is passed through at packet level with zero overhead.
- Loop prevention: connections to your own proxy servers always go direct.

**Proxies**
- SOCKS5 (with username/password and UDP), SOCKS4, SOCKS4a, HTTP CONNECT, and HTTPS (CONNECT over TLS to the proxy, with SNI override or self-signed certificates).
- **Chains**: you → A → B → C → site.
- **Groups**: *Failover* (first working proxy), *Fastest* (lowest measured latency), *Round robin* and *Random*. Failed members back off automatically. Groups can contain chains.
- **Checker**: reach the proxy → open a tunnel → HTTP request → exit IP → UDP (a real DNS query through the proxy). Results are shown step by step.
- Paste a whole list of proxies at once (`socks5://user:pass@host:port#Name`, `host:port:user:pass`, `user:pass@host:port`, …).

**Seeing what happens**
- Dashboard with live up/down speeds and a 5-minute chart, routing breakdown, top apps, top destinations, proxy usage and health.
- Connections view with live speeds, filters (proxied/direct/blocked/failed, TCP/UDP), search, a details panel (hostname source, path through the chain, errors), and **"Route this app / this site…"** buttons that create a rule on the spot.
- Traffic per application, destination and proxy. Logs with filters, search and follow mode, also written to a rotating log file.

**Import / export**: preview everything before applying, then choose to add it to the current profile, replace its contents, or create a new profile. Duplicates are merged and IDs are remapped.

| Format | Import | Export | Notes |
|---|:-:|:-:|---|
| SentinelProxy profile `.json` | ✓ | ✓ | everything |
| Proxifier `.ppx` | ✓ | ✓ | proxies, chains, rules, DNS option. Proxifier-encrypted passwords can't be read (you'll be told) |
| Clash / Mihomo `.yaml` | ✓ | ✓ | socks5/http proxies, groups (`select`, `url-test`, `fallback`, `load-balance`, `relay`), `dialer-proxy` chains, rules. Multi-condition rules export as Mihomo `AND`/`OR` |
| sing-box `.json` | ✓ | ✓ | socks/http outbounds, selector/urltest, `detour` chains, route rules (1.11+ actions) |
| ProxyBridge rules `.json` | ✓ | ✓ | proxies are linked by name |
| FoxyProxy `.json` | ✓ | | proxies |
| Proxy list `.txt` | ✓ | ✓ | URIs, `host:port[:user:pass]`, `user:pass@host:port` |
| CSV | ✓ | ✓ | `name,type,host,port,username,password` |

**Also**
- A local SOCKS5/SOCKS4/HTTP proxy port (default `127.0.0.1:2080`, with optional auth) for apps you configure by hand, or for other devices on your network (`0.0.0.0:2080`). Per-app rules still apply to local apps.
- An optional Windows system-proxy toggle, restored when you turn it off.
- Profiles (create, duplicate, rename, switch), tray icon with an on/off toggle, close to tray, start on launch, and dark and light themes.
- Headless/server mode: the same UI served in a browser, for a VPS or a home server.

![Rules and the rule tester](docs/screenshots/rules.png)
![Connection details](docs/screenshots/connection-details.png)

## Getting started (Windows)

1. Download **`SentinelProxy-<version>-setup.exe`** from [Releases](../../releases) and run it. The installer adds Start Menu and desktop shortcuts, and offers two options:
   - **Always run as administrator**, needed for system-wide capture of every app.
   - **Start when I sign in**, which starts in the tray, elevated, with no UAC prompt.

   It installs the WebView2 runtime if it's missing, and the uninstaller removes everything (and optionally your profiles).
   Prefer portable? Unzip `SentinelProxy-<version>-windows-x64.zip` and run `SentinelProxy.exe`, keeping `WinDivert.dll` and `WinDivert64.sys` next to it.
2. Without admin rights the **local proxy** works right away. For **system-wide capture**, run as administrator (or click **Restart as administrator** in the app).
3. **Proxies → Add proxy**, or **Import / Export** to bring in your Proxifier profile.
4. **Rules → New rule** (templates included), then flip **Proxying on**.

Coming from Proxifier: Proxifier → *File → Export Profile*, then SentinelProxy → *Import / Export*. To keep proxy passwords, first set *Profile → Advanced → Encryption* to "Do not encrypt" in Proxifier.

## How it works

```
             ┌──────────── WinDivert (kernel) ────────────┐
  app ──SYN──▶ outbound packet ─▶ NAT core: owner PID, Classify ─┬─ certainly direct ─▶ unchanged (bypass, counted)
             └─────────────────────────────────────────────┘    └─ otherwise ─▶ reflected into the local relay
                                                                                   │
  local relay ─▶ engine: sniff SNI/Host → rules → proxy / chain / group / direct / block ─▶ internet
```

- `internal/intercept`: the WinDivert backend reflects redirected packets into local TCP/UDP relays (a "streamdump" style NAT). It uses socket-layer events for the owning PID, a sniff-only handle to learn hostnames from DNS responses, and adds a firewall rule so the relay works on VPN and Public networks. On Linux, the backend uses nftables `redirect` and `SO_ORIGINAL_DST` (TCP).
- `internal/engine`: routing, hostname sniffing, relaying with half-close, UDP sessions, the connection tracker and statistics, fake-IP DNS, and health checks.
- `internal/proxy`: protocol clients, chains, groups, health and the checker. `internal/rules` and `internal/match`: the compiled rule engine.
- `internal/importexport`: all formats and the merge logic. `internal/service`: the API the Svelte UI calls through Wails bindings.

## Building

Requirements: Go 1.26+, Node 22 + pnpm, and [Task](https://taskfile.dev).

```bash
task build:windows   # dist/SentinelProxy/SentinelProxy.exe + WinDivert (cross-compiles from any OS)
# installer (on Windows, Inno Setup 6): ISCC.exe /DAppVersion=0.1.1 build\windows\installer.iss -> dist\SentinelProxy-0.1.1-setup.exe
task build:server    # bin/sentinelproxy-server: headless, UI at http://127.0.0.1:8765
task check           # svelte-check, go vet, go test -race
```

CI (`.github/workflows/build.yml`) runs the tests on Linux and Windows, runs a real nftables capture test, and publishes the Windows build as an artifact (and as a Release for `v*` tags).

Command line: `--start` (turn on at launch), `--minimized`, `--profile NAME`, `--data DIR`. A file named `portable` next to the exe keeps all data in `data\` beside it.

## Platform notes and limitations

- **Windows 10/11 x64**: full support. System-wide capture needs administrator rights.
- Some games' anti-cheat systems (for example Vanguard or EasyAntiCheat) refuse to run while a packet driver like WinDivert is loaded. Use the local proxy port for those cases.
- **Linux**: system-wide capture covers TCP (run as root, nftables). Use the local proxy port for UDP apps. The desktop window needs WebKitGTK; the headless build has no GUI dependencies.
- **macOS**: local proxy and headless mode only (no system-wide capture yet).
- UDP only goes through SOCKS5 proxies (single proxy or group). Chains and HTTP proxies carry TCP only; UDP for those routes is blocked or sent direct, depending on the *UDP fallback* setting.

## Credits

[WinDivert](https://github.com/basil00/WinDivert) by basil00 (LGPLv3), redistributed unmodified · [Wails](https://wails.io) · [Svelte](https://svelte.dev)
