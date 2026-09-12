# 🗺️ NetMapper — Automatic Multi-Segment Network Discovery & Topology Mapping

> A tool that automatically detects every network reachable from your machine — even across different ranges (192.168.0.x, 192.168.1.x, 10.0.0.x, 172.26.0.x...) — discovers the devices on each one by combining active and passive techniques, correlates them against known vulnerabilities and security signals, and builds an interactive, always-up-to-date topology map.

---

## 📋 Table of contents

1. [Motivation & scope](#-motivation--scope)
2. [Legal & ethical considerations](#-legal--ethical-considerations)
3. [Architecture](#-architecture)
4. [Detailed program walkthrough](#-detailed-program-walkthrough)
5. [Tech stack](#-tech-stack)
6. [Repository structure](#-repository-structure)
7. [Roadmap & commit plan](#-roadmap--commit-plan)
8. [Installation guide](#-installation-guide)
9. [Getting it running](#-getting-it-running)
10. [Using the dashboard](#-using-the-dashboard)
11. [Screenshots](#-screenshots)
12. [Testing & CI](#-testing--ci)
13. [Built-in enhancements](#-built-in-enhancements)
14. [Future improvements](#-future-improvements)
15. [License](#-license)

---

## 🎯 Motivation & scope

Most network scanning tools assume you're working on a single, manually-configured range (`192.168.1.0/24`). Real networks — homelabs with VLANs, Docker, VPNs, or corporate networks — have several segments alive at once, and you usually don't know all of them up front.

**NetMapper** solves this in two stages:

1. **Discovers which networks exist and are reachable** from the machine it runs on, without you having to list them by hand.
2. **Maps every discovered network**, combining active discovery (ARP/NDP, ICMP, SNMP, port scanning, banner grabbing, TLS inspection) with passive discovery (traffic capture, ARP/DHCP spoofing detection, LLDP neighbor discovery), and builds an interactive topology graph that keeps itself up to date.

The end result is a web dashboard where you can see, in real time, every reachable device in your environment, grouped by network, with their actual communication relationships — plus (see [Built-in enhancements](#-built-in-enhancements)) which devices aren't on your authorized list, which ones an IDS or NetMapper's own passive sensors have flagged as anomalous, which known CVEs their exposed services might be affected by, how each device's fingerprint has changed over time, and a downloadable weekly PDF summary of all of it.

---

## ⚖️ Legal & ethical considerations

This needs to be explicit in the repository itself (and it's worth bringing up in any interview about this project):

- This tool is meant **exclusively for auditing networks you own** (your homelab, your home network, or a network you have explicit authorization to scan).
- Actively scanning networks that aren't yours without permission is **illegal** in most countries.
- `ALLOWED_NETWORKS` isn't a cosmetic setting — it's the actual safety gate. Any network the pipeline detects but that isn't listed there gets recorded as "known" and is **never** actively scanned. See [`_apply_device_authorization`/`is_network_allowed`](#-detailed-program-walkthrough) below for exactly how that's enforced in code, not just in this paragraph.
- Traceroute is likewise on-demand and per-device — nothing probes a target unless you explicitly request it from the dashboard, and every request is scoped to a device NetMapper already discovered on an authorized network.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  STAGE 0 — NETWORK DISCOVERY                     │
│  Local interfaces (IPv4+IPv6) · Routing table · Router queries · │
│  Whitelist check against ALLOWED_NETWORKS                        │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  authorized target subnets
┌───────────────────────────────▼────────────────────────────────────┐
│                  STAGE 1 — HOST DISCOVERY                          │
│  ARP (local IPv4) · NDP/ICMPv6 (local IPv6) · async TCP (remote)  │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  live hosts per subnet
┌───────────────────────────────▼────────────────────────────────────┐
│              STAGE 2 — DEVICE FINGERPRINTING                      │
│  Selective port scanning · OUI/MAC vendor lookup ·                │
│  mDNS/UPnP listening · rule-based device-type inference ·         │
│  banner grabbing · TLS certificate inspection                     │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  per-device metadata
┌───────────────────────────────▼────────────────────────────────────┐
│              STAGE 3 — PASSIVE DISCOVERY                          │
│  Traffic capture (Scapy, IPv4+IPv6) · DNS query analysis ·        │
│  ARP/DHCP spoofing detection · LLDP physical-neighbor discovery   │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              STAGE 4 — FUSION ENGINE                              │
│  Merges every source into one coherent graph model, resolving    │
│  conflicts (DHCP-reassigned IPs, duplicates), tracking            │
│  authorization, security alerts (NetGuardian + local ARP watcher) │
│  and CVE findings per device                                      │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              STAGE 5 — GRAPH ANALYSIS                             │
│  Community detection (Louvain) · Betweenness centrality ·         │
│  Hierarchy inference (hop-count layers)                           │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              STAGE 6 — PERSISTENCE                                │
│  SQLite today (Repository interface; Neo4jRepository is an        │
│  explicit stub for a real graph database later) — snapshot        │
│  retention/pruning, per-sensor device scoping, pipeline health     │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              STAGE 7 — BACKEND API                                │
│  FastAPI + WebSocket — serves the graph, queues on-demand         │
│  traceroutes, generates the weekly PDF report, exposes /api/health │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              STAGE 8 — FRONTEND                                   │
│  React + Cytoscape.js — interactive map, search + subnet grouping,│
│  dark/light theme, time-lapse, PNG/GraphML export, traceroute and │
│  weekly-report actions, unauthorized/security/CVE overlays        │
└──────────────────────────────────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   NetGuardian (optional)  │
                    │   IDS anomaly alerts,     │
                    │   polled and correlated   │
                    │   by source IP            │
                    └───────────────────────────┘
```

**Why it grew past the original plan:** a `common/` package appeared early on so discovery, analysis and backend could share configuration, persistence and severity logic without duplicating it (the same pattern used in [NetGuardian](https://github.com/gsan-dev/NetGuardian)), and Neo4j was deliberately deprioritized in favor of SQLite-first — see the [database note](#️-installation-guide) below. Every enhancement listed in the original "Future improvements" section (four items) and a second, larger round of improvements (thirteen more, spanning security, topology, UX and reliability) all ended up folded straight into the main pipeline instead of staying a wishlist — see [Built-in enhancements](#-built-in-enhancements).

---

## 🔬 Detailed program walkthrough

This section explains **what each module actually does internally** and why it's built that way — the part worth understanding well enough to defend in an interview.

### `network_discovery.py` — Network discovery (Stage 0)

Answers "which networks am I on, and which can I reach?" by combining three sources, from least to most authoritative:

- **Routing table** (`pyroute2`, Linux only, both `AF_INET` and `AF_INET6`): reveals networks that are *not* directly connected but reachable through a gateway — this is what lets you see a 10.0.0.x network even though your machine sits physically on 192.168.1.x.
- **Local interfaces** (`netifaces`): every network interface (Ethernet, Wi-Fi, VPN, Docker bridges) has its own IP+mask, from which a directly-connected CIDR is derived — IPv4 and IPv6 addresses alike (IPv6 link-local addresses, including the `%iface` scope-id netifaces attaches to them, are correctly excluded).
- **SNMP query to a managed router** (optional, IPv4 only — `ipAddrTable` is a classic MIB-II table; IPv6 would need RFC 4293's `ipAddressTable`, not implemented): the most reliable source when available, since the router knows its configured subnets/VLANs with certainty.

When two sources describe the same network, the more reliable one wins, but every distinct CIDR is kept.

Every detected network is checked against `ALLOWED_NETWORKS` (`Settings.is_network_allowed`) and persisted either way — authorized ones get actively scanned, the rest are recorded as "known" and never touched.

### `host_discovery.py` — Host discovery (Stage 1)

Picks a technique per subnet instead of applying the same one everywhere:

- **Directly-connected IPv4**: ARP scan (layer 2) — near-instant and very reliable within the same physical segment.
- **Directly-connected IPv6**: ARP doesn't exist in IPv6 (NDP replaces it), and a typical /64 has 2⁶⁴ addresses — far too many to brute-force. Instead, an ICMPv6 Echo Request goes out to the link's all-nodes multicast address (`ff02::1`), and every live host on the link answers with its own source address.
- **Remote networks** (IPv4 or IPv6, reachable only through routing): neither ARP nor link-local multicast reach past the local segment, so an async TCP probe against common ports is used instead (a RST also counts as "host alive"). A configurable size cap skips subnets too large to probe reasonably (a remote /64 is never brute-forced).

### `device_fingerprint.py` — Device characterization (Stage 2)

For every live host:
- Resolves the vendor from the first bytes of the MAC (IEEE OUI database, via `manuf`).
- Runs a selective (not exhaustive, to stay non-aggressive) port scan over the most common ports.
- Combines vendor + open ports through a simple, explainable scoring rule engine (`common/device_types.py`) to infer the device type (router, NAS, IP camera, printer, server, mobile, IoT...).
- Passively listens for mDNS/UPnP announcements, which many home devices broadcast on their own — free fingerprinting information without having to scan actively.
- **Banner grabbing** (`BANNER_GRAB_ENABLED`, on by default): once a port is confirmed open, reads the service's own greeting — SSH/FTP/SMTP/SMB send it unprompted, HTTP-like ports (80/8000/8080) need a minimal `HEAD /` request first to expose the `Server:` header. This is the raw signal the CVE correlation feature (Stage 4) later parses into product+version.
- **TLS certificate inspection** (`TLS_INSPECT_ENABLED`, on by default): for the TLS-looking ports already found open (443/8443/993/995), performs a handshake with certificate verification deliberately turned off — many home devices (routers, NAS, cameras) use self-signed certificates that a strict client would reject outright — and reads subject, issuer, expiry date, and whether the certificate is expired or self-signed, using the `cryptography` library to parse the raw DER certificate.

### `passive_capture.py` — Passive discovery (Stage 3)

Using Scapy in listen mode, groups observed traffic by IP pair into time windows, producing edges of the form `(source, destination, bytes, connection_count)` — this is what lets the map show **real communication relationships**, not just presence. It parses both IPv4 and IPv6 packets, and also tracks which domains each source IP resolves via DNS — a free fingerprinting signal (a device that only resolves Apple domains is probably an iPhone/Mac).

Two more passive watchers share the same capture loop, each only enabled — and only added to the BPF filter — when its setting is on, to avoid capturing traffic nobody asked for:

- **ARP/DHCP spoofing detection** (`ArpWatcher`, `ARP_SPOOF_DETECTION_ENABLED`, on by default): watches ARP frames (`who-has`/`is-at`) and tracks which MAC last claimed each IP. If the same IP suddenly gets claimed by a *different* MAC, that's the classic signature of ARP or DHCP spoofing. There's no way to tell, from ARP alone, which of the two MACs is the legitimate one — so both known devices get flagged (`security_max_severity: high`, `security_alert_source: local-arp`) rather than guessing which one is the attacker.
- **LLDP physical-neighbor discovery** (`LldpNeighborTracker`, `LLDP_DISCOVERY_ENABLED`, on by default): listens for LLDP frames (EtherType `0x88cc`), which managed switches/APs typically broadcast to announce themselves (chassis ID, port ID, system name) to whatever is plugged directly into them. Deliberately scoped honestly: this is *not* a full network topology map, only what this one sensor's NIC can hear on its own segment — a device only gets a `physical_neighbor` entry if it emits LLDP itself.

### `common/cve_lookup.py` — CVE correlation (opt-in, off by default)

Takes the banners grabbed in Stage 2 and, only for a handful of recognized service signatures (OpenSSH, Apache, nginx, ProFTPD, vsftpd, IIS, Samba, MySQL, lighttpd), extracts a `(product, version)` pair and queries the public [NVD](https://nvd.nist.gov/) REST API (v2.0) by keyword search for known CVEs. It's gated behind `CVE_LOOKUP_ENABLED=false` by default and runs as its own pass (`Pipeline.run_cve_lookup_pass`), separate from per-host fingerprinting, for two reasons:

- NVD's public API has strict rate limits (5 requests/30s without a key, 50/30s with `NVD_API_KEY` configured) — hammering it once per host per scan would get the sensor throttled or blocked.
- Every `product:version` lookup is cached in a `cve_cache` table for `CVE_LOOKUP_INTERVAL_SECONDS` (a day, by default) before it's repeated, and a small sleep between *actual* NVD calls (not cache hits) keeps the sensor within the rate limit even across many devices.

An unrecognized banner is simply ignored rather than sent to NVD as noisy free text — false positives from a garbage query are worse than no result at all.

### `discovery/traceroute.py` — On-demand traceroute

A classic TTL-increasing traceroute (`IP(ttl=1..N)/ICMP()`, reading the intermediate router or the final echo reply at each hop) — but it never runs on its own initiative. The backend has no raw-socket privileges (nor should it, just to serve a REST API), so `POST /api/devices/{mac}/traceroute` only inserts a row into `traceroute_requests` with `status=pending`; the discovery pipeline, which already runs with the privileges ARP/NDP scanning needs anyway, polls that table every pass (`Pipeline.run_traceroute_pass`) and resolves whichever requests are waiting, writing back the hop list (or an error) for the frontend to pick up with `GET /api/devices/{mac}/traceroute`.

### `fusion_engine.py` — Fusion engine (Stage 4)

The most delicate module in the project. It receives data from the active sources above and from passive capture — which can arrive at different times and with inconsistencies — and:
- Deduplicates devices using the **MAC as the stable identifier** (more reliable than the IP, which can change via DHCP). Hosts without a real MAC (discovered via remote TCP probing, outside the local L2 segment) get an `"unknown-<ip>"` placeholder identity instead.
- Resolves DHCP reassignment: if an IP that belonged to one device is now reported by another, it's reassigned and retired from the previous one.
- Builds the final graph combining nodes (devices) and edges (both active relations and passively observed ones) — an IP with no known device (e.g. an Internet server) is kept as-is as an "external" graph node.
- Tracks each device's authorization status, service banners, TLS certificates, CVE findings, physical-neighbor info, and any correlated security alerts (see [Built-in enhancements](#-built-in-enhancements)) — without knowing about the whitelist, NetGuardian, or NVD themselves, to keep it decoupled from global configuration and external services.
- `security_alert_source` distinguishes *where* the current alert came from (`netguardian` vs. `local-arp`) so the dashboard and the weekly report can say more than just "something's wrong."

### `graph_analysis.py` — Graph analysis (Stage 5)

Over the already-built graph:
- **Community detection** (Louvain algorithm, via `python-louvain`, weighted by connection count): automatically groups devices that interact heavily with each other.
- **Betweenness centrality**: identifies which nodes are critical bridge points (if they go down, they fragment connectivity).
- **Layer inference**: using hop-count from a root node (typically the gateway), positions devices into hierarchical levels so the map draws in an ordered way instead of a flat tangle. Falls back to the highest-degree node as a pseudo-root when no gateway is configured, and marks unreachable nodes with layer `-1` instead of failing.

### `common/db.py` — Persistence & pipeline health (Stage 6)

SQLite by default (`SQLiteRepository`), behind an abstract `Repository` interface so nothing above it needs to know or care which engine is in use — `Neo4jRepository` exists as an explicit stub for when a real graph database is worth the operational cost. Beyond storing devices/relations/snapshots, this layer also handles:

- **Snapshot retention**: `prune_old_graph_snapshots` deletes analysis snapshots older than `GRAPH_SNAPSHOT_RETENTION_SECONDS` (30 days by default) on every analysis pass, always keeping at least the most recent one so time-lapse never runs dry.
- **Pipeline health**: a single-row `pipeline_status` table records the timestamp of the last discovery pass and the last analysis pass, which `GET /api/health` uses to report `sensor_healthy` — if the sensor process died silently, the dashboard says so instead of just going quiet.
- **Distributed sensors**: every device row carries a `last_sensor_id` (from `SENSOR_ID` in `.env`), and `mark_stale_devices_inactive` only retires devices last seen by *that same* sensor — so multiple NetMapper sensors on isolated segments (e.g. one per VLAN, each without routed connectivity to the others) can safely share one database without one sensor's absence marking the other's devices as gone.
- **`get_weekly_summary`** is deliberately a *concrete* method on the abstract `Repository` base class, built only from `list_devices()` and `get_latest_graph_snapshot()` — so `Neo4jRepository` gets weekly-report support for free the moment it implements those two methods, without duplicating this aggregation logic.

### `common/reports.py` — Weekly PDF report

Generates a one-page PDF (via `fpdf2`, same pattern as [NetGuardian](https://github.com/gsan-dev/NetGuardian)'s report generator) summarizing the last 7 days: total/new devices, unauthorized devices, security alerts (from either source), and CVE findings — plus the latest graph's node/edge/community counts. `GET /api/reports/weekly` builds it on demand from `Repository.get_weekly_summary()` and streams it back as a download.

### Backend (FastAPI)

Serves the graph over REST (`GET /api/networks`, `/api/devices`, `/api/devices/{mac}`, `/api/devices/{mac}/history`, `/api/graph`, `/api/graph/snapshots`, `/api/reports/weekly`), queues and resolves on-demand traceroutes (`POST`/`GET /api/devices/{mac}/traceroute`), reports its own and the sensor's health (`GET /api/health`), and a WebSocket channel (`/ws`) that pushes the full current graph state to every connected client every few seconds. Sensor (discovery pipeline) and backend are fully decoupled: one writes to SQLite, the other only reads and broadcasts.

### Frontend (React + Cytoscape.js)

Renders the graph with automatic layouts (hierarchical/breadthfirst or force-directed/cose), lets you search devices by MAC/IP/vendor/type, filter by subnet, optionally group nodes into collapsible compound clusters per subnet, colors nodes by device type, flags unauthorized devices with a dashed red border, draws a severity-colored halo around devices with recent security alerts (from NetGuardian or the local ARP watcher), and offers a **time-lapse** mode that replays how the topology changed over time using the snapshot history already stored in the database — including full historical topology, not just metrics, since every snapshot stores the actual devices/relations at that point in time. A dark/light theme toggle (persisted in `localStorage`) restyles the whole UI including the graph canvas itself, since Cytoscape doesn't inherit CSS and has to be rebuilt from the same custom-property tokens the rest of the page uses. The device detail panel also exposes an on-demand **Traceroute** button (polls until the sensor resolves it) and the topbar has a one-click **weekly PDF report** download.

---

## 🧰 Tech stack

| Layer | Technology | Why |
|---|---|---|
| Network discovery | netifaces, pyroute2 | Direct access to interfaces and the system routing table (IPv4 + IPv6) |
| Host scanning | Scapy (ARP/NDP), asyncio + sockets (remote) | ARP/NDP are fast locally; async is needed to scale on remote networks |
| Fingerprinting | manuf (OUI lookup), custom rules | Vendor and device-type identification without depending on external services |
| TLS inspection | `cryptography` | Parses raw DER certificates without needing full chain validation |
| CVE correlation | NVD REST API (`requests`) | Public, free, no local vulnerability database to maintain |
| Passive capture | Scapy | De facto standard for packet manipulation/sniffing in Python; also parses ARP and LLDP frames |
| Graph & analysis | NetworkX (+ python-louvain) | Community/centrality analysis already implemented and battle-tested |
| Persistence | SQLite (default, works today) → Neo4j (stub, for a real graph database later) | Start fast with zero external dependencies; swap the `Repository` implementation when you actually need Cypher queries |
| Backend | FastAPI | Native async, easy WebSockets, automatic docs |
| PDF reports | `fpdf2` | Lightweight, no external renderer dependency, same library NetGuardian already uses |
| Frontend | React + Vite + Cytoscape.js | Graph layouts out of the box, saves weeks of development |
| Security integration | NetGuardian (optional) | Reuses an existing anomaly-detection IDS instead of reimplementing one |
| CI | GitHub Actions | Pytest suite + frontend build run on every push/PR to `main` |
| Containers | Docker + docker-compose | Reproducible homelab deployment |

---

## 📁 Repository structure

```
netmapper/
├── README.md
├── LICENSE
├── .gitignore / .dockerignore
├── .github/workflows/ci.yml     # pytest + frontend build on every push/PR
├── docker-compose.yml
├── .env.example                 # reference for every available setting
├── requirements-dev.txt         # discovery + analysis + backend + pytest
│
├── common/                      # shared by discovery, analysis and backend
│   ├── config.py                  # settings from .env (ALLOWED_NETWORKS, ALLOWED_DEVICES, SENSOR_ID...)
│   ├── db.py                      # Repository (SQLite today, Neo4j as an explicit stub)
│   ├── device_types.py            # device-type inference rule engine
│   ├── severity.py                # shared none<low<medium<high ordering
│   ├── netguardian_client.py      # optional NetGuardian integration client
│   ├── cve_lookup.py              # banner → product/version → NVD keyword search
│   └── reports.py                 # weekly PDF report generator (fpdf2)
│
├── discovery/
│   ├── main.py                    # orchestrates the whole pipeline (--continuous)
│   ├── network_discovery.py       # Stage 0: netifaces + pyroute2 + SNMP, IPv4+IPv6
│   ├── host_discovery.py          # Stage 1: ARP/NDP (local) + TCP probing (remote)
│   ├── device_fingerprint.py      # Stage 2: OUI + ports + mDNS + banner grabbing + TLS inspection
│   ├── passive_capture.py         # Stage 3: Scapy windows + DNS queries + ARP spoof + LLDP
│   ├── fusion_engine.py           # Stage 4: the most delicate module
│   ├── traceroute.py              # on-demand traceroute (resolved from pending backend requests)
│   ├── Dockerfile
│   └── requirements.txt
│
├── analysis/
│   ├── graph_analysis.py          # Stage 5: communities, centrality, layers
│   └── requirements.txt
│
├── backend/
│   ├── main.py                    # FastAPI + WebSocket + graph broadcaster + /api/health
│   ├── ws_manager.py
│   ├── routes/
│   │   ├── networks.py
│   │   ├── devices.py               # includes /{mac}/history and /{mac}/traceroute
│   │   ├── graph.py
│   │   ├── reports.py               # GET /api/reports/weekly
│   │   └── ws.py
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── NetworkGraph.jsx     # Cytoscape.js, theme-aware, subnet grouping
│   │   │   ├── FilterPanel.jsx      # search, filters, legend, device detail + history + traceroute
│   │   │   └── TimelapseControls.jsx
│   │   ├── deviceTypes.js           # same palette as common/device_types.py
│   │   ├── api.js
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── Dockerfile / nginx.conf
│   ├── package.json
│   └── vite.config.js
│
├── data/                         # SQLite database (gitignored)
├── reports/                      # generated weekly PDFs (gitignored)
├── tests/                        # pytest for discovery + analysis + backend + common
└── docs/
    └── capturas/                 # real screenshots of the dashboard
```

---

## 🗺️ Roadmap & commit plan

### Stage 0 — Setup
- [x] `chore: inicializar repositorio con estructura de carpetas`
- [x] `chore: .gitignore, README inicial y licencia`
- [x] `chore: aviso legal de uso responsable en el README`

### Stage 1 — Network discovery
- [x] `feat: enumerar interfaces locales y calcular CIDR con netifaces`
- [x] `feat: parseo de la tabla de rutas del sistema con pyroute2`
- [x] `feat: consulta SNMP a routers/switches gestionables`
- [x] `test: pruebas del módulo network_discovery`

### Stage 2 — Host discovery
- [x] `feat: ARP scanning para redes directamente conectadas`
- [x] `feat: escaneo asíncrono ICMP/TCP para redes remotas`
- [x] `perf: paralelización del escaneo por subred`

### Stage 3 — Device characterization
- [x] `feat: lookup de fabricante por MAC (OUI)`
- [x] `feat: port scanning selectivo y detección de banners`
- [x] `feat: escucha pasiva de mDNS/UPnP`
- [x] `feat: motor de reglas para inferir tipo de dispositivo`

### Stage 4 — Passive discovery
- [x] `feat: captura de tráfico y agregación por ventanas`
- [x] `feat: extracción de relaciones origen-destino`
- [x] `feat: análisis de consultas DNS por dispositivo`

### Stage 5 — Fusion & graph analysis
- [x] `feat: motor de fusión de datos multi-fuente`
- [x] `feat: deduplicación y resolución de conflictos por MAC`
- [x] `feat: detección de comunidades (Louvain)`
- [x] `feat: cálculo de centralidad e inferencia de capas`
- [x] `test: pruebas del motor de fusión y análisis de grafo`

### Stage 6 — Persistence & backend
- [x] `feat: capa de persistencia SQLite con interfaz abstracta (Neo4jRepository como stub)`
- [x] `feat: endpoints REST (/networks, /devices, /graph)`
- [x] `feat: WebSocket para actualizaciones en vivo`

### Stage 7 — Frontend
- [x] `feat: scaffold de React + Vite`
- [x] `feat: renderizado del grafo con Cytoscape.js`
- [x] `feat: filtros por subred y por capa jerárquica`
- [x] `feat: modo time-lapse de evolución de topología`
- [x] `feat: exportación del mapa (imagen/diagrama)`
- [x] `style: pulido visual del panel`

### Stage 8 — Dockerization & wrap-up
- [x] `feat: Dockerfile por servicio + docker-compose.yml`
- [x] `docs: capturas de pantalla y resultados`
- [x] `chore: limpieza final y revisión de código`

### Stage 9 — First round of built-in enhancements (originally listed as future improvements)
- [x] `feat: soporte IPv6 en descubrimiento de redes/hosts/captura pasiva`
- [x] `feat: detección de dispositivos no autorizados (ALLOWED_DEVICES)`
- [x] `feat: huella histórica por dispositivo (device footprint)`
- [x] `feat: integración con NetGuardian — superpone alertas de anomalías en el mapa`

### Stage 10 — Second round of built-in enhancements (security, topology, UX, reliability, CI)
- [x] `feat: banner grabbing de servicios abiertos (base para CVEs)`
- [x] `feat: inspección de certificados TLS`
- [x] `feat: correlación de banners con CVEs conocidos (NVD)`
- [x] `feat: detección de ARP/DHCP spoofing`
- [x] `feat: topología física parcial vía LLDP`
- [x] `feat: traceroute bajo demanda`
- [x] `feat: informe semanal de red en PDF`
- [x] `feat: búsqueda, agrupación por subred y tema claro/oscuro en el frontend`
- [x] `feat: retención/purga de snapshots de grafo + endpoint de salud con última pasada`
- [x] `feat: soporte multi-sensor (SENSOR_ID) para segmentos aislados`
- [x] `ci: GitHub Actions (pytest + build de frontend)`

All stages are complete — the commit history in this repo follows this roadmap stage by stage, each with its own descriptive commit. A reverse proxy in front of the backend/frontend was deliberately left out of this round (see [Future improvements](#-future-improvements)) since it's meant to sit behind an existing nginx Proxy Manager instance instead of being reimplemented here.

---

## ⚙️ Installation guide

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker and docker-compose (optional, but recommended for homelab deployment)
- Administrator/root permissions (needed for ARP/NDP scanning, packet capture, and traceroute)
- Management access (SNMP/API) to your router — optional, but improves accuracy
- (Optional) A running [NetGuardian](https://github.com/gsan-dev/NetGuardian) instance, if you want anomaly alerts overlaid on the map
- (Optional) An [NVD API key](https://nvd.nist.gov/developers/request-an-api-key), if you want faster CVE correlation than the public rate limit allows

### 1. Clone the repository

```bash
git clone https://github.com/gsan-dev/NetMapper.git
cd NetMapper
```

### 2. Python virtual environment and dependencies

```bash
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r discovery/requirements.txt
pip install -r analysis/requirements.txt
pip install -r backend/requirements.txt
```

### 3. Frontend dependencies

```bash
cd frontend
npm install
cd ..
```

### 4. Environment variables

Copy the template and adjust it to your network:

```bash
cp .env.example .env
```

`.env.example` is the always-up-to-date reference for every available setting. At minimum, review:

```env
ALLOWED_NETWORKS=192.168.0.0/24,192.168.1.0/24,10.0.0.0/24
SNMP_COMMUNITY=public
SCAN_INTERVAL_SECONDS=300
DB_BACKEND=sqlite   # see the database note below

# Optional enhancements — safe defaults, opt in to what you need
ALLOWED_DEVICES=                # comma-separated known MACs; empty = nothing flagged
NETGUARDIAN_ENABLED=false       # set true + fill NETGUARDIAN_* to overlay IDS alerts
CVE_LOOKUP_ENABLED=false        # off by default: makes outbound requests to NVD
SENSOR_ID=default                # give each sensor a unique id if you run more than one
```

Everything from banner grabbing to ARP-spoof detection to LLDP discovery ships **on** by default (they're all passive or non-intrusive); CVE lookup and NetGuardian integration ship **off**, since both involve external calls or another running service.

> `ALLOWED_NETWORKS` is deliberate: even though the program will auto-detect more networks, it only ever actively scans the ones you've explicitly authorized here. It's your security whitelist — see [Legal & ethical considerations](#️-legal--ethical-considerations).

> **Database note:** the original plan pointed at Neo4j from the start. The final implementation prioritized SQLite (`DB_BACKEND=sqlite`, default) instead, to avoid depending on an external graph server just to get running — the same "SQLite first, specialized engine later" philosophy used in [NetGuardian](https://github.com/gsan-dev/NetGuardian). `common/db.py` already defines the `Repository` interface and an explicit `Neo4jRepository` stub — implementing that class against the same interface won't require touching discovery, analysis, or backend at all. If you want Neo4j today, that's the piece left to write.

Generate `frontend/.env` with your backend URL (`cp frontend/.env.example frontend/.env`) if the backend isn't running on `localhost:8100`.

---

## 🚀 Getting it running

### Step 1 — Run network discovery once, to validate

```bash
cd discovery
python3 network_discovery.py
```

This prints the detected subnets (local, via routing table, and via router if SNMP is configured) and whether each one is authorized for active scanning per `ALLOWED_NETWORKS`. Check it matches what you expect before continuing.

### Step 2 — Launch the full scanning pipeline

```bash
sudo python3 main.py --continuous
```

Root is required for ARP/NDP scanning, passive capture, and traceroute. `--continuous` keeps the pipeline looping every `SCAN_INTERVAL_SECONDS`, persisting each pass to `data/netmapper.db`. Without the flag, it runs a single full pass (discovery + analysis) and exits — useful for validating your configuration before leaving it running for real.

### Step 3 — Start the backend

```bash
cd backend
uvicorn main:app --reload --port 8100
```

### Step 4 — Start the frontend

```bash
cd frontend
npm run dev
```

Open the dashboard at `http://localhost:5174`.

### Step 5 (recommended alternative) — Everything with Docker

```bash
docker-compose up --build -d
docker-compose logs -f
```

> **Putting it behind a reverse proxy** (e.g. nginx Proxy Manager) is intentionally left as a deployment-time decision rather than baked into `docker-compose.yml` — point it at the frontend container's port and, if you want the API reachable externally too, at the backend's.

---

## 🖥️ Using the dashboard

- **Overview**: every detected network as a filter option, with its status (scanned / not scanned — outside `ALLOWED_NETWORKS`), plus live counts of devices/relations/networks and how many devices are currently unauthorized.
- **Search & grouping**: a free-text search box filters by MAC, IP, vendor or device type; an "group by subnet" toggle collapses devices into per-subnet compound clusters on the graph instead of one flat cloud of nodes.
- **Interactive map**: nodes colored by device type, edges weighted by observed traffic volume; unauthorized devices get a dashed red border, and devices with recent security alerts (NetGuardian or NetMapper's own local ARP-spoof watcher) get a severity-colored halo (amber/orange/red for low/medium/high).
- **Dark/light theme**: a topbar toggle switches the whole UI (including the graph canvas colors) and remembers your choice for next time.
- **Side panel**: clicking a node shows its full metadata (IPs, MAC, vendor, open ports, authorization status), its security alert summary with the alert's origin, its physical LLDP neighbor when known, and its historical footprint — first-seen timestamp plus a collapsed list of actual device-type/vendor transitions over time. A **Traceroute** button queues an on-demand trace to that device and polls for the hop-by-hop result once the sensor resolves it.
- **Time-lapse**: a slider over the stored analysis history that reconstructs the *exact* topology at any past point (not just current devices repainted with old metrics), with a toggle back to live mode.
- **Export**: download the current map as a PNG, or as GraphML (draw.io imports this natively: *File → Import from → Device*), or download a **weekly PDF report** summarizing devices, alerts and CVE findings from the topbar.

---

## 📸 Screenshots

Force-directed (cose) layout, a central router and six devices around it, colored by type:

![Force-directed map](docs/capturas/force-directed.png)

The same topology in hierarchical (breadthfirst) layout, handy for seeing at a glance what hangs directly off the gateway:

![Hierarchical map](docs/capturas/hierarchical.png)

Both built-in enhancements visible at once: the IP camera has a dashed red border (not on the `ALLOWED_DEVICES` whitelist) and the mobile device carries a red halo (a high-severity security alert against it):

![Unauthorized device and security alert halo](docs/capturas/topology-features.png)

Clicking that flagged device shows its full detail panel — authorization status, alert count/severity/reason/source, and first-seen timestamp:

![Device detail panel with security and history info](docs/capturas/device-detail.png)

> Captured against the real running stack (backend + frontend) with example data seeded directly into the database, verifying along the way that there are no console errors and that both export modes (PNG/GraphML), the traceroute button, and the weekly PDF report all work end to end.

---

## 🧪 Testing & CI

All tests live in `tests/` at the repo root (a single `conftest.py` adds `discovery/`, `analysis/`, `backend/` and the repo root to `sys.path`):

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt

cd tests
pytest -q
```

217 tests cover network/host discovery (IPv4 and IPv6), device fingerprinting (including banner grabbing and TLS inspection), passive capture (including ARP-spoof detection and LLDP parsing), CVE correlation, on-demand traceroute, the fusion engine, graph analysis, persistence (including snapshot retention and the weekly-report aggregation), the backend API, the PDF report generator, the NetGuardian client, and the full pipeline orchestration — all executed and green on this machine (unlike NetGuardian, there's no dependency here on native extensions blocked by a Windows Application Control policy). External calls (NVD, real traceroute probes) are always mocked in tests — nothing in the suite touches the network or the internet.

`.github/workflows/ci.yml` runs the same pytest suite plus a frontend production build (`npm run build`) on every push and pull request to `main`.

---

## 🚀 Built-in enhancements

Both rounds of "future improvements" this project went through ended up implemented directly, not left for later — each behind its own opt-in setting where it makes sense, defaulting to whatever's safest so nothing surprising happens for anyone who doesn't touch `.env`.

### First round — originally the README's "Future improvements" section

- **NetGuardian integration** (`NETGUARDIAN_ENABLED`): `common/netguardian_client.py` polls a running [NetGuardian](https://github.com/gsan-dev/NetGuardian) IDS instance for anomaly alerts and correlates them by source IP with devices NetMapper already knows about — no anomaly-detection logic duplicated here. Flagged devices get a severity-colored halo on the map and a detail panel entry with alert count/severity/reason.
- **IPv6 support**: local and routed IPv6 network discovery, NDP-based host discovery for directly-connected IPv6 segments (ARP doesn't exist in IPv6), and IPv6 packet parsing in passive capture. SNMP router discovery stays IPv4-only (documented limitation, not silently pretended away).
- **Unauthorized device detection** (`ALLOWED_DEVICES`): an optional MAC whitelist. Devices not on it get flagged (`is_authorized: false`) and rendered with a dashed red border on the map — empty by default, so nobody gets false positives until they opt in.
- **Device historical footprint**: `GET /api/devices/{mac}/history` reconstructs a device's timeline (first seen, device-type/vendor changes) directly from the graph snapshots already stored for time-lapse — no extra table needed.

### Second round — security, topology, UX and reliability

**Security**
- **Banner grabbing** (`BANNER_GRAB_ENABLED`): reads the service greeting off every open port found in Stage 2 — the raw material CVE correlation parses.
- **TLS certificate inspection** (`TLS_INSPECT_ENABLED`): reads subject/issuer/expiry/self-signed status off TLS-looking ports, without validating the trust chain (many homelab devices are self-signed by design).
- **CVE correlation** (`CVE_LOOKUP_ENABLED`, opt-in): matches recognized banners against the public NVD database, cached and rate-limited so it never floods a third-party service.
- **ARP/DHCP spoofing detection** (`ARP_SPOOF_DETECTION_ENABLED`): flags when the same IP gets claimed by two different MACs on the wire — a live, local complement to whatever NetGuardian might report from its own vantage point.

**Topology & analysis**
- **LLDP physical-neighbor discovery** (`LLDP_DISCOVERY_ENABLED`): captures what managed switches/APs announce about themselves to devices plugged directly into them — a partial, honestly-scoped slice of the physical topology, not a claim of full L2 mapping.
- **On-demand traceroute**: request a hop-by-hop trace to any known device straight from its detail panel; resolved by the sensor process (which has the privileges to do it), not the backend.
- **Distributed sensors** (`SENSOR_ID`): multiple NetMapper sensors on isolated segments can share one database — each only retires the devices *it* last saw, never another sensor's.

**Frontend / UX**
- **Search filter**: free-text device search by MAC/IP/vendor/type.
- **Subnet grouping**: collapsible compound clusters per subnet on the graph, instead of one flat node cloud.
- **Light theme**: a full dark/light toggle, including the Cytoscape canvas itself.
- **Weekly PDF report**: one-click download summarizing the last 7 days of devices, alerts and CVEs.

**Reliability**
- **Graph-snapshot retention**: old analysis snapshots are pruned past `GRAPH_SNAPSHOT_RETENTION_SECONDS`, always keeping at least the latest one so time-lapse never breaks.
- **Health endpoint**: `GET /api/health` reports `sensor_healthy` based on the last recorded discovery pass, so a silently-dead sensor process is visible instead of the dashboard just going quiet.

**CI/Deploy**
- **GitHub Actions CI**: pytest suite + frontend production build run automatically on every push/PR to `main`.
- Reverse proxy setup was deliberately **excluded** from this round — it's meant to sit behind an existing nginx Proxy Manager instance rather than be reimplemented in `docker-compose.yml`.

---

## 🔮 Future improvements

With both rounds above now built, here's what's actually still open:

- **Reverse proxy wiring**: fronting the backend/frontend containers with the existing nginx Proxy Manager setup (deliberately deferred, not forgotten).
- A real `Neo4jRepository` implementation, for genuine Cypher-based topology queries instead of SQLite JSON blobs — `get_weekly_summary` and every other `Repository` method are already written against the abstract interface, so this is purely additive.
- IPv6 SNMP router discovery via RFC 4293's `ipAddressTable` (today's SNMP discovery is IPv4-only).
- CDP support alongside LLDP for physical-neighbor discovery (Cisco-proprietary, so it was deprioritized in favor of the open, vendor-neutral standard — but it would extend coverage on Cisco-heavy networks).
- Alerting rules (webhook/Telegram/Discord) when an unauthorized device joins the network, a security alert reaches "high" severity, or a newly-found CVE is critical — right now all three are visible on the map and in the weekly report, but nothing pushes a real-time notification.
- Multi-user auth on the backend API (currently open — fine for a private homelab LAN, not for anything exposed further).
- A dedicated diff view between two time-lapse snapshots (today you scrub between full topologies one at a time; a side-by-side "what changed" view would be more direct).
- Scheduling the weekly PDF report to generate and be delivered automatically (e.g. by email) instead of only on-demand from the dashboard.

---

## 📄 License

MIT — use, modify and share freely, crediting the source. Remember: only for networks you own or have explicit authorization to scan.
