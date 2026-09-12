# 🗺️ NetMapper — Descubrimiento y Mapeo Automático de Redes Multi-Segmento

> Herramienta que detecta automáticamente todas las redes accesibles desde tu máquina (aunque estén en rangos distintos: 192.168.0.x, 192.168.1.x, 10.0.0.x, 172.26.0.x...), descubre los dispositivos de cada una combinando técnicas activas y pasivas, y construye un mapa de topología interactivo y siempre actualizado.

---

## 📋 Tabla de contenidos

1. [Motivación y alcance](#-motivación-y-alcance)
2. [Consideraciones legales y éticas](#-consideraciones-legales-y-éticas)
3. [Arquitectura general](#-arquitectura-general)
4. [Análisis detallado del programa](#-análisis-detallado-del-programa)
5. [Stack tecnológico](#-stack-tecnológico)
6. [Estructura del repositorio](#-estructura-del-repositorio)
7. [Roadmap y plan de commits](#-roadmap-y-plan-de-commits)
8. [Guía de instalación](#-guía-de-instalación)
9. [Pasos a seguir para ejecutarlo](#-pasos-a-seguir-para-ejecutarlo)
10. [Uso del panel](#-uso-del-panel)
11. [Capturas](#-capturas)
12. [Testing](#-testing)
13. [Mejoras futuras](#-mejoras-futuras)
14. [Licencia](#-licencia)

---

## 🎯 Motivación y alcance

La mayoría de herramientas de escaneo de red asumen que trabajas sobre un único rango (`192.168.1.0/24`) configurado a mano. En redes reales —homelabs con VLANs, Docker, VPNs, o redes corporativas— conviven varios segmentos a la vez, y el usuario normalmente no conoce todos de antemano.

**NetMapper** resuelve esto en dos etapas:

1. **Descubre qué redes existen y son alcanzables** desde la máquina donde corre, sin que el usuario tenga que indicarlas manualmente.
2. **Mapea cada red descubierta**, combinando descubrimiento activo (ARP, ICMP, SNMP, port scanning) y pasivo (captura de tráfico), y construye un grafo de topología interactivo que se actualiza solo.

El resultado final es un panel web donde ves, en tiempo real, todos los dispositivos accesibles del entorno, agrupados por red, con sus relaciones de comunicación.

---

## ⚖️ Consideraciones legales y éticas

Antes de nada, esto tiene que quedar explícito en el propio repositorio (y es importante mencionarlo en cualquier entrevista):

- Esta herramienta está pensada **exclusivamente para auditar redes de tu propiedad** (tu homelab, tu red doméstica, o una red donde tengas autorización explícita).
- El escaneo activo de redes ajenas sin permiso es **ilegal** en la gran mayoría de países.
- El propio README del proyecto debe incluir un aviso de uso responsable, y el programa debe, idealmente, pedir confirmación explícita antes de escanear cualquier rango nuevo detectado.

---

## 🏗️ Arquitectura general

```
┌──────────────────────────────────────────────────────────────────┐
│                 FASE 0 — DESCUBRIMIENTO DE REDES                 │
│  Interfaces locales · Tabla de rutas · Consulta a routers ·      │
│  Expansión recursiva por gateways                                 │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  lista de subredes objetivo
┌───────────────────────────────▼────────────────────────────────────┐
│                 FASE 1 — DESCUBRIMIENTO DE HOSTS                  │
│  ARP scan (redes locales) · ICMP sweep · Escaneo async (remotas)  │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  hosts vivos por subred
┌───────────────────────────────▼────────────────────────────────────┐
│              FASE 2 — CARACTERIZACIÓN DE DISPOSITIVOS             │
│  Port scanning selectivo · Fingerprinting (OUI/MAC) ·             │
│  mDNS/UPnP · SNMP a switches/routers gestionables                 │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  metadata por dispositivo
┌───────────────────────────────▼────────────────────────────────────┐
│              FASE 3 — DESCUBRIMIENTO PASIVO                       │
│  Captura de tráfico (Scapy) · Análisis de consultas DNS ·         │
│  Relaciones "quién habla con quién"                               │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              FASE 4 — MOTOR DE FUSIÓN DE DATOS                    │
│  Combina todas las fuentes en un modelo de grafo coherente,       │
│  resolviendo conflictos (IPs reasignadas por DHCP, duplicados)    │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              FASE 5 — ANÁLISIS DE GRAFO                           │
│  Detección de comunidades (Louvain) · Centralidad ·               │
│  Inferencia de jerarquía (capas por nº de saltos)                 │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              FASE 6 — PERSISTENCIA                                │
│  Neo4j (o NetworkX + PostgreSQL) — modelo de grafo real           │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              FASE 7 — BACKEND API                                 │
│  FastAPI + WebSocket — expone el grafo y empuja cambios en vivo   │
└───────────────────────────────┬────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────┐
│              FASE 8 — FRONTEND                                    │
│  React + Cytoscape.js — mapa interactivo, filtros por red/capa,   │
│  time-lapse, exportación                                          │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Análisis detallado del programa

Esta sección explica **qué hace cada módulo internamente** y por qué está diseñado así — es la parte que conviene entender bien para poder defenderla en una entrevista.

### `network_discovery.py` — Descubrimiento de redes (Fase 0)

Responsable de responder "¿en qué redes estoy y a cuáles puedo llegar?". Combina tres fuentes:

- **Interfaces locales** (`netifaces`): cada interfaz de red de la máquina (Ethernet, Wi-Fi, VPN, bridges de Docker) tiene una IP y máscara propias, de las que se deriva un rango CIDR directamente conectado.
- **Tabla de rutas** (`pyroute2`): revela redes *no* conectadas directamente pero alcanzables a través de un gateway — esto es lo que te permite ver tu 10.0.0.x aunque tu máquina esté físicamente en 192.168.1.x.
- **Consulta a routers gestionables** (SNMP/API): si el router lo permite, es la fuente más fiable, porque el router conoce con certeza todas las subredes y VLANs configuradas.

El resultado de esta fase es una lista de objetos `Subred` con metadata: CIDR, cómo se descubrió (directa/ruta/router), y si es alcanzable o solo "conocida".

### `host_discovery.py` — Descubrimiento de hosts (Fase 1)

Por cada subred objetivo:
- Si es una red **directamente conectada**, usa ARP scanning (capa 2), que es casi instantáneo y muy fiable dentro del mismo segmento físico.
- Si es una red **remota** (accesible solo vía routing), usa ICMP sweep o escaneo TCP asíncrono, ya que ARP no funciona más allá de tu segmento local.

Este módulo es el que decide *cómo* escanear según el tipo de red, en vez de aplicar la misma técnica a todo — es una de las decisiones de diseño que vale la pena resaltar.

### `device_fingerprint.py` — Caracterización de dispositivos (Fase 2)

Para cada host vivo:
- Extrae el fabricante a partir de los primeros bytes de la MAC (base de datos OUI del IEEE).
- Hace un escaneo de puertos selectivo (no exhaustivo, para no ser agresivo) sobre los puertos más comunes.
- Combina banners de servicio + fabricante + puertos abiertos con un sistema de reglas simple para inferir el tipo de dispositivo (router, NAS, cámara IP, impresora, servidor, móvil).
- Escucha anuncios mDNS/UPnP pasivamente, que muchos dispositivos domésticos emiten solos y dan información gratis sin necesidad de escanear activamente.

### `passive_capture.py` — Descubrimiento pasivo (Fase 3)

Con Scapy en modo escucha, agrupa tráfico observado por pares de IPs en ventanas de tiempo, generando aristas del tipo `(origen, destino, bytes, nº_conexiones)`. Esto es lo que permite mostrar **relaciones reales de comunicación**, no solo presencia.

### `fusion_engine.py` — Motor de fusión (Fase 4)

Es el módulo más delicado del proyecto. Recibe datos de las tres fuentes anteriores (que pueden llegar en momentos distintos y con inconsistencias) y:
- Deduplica dispositivos usando la MAC como identificador estable (más fiable que la IP, que puede cambiar por DHCP).
- Resuelve conflictos temporales (ej: una IP que antes pertenecía a un dispositivo y ahora a otro).
- Construye el grafo final combinando nodos (dispositivos) y aristas (relaciones activas + observadas pasivamente).

### `graph_analysis.py` — Análisis de grafo (Fase 5)

Sobre el grafo ya construido:
- **Detección de comunidades** (algoritmo de Louvain, vía `networkx` o `python-louvain`): agrupa automáticamente dispositivos que interactúan mucho entre sí.
- **Centralidad de intermediación**: identifica qué nodos son puntos críticos de la red (si caen, fragmentan la conectividad).
- **Inferencia de capas**: usando el nº de saltos (TTL/traceroute) desde el nodo raíz, posiciona los dispositivos en niveles jerárquicos (core → distribución → acceso) para que el mapa se dibuje de forma ordenada y no como una maraña plana.

### Backend (`FastAPI`)

Expone el grafo vía REST (`GET /networks`, `GET /devices`, `GET /graph`) y un canal WebSocket (`/ws/live`) que empuja al frontend cualquier cambio detectado (nuevo dispositivo, nueva relación, dispositivo caído) en cuanto ocurre, sin necesidad de refrescar la página.

### Frontend (`React` + `Cytoscape.js`)

Renderiza el grafo con layouts automáticos (jerárquico o "force-directed"), permite filtrar por subred o por capa, colorea nodos por tipo de dispositivo, y ofrece un modo "time-lapse" que reproduce cómo ha cambiado la topología a lo largo del tiempo usando el histórico guardado en base de datos.

---

## 🧰 Stack tecnológico

| Capa | Tecnología | Por qué |
|---|---|---|
| Descubrimiento de redes | netifaces, pyroute2 | Acceso directo a interfaces y tabla de rutas del sistema |
| Escaneo de hosts | Scapy (ARP), asyncio + sockets (remoto) | ARP es rápido en local; async necesario para escalar en redes remotas |
| Fingerprinting | manuf (OUI lookup), reglas propias | Identificación de fabricante y tipo de dispositivo sin depender de servicios externos |
| Captura pasiva | Scapy / pyshark | Estándar de facto para manipulación y sniffing de paquetes en Python |
| Grafo y análisis | NetworkX (+ python-louvain) | Todo el análisis de comunidades/centralidad ya implementado y probado |
| Persistencia | Neo4j (recomendado) o PostgreSQL | Un grafo se modela naturalmente como grafo; Neo4j simplifica consultas de topología |
| Backend | FastAPI | Async nativo, WebSockets sencillos, documentación automática |
| Frontend | React + Vite + Cytoscape.js | Layouts de grafo listos de fábrica, ahorra semanas de desarrollo |
| Contenedores | Docker + docker-compose | Despliegue reproducible en el homelab |

---

## 📁 Estructura del repositorio

La estructura final creció un poco respecto al plan inicial: apareció
`common/` para que discovery/analysis/backend compartan configuración
y base de datos sin duplicar código (mismo patrón que en NetGuardian),
y `data/oui_database.txt` no existe como archivo propio porque la
librería `manuf` ya trae su propia base OUI empaquetada — mantener una
copia local habría sido redundante.

```
netmapper/
├── README.md
├── LICENSE
├── .gitignore / .dockerignore
├── docker-compose.yml
├── .env.example                 # referencia de toda la configuración
├── requirements-dev.txt         # discovery + analysis + backend + pytest
│
├── common/                      # compartido por discovery, analysis y backend
│   ├── config.py                  # settings desde .env (incluye ALLOWED_NETWORKS)
│   ├── db.py                      # Repository (SQLite hoy, Neo4j como stub futuro)
│   └── device_types.py            # motor de reglas de inferencia de tipo
│
├── discovery/
│   ├── main.py                    # orquesta todo el pipeline (--continuous)
│   ├── network_discovery.py       # Fase 0: netifaces + pyroute2 + SNMP
│   ├── host_discovery.py          # Fase 1: ARP (local) + sondeo TCP (remoto)
│   ├── device_fingerprint.py      # Fase 2: OUI + puertos + mDNS
│   ├── passive_capture.py         # Fase 3: Scapy + ventanas + consultas DNS
│   ├── fusion_engine.py           # Fase 4: el módulo más delicado
│   ├── Dockerfile
│   └── requirements.txt
│
├── analysis/
│   ├── graph_analysis.py          # Fase 5: comunidades, centralidad, capas
│   └── requirements.txt
│
├── backend/
│   ├── main.py                    # FastAPI + WebSocket + difusión del grafo
│   ├── ws_manager.py
│   ├── routes/
│   │   ├── networks.py
│   │   ├── devices.py
│   │   ├── graph.py
│   │   └── ws.py
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── NetworkGraph.jsx     # Cytoscape.js
│   │   │   ├── FilterPanel.jsx
│   │   │   └── TimelapseControls.jsx
│   │   ├── deviceTypes.js           # misma paleta que common/device_types.py
│   │   ├── api.js
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── Dockerfile / nginx.conf
│   ├── package.json
│   └── vite.config.js
│
├── data/                         # base SQLite (gitignored)
├── tests/                        # pytest de discovery + analysis + backend + common
└── docs/
    └── capturas/                 # screenshots reales del panel
```

---

## 🗺️ Roadmap y plan de commits

### Fase 0 — Setup
- [x] `chore: inicializar repositorio con estructura de carpetas`
- [x] `chore: .gitignore, README inicial y licencia`
- [x] `chore: aviso legal de uso responsable en el README`

### Fase 1 — Descubrimiento de redes
- [x] `feat: enumerar interfaces locales y calcular CIDR con netifaces`
- [x] `feat: parseo de la tabla de rutas del sistema con pyroute2`
- [x] `feat: consulta SNMP a routers/switches gestionables`
- [x] `test: pruebas del módulo network_discovery`

### Fase 2 — Descubrimiento de hosts
- [x] `feat: ARP scanning para redes directamente conectadas`
- [x] `feat: escaneo asíncrono ICMP/TCP para redes remotas`
- [x] `perf: paralelización del escaneo por subred`

### Fase 3 — Caracterización de dispositivos
- [x] `feat: lookup de fabricante por MAC (OUI)`
- [x] `feat: port scanning selectivo y detección de banners`
- [x] `feat: escucha pasiva de mDNS/UPnP`
- [x] `feat: motor de reglas para inferir tipo de dispositivo`

### Fase 4 — Descubrimiento pasivo
- [x] `feat: captura de tráfico y agregación por ventanas`
- [x] `feat: extracción de relaciones origen-destino`
- [x] `feat: análisis de consultas DNS por dispositivo`

### Fase 5 — Fusión y análisis de grafo
- [x] `feat: motor de fusión de datos multi-fuente`
- [x] `feat: deduplicación y resolución de conflictos por MAC`
- [x] `feat: detección de comunidades (Louvain)`
- [x] `feat: cálculo de centralidad e inferencia de capas`
- [x] `test: pruebas del motor de fusión y análisis de grafo`

### Fase 6 — Persistencia y backend
- [x] `feat: capa de persistencia SQLite con interfaz abstracta (Neo4jRepository como stub)`
- [x] `feat: endpoints REST (/networks, /devices, /graph)`
- [x] `feat: WebSocket para actualizaciones en vivo`

### Fase 7 — Frontend
- [x] `feat: scaffold de React + Vite`
- [x] `feat: renderizado del grafo con Cytoscape.js`
- [x] `feat: filtros por subred y por capa jerárquica`
- [x] `feat: modo time-lapse de evolución de topología`
- [x] `feat: exportación del mapa (imagen/diagrama)`
- [x] `style: pulido visual del panel`

### Fase 8 — Dockerización y cierre
- [x] `feat: Dockerfile por servicio + docker-compose.yml`
- [x] `docs: capturas de pantalla y resultados`
- [x] `chore: limpieza final y revisión de código`

---

## ⚙️ Guía de instalación

### Requisitos previos

- Python 3.11+
- Node.js 18+
- Docker y docker-compose (opcional, pero recomendado para el homelab)
- Permisos de administrador/root (necesarios para ARP scanning y captura de tráfico)
- Acceso de gestión (SNMP/API) al router, opcional pero recomendado para mejor precisión

### 1. Clonar el repositorio

```bash
git clone https://github.com/gsan-dev/NetMapper.git
cd NetMapper
```

### 2. Entorno virtual y dependencias Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r discovery/requirements.txt
pip install -r analysis/requirements.txt
pip install -r backend/requirements.txt
```

### 3. Dependencias del frontend

```bash
cd frontend
npm install
cd ..
```

### 4. Variables de entorno

Copia la plantilla y ajústala a tu red:

```bash
cp .env.example .env
```

`.env.example` es la referencia siempre actualizada de toda la configuración disponible. Como mínimo revisa:

```env
ALLOWED_NETWORKS=192.168.0.0/24,192.168.1.0/24,10.0.0.0/24,172.26.0.0/24
SNMP_COMMUNITY=public
SCAN_INTERVAL_SECONDS=300
DB_BACKEND=sqlite   # ver nota sobre Neo4j más abajo
```

> `ALLOWED_NETWORKS` es intencional: aunque el programa detecte más redes automáticamente, solo escaneará activamente las que hayas autorizado explícitamente aquí. Es tu "lista blanca" de seguridad.

> **Nota sobre la base de datos:** el plan original apuntaba a Neo4j desde el principio. En la implementación final se priorizó SQLite (`DB_BACKEND=sqlite`, por defecto) para no depender de un servidor de grafo externo solo para arrancar, siguiendo la misma filosofía "SQLite primero, motor especializado después" que NetGuardian. `common/db.py` ya define la interfaz `Repository` y un `Neo4jRepository` como stub explícito — implementarlo sobre esa misma interfaz no requiere tocar discovery, analysis ni backend. Si quieres Neo4j desde ya, esa es la pieza que falta por escribir.

Genera el frontend/.env con la URL del backend (`cp frontend/.env.example frontend/.env`) si el backend no corre en `localhost:8100`.

---

## 🚀 Pasos a seguir para ejecutarlo

### Paso 1 — Ejecutar el descubrimiento de redes (una vez, para validar)

```bash
cd discovery
python3 network_discovery.py
```

Esto imprime por consola la lista de subredes detectadas (locales, por tabla de rutas, y por router si está configurado SNMP) y si cada una está autorizada para escaneo activo según `ALLOWED_NETWORKS`. Revisa que coincide con lo que esperas antes de continuar.

### Paso 2 — Lanzar el pipeline completo de escaneo

```bash
sudo python3 main.py --continuous
```

Hace falta root para ARP scanning y captura pasiva. El flag `--continuous` deja el pipeline corriendo en bucle cada `SCAN_INTERVAL_SECONDS`, persistiendo cada pasada en `data/netmapper.db`. Sin el flag, hace una sola pasada completa (descubrimiento + análisis) y termina — útil para probar la configuración antes de dejarlo corriendo de verdad.

### Paso 3 — Levantar el backend

```bash
cd backend
uvicorn main:app --reload --port 8100
```

### Paso 4 — Levantar el frontend

```bash
cd frontend
npm run dev
```

Accede al panel en `http://localhost:5174`.

### Paso 5 (alternativa recomendada) — Todo junto con Docker

```bash
docker-compose up --build -d
docker-compose logs -f
```

---

## 🖥️ Uso del panel

- **Vista general**: todas las redes detectadas como pestañas/filtros, con su estado (escaneada / parcialmente accesible / solo conocida).
- **Mapa interactivo**: nodos coloreados por tipo de dispositivo, aristas con grosor proporcional al volumen de tráfico observado.
- **Panel lateral**: al hacer clic en un nodo, ves su metadata completa (IP, MAC, fabricante, puertos abiertos, servicios detectados).
- **Time-lapse**: barra temporal para ver cómo ha cambiado la red en las últimas horas/días.
- **Exportar**: botón para descargar el mapa actual como PNG, o como GraphML (draw.io lo importa de forma nativa: *File → Import from → Device*).

---

## 📸 Capturas

Disposición force-directed (cose), con un router central y seis dispositivos alrededor, coloreados por tipo:

![Mapa force-directed](docs/capturas/force-directed.png)

La misma topología en disposición jerárquica (breadthfirst), útil para ver de un vistazo qué cuelga directamente del gateway:

![Mapa jerárquico](docs/capturas/hierarchical.png)

> Capturadas con el stack real corriendo (backend + frontend) contra datos de ejemplo sembrados directamente en la base de datos, verificando también que no hay errores de consola y que ambos modos de exportación (PNG/GraphML) descargan un archivo real.

---

## 🧪 Testing

Todos los tests viven en `tests/` en la raíz (un único `conftest.py` añade `discovery/`, `analysis/`, `backend/` y la raíz del repo a `sys.path`):

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt

cd tests
pytest -q
```

92 tests cubren descubrimiento de redes/hosts, fingerprinting de dispositivos, captura pasiva, el motor de fusión, el análisis de grafo, persistencia, la API del backend y la orquestación completa del pipeline — todos ejecutados y en verde en esta máquina (a diferencia de NetGuardian, aquí no hay ninguna dependencia con extensiones nativas bloqueadas por directivas de Windows).

---

## 🔮 Mejoras futuras

- Integración con IDS tipo NetGuardian (tu proyecto anterior) para superponer alertas de anomalías directamente sobre el mapa.
- Soporte IPv6.
- Perfil de "huella histórica" por dispositivo (cuándo apareció por primera vez, cambios de comportamiento a lo largo del tiempo).
- Detección automática de dispositivos "no autorizados" comparando contra una lista blanca definida por el usuario.

---

## 📄 Licencia

MIT — usa, modifica y comparte libremente citando la fuente. Recuerda: solo para redes propias o con autorización explícita.
