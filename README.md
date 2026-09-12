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
11. [Testing](#-testing)
12. [Mejoras futuras](#-mejoras-futuras)
13. [Licencia](#-licencia)

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

```
netmapper/
├── README.md
├── .gitignore
├── docker-compose.yml
├── discovery/
│   ├── network_discovery.py   # Fase 0
│   ├── host_discovery.py      # Fase 1
│   ├── device_fingerprint.py  # Fase 2
│   ├── passive_capture.py     # Fase 3
│   ├── fusion_engine.py       # Fase 4
│   └── requirements.txt
├── analysis/
│   ├── graph_analysis.py      # Fase 5
│   └── requirements.txt
├── backend/
│   ├── main.py
│   ├── routes/
│   │   ├── networks.py
│   │   ├── devices.py
│   │   └── ws.py
│   ├── db.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── NetworkGraph.jsx
│   │   │   ├── FilterPanel.jsx
│   │   │   └── TimelapseControls.jsx
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── data/
│   └── oui_database.txt        # base de datos de fabricantes por MAC
├── tests/
│   ├── test_network_discovery.py
│   ├── test_fusion_engine.py
│   └── test_graph_analysis.py
└── docs/
    └── capturas/
```

---

## 🗺️ Roadmap y plan de commits

### Fase 0 — Setup
- [ ] `chore: inicializar repositorio con estructura de carpetas`
- [ ] `chore: .gitignore, README inicial y licencia`
- [ ] `chore: aviso legal de uso responsable en el README`

### Fase 1 — Descubrimiento de redes
- [ ] `feat: enumerar interfaces locales y calcular CIDR con netifaces`
- [ ] `feat: parseo de la tabla de rutas del sistema con pyroute2`
- [ ] `feat: consulta SNMP a routers/switches gestionables`
- [ ] `test: pruebas del módulo network_discovery`

### Fase 2 — Descubrimiento de hosts
- [ ] `feat: ARP scanning para redes directamente conectadas`
- [ ] `feat: escaneo asíncrono ICMP/TCP para redes remotas`
- [ ] `perf: paralelización del escaneo por subred`

### Fase 3 — Caracterización de dispositivos
- [ ] `feat: lookup de fabricante por MAC (OUI)`
- [ ] `feat: port scanning selectivo y detección de banners`
- [ ] `feat: escucha pasiva de mDNS/UPnP`
- [ ] `feat: motor de reglas para inferir tipo de dispositivo`

### Fase 4 — Descubrimiento pasivo
- [ ] `feat: captura de tráfico y agregación por ventanas`
- [ ] `feat: extracción de relaciones origen-destino`
- [ ] `feat: análisis de consultas DNS por dispositivo`

### Fase 5 — Fusión y análisis de grafo
- [ ] `feat: motor de fusión de datos multi-fuente`
- [ ] `feat: deduplicación y resolución de conflictos por MAC`
- [ ] `feat: detección de comunidades (Louvain)`
- [ ] `feat: cálculo de centralidad e inferencia de capas`
- [ ] `test: pruebas del motor de fusión y análisis de grafo`

### Fase 6 — Persistencia y backend
- [ ] `feat: modelo de grafo en Neo4j`
- [ ] `feat: endpoints REST (/networks, /devices, /graph)`
- [ ] `feat: WebSocket para actualizaciones en vivo`

### Fase 7 — Frontend
- [ ] `feat: scaffold de React + Vite`
- [ ] `feat: renderizado del grafo con Cytoscape.js`
- [ ] `feat: filtros por subred y por capa jerárquica`
- [ ] `feat: modo time-lapse de evolución de topología`
- [ ] `feat: exportación del mapa (imagen/diagrama)`
- [ ] `style: pulido visual del panel`

### Fase 8 — Dockerización y cierre
- [ ] `feat: Dockerfile por servicio + docker-compose.yml`
- [ ] `docs: capturas de pantalla y resultados`
- [ ] `chore: limpieza final y revisión de código`

---

## ⚙️ Guía de instalación

### Requisitos previos

- Python 3.11+
- Node.js 18+
- Docker y docker-compose
- Neo4j (o usar la imagen oficial vía Docker)
- Permisos de administrador/root (necesarios para ARP scanning y captura de tráfico)
- Acceso de gestión (SNMP/API) al router, opcional pero recomendado para mejor precisión

### 1. Clonar el repositorio

```bash
git clone https://github.com/TU-USUARIO/netmapper.git
cd netmapper
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

Crea un archivo `.env` en la raíz:

```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=tu_password
SNMP_COMMUNITY=public
SCAN_INTERVAL_SECONDS=300
ALLOWED_NETWORKS=192.168.0.0/24,192.168.1.0/24,10.0.0.0/24,172.26.0.0/24
```

> `ALLOWED_NETWORKS` es intencional: aunque el programa detecte más redes automáticamente, solo escaneará activamente las que hayas autorizado explícitamente aquí. Es tu "lista blanca" de seguridad.

---

## 🚀 Pasos a seguir para ejecutarlo

### Paso 1 — Levantar Neo4j

```bash
docker run -d --name netmapper-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/tu_password \
  neo4j:5
```

### Paso 2 — Ejecutar el motor de descubrimiento (una vez, para validar)

```bash
cd discovery
sudo python3 network_discovery.py
```

Esto debería imprimir por consola la lista de subredes detectadas (locales, por tabla de rutas, y por router si está configurado SNMP). Revisa que coincide con lo que esperas antes de continuar.

### Paso 3 — Lanzar el pipeline completo de escaneo

```bash
sudo python3 main.py --continuous
```

El flag `--continuous` deja el escaneo corriendo en bucle cada `SCAN_INTERVAL_SECONDS`, alimentando Neo4j con cada pasada.

### Paso 4 — Levantar el backend

```bash
cd backend
uvicorn main:app --reload --port 8000
```

### Paso 5 — Levantar el frontend

```bash
cd frontend
npm run dev
```

Accede al panel en `http://localhost:5173`.

### Paso 6 (alternativa recomendada) — Todo junto con Docker

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
- **Exportar**: botón para descargar el mapa actual como PNG o como archivo compatible con draw.io.

---

## 🧪 Testing

```bash
cd discovery && pytest tests/
cd ../analysis && pytest tests/
cd ../backend && pytest tests/
```

---

## 🔮 Mejoras futuras

- Integración con IDS tipo NetGuardian (tu proyecto anterior) para superponer alertas de anomalías directamente sobre el mapa.
- Soporte IPv6.
- Perfil de "huella histórica" por dispositivo (cuándo apareció por primera vez, cambios de comportamiento a lo largo del tiempo).
- Detección automática de dispositivos "no autorizados" comparando contra una lista blanca definida por el usuario.

---

## 📄 Licencia

MIT — usa, modifica y comparte libremente citando la fuente. Recuerda: solo para redes propias o con autorización explícita.
