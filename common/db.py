"""Capa de acceso a datos de NetMapper.

Define una interfaz abstracta (`Repository`) para que discovery/analysis
y backend no dependan del motor de base de datos concreto. Hoy solo
hay una implementación real (`SQLiteRepository`); `Neo4jRepository`
queda como stub explícito para cuando se quiera dar el salto a un
grafo real con Cypher (ver Mejoras futuras en el README) sin tocar el
resto del código.

Se usa sqlite3 puro (sin ORM): cada operación abre y cierra su propia
conexión de corta vida, seguro para acceso concurrente desde varios
procesos (el pipeline de discovery/analysis + el backend) en el
volumen de datos de un homelab.
"""
from __future__ import annotations

import json
import sqlite3
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    discovery_method TEXT NOT NULL,
    interface TEXT,
    gateway TEXT,
    reachable INTEGER NOT NULL DEFAULT 1,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL UNIQUE,
    ips TEXT NOT NULL DEFAULT '[]',
    vendor TEXT,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    open_ports TEXT NOT NULL DEFAULT '[]',
    mdns_services TEXT NOT NULL DEFAULT '[]',
    dns_queries TEXT NOT NULL DEFAULT '{}',
    subnet_cidrs TEXT NOT NULL DEFAULT '[]',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_mac TEXT NOT NULL,
    dst_mac TEXT NOT NULL,
    bytes_total INTEGER NOT NULL DEFAULT 0,
    connections INTEGER NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL,
    UNIQUE(src_mac, dst_mac)
);
CREATE INDEX IF NOT EXISTS idx_relations_src ON relations(src_mac);

CREATE TABLE IF NOT EXISTS graph_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    node_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    communities TEXT NOT NULL,
    centrality TEXT NOT NULL,
    layers TEXT NOT NULL,
    devices TEXT NOT NULL DEFAULT '[]',
    relations TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_graph_snapshots_created_at ON graph_snapshots(created_at);
"""


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


def _device_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["ips"] = json.loads(d["ips"])
    d["open_ports"] = json.loads(d["open_ports"])
    d["mdns_services"] = json.loads(d["mdns_services"])
    d["dns_queries"] = json.loads(d["dns_queries"])
    d["subnet_cidrs"] = json.loads(d["subnet_cidrs"])
    return d


class Repository(ABC):
    """Interfaz de persistencia independiente del motor de base de datos."""

    @abstractmethod
    def init_schema(self) -> None: ...

    @abstractmethod
    def upsert_network(self, network: dict[str, Any]) -> int: ...

    @abstractmethod
    def list_networks(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def upsert_device(self, device: dict[str, Any]) -> int: ...

    @abstractmethod
    def mark_stale_devices_inactive(self, active_macs: set[str]) -> None: ...

    @abstractmethod
    def list_devices(self, active_only: bool = True) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_device_by_mac(self, mac: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def upsert_relation(self, relation: dict[str, Any]) -> int: ...

    @abstractmethod
    def list_relations(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def insert_graph_snapshot(self, snapshot: dict[str, Any]) -> int: ...

    @abstractmethod
    def list_graph_snapshots(self, limit: int = 50) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_latest_graph_snapshot(self) -> dict[str, Any] | None: ...


class SQLiteRepository(Repository):
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # --- Redes ---

    def upsert_network(self, network: dict[str, Any]) -> int:
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO networks (cidr, discovery_method, interface, gateway, reachable, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cidr) DO UPDATE SET
                    discovery_method = excluded.discovery_method,
                    interface = COALESCE(excluded.interface, networks.interface),
                    gateway = COALESCE(excluded.gateway, networks.gateway),
                    reachable = excluded.reachable,
                    last_seen = excluded.last_seen
                """,
                (
                    network["cidr"],
                    network["discovery_method"],
                    network.get("interface"),
                    network.get("gateway"),
                    int(network.get("reachable", True)),
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT id FROM networks WHERE cidr = ?", (network["cidr"],)
            ).fetchone()
            return row["id"]

    def list_networks(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM networks ORDER BY cidr").fetchall()
            return [_row_to_dict(r) for r in rows]

    # --- Dispositivos ---

    def upsert_device(self, device: dict[str, Any]) -> int:
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO devices (
                    mac, ips, vendor, device_type, open_ports, mdns_services,
                    dns_queries, subnet_cidrs, first_seen, last_seen, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(mac) DO UPDATE SET
                    ips = excluded.ips,
                    vendor = COALESCE(excluded.vendor, devices.vendor),
                    device_type = excluded.device_type,
                    open_ports = excluded.open_ports,
                    mdns_services = excluded.mdns_services,
                    dns_queries = excluded.dns_queries,
                    subnet_cidrs = excluded.subnet_cidrs,
                    last_seen = excluded.last_seen,
                    active = 1
                """,
                (
                    device["mac"],
                    json.dumps(sorted(device.get("ips", []))),
                    device.get("vendor"),
                    device.get("device_type", "unknown"),
                    json.dumps(sorted(device.get("open_ports", []))),
                    json.dumps(sorted(device.get("mdns_services", []))),
                    json.dumps(device.get("dns_queries", {})),
                    json.dumps(sorted(device.get("subnet_cidrs", []))),
                    device.get("first_seen", now),
                    device.get("last_seen", now),
                ),
            )
            row = conn.execute(
                "SELECT id FROM devices WHERE mac = ?", (device["mac"],)
            ).fetchone()
            return row["id"]

    def mark_stale_devices_inactive(self, active_macs: set[str]) -> None:
        with self._connect() as conn:
            rows = conn.execute("SELECT mac FROM devices WHERE active = 1").fetchall()
            stale = [r["mac"] for r in rows if r["mac"] not in active_macs]
            if stale:
                conn.executemany(
                    "UPDATE devices SET active = 0 WHERE mac = ?", [(m,) for m in stale]
                )

    def list_devices(self, active_only: bool = True) -> list[dict[str, Any]]:
        query = "SELECT * FROM devices"
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY last_seen DESC"
        with self._connect() as conn:
            return [_device_row_to_dict(r) for r in conn.execute(query).fetchall()]

    def get_device_by_mac(self, mac: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            return _device_row_to_dict(row) if row else None

    # --- Relaciones ---

    def upsert_relation(self, relation: dict[str, Any]) -> int:
        """Reemplaza bytes_total/connections con el valor acumulado actual.

        El motor de fusión ya mantiene el acumulado en memoria durante
        la vida del proceso; aquí solo se persiste el snapshot más
        reciente, no se vuelve a sumar.
        """
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO relations (src_mac, dst_mac, bytes_total, connections, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(src_mac, dst_mac) DO UPDATE SET
                    bytes_total = excluded.bytes_total,
                    connections = excluded.connections,
                    last_seen = excluded.last_seen
                """,
                (
                    relation["src_mac"],
                    relation["dst_mac"],
                    relation.get("bytes_total", 0),
                    relation.get("connections", 0),
                    now,
                ),
            )
            row = conn.execute(
                "SELECT id FROM relations WHERE src_mac = ? AND dst_mac = ?",
                (relation["src_mac"], relation["dst_mac"]),
            ).fetchone()
            return row["id"]

    def list_relations(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM relations ORDER BY bytes_total DESC").fetchall()
            return [_row_to_dict(r) for r in rows]

    # --- Snapshots del análisis de grafo (para el modo time-lapse) ---

    def insert_graph_snapshot(self, snapshot: dict[str, Any]) -> int:
        """Persiste una pasada de análisis completa, incluyendo la propia
        topología (devices/relations) en ese momento — no solo las
        métricas — para que el modo time-lapse del frontend pueda
        reconstruir cómo era el mapa en cualquier punto del histórico.
        """
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO graph_snapshots (
                    created_at, node_count, edge_count, communities, centrality,
                    layers, devices, relations
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.get("created_at", time.time()),
                    snapshot["node_count"],
                    snapshot["edge_count"],
                    json.dumps(snapshot.get("communities", {})),
                    json.dumps(snapshot.get("centrality", {})),
                    json.dumps(snapshot.get("layers", {})),
                    json.dumps(snapshot.get("devices", [])),
                    json.dumps(snapshot.get("relations", [])),
                ),
            )
            return cur.lastrowid

    def _snapshot_row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["communities"] = json.loads(d["communities"])
        d["centrality"] = json.loads(d["centrality"])
        d["layers"] = json.loads(d["layers"])
        d["devices"] = json.loads(d["devices"])
        d["relations"] = json.loads(d["relations"])
        return d

    def list_graph_snapshots(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM graph_snapshots ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [self._snapshot_row_to_dict(r) for r in reversed(rows)]

    def get_latest_graph_snapshot(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM graph_snapshots ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            return self._snapshot_row_to_dict(row) if row else None


class Neo4jRepository(Repository):
    """Stub para la mejora futura: migrar a Neo4j para un modelo de grafo real.

    Cuando se quiera dar el salto, esta clase debe implementar la misma
    interfaz `Repository` usando el driver oficial `neo4j`, modelando
    cada Device como un nodo `(:Device {mac, vendor, device_type, ...})`
    y cada Relation como una relación `[:COMMUNICATES_WITH {bytes_total,
    connections}]` — de modo que discovery/analysis/backend no cambien
    ni una línea.
    """

    def __init__(self, uri: str, user: str, password: str):
        self.uri = uri
        self.user = user
        self.password = password

    def _not_implemented(self) -> None:
        raise NotImplementedError(
            "Neo4jRepository todavía no está implementado. Configura "
            "DB_BACKEND=sqlite en .env mientras tanto (ver Mejoras futuras en el README)."
        )

    def init_schema(self) -> None:
        self._not_implemented()

    def upsert_network(self, network: dict[str, Any]) -> int:
        self._not_implemented()

    def list_networks(self) -> list[dict[str, Any]]:
        self._not_implemented()

    def upsert_device(self, device: dict[str, Any]) -> int:
        self._not_implemented()

    def mark_stale_devices_inactive(self, active_macs: set[str]) -> None:
        self._not_implemented()

    def list_devices(self, active_only: bool = True) -> list[dict[str, Any]]:
        self._not_implemented()

    def get_device_by_mac(self, mac: str) -> dict[str, Any] | None:
        self._not_implemented()

    def upsert_relation(self, relation: dict[str, Any]) -> int:
        self._not_implemented()

    def list_relations(self) -> list[dict[str, Any]]:
        self._not_implemented()

    def insert_graph_snapshot(self, snapshot: dict[str, Any]) -> int:
        self._not_implemented()

    def list_graph_snapshots(self, limit: int = 50) -> list[dict[str, Any]]:
        self._not_implemented()

    def get_latest_graph_snapshot(self) -> dict[str, Any] | None:
        self._not_implemented()


_repository_singleton: Repository | None = None


def get_repository() -> Repository:
    """Factoría: devuelve la implementación de Repository según DB_BACKEND."""
    global _repository_singleton
    if _repository_singleton is not None:
        return _repository_singleton

    from common.config import settings  # import diferido para evitar ciclos

    if settings.db_backend == "neo4j":
        repo: Repository = Neo4jRepository(
            uri=settings.neo4j_uri, user=settings.neo4j_user, password=settings.neo4j_password
        )
    else:
        repo = SQLiteRepository(settings.db_path_absolute)
        repo.init_schema()

    _repository_singleton = repo
    return repo
