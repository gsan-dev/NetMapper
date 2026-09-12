"""Análisis de grafo (Fase 5).

Sobre el grafo ya fusionado (dispositivos + relaciones de
`fusion_engine`), calcula tres cosas que el frontend usa para que el
mapa no sea una maraña plana:

- **Detección de comunidades** (Louvain): agrupa automáticamente
  dispositivos que interactúan mucho entre sí.
- **Centralidad de intermediación**: identifica qué nodos son puntos
  críticos de la red (si caen, fragmentan la conectividad).
- **Inferencia de capas**: nº de saltos desde un nodo raíz (típicamente
  el gateway), para poder dibujar el mapa en niveles jerárquicos
  (core -> distribución -> acceso).
"""
from __future__ import annotations

import logging
from typing import Any

import networkx as nx

logger = logging.getLogger("netmapper.graph_analysis")

try:
    import community as community_louvain

    _LOUVAIN_AVAILABLE = True
except ImportError:  # pragma: no cover
    community_louvain = None
    _LOUVAIN_AVAILABLE = False


def build_graph(devices: list, relations: list) -> nx.Graph:
    """Construye un grafo no dirigido de NetworkX a partir de Device/Relation.

    Las relaciones duplicadas (mismo par de nodos, reportadas en
    llamadas distintas) se acumulan en vez de sobrescribirse.
    """
    graph = nx.Graph()
    for device in devices:
        graph.add_node(
            device.mac,
            vendor=device.vendor,
            device_type=device.device_type,
            ips=sorted(device.ips),
        )

    for relation in relations:
        if relation.src_mac == relation.dst_mac:
            continue  # un dispositivo no puede ser su propio vecino en el mapa
        if graph.has_edge(relation.src_mac, relation.dst_mac):
            edge = graph[relation.src_mac][relation.dst_mac]
            edge["bytes_total"] += relation.bytes_total
            edge["connections"] += relation.connections
        else:
            graph.add_edge(
                relation.src_mac,
                relation.dst_mac,
                bytes_total=relation.bytes_total,
                connections=relation.connections,
            )

    return graph


def detect_communities(graph: nx.Graph) -> dict[str, int]:
    """Devuelve {mac: id_de_comunidad} usando el algoritmo de Louvain."""
    if graph.number_of_nodes() == 0:
        return {}
    if not _LOUVAIN_AVAILABLE:
        logger.warning("python-louvain no disponible; se omite la detección de comunidades")
        return dict.fromkeys(graph.nodes, 0)
    try:
        return community_louvain.best_partition(graph, weight="connections")
    except Exception:
        logger.exception("Error detectando comunidades")
        return dict.fromkeys(graph.nodes, 0)


def compute_centrality(graph: nx.Graph) -> dict[str, float]:
    """Centralidad de intermediación (betweenness) de cada nodo."""
    if graph.number_of_nodes() == 0:
        return {}
    return nx.betweenness_centrality(graph, weight=None)


def infer_layers(graph: nx.Graph, root: str | None) -> dict[str, int]:
    """Nº de saltos desde `root` (típicamente el gateway) para cada nodo.

    Si no se conoce la raíz (o no está en el grafo), se usa el nodo de
    mayor grado como pseudo-raíz. Los nodos en otro componente conexo
    (no alcanzables desde la raíz) reciben la capa -1 en vez de fallar.
    """
    if graph.number_of_nodes() == 0:
        return {}

    if root is None or root not in graph:
        root = max(graph.degree, key=lambda item: item[1])[0]

    lengths = nx.single_source_shortest_path_length(graph, root)
    return {node: lengths.get(node, -1) for node in graph.nodes}


def analyze(devices: list, relations: list, gateway_mac: str | None = None) -> dict[str, Any]:
    """Pipeline completo: construye el grafo y calcula las tres métricas."""
    graph = build_graph(devices, relations)

    return {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "communities": detect_communities(graph),
        "centrality": compute_centrality(graph),
        "layers": infer_layers(graph, gateway_mac),
    }
