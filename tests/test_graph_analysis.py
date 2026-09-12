"""Pruebas del análisis de grafo (Fase 5)."""
from unittest.mock import patch

import graph_analysis as ga
from fusion_engine import Device, Relation


def _device(mac, device_type="unknown", vendor=None):
    return Device(mac=mac, ips={f"10.0.0.{mac[-1]}"}, vendor=vendor, device_type=device_type)


def _relation(src, dst, bytes_total=100, connections=1):
    return Relation(src_mac=src, dst_mac=dst, bytes_total=bytes_total, connections=connections)


def test_build_graph_creates_nodes_and_edges():
    devices = [_device("mac-1"), _device("mac-2")]
    relations = [_relation("mac-1", "mac-2", bytes_total=500, connections=3)]

    graph = ga.build_graph(devices, relations)

    assert set(graph.nodes) == {"mac-1", "mac-2"}
    assert graph.has_edge("mac-1", "mac-2")
    assert graph["mac-1"]["mac-2"]["bytes_total"] == 500
    assert graph["mac-1"]["mac-2"]["connections"] == 3


def test_build_graph_accumulates_duplicate_relations():
    devices = [_device("mac-1"), _device("mac-2")]
    relations = [
        _relation("mac-1", "mac-2", bytes_total=100, connections=1),
        _relation("mac-1", "mac-2", bytes_total=50, connections=2),
    ]

    graph = ga.build_graph(devices, relations)

    assert graph["mac-1"]["mac-2"]["bytes_total"] == 150
    assert graph["mac-1"]["mac-2"]["connections"] == 3


def test_build_graph_skips_self_loops():
    devices = [_device("mac-1")]
    relations = [_relation("mac-1", "mac-1")]

    graph = ga.build_graph(devices, relations)

    assert graph.number_of_edges() == 0


def test_detect_communities_empty_graph_returns_empty():
    graph = ga.build_graph([], [])
    assert ga.detect_communities(graph) == {}


def test_detect_communities_without_louvain_returns_zero_for_all():
    devices = [_device("mac-1"), _device("mac-2")]
    relations = [_relation("mac-1", "mac-2")]
    graph = ga.build_graph(devices, relations)

    with patch.object(ga, "_LOUVAIN_AVAILABLE", False):
        communities = ga.detect_communities(graph)

    assert communities == {"mac-1": 0, "mac-2": 0}


def test_detect_communities_separates_disconnected_clusters():
    # Dos triángulos densamente conectados entre sí, pero sin ninguna
    # arista entre los dos grupos -> deberían caer en comunidades distintas.
    devices = [_device(f"mac-{i}") for i in range(1, 7)]
    relations = [
        _relation("mac-1", "mac-2", connections=10),
        _relation("mac-2", "mac-3", connections=10),
        _relation("mac-1", "mac-3", connections=10),
        _relation("mac-4", "mac-5", connections=10),
        _relation("mac-5", "mac-6", connections=10),
        _relation("mac-4", "mac-6", connections=10),
    ]
    graph = ga.build_graph(devices, relations)

    communities = ga.detect_communities(graph)

    group_a = {communities["mac-1"], communities["mac-2"], communities["mac-3"]}
    group_b = {communities["mac-4"], communities["mac-5"], communities["mac-6"]}
    assert len(group_a) == 1
    assert len(group_b) == 1
    assert group_a != group_b


def test_compute_centrality_empty_graph():
    assert ga.compute_centrality(ga.build_graph([], [])) == {}


def test_compute_centrality_higher_for_bridge_node():
    # A-B-C y B-D: B es el único puente entre {A,C} y D.
    devices = [_device(m) for m in ("mac-a", "mac-b", "mac-c", "mac-d")]
    relations = [
        _relation("mac-a", "mac-b"),
        _relation("mac-b", "mac-c"),
        _relation("mac-b", "mac-d"),
    ]
    graph = ga.build_graph(devices, relations)

    centrality = ga.compute_centrality(graph)

    assert centrality["mac-b"] > centrality["mac-a"]
    assert centrality["mac-b"] > centrality["mac-d"]


def test_infer_layers_computes_hop_distance_from_root():
    devices = [_device(m) for m in ("gw", "mac-1", "mac-2")]
    relations = [_relation("gw", "mac-1"), _relation("mac-1", "mac-2")]
    graph = ga.build_graph(devices, relations)

    layers = ga.infer_layers(graph, root="gw")

    assert layers == {"gw": 0, "mac-1": 1, "mac-2": 2}


def test_infer_layers_uses_highest_degree_node_when_root_missing():
    devices = [_device(m) for m in ("mac-1", "mac-2", "mac-3")]
    relations = [_relation("mac-1", "mac-2"), _relation("mac-1", "mac-3")]
    graph = ga.build_graph(devices, relations)

    layers = ga.infer_layers(graph, root=None)

    assert layers["mac-1"] == 0  # mac-1 tiene grado 2, el más alto


def test_infer_layers_marks_unreachable_nodes_as_minus_one():
    devices = [_device(m) for m in ("mac-1", "mac-2", "mac-3")]
    relations = [_relation("mac-1", "mac-2")]  # mac-3 queda aislado
    graph = ga.build_graph(devices, relations)

    layers = ga.infer_layers(graph, root="mac-1")

    assert layers["mac-3"] == -1


def test_infer_layers_empty_graph():
    assert ga.infer_layers(ga.build_graph([], []), root="gw") == {}


def test_analyze_returns_all_expected_keys():
    devices = [_device("mac-1"), _device("mac-2")]
    relations = [_relation("mac-1", "mac-2")]

    result = ga.analyze(devices, relations, gateway_mac="mac-1")

    assert result["node_count"] == 2
    assert result["edge_count"] == 1
    assert set(result["communities"].keys()) == {"mac-1", "mac-2"}
    assert set(result["centrality"].keys()) == {"mac-1", "mac-2"}
    assert result["layers"] == {"mac-1": 0, "mac-2": 1}
