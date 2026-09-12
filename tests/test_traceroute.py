"""Pruebas del traceroute bajo demanda (mejora futura ya implementada)."""
from unittest.mock import MagicMock, patch

import traceroute as tr


def _fake_reply(src, icmp_type=11):
    reply = MagicMock()
    reply.src = src
    reply.haslayer.return_value = True
    icmp_layer = MagicMock(type=icmp_type)
    reply.__getitem__ = MagicMock(return_value=icmp_layer)
    return reply


def test_run_traceroute_stops_at_destination():
    target = "8.8.8.8"
    hop1 = _fake_reply("192.168.1.1", icmp_type=11)  # time exceeded, salto intermedio
    hop2 = _fake_reply(target, icmp_type=0)  # echo reply, llegó al destino

    with patch.object(tr, "sr1", side_effect=[hop1, hop2]):
        hops = tr.run_traceroute(target, max_hops=30, timeout=1)

    assert len(hops) == 2
    assert hops[0]["ip"] == "192.168.1.1"
    assert hops[1]["ip"] == target


def test_run_traceroute_records_timeouts_as_none():
    with patch.object(tr, "sr1", side_effect=[None, None]):
        hops = tr.run_traceroute("8.8.8.8", max_hops=2, timeout=1)

    assert hops == [
        {"ttl": 1, "ip": None, "rtt_ms": None},
        {"ttl": 2, "ip": None, "rtt_ms": None},
    ]


def test_run_traceroute_respects_max_hops_without_reaching_destination():
    hop = _fake_reply("10.0.0.1", icmp_type=11)

    with patch.object(tr, "sr1", return_value=hop):
        hops = tr.run_traceroute("8.8.8.8", max_hops=3, timeout=1)

    assert len(hops) == 3


def test_run_traceroute_raises_without_scapy():
    with patch.object(tr, "_SCAPY_AVAILABLE", False):
        try:
            tr.run_traceroute("8.8.8.8")
            assert False, "debería haber lanzado RuntimeError"
        except RuntimeError:
            pass
