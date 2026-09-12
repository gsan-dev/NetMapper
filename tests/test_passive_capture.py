"""Pruebas de la captura pasiva y agregación por ventanas (Fase 3)."""
import time

from scapy.all import DNS, DNSQR, IP, UDP, Ether, IPv6, Raw

from passive_capture import Edge, PacketObservation, PassiveCapture, WindowAggregator, parse_packet


def test_parse_packet_plain_ip():
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / Raw(b"x" * 50)
    obs = parse_packet(pkt)

    assert obs is not None
    assert obs.src_ip == "10.0.0.5"
    assert obs.dst_ip == "10.0.0.1"
    assert obs.length > 50
    assert obs.dns_query is None


def test_parse_packet_plain_ipv6():
    # Ether con src/dst explícitos: sin ellos, scapy intenta resolver la
    # interfaz de salida para un destino IPv6 (para autocompletar la MAC),
    # lo que falla en máquinas sin una ruta IPv6 real configurada.
    eth = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
    pkt = eth / IPv6(src="2001:db8::10", dst="2001:db8::1") / Raw(b"x" * 50)
    obs = parse_packet(pkt)

    assert obs is not None
    assert obs.src_ip == "2001:db8::10"
    assert obs.dst_ip == "2001:db8::1"
    assert obs.length > 50


def test_parse_packet_extracts_dns_query():
    pkt = (
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.1")
        / UDP(sport=51000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    obs = parse_packet(pkt)

    assert obs is not None
    assert obs.dns_query == "example.com"


def test_parse_packet_ignores_dns_responses():
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.5")
        / UDP(sport=53, dport=51000)
        / DNS(qr=1, qd=DNSQR(qname="example.com"), an=[])
    )
    obs = parse_packet(pkt)

    assert obs is not None
    assert obs.dns_query is None


def test_parse_packet_non_ip_returns_none():
    assert parse_packet(Ether()) is None


def test_window_aggregator_accumulates_edges_and_dns():
    aggregator = WindowAggregator(window_seconds=10)

    aggregator.add(PacketObservation(src_ip="10.0.0.5", dst_ip="10.0.0.1", length=100))
    aggregator.add(PacketObservation(src_ip="10.0.0.5", dst_ip="10.0.0.1", length=200))
    aggregator.add(
        PacketObservation(
            src_ip="10.0.0.5", dst_ip="8.8.8.8", length=60, dns_query="example.com"
        )
    )

    assert len(aggregator) == 2  # dos pares (src,dst) distintos

    start, end, edges, dns = aggregator.flush(now=aggregator._window_start + 11)
    edges_by_key = {e.key: e for e in edges}

    assert edges_by_key[("10.0.0.5", "10.0.0.1")].bytes_total == 300
    assert edges_by_key[("10.0.0.5", "10.0.0.1")].connections == 2
    assert dns == {"10.0.0.5": {"example.com": 1}}
    assert len(aggregator) == 0  # se reinicia tras el flush


def test_window_aggregator_should_flush():
    aggregator = WindowAggregator(window_seconds=10)
    assert aggregator.should_flush(now=aggregator._window_start + 5) is False
    assert aggregator.should_flush(now=aggregator._window_start + 11) is True


def test_passive_capture_handle_packet_feeds_aggregator():
    windows_received = []

    def on_window(start, end, edges, dns):
        windows_received.append(edges)

    capture = PassiveCapture(interface="lo", window_seconds=10, on_window=on_window)
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / Raw(b"x" * 10)

    capture._handle_packet(pkt)
    capture._handle_packet(pkt)

    assert len(capture.aggregator) == 1
