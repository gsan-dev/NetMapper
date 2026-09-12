"""Pruebas de la captura pasiva y agregación por ventanas (Fase 3)."""
import time

from scapy.all import ARP, DNS, DNSQR, IP, UDP, Ether, IPv6, Raw

from passive_capture import (
    ArpWatcher,
    Edge,
    PacketObservation,
    PassiveCapture,
    WindowAggregator,
    parse_arp_packet,
    parse_packet,
)


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


def test_passive_capture_defaults_to_ip_only_filter():
    capture = PassiveCapture(interface="lo", window_seconds=10, on_window=lambda *a: None)
    assert capture.bpf_filter == "ip"


def test_passive_capture_uses_ip_or_arp_filter_when_arp_detection_enabled():
    capture = PassiveCapture(
        interface="lo",
        window_seconds=10,
        on_window=lambda *a: None,
        arp_spoof_detection_enabled=True,
    )
    assert capture.bpf_filter == "ip or arp"


def test_parse_arp_packet_extracts_ip_and_mac():
    pkt = Ether() / ARP(op=2, psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:01")
    claim = parse_arp_packet(pkt)

    assert claim is not None
    assert claim.ip == "192.168.1.10"
    assert claim.mac == "aa:bb:cc:dd:ee:01"


def test_parse_arp_packet_returns_none_for_non_arp():
    assert parse_arp_packet(Ether() / IP(src="10.0.0.5", dst="10.0.0.1")) is None


def test_arp_watcher_ignores_first_claim_and_repeated_claims():
    watcher = ArpWatcher()
    assert watcher.observe(_arp_claim("192.168.1.10", "aa:bb:cc:dd:ee:01")) is None
    assert watcher.observe(_arp_claim("192.168.1.10", "aa:bb:cc:dd:ee:01")) is None


def test_arp_watcher_flags_ip_claimed_by_different_mac():
    watcher = ArpWatcher()
    watcher.observe(_arp_claim("192.168.1.10", "aa:bb:cc:dd:ee:01"))

    alert = watcher.observe(_arp_claim("192.168.1.10", "ff:ff:ff:ff:ff:ff"), now=123.0)

    assert alert is not None
    assert alert.ip == "192.168.1.10"
    assert alert.known_mac == "aa:bb:cc:dd:ee:01"
    assert alert.new_mac == "ff:ff:ff:ff:ff:ff"
    assert alert.detected_at == 123.0


def _arp_claim(ip, mac):
    from passive_capture import ArpClaim

    return ArpClaim(ip=ip, mac=mac)


def test_passive_capture_reports_arp_spoof_alert_via_callback():
    alerts_received = []
    capture = PassiveCapture(
        interface="lo",
        window_seconds=10,
        on_window=lambda *a: None,
        arp_spoof_detection_enabled=True,
        on_arp_spoof_alert=alerts_received.append,
    )

    claim_pkt = Ether() / ARP(op=2, psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:01")
    spoof_pkt = Ether() / ARP(op=2, psrc="192.168.1.10", hwsrc="ff:ff:ff:ff:ff:ff")

    capture._handle_packet(claim_pkt)
    capture._handle_packet(spoof_pkt)

    assert len(alerts_received) == 1
    assert alerts_received[0].known_mac == "aa:bb:cc:dd:ee:01"
    assert alerts_received[0].new_mac == "ff:ff:ff:ff:ff:ff"


def test_passive_capture_skips_arp_watching_when_disabled():
    capture = PassiveCapture(interface="lo", window_seconds=10, on_window=lambda *a: None)
    pkt = Ether() / ARP(op=2, psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:01")

    capture._handle_packet(pkt)  # no debe lanzar aunque no haya watcher activo

    assert capture._arp_watcher is None
