#!/usr/bin/env python3
import logging
from scapy.all import IP, ICMP, TCP, UDP, sr, conf

conf.verb = 0


def craft_discovery_pkts(protocols, ip_range, pkt_count=None, port=80):
    if isinstance(protocols, str):
        protocols = [protocols]

    if pkt_count is None:
        pkt_count = {}

    all_packets = []

    for proto in protocols:
        proto = proto.upper()

        num_packets = pkt_count.get(proto, 1)

        for _ in range(num_packets):

            if proto == "ICMP":               
                pkt = IP(dst=ip_range) / ICMP(type=13, code=0)
                all_packets.append(pkt)

            elif proto == "TCP":               
                pkt = IP(dst=ip_range) / TCP(dport=port, flags="A")
                all_packets.append(pkt)

            elif proto == "UDP":
                pkt = IP(dst=ip_range) / UDP(dport=port)
                all_packets.append(pkt)

            else:
                print(f"[!] Protocolo no reconocido: '{proto}'. Se ignora.")

    return all_packets


def find_active_hosts(protocols, ip_range, pkt_count=None, port=80, timeout=2):


    print(f"[*] Construyendo paquetes para el rango: {ip_range}")
    packets = craft_discovery_pkts(protocols, ip_range, pkt_count, port)
    print(f"[*] Total de paquetes construidos: {len(packets)}")
    print(f"[*] Enviando y esperando respuestas (timeout={timeout}s)...\n")

    active_ips = []

    for pkt in packets:

        answered, unanswered = sr(pkt, timeout=timeout, verbose=0)

        for sent, received in answered:
            src_ip = received[IP].src

            if src_ip not in active_ips:
                active_ips.append(src_ip)
                print(f"[+] Host activo detectado: {src_ip}")

        if len(unanswered) > 0 and len(answered) == 0:
            dst = pkt[IP].dst
            proto_name = pkt.lastlayer().__class__.__name__
            print(f"[-] Sin respuesta de {dst} con protocolo {proto_name}")

    return active_ips


if __name__ == "__main__":
   

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    print("=" * 55)
    print("     Descubrimiento de Hosts con Scapy")
    print("     Práctica 2 - Reconocimiento Activo")
    print("=" * 55)
    print()

    targets = ["172.20.0.1", "172.20.0.2", "172.20.0.3"]
    protocols_list = ["ICMP", "TCP", "UDP"]
    scan_port = 80

    print(f"[*] Targets: {targets}")
    print(f"[*] Protocolos: {protocols_list}")
    print(f"[*] Puerto L4: {scan_port}")
    print()

    active = []
    for ip in targets:
        hosts = find_active_hosts(
            protocols=protocols_list,
            ip_range=ip,
            port=scan_port,
            timeout=2,
        )
        active.extend(hosts)

    print()
    print("=" * 55)
    print(f"  Resumen: {len(active)} host(s) activo(s)")
    print("=" * 55)
    for ip in active:
        print(f"  -> {ip}")
    print()

    print("[*] Probando con una IP que no debería estar activa...")
    inactive_test = "172.20.0.200"
    pkts_inactivo = craft_discovery_pkts(["ICMP", "TCP"], inactive_test, port=80)
    for pkt in pkts_inactivo:
        answered, _ = sr(pkt, timeout=2, verbose=0)
        proto_name = pkt.lastlayer().__class__.__name__
        if answered:
            print(f"[+] Respuesta inesperada de {inactive_test}!")
        else:
            print(f"[-] {inactive_test} no responde a {proto_name} -> Host inactivo")