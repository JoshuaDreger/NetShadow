import ipaddress
from scapy.all import rdpcap, IP, IPv6


_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def _is_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS) or addr.is_link_local or addr.is_multicast
    except ValueError:
        return True


def extract_external_ips(pcap_path: str) -> list[str]:
    packets = rdpcap(pcap_path)
    seen = set()
    for pkt in packets:
        for layer in (IP, IPv6):
            if pkt.haslayer(layer):
                for addr in (pkt[layer].src, pkt[layer].dst):
                    if not _is_internal(addr):
                        seen.add(addr)
    return sorted(seen)
