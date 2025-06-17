import os
import subprocess
import tempfile
import pytest
from scapy.all import Ether, IP, TCP, UDP, wrpcap
from scapy.layers.tls.all import TLS, TLSClientHello


def run_filter(packet, orig_filter, ips):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_pcap:
        wrpcap(tmp_pcap.name, [packet])
    try:
        cmd = ['./filter', tmp_pcap.name, orig_filter] + ips
        proc = subprocess.run(cmd)
        return 1 if proc.returncode == 0 else 0
    finally:
        os.unlink(tmp_pcap.name)


@pytest.mark.parametrize(
    "packets,orig_filter,ips,expected",
    [
        (
            [
                Ether()/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(),
                Ether()/IP(src='2.2.2.2', dst='2.2.2.2')/TCP(),
                Ether()/IP(src='3.3.3.3', dst='2.2.2.2')/TCP(),
                Ether()/IP(src='1.1.1.1', dst='2.2.2.2')/UDP(),
            ],
            'tcp',
            ['1.1.1.1', '3.3.3.3'],
            [1, 0, 1, 0],
        ),
        (
            [
                *[Ether()/IP(src=f'10.0.0.{i}', dst='8.8.8.8')/TCP() for i in range(1, 51)],
                Ether()/IP(src='10.0.1.1', dst='8.8.8.8')/TCP(),
                Ether()/IP(src='10.0.0.1', dst='8.8.8.8')/UDP(),
            ],
            'tcp',
            [f'10.0.0.{i}' for i in range(1, 51)],
            [1]*50 + [0, 0],
        ),
        (
            [
                Ether()/IP(src='4.4.4.4', dst='5.5.5.5')/TCP(),
                Ether()/IP(src='4.4.4.4', dst='5.5.5.5')/UDP(),
            ],
            'tcp',
            [],
            [0, 0],
        ),
        (
            [
                Ether()/IP(src='1.1.1.1', dst='2.2.2.2')/
                TCP(dport=443)/TLS()/TLSClientHello(),
                Ether()/IP(src='2.2.2.2', dst='2.2.2.2')/
                TCP(dport=443)/TLS()/TLSClientHello(),
                Ether()/IP(src='1.1.1.1', dst='2.2.2.2')/UDP(dport=443),
            ],
            'tcp port 443',
            ['1.1.1.1'],
            [1, 0, 0],
        ),
    ],
)
def test_whitelist(packets, orig_filter, ips, expected):
    result = [run_filter(pkt, orig_filter, ips) for pkt in packets]
    assert result == expected

