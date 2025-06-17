import os
import subprocess
import tempfile
from scapy.all import Ether, IP, TCP, UDP, wrpcap


def run_filter(packets, orig_filter, ips):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
        wrpcap(tmp.name, packets)
    try:
        cmd = ['./filter', tmp.name, orig_filter] + ips
        result = subprocess.run(cmd, text=True, check=True, stdout=subprocess.PIPE)
        output = [int(line) for line in result.stdout.strip().splitlines()]
        return output
    finally:
        os.unlink(tmp.name)

def test_basic_whitelist():
    packets = [
        Ether()/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(),
        Ether()/IP(src='2.2.2.2', dst='2.2.2.2')/TCP(),
        Ether()/IP(src='3.3.3.3', dst='2.2.2.2')/TCP(),
        Ether()/IP(src='1.1.1.1', dst='2.2.2.2')/UDP(),
    ]
    result = run_filter(packets, 'tcp', ['1.1.1.1', '3.3.3.3'])
    assert result == [1, 0, 1, 0]

def test_many_ips():
    ips = [f'10.0.0.{i}' for i in range(1, 51)]
    packets = [Ether()/IP(src=ip, dst='8.8.8.8')/TCP() for ip in ips]
    packets.append(Ether()/IP(src='10.0.1.1', dst='8.8.8.8')/TCP())
    packets.append(Ether()/IP(src=ips[0], dst='8.8.8.8')/UDP())
    result = run_filter(packets, 'tcp', ips)
    expected = [1]*50 + [0] + [0]
    assert result == expected
