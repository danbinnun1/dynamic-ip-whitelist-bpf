import os
import subprocess
import tempfile
from scapy.all import Ether, IP, TCP, UDP, wrpcap


def run_filter(packets, orig_filter, ips):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_pcap:
        wrpcap(tmp_pcap.name, packets)
    fd, out_path = tempfile.mkstemp()
    os.close(fd)
    try:
        cmd = ['./filter', tmp_pcap.name, orig_filter, out_path] + ips
        subprocess.run(cmd, check=True)
        with open(out_path, 'rb') as f:
            data = f.read()
        return [b for b in data]
    finally:
        os.unlink(tmp_pcap.name)
        os.unlink(out_path)

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

def test_no_whitelist():
    packets = [
        Ether()/IP(src='4.4.4.4', dst='5.5.5.5')/TCP(),
        Ether()/IP(src='4.4.4.4', dst='5.5.5.5')/UDP(),
    ]
    result = run_filter(packets, 'tcp', [])
    assert result == [1, 0]
