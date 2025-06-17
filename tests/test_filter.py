import os
import subprocess
import tempfile
from scapy.all import Ether, IP, TCP, UDP, wrpcap


def run_filter(packets, orig_filter, ips, expect_code=0):
    """Run the compiled filter binary and return its stdout lines.

    Parameters
    ----------
    packets : list
        Packets to write to a temporary pcap file.
    orig_filter : str
        libpcap filter expression.
    ips : list[str]
        Whitelisted IP addresses.
    expect_code : int, optional
        Expected process return code.  The default is 0.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
        wrpcap(tmp.name, packets)
    try:
        cmd = ['./filter', tmp.name, orig_filter] + ips
        result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        assert result.returncode == expect_code, result.stderr
        return [int(line) for line in result.stdout.strip().splitlines() if line]
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


def test_invalid_ip():
    packets = [Ether()/IP(src='1.1.1.1', dst='2.2.2.2')/TCP()]
    run_filter(packets, 'tcp', ['bad.ip'], expect_code=3)


def test_missing_args():
    # invoke without whitelist IPs
    packets = [Ether()/IP(src='1.1.1.1', dst='2.2.2.2')/TCP()]
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
        wrpcap(tmp.name, packets)
    try:
        cmd = ['./filter', tmp.name, 'tcp']
        result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        assert result.returncode == 1
    finally:
        os.unlink(tmp.name)


def test_too_many_ips():
    ips = [f'192.168.0.{i}' for i in range(0, 256)]
    packets = [Ether()/IP(src=ips[0], dst='1.1.1.1')/TCP()]
    run_filter(packets, 'tcp', ips, expect_code=4)
