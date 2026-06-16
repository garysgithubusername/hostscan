"""Unit tests for hostscan parsing and validation (no real network scans)."""

import pytest

import hostscan


SAMPLE_OUTPUT = """\
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0021s latency).
Nmap scan report for 192.168.1.42
Host is up (0.015s latency).
Nmap scan report for laptop.local (192.168.1.50)
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.51 seconds
"""


def test_parse_hosts_counts_and_extracts():
    hosts = hostscan.parse_hosts(SAMPLE_OUTPUT)
    assert len(hosts) == 3
    assert hosts[0].address == "192.168.1.1"
    assert hosts[0].hostname == "router.local"
    assert hosts[1].address == "192.168.1.42"
    assert hosts[1].hostname is None
    assert hosts[2].address == "192.168.1.50"
    assert hosts[2].hostname == "laptop.local"


def test_parse_hosts_empty():
    assert hostscan.parse_hosts("Nmap done: 0 hosts up\n") == []


@pytest.mark.parametrize(
    "target",
    ["192.168.1.0/24", "10.0.0.5", "192.168.1.1-50", "127.0.0.1", "::1"],
)
def test_validate_target_accepts_valid(target):
    assert hostscan.validate_target(target) == target


@pytest.mark.parametrize(
    "target",
    [
        "",
        "192.168.1.1; rm -rf /",
        "google.com",
        "not an ip",
        "10.0.0.0/99",
        "10.0.0.250-260",  # octet > 255
        "10.0.0.50-2",  # end < start
    ],
)
def test_validate_target_rejects_invalid(target):
    with pytest.raises(ValueError):
        hostscan.validate_target(target)


def test_estimate_host_count():
    assert hostscan.estimate_host_count("192.168.1.0/24") == 256
    assert hostscan.estimate_host_count("10.0.0.5") == 1
    assert hostscan.estimate_host_count("192.168.1.1-50") is None


def test_build_command_uses_ping_scan():
    cmd = hostscan.build_command("/usr/bin/nmap", "10.0.0.0/24", ["-T4"])
    assert cmd == ["/usr/bin/nmap", "-sn", "10.0.0.0/24", "-T4"]


import ipaddress


def _scope(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


def test_load_scope_file_parses_and_skips_comments(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text(
        "# approved ranges\n"
        "10.0.0.0/24\n"
        "\n"
        "192.168.1.0/24  # office LAN\n"
    )
    nets = hostscan.load_scope_file(str(f))
    assert [str(n) for n in nets] == ["10.0.0.0/24", "192.168.1.0/24"]


def test_load_scope_file_rejects_bad_entry(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("10.0.0.0/24\nnonsense\n")
    with pytest.raises(SystemExit):
        hostscan.load_scope_file(str(f))


def test_load_scope_file_missing(tmp_path):
    with pytest.raises(SystemExit):
        hostscan.load_scope_file(str(tmp_path / "nope.txt"))


def test_target_addresses_cidr_ip_and_range():
    assert hostscan.target_addresses("10.0.0.5") == [ipaddress.ip_address("10.0.0.5")]
    assert len(hostscan.target_addresses("10.0.0.0/30")) == 2  # .hosts() drops net+bcast
    rng = hostscan.target_addresses("192.168.1.1-3")
    assert [str(a) for a in rng] == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_enforce_scope_allows_in_scope():
    # Fully contained: should not raise.
    hostscan.enforce_scope("10.0.0.0/25", _scope("10.0.0.0/24"))
    hostscan.enforce_scope("10.0.0.5", _scope("10.0.0.0/24"))
    hostscan.enforce_scope("10.0.0.1-50", _scope("10.0.0.0/24"))


@pytest.mark.parametrize(
    "target",
    ["192.168.5.0/24", "8.8.8.8", "10.0.1.0/24", "172.16.0.0/24"],
)
def test_enforce_scope_refuses_out_of_scope(target):
    with pytest.raises(SystemExit):
        hostscan.enforce_scope(target, _scope("10.0.0.0/24"))


def test_scan_result_active_count():
    result = hostscan.ScanResult(
        target="10.0.0.0/30",
        hosts=[hostscan.Host("10.0.0.1"), hostscan.Host("10.0.0.2")],
    )
    assert result.active_count == 2
