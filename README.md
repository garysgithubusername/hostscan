# hostscan

A small CLI that counts the **active hosts** on a network by wrapping `nmap -sn`
(ping sweep / host discovery, no port scanning).

> ⚠️ **Legal use only.** Scan networks you own or have explicit written
> permission to test. Unauthorized scanning may violate law and acceptable-use
> policies. The tool prompts for authorization confirmation before every scan.

## Prerequisites

- Python 3.10+
- `nmap` on your PATH (`brew install nmap` on macOS)

## Usage

```bash
# Count active hosts on your local /24 (prompts for authorization)
python hostscan.py 192.168.1.0/24

# List each live host, skip the prompt (when permission is already confirmed)
python hostscan.py 192.168.1.0/24 --list --yes

# Single host or an octet range
python hostscan.py 10.0.0.5
python hostscan.py 192.168.1.1-50

# Pass extra flags straight through to nmap (repeatable)
python hostscan.py 192.168.1.0/24 --nmap-arg -T4 --nmap-arg -n

# Restrict scans to an approved engagement scope
python hostscan.py 10.0.0.0/25 --scope-file scope.txt
```

### Options

| Flag | Description |
|------|-------------|
| `--list` | Print each active host's IP/hostname, not just the count. |
| `--scope-file PATH` | Refuse any target not fully inside the approved IP/CIDR list. |
| `--yes` | Skip the interactive authorization prompt. |
| `--timeout N` | Abort the scan after `N` seconds (default 600). |
| `--nmap-arg ARG` | Forward a raw argument to nmap (repeatable). |

### Scope files

A scope file pins the tool to networks you're authorized to assess — useful for
pentest engagements where the rules of engagement name specific IP ranges. One
IP or CIDR per line; blank lines and `#` comments are ignored:

```
# Engagement: ACME-2026 — authorized ranges only
10.0.0.0/24       # production DMZ
192.168.50.0/24   # office LAN
```

If **any** address the target covers falls outside every approved network, the
scan is refused before nmap runs. A malformed entry aborts the run rather than
silently widening scope.

## Notes

- Targets are validated as IP / CIDR / octet-range; hostnames and shell
  metacharacters are rejected. The tool never invokes a shell (`shell=False`).
- Some discovery techniques are more accurate with elevated privileges; if nmap
  asks for them, run with `sudo`.

## Tests

```bash
pip install pytest
pytest -q
```

Tests cover output parsing and target validation only — they perform no real
network scans.
