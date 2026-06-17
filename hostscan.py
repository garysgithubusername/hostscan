#!/usr/bin/env python3
"""Host discovery tool: count active hosts on networks you are authorized to scan.

Wraps `nmap -sn` (ping sweep / no port scan) to discover which hosts in a target
range are up, then reports the count. Intended for legitimate network
administration and authorized security testing only.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# An IPv4 or IPv6 network as parsed from a scope file.
ScopeNet = ipaddress.IPv4Network | ipaddress.IPv6Network


# nmap reports each live host on a line like:
#   Nmap scan report for hostname (192.168.1.5)
#   Nmap scan report for 192.168.1.5
_HOST_LINE = re.compile(
    r"^Nmap scan report for (?:(?P<name>\S+) \((?P<ip_paren>[\d.]+)\)|(?P<ip>[\d.:a-fA-F]+))"
)


@dataclass
class Host:
    """A single host found to be up."""

    address: str
    hostname: str | None = None


@dataclass
class ScanResult:
    """Aggregated outcome of a host-discovery scan."""

    target: str
    hosts: list[Host] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    started_at: str = ""
    duration_seconds: float = 0.0

    @property
    def active_count(self) -> int:
        return len(self.hosts)


def ensure_nmap_available() -> str:
    """Return the path to the nmap binary, or exit with a helpful message."""
    path = shutil.which("nmap")
    if path is None:
        sys.exit(
            "Error: nmap is not installed or not on PATH.\n"
            "Install it with:  brew install nmap   (macOS)\n"
            "                  sudo apt install nmap  (Debian/Ubuntu)"
        )
    return path


def validate_target(target: str) -> str:
    """Validate that the target is a sane CIDR, single IP, or hyphenated range.

    Raises ValueError on clearly invalid input. We deliberately keep this
    permissive enough for nmap's range syntax (e.g. 192.168.1.1-50) while
    rejecting obvious garbage and shell-injection attempts.
    """
    target = target.strip()
    if not target:
        raise ValueError("Empty target.")

    # Reject characters that have no place in a host/network spec. This also
    # blocks shell metacharacters as defense in depth (we never use shell=True).
    if not re.fullmatch(r"[0-9a-fA-F.:/\-]+", target):
        raise ValueError(f"Target contains invalid characters: {target!r}")

    # If it parses cleanly as a network or address, great.
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Otherwise accept nmap's trailing octet-range syntax: 192.168.1.1-50
    if re.fullmatch(r"[\d.]+-\d+", target):
        base, _, end = target.partition("-")
        try:
            ipaddress.ip_address(base)  # base must be a full, valid IPv4 address
        except ValueError:
            raise ValueError(f"Range base {base!r} is not a valid address: {target!r}")
        start_last = int(base.rsplit(".", 1)[1])
        end_last = int(end)
        if not (start_last <= end_last <= 255):
            raise ValueError(
                f"Invalid octet range in {target!r}: end must satisfy {start_last} <= end <= 255."
            )
        return target

    raise ValueError(
        f"Target {target!r} is not a valid IP, CIDR, or range. "
        "Examples: 192.168.1.0/24, 10.0.0.5, 192.168.1.1-50"
    )


def load_scope_file(path: str) -> list[ScopeNet]:
    """Load approved networks from a scope file.

    Format: one IP or CIDR per line. Blank lines and lines starting with '#'
    are ignored, as is any trailing '# comment' on a line. Each entry must be a
    valid IP/CIDR; anything else aborts the run so a typo can never silently
    widen the approved scope.
    """
    file_path = Path(path)
    if not file_path.is_file():
        sys.exit(f"Error: scope file not found: {path}")

    networks: list[ScopeNet] = []
    for lineno, raw in enumerate(file_path.read_text().splitlines(), start=1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            sys.exit(f"Error: invalid entry in scope file {path}:{lineno}: {entry!r} ({exc})")

    if not networks:
        sys.exit(f"Error: scope file {path} contains no usable networks.")
    return networks


def target_addresses(target: str) -> list[ipaddress._BaseAddress]:
    """Enumerate every address a validated target covers.

    Handles single IPs, CIDRs, and nmap's trailing octet-range syntax
    (e.g. 192.168.1.1-50). Used to verify a target is fully inside scope.
    """
    try:
        return list(ipaddress.ip_network(target, strict=False).hosts()) or [
            ipaddress.ip_address(target.split("/")[0])
        ]
    except ValueError:
        pass
    try:
        return [ipaddress.ip_address(target)]
    except ValueError:
        pass

    # Trailing octet range: 192.168.1.1-50  ->  192.168.1.1 .. 192.168.1.50
    base, _, end = target.partition("-")
    octets = base.split(".")
    start_last = int(octets[-1])
    end_last = int(end)
    prefix = ".".join(octets[:-1])
    return [
        ipaddress.ip_address(f"{prefix}.{last}")
        for last in range(start_last, end_last + 1)
    ]


def enforce_scope(target: str, scope: list[ScopeNet]) -> None:
    """Abort unless every address the target covers falls within an approved network."""
    out_of_scope = [
        str(addr)
        for addr in target_addresses(target)
        if not any(addr in net for net in scope)
    ]
    if out_of_scope:
        shown = ", ".join(out_of_scope[:5])
        more = f" (+{len(out_of_scope) - 5} more)" if len(out_of_scope) > 5 else ""
        approved = ", ".join(str(net) for net in scope)
        sys.exit(
            f"Refusing to scan: target {target!r} includes addresses outside the approved "
            f"scope.\n  Out of scope: {shown}{more}\n  Approved scope: {approved}"
        )


def estimate_host_count(target: str) -> int | None:
    """Best-effort estimate of how many addresses a target covers (for the prompt)."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.num_addresses
    except ValueError:
        return None


def confirm_authorization(target: str, assume_yes: bool) -> None:
    """Require explicit confirmation that the user is authorized to scan.

    Scanning networks you do not own or lack permission to test may be illegal.
    This gate makes that responsibility explicit.
    """
    if assume_yes:
        return

    size = estimate_host_count(target)
    size_note = f" (~{size} addresses)" if size else ""
    print(
        f"\nYou are about to run host discovery against: {target}{size_note}\n"
        "Only scan networks you OWN or have EXPLICIT WRITTEN PERMISSION to test.\n"
        "Unauthorized scanning may violate law and acceptable-use policies.\n"
    )
    answer = input("Type 'yes' to confirm you are authorized to scan this target: ")
    if answer.strip().lower() not in {"yes", "y"}:
        sys.exit("Aborted: authorization not confirmed.")


def build_command(
    nmap_path: str,
    target: str,
    extra_args: list[str],
    stats_every: str | None = None,
) -> list[str]:
    """Construct the nmap argument vector for a ping-sweep host discovery scan.

    When ``stats_every`` is set (e.g. "2s"), nmap is asked to emit periodic
    progress lines so we can render a live status during long scans.
    """
    # -sn : ping scan, no port scan (host discovery only)
    cmd = [nmap_path, "-sn", target]
    if stats_every:
        cmd += ["--stats-every", stats_every]
    cmd.extend(extra_args)
    return cmd


# nmap's --stats-every timing line looks like:
#   Ping Scan Timing: About 45.31% done; ETC: 12:00 (0:00:05 remaining)
_PERCENT_LINE = re.compile(r"About ([\d.]+)% done")


class _Progress:
    """Renders a single, self-updating status line while a scan runs.

    Only active on an interactive terminal; when output is piped or --quiet is
    set it does nothing, so captured stdout stays clean for parsing/scripting.
    """

    def __init__(self, target: str, enabled: bool, stream=sys.stderr) -> None:
        self.enabled = enabled and stream.isatty()
        self.stream = stream
        self.target = target
        self.hosts = 0
        self.percent: float | None = None
        self.start = time.monotonic()

    def on_line(self, line: str) -> None:
        """Inspect one line of nmap stdout and refresh the status line."""
        if not self.enabled:
            return
        if _HOST_LINE.match(line):
            self.hosts += 1
        match = _PERCENT_LINE.search(line)
        if match:
            self.percent = float(match.group(1))
        self._render()

    def _render(self) -> None:
        elapsed = int(time.monotonic() - self.start)
        pct = f" · {self.percent:.0f}% done" if self.percent is not None else ""
        self.stream.write(
            f"\r  scanning {self.target} … {self.hosts} host(s) up{pct} · {elapsed}s "
        )
        self.stream.flush()

    def finish(self) -> None:
        """Erase the status line so the final report prints cleanly."""
        if self.enabled:
            self.stream.write("\r" + " " * 72 + "\r")
            self.stream.flush()


def parse_hosts(nmap_stdout: str) -> list[Host]:
    """Extract the list of up hosts from nmap stdout.

    We only count a 'Nmap scan report' block as a live host when the scan was a
    ping scan (-sn), where a report line implies the host is up.
    """
    hosts: list[Host] = []
    lines = nmap_stdout.splitlines()
    for i, line in enumerate(lines):
        match = _HOST_LINE.match(line)
        if not match:
            continue
        ip = match.group("ip_paren") or match.group("ip")
        hostname = match.group("name")
        # Confirm the following lines mark the host as up (defensive against
        # formatting variations). If we can find a "Host is up" within the block
        # we trust it; otherwise the report line itself is sufficient for -sn.
        hosts.append(Host(address=ip, hostname=hostname))
    return hosts


def stream_subprocess(
    command: list[str], timeout: int, on_line: Callable[[str], None]
) -> subprocess.CompletedProcess:
    """Run a command, forwarding each stdout line to ``on_line`` as it arrives.

    Returns a CompletedProcess with the full stdout/stderr captured, so callers
    parse exactly as they would with subprocess.run — the streaming is purely
    additive (it powers the live progress display). Raises
    subprocess.TimeoutExpired if the command runs longer than ``timeout``.
    """
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # line-buffered, so progress lines surface promptly
    )

    # Drain stderr on a thread so a large error stream can't deadlock us while
    # we block reading stdout.
    stderr_chunks: list[str] = []
    stderr_thread = threading.Thread(
        target=lambda: stderr_chunks.extend(proc.stderr or []),
        daemon=True,
    )
    stderr_thread.start()

    # Iterating proc.stdout has no per-read timeout, so enforce the overall
    # limit with a watchdog that kills the process.
    timed_out = threading.Event()

    def _kill_on_timeout() -> None:
        timed_out.set()
        proc.kill()

    watchdog = threading.Timer(timeout, _kill_on_timeout)
    watchdog.start()

    stdout_lines: list[str] = []
    try:
        for line in proc.stdout or []:
            stdout_lines.append(line)
            on_line(line)
        proc.wait()
    finally:
        watchdog.cancel()
        stderr_thread.join(timeout=1)

    if timed_out.is_set():
        raise subprocess.TimeoutExpired(command, timeout)

    return subprocess.CompletedProcess(
        command,
        proc.returncode,
        stdout="".join(stdout_lines),
        stderr="".join(stderr_chunks),
    )


def run_scan(
    target: str, extra_args: list[str], timeout: int, quiet: bool = False
) -> ScanResult:
    """Execute the scan and return a structured result."""
    nmap_path = ensure_nmap_available()
    progress = _Progress(target, enabled=not quiet)
    # Only ask nmap for periodic stats when we'll actually render them, so piped
    # output isn't peppered with progress lines.
    stats_every = "2s" if progress.enabled else None
    command = build_command(nmap_path, target, extra_args, stats_every=stats_every)
    started = datetime.now(timezone.utc)

    if not quiet:
        print(f"Scanning {target} … (Ctrl-C to abort)", file=sys.stderr)

    try:
        completed = stream_subprocess(command, timeout, progress.on_line)
    except subprocess.TimeoutExpired:
        progress.finish()
        sys.exit(f"Error: scan timed out after {timeout}s. Try a smaller range or raise --timeout.")
    except FileNotFoundError:
        progress.finish()
        sys.exit("Error: nmap binary disappeared mid-run.")
    finally:
        progress.finish()

    duration = (datetime.now(timezone.utc) - started).total_seconds()

    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        hint = ""
        if "root" in stderr.lower() or "privilege" in stderr.lower():
            hint = "\nHint: some scan types need elevated privileges. Try: sudo hostscan ..."
        sys.exit(f"nmap exited with code {completed.returncode}:\n{stderr}{hint}")

    hosts = parse_hosts(completed.stdout)
    return ScanResult(
        target=target,
        hosts=hosts,
        command=command,
        started_at=started.isoformat(),
        duration_seconds=round(duration, 2),
    )


def print_report(result: ScanResult, show_hosts: bool) -> None:
    """Print a human-readable summary of the scan."""
    print("\n" + "=" * 56)
    print(f"  Target:        {result.target}")
    print(f"  Started:       {result.started_at}")
    print(f"  Duration:      {result.duration_seconds}s")
    print(f"  Active hosts:  {result.active_count}")
    print("=" * 56)

    if show_hosts and result.hosts:
        print("\nLive hosts:")
        for host in result.hosts:
            label = f"  {host.address}"
            if host.hostname:
                label += f"  ({host.hostname})"
            print(label)
    print()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="hostscan",
        description="Count active hosts on networks you are authorized to scan (wraps nmap -sn).",
        epilog="Example: python hostscan.py 192.168.1.0/24 --list",
    )
    parser.add_argument(
        "target",
        help="Target to scan: CIDR (192.168.1.0/24), single IP (10.0.0.5), or range (192.168.1.1-50).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        dest="show_hosts",
        help="List the IP/hostname of each active host, not just the count.",
    )
    parser.add_argument(
        "--scope-file",
        metavar="PATH",
        help="File of approved IP/CIDR entries (one per line, '#' comments allowed). "
        "The target must fall entirely within this scope or the scan is refused.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive authorization prompt (use only when you have confirmed permission).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Maximum seconds to allow the scan to run (default: 600).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the live progress display (auto-disabled when output is piped).",
    )
    parser.add_argument(
        "--nmap-arg",
        action="append",
        default=[],
        dest="extra_args",
        metavar="ARG",
        help="Pass an extra raw argument through to nmap (repeatable). Example: --nmap-arg -T4",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    try:
        target = validate_target(args.target)
    except ValueError as exc:
        sys.exit(f"Error: {exc}")

    if args.scope_file:
        scope = load_scope_file(args.scope_file)
        enforce_scope(target, scope)

    confirm_authorization(target, assume_yes=args.yes)
    result = run_scan(
        target, extra_args=args.extra_args, timeout=args.timeout, quiet=args.quiet
    )
    print_report(result, show_hosts=args.show_hosts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())