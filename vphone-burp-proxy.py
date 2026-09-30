#!/usr/bin/env python3
"""Toggle an HTTP/HTTPS proxy on a vphone Ethernet interface.

Applies only to the guest. Does not change the Mac's Wi-Fi or system proxy.

Usage:
  ./vphone-burp-proxy.py on
  ./vphone-burp-proxy.py off
  ./vphone-burp-proxy.py status

Optional:
  --guest 192.168.64.5   --port 8080   --host 192.168.64.1
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import plistlib
import shutil
import socket
import subprocess
import sys
from pathlib import Path

SSH_PORT = 22222
SSH_USER = "root"
SSH_PASS = os.environ.get("VPHONE_SSH_PASS", "alpine")
GUEST_PATH = (
    "/var/jb/usr/bin:/var/jb/bin:/var/jb/sbin:/var/jb/usr/sbin:"
    "/usr/bin:/usr/sbin:/bin:/sbin:"
    "/iosbinpack64/usr/bin:/iosbinpack64/bin:/iosbinpack64/usr/sbin"
)
PLIST_PATHS = (
    "/var/preferences/SystemConfiguration/preferences.plist",
    "/Library/Preferences/SystemConfiguration/preferences.plist",
)
BAK_PATH = "/var/preferences/SystemConfiguration/preferences.plist.bak"
SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=5",
    "-p", str(SSH_PORT),
]


class Fail(Exception):
    pass


def which_sshpass() -> str:
    path = shutil.which("sshpass")
    if not path:
        raise Fail("sshpass not found (brew install sshpass)")
    return path


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, **kwargs)


def ssh_cmd(guest: str, remote: str, data: bytes | None = None) -> subprocess.CompletedProcess:
    cmd = [
        which_sshpass(), "-p", SSH_PASS, "ssh", *SSH_OPTS,
        f"{SSH_USER}@{guest}",
        f"export PATH={GUEST_PATH}; [ -r /var/jb/etc/profile ] && . /var/jb/etc/profile; {remote}",
    ]
    return subprocess.run(cmd, input=data, capture_output=True)


def ssh_ok(guest: str, remote: str, data: bytes | None = None) -> bytes:
    p = ssh_cmd(guest, remote, data=data)
    if p.returncode != 0:
        err = (p.stderr or b"").decode("utf-8", "replace").strip()
        out = (p.stdout or b"").decode("utf-8", "replace").strip()
        raise Fail(f"ssh failed ({p.returncode}): {err or out or remote}")
    return p.stdout or b""


def tcp_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def host_nat_ips() -> list[str]:
    """IPv4 addresses on vmnet/bridge interfaces (vphone NAT), never Wi-Fi."""
    p = run(["ifconfig"])
    ips: list[str] = []
    iface = ""
    is_nat = False
    for line in (p.stdout or "").splitlines():
        if line and not line[0].isspace():
            iface = line.split(":", 1)[0]
            is_nat = iface.startswith("bridge") or iface.startswith("vmenet")
            continue
        if not is_nat:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "inet":
            ip = parts[1]
            if ip != "127.0.0.1":
                ips.append(ip)
    return ips


def discover_guest(explicit: str | None) -> str:
    if explicit:
        if not tcp_open(explicit, SSH_PORT, timeout=2):
            raise Fail(f"no SSH on {explicit}:{SSH_PORT}")
        return explicit

    nats = host_nat_ips()
    nets = [ipaddress.ip_network(f"{h}/24", strict=False) for h in nats]
    candidates: list[str] = []
    p = run(["arp", "-a"])
    for line in (p.stdout or "").splitlines():
        if "incomplete" in line:
            continue
        if "(" not in line or ")" not in line:
            continue
        ip = line.split("(", 1)[1].split(")", 1)[0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_multicast or addr.is_link_local:
            continue
        if ip in nats:
            continue
        if any(addr in net for net in nets):
            candidates.append(ip)

    seen = []
    for ip in candidates:
        if ip not in seen:
            seen.append(ip)
    for ip in seen:
        if tcp_open(ip, SSH_PORT):
            return ip
    raise Fail(
        "could not find a vphone guest on SSH :22222. "
        "Pass --guest <ip> (check `arp -a` on bridge100)."
    )


def guest_gateway(guest: str) -> str:
    out = ssh_ok(guest, "netstat -rn -f inet").decode("utf-8", "replace")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("default", "0/0"):
            return parts[1]
    nats = host_nat_ips()
    if nats:
        return nats[0]
    raise Fail("could not read guest default gateway")


def burp_listening(host: str, port: int) -> bool:
    p = run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"])
    text = p.stdout or ""
    return f"{host}:{port}" in text or f"*:{port}" in text or f"0.0.0.0:{port}" in text


def pull_plist(guest: str) -> bytes:
    return ssh_ok(guest, f"cat {PLIST_PATHS[0]}")


def push_plist(guest: str, blob: bytes) -> None:
    for path in PLIST_PATHS:
        ssh_ok(guest, f"cat > {path}", data=blob)
        ssh_ok(guest, f"chmod 644 {path}")


def ensure_bak(guest: str, current: bytes) -> None:
    check = ssh_cmd(guest, f"test -s {BAK_PATH}")
    if check.returncode == 0:
        return
    ssh_ok(guest, f"cat > {BAK_PATH}", data=current)
    ssh_ok(guest, f"chmod 644 {BAK_PATH}")


def load(blob: bytes) -> dict:
    return plistlib.loads(blob)


def dump(data: dict) -> bytes:
    return plistlib.dumps(data, fmt=plistlib.FMT_BINARY)


def ethernet_services(data: dict) -> list[tuple[str, dict]]:
    services = data.get("NetworkServices") or {}
    out = []
    for uuid, svc in services.items():
        iface = (svc or {}).get("Interface") or {}
        if iface.get("Type") == "Ethernet":
            out.append((uuid, svc))
    return out


def proxy_dict(host: str, port: int, nat_cidr: str) -> dict:
    return {
        "ExceptionsList": ["*.local", "169.254/16", nat_cidr],
        "FTPPassive": 1,
        "HTTPEnable": 1,
        "HTTPPort": port,
        "HTTPProxy": host,
        "HTTPSEnable": 1,
        "HTTPSPort": port,
        "HTTPSProxy": host,
        "SOCKSEnable": 0,
    }


def strip_proxy(proxies: dict) -> dict:
    kept = {k: v for k, v in (proxies or {}).items() if k in ("FTPPassive", "ExceptionsList")}
    if "FTPPassive" not in kept:
        kept["FTPPassive"] = 1
    exceptions = list(kept.get("ExceptionsList") or ["*.local", "169.254/16"])
    kept["ExceptionsList"] = [e for e in exceptions if not str(e).endswith(".0/24") or str(e).startswith("169.")]
    if "*.local" not in kept["ExceptionsList"]:
        kept["ExceptionsList"].insert(0, "*.local")
    if "169.254/16" not in kept["ExceptionsList"]:
        kept["ExceptionsList"].append("169.254/16")
    return kept


def describe(data: dict) -> list[str]:
    lines = []
    for uuid, svc in ethernet_services(data):
        iface = svc.get("Interface") or {}
        name = iface.get("DeviceName") or iface.get("UserDefinedName") or uuid[:8]
        px = svc.get("Proxies") or {}
        if px.get("HTTPEnable") == 1 or px.get("HTTPSEnable") == 1:
            lines.append(
                f"  {name}: HTTP {px.get('HTTPProxy')}:{px.get('HTTPPort')}  "
                f"HTTPS {px.get('HTTPSProxy')}:{px.get('HTTPSPort')}"
            )
        else:
            lines.append(f"  {name}: proxy off")
    vpn = []
    for uuid, svc in (data.get("NetworkServices") or {}).items():
        iface = (svc or {}).get("Interface") or {}
        if iface.get("Type") == "VPN":
            vpn.append((svc or {}).get("UserDefinedName") or uuid[:8])
    if vpn:
        lines.append(f"  VPN profiles present (leave disconnected): {', '.join(vpn)}")
    return lines or ["  no Ethernet services found"]


def nat_cidr_for(host: str) -> str:
    return str(ipaddress.ip_network(f"{host}/24", strict=False))


def apply_on(data: dict, host: str, port: int) -> dict:
    cidr = nat_cidr_for(host)
    found = ethernet_services(data)
    if not found:
        raise Fail("no Ethernet NetworkServices in preferences.plist")
    for _, svc in found:
        base = dict(svc.get("Proxies") or {})
        base.update(proxy_dict(host, port, cidr))
        svc["Proxies"] = base
    return data


def apply_off(data: dict) -> dict:
    for _, svc in ethernet_services(data):
        svc["Proxies"] = strip_proxy(svc.get("Proxies") or {})
    return data


def reload_configd(guest: str) -> None:
    ssh_ok(guest, "killall configd")


def cmd_status(guest: str, host: str, port: int) -> int:
    data = load(pull_plist(guest))
    print(f"guest        {guest}")
    print(f"NAT gateway  {host}  (this is the proxy host — not your Mac Wi-Fi IP)")
    print(f"Burp port    {port}  listening={burp_listening(host, port)}")
    print("Ethernet:")
    print("\n".join(describe(data)))
    return 0


def cmd_on(guest: str, host: str, port: int) -> int:
    current = pull_plist(guest)
    ensure_bak(guest, current)
    data = apply_on(load(current), host, port)
    push_plist(guest, dump(data))
    reload_configd(guest)
    print(f"proxy ON  {host}:{port}  guest={guest}")
    print("\n".join(describe(data)))
    if not burp_listening(host, port):
        print(
            f"\nWARNING: nothing is listening on {host}:{port}.\n"
            f"In Burp: Proxy → Bind to address {host} (or all interfaces), port {port}.\n"
            "Until Burp is up, Safari/app HTTP(S) on the VM will fail."
        )
    print(
        "\nDoes not follow Mac Wi-Fi IP changes — it should not.\n"
        "Guest always reaches the host at the NAT gateway above.\n"
        "This write is on disk: run `off` before reboot if you do not want it after restart.\n"
        "Hiddify/VPN must stay disconnected. Burp intercept OFF for the first test.\n"
        "Safari → http://example.com and check Burp HTTP history."
    )
    return 0


def cmd_off(guest: str, host: str, port: int) -> int:
    bak = ssh_cmd(guest, f"cat {BAK_PATH}")
    if bak.returncode == 0 and bak.stdout:
        push_plist(guest, bak.stdout)
        data = load(bak.stdout)
        print("proxy OFF (restored original preferences.plist.bak)")
    else:
        data = apply_off(load(pull_plist(guest)))
        push_plist(guest, dump(data))
        print("proxy OFF (stripped HTTP/HTTPS proxy keys; no bak found)")
    reload_configd(guest)
    print("\n".join(describe(data)))
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=("on", "off", "status"))
    p.add_argument("--guest", help="guest IPv4 (auto-detect via ARP + SSH :22222)")
    p.add_argument("--host", help="proxy host (default: guest default gateway / NAT)")
    p.add_argument("--port", type=int, default=8080, help="Burp listen port (default 8080)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        guest = discover_guest(args.guest)
        host = args.host or guest_gateway(guest)
        if args.action == "status":
            return cmd_status(guest, host, args.port)
        if args.action == "on":
            return cmd_on(guest, host, args.port)
        return cmd_off(guest, host, args.port)
    except Fail as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
