"""
Host discovery module with port scanning and OS detection.

Primary method: ARP using scapy (fast, local L2).
Fallback: nmap -sn via python-nmap.
Enhanced: Includes port scanning and OS detection per host.

Exports:
  discover_hosts(subnet: str, prefer_arp: bool = True, scan_ports: bool = True) -> dict
"""

from datetime import datetime
import json
from pathlib import Path
from typing import List, Dict
from loguru import logger
from detection.utils.storage import JSONStorage
from detection.utils.arpResultParser import ARPResultParser

# Optional imports (scapy and nmap)
try:
    from scapy.all import srp, Ether, ARP, conf
    _HAVE_SCAPY = True
except Exception:
    _HAVE_SCAPY = False

try:
    import nmap
    _HAVE_NMAP = True
except Exception:
    _HAVE_NMAP = False

from netaddr import IPNetwork

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
storage = JSONStorage(output_dir=DATA_DIR, prefix="discovery")
parser = ARPResultParser()


def _arp_scan(subnet: str) -> List[Dict]:
    """
    Discover live hosts using ARP (Layer 2) scanning via scapy.
    Fast and reliable for local networks.

    Returns:
        List of dicts with 'ip' and 'mac' keys
    """
    if not _HAVE_SCAPY:
        raise RuntimeError("scapy is not available")

    logger.info("Running ARP scan on {}", subnet)

    # Prepare ARP request
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send packets and receive responses
    ans, _ = srp(packet, timeout=2, verbose=False)

    # Use parser to extract host information
    hosts = parser.parse_arp(ans)
    logger.info("ARP scan found {} hosts", len(hosts))
    return hosts


def _nmap_ping_sweep(subnet: str) -> List[Dict]:
    """
    Discover live hosts using nmap ping sweep.

    Returns:
        List of dicts with 'ip' and 'mac' keys
    """
    if not _HAVE_NMAP:
        raise RuntimeError("python-nmap is not available")

    logger.info("Running nmap -sn ping sweep on {}", subnet)
    nm = nmap.PortScanner()
    res = nm.scan(hosts=subnet, arguments='-n -sn')

    # Use parser to extract host information
    hosts = parser.parse_nmap(res, subnet)
    logger.info("nmap ping sweep found {} hosts", len(hosts))
    return hosts


def _scan_host_ports(ip: str) -> Dict:
    """
    Scan a single host for open ports, services, and OS.

    Args:
        ip: IP address to scan

    Returns:
        Dict with 'ports', 'os', 'mac', and optional 'vendor' keys
    """
    if not _HAVE_NMAP:
        raise RuntimeError("python-nmap is not available")

    logger.info("Scanning ports on {}", ip)
    nm = nmap.PortScanner()

    try:
        # Scan common ports with service detection and OS detection
        # -sV: Service version detection
        # -O: OS detection
        # --osscan-guess: Guess OS more aggressively
        # -T4: Faster timing template
        nm.scan(hosts=ip, arguments='-sV -O --osscan-guess -T4')

        # Use parser to extract port and OS information
        result = parser.parse_nmap_ports(nm, ip)

        ports_count = len(result["ports"])
        logger.info("Found {} open ports on {} (MAC: {}, OS: {})",
                    ports_count, ip, result.get("mac") or "N/A", result.get("os"))
        return result

    except Exception as e:
        logger.error("Error scanning {}: {}", ip, e)
        return {
            "ports": [],
            "os": "unknown",
            "mac": None,
            "os_accuracy": 0
        }


def discover_hosts(subnet: str, prefer_arp: bool = True, scan_ports: bool = True, save: bool = True) -> Dict:
    """
    Discover live hosts on a subnet with optional port scanning.

    Args:
        subnet: Network subnet in CIDR notation (e.g., "192.168.1.0/24")
        prefer_arp: Prefer ARP scanning over nmap (requires scapy, local network only)
        scan_ports: Whether to scan ports on discovered hosts (requires nmap)
        save: Whether to save results to file

    Returns:
        Dict with subnet, timestamp, tool, count, and hosts information.
        Each host contains: ip, mac, ports, os, vendor (if available)
    """
    # Validate subnet
    try:
        _ = IPNetwork(subnet)
    except Exception as e:
        logger.error("Invalid subnet '{}': {}", subnet, e)
        raise

    start = datetime.utcnow().isoformat() + "Z"
    hosts = []
    tool_used = None
    discovered_hosts = []

    # Try ARP scan first if preferred and available
    if prefer_arp and _HAVE_SCAPY:
        try:
            discovered_hosts = _arp_scan(subnet)
            tool_used = "scapy-arp"
        except Exception as e:
            logger.warning("ARP scan failed, falling back to nmap: {}", e)
            discovered_hosts = []

    # Fall back to nmap if ARP not available or failed
    if not discovered_hosts and _HAVE_NMAP:
        try:
            discovered_hosts = _nmap_ping_sweep(subnet)
            tool_used = "nmap-sn"
        except Exception as e:
            logger.error("nmap operations failed: {}", e)
            raise

    if not discovered_hosts:
        raise RuntimeError("No discovery method available or no hosts found")

    # Process discovered hosts
    if scan_ports and _HAVE_NMAP:
        logger.info("Starting port scanning on {} hosts", len(discovered_hosts))
        for host in discovered_hosts:
            ip = host["ip"]

            # Scan ports and get detailed information
            scan_result = _scan_host_ports(ip)

            # Merge discovery data with port scan results
            merged_host = parser.merge_host_data(host, scan_result)
            hosts.append(merged_host)
    else:
        # Just include basic host info without port scanning
        hosts = []
        for h in discovered_hosts:
            hosts.append({
                "ip": h["ip"],
                "mac": h.get("mac"),
                "vendor": "",
                "ports": [],
                "os": "unknown",
                "os_accuracy": 0
            })

    result = {
        "subnet": subnet,
        "timestamp": start,
        "tool": tool_used,
        "count": len(hosts),
        "hosts": hosts
    }

    if save:
        path = storage.save(result)
        logger.info("Saved discovery results to: {}", path)

    return result


# Allow module-level quick test
if __name__ == "__main__":
    import argparse

    arg_parser = argparse.ArgumentParser(
        description="Network host discovery with port scanning"
    )
    arg_parser.add_argument("--subnet", required=True,
                            help="Subnet in CIDR notation (e.g., 192.168.1.0/24)")
    arg_parser.add_argument("--no-save", action="store_true",
                            help="Don't save results to file")
    arg_parser.add_argument("--no-ports", action="store_true",
                            help="Skip port scanning")
    arg_parser.add_argument("--no-arp", action="store_true",
                            help="Don't prefer ARP scanning (use nmap)")
    args = arg_parser.parse_args()

    out = discover_hosts(
        args.subnet,
        prefer_arp=not args.no_arp,
        scan_ports=not args.no_ports,
        save=not args.no_save
    )
    print(json.dumps(out, indent=2))