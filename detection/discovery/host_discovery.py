"""
Host discovery module.

Primary method: ARP using scapy (fast, local L2).
Fallback: nmap -sn via python-nmap.

Exports:
  discover_hosts(subnet: str, prefer_arp: bool = True) -> dict
"""

from datetime import datetime
import json
import os
from pathlib import Path
from typing import List, Dict
from loguru import logger
import time

# Optional imports (scapy and nmap)
try:
    from scapy.all import srp, Ether, ARP, conf  # scapy present
    _HAVE_SCAPY = True
except Exception:
    _HAVE_SCAPY = False

try:
    import nmap  # python-nmap
    _HAVE_NMAP = True
except Exception:
    _HAVE_NMAP = False

from netaddr import IPNetwork

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

def _save_json(data: dict, outdir: Path = DATA_DIR) -> Path:
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    path = outdir / f"discovery_{timestamp}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path

def _parse_arp_results(ans) -> List[Dict]:
    hosts = []
    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        hosts.append({"ip": ip, "mac": mac})
    return hosts

def _arp_discover(subnet: str, timeout: int = 2, verbose: bool = False) -> List[Dict]:
    if not _HAVE_SCAPY:
        raise RuntimeError("scapy is not available")
    # required: run as root for many platforms
    # configure scapy to not be noisy
    conf.verb = 0
    logger.info("Running ARP discovery with scapy on {}", subnet)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    ans, _ = srp(pkt, timeout=timeout, verbose=0)
    hosts = _parse_arp_results(ans)
    logger.info("ARP discovery found {} hosts", len(hosts))
    return hosts

def _nmap_ping_sweep(subnet: str) -> List[Dict]:
    if not _HAVE_NMAP:
        raise RuntimeError("python-nmap is not available")
    logger.info("Running nmap -sn ping sweep on {}", subnet)
    nm = nmap.PortScanner()
    # run nmap ping-scan
    # Using -n to skip DNS, -sn for ping only
    res = nm.scan(hosts=subnet, arguments='-n -sn')
    hosts = []
    # python-nmap structures results by host
    for host in res.get('scan', {}):
        state = res['scan'][host].get('status', {}).get('state')
        if state == 'up':
            mac = None
            addresses = res['scan'][host].get('addresses', {})
            mac = addresses.get('mac')
            hosts.append({"ip": host, "mac": mac})
    logger.info("nmap ping sweep found {} hosts", len(hosts))
    return hosts

def discover_hosts(subnet: str, prefer_arp: bool = True, save: bool = True) -> Dict:
    """
    Discover live hosts on a subnet.

    Returns a dict:
    {
      "subnet": "...",
      "timestamp": "...",
      "tool": "arp" / "nmap",
      "hosts": [ {"ip": "...", "mac": "..."} ]
    }
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

    # Try ARP first if preferred and scapy available
    if prefer_arp and _HAVE_SCAPY:
        try:
            # scapy may require root; if it fails, fallback to nmap
            hosts = _arp_discover(subnet)
            tool_used = "scapy-arp"
        except Exception as e:
            logger.warning("ARP discovery failed or requires privileges: {}", e)

    # Fallback to nmap ping sweep
    if not hosts:
        if _HAVE_NMAP:
            try:
                hosts = _nmap_ping_sweep(subnet)
                tool_used = "nmap-sn"
            except Exception as e:
                logger.error("nmap ping sweep failed: {}", e)
                raise
        else:
            raise RuntimeError("No discovery method available (scapy or python-nmap required)")

    result = {
        "subnet": subnet,
        "timestamp": start,
        "tool": tool_used,
        "count": len(hosts),
        "hosts": hosts
    }

    if save:
        path = _save_json(result)
        logger.info("Saved discovery results to: {}", path)

    return result

# Allow module-level quick test
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--subnet", required=True)
    parser.add_argument("--no-save", action="store_true")
    args = parser.parse_args()
    out = discover_hosts(args.subnet, save=not args.no_save)
    print(json.dumps(out, indent=2))
