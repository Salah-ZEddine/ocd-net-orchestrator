"""CLI entrypoint for the discovery stage."""

import argparse
from loguru import logger
from detection.discovery.host_discovery import discover_hosts

def parse_args():
    p = argparse.ArgumentParser(prog="ocd-discovery", description="Orange CyberDefense - Discovery Stage")
    p.add_argument("--subnet", "-s", required=True, help="Target subnet (e.g. 192.168.1.0/24)")
    p.add_argument("--prefer-arp", action="store_true", help="Prefer ARP (scapy) discovery if available")
    p.add_argument("--no-save", action="store_true", help="Do not save results to disk")
    return p.parse_args()

def main():
    args = parse_args()
    logger.info("Starting discovery for subnet {}", args.subnet)
    res = discover_hosts(args.subnet, prefer_arp=args.prefer_arp, save=(not args.no_save))
    logger.info("Discovery finished: {} hosts found", res.get("count", 0))
    # Print summary to stdout
    for h in res.get("hosts", []):
        print(f"{h.get('ip')}  {h.get('mac') or ''}")

if __name__ == "__main__":
    main()
