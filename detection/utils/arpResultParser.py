"""
ARP result parser class with nmap support.
"""
from typing import List, Dict, Any, Optional
from loguru import logger


class ARPResultParser:
    """
    Parses ARP scan results from scapy and nmap results.

    Example:
        parser = ARPResultParser()
        # For ARP results
        hosts = parser.parse_arp(ans)
        # For nmap results
        hosts = parser.parse_nmap(nm, subnet)
        # For port scan results
        port_info = parser.parse_nmap_ports(nm, ip)
    """

    def parse_arp(self, ans) -> List[Dict]:
        """
        Parse ARP scan results from scapy.

        Args:
            ans: Answered packets from scapy srp() function

        Returns:
            List of dictionaries with 'ip' and 'mac' keys
        """
        hosts = []
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            hosts.append({"ip": ip, "mac": mac})

        logger.info("Parsed {} hosts from ARP results", len(hosts))
        return hosts

    def parse_nmap(self, nmap_result: Any, subnet: str) -> List[Dict]:
        """
        Parse nmap ping sweep results.

        Args:
            nmap_result: Result from nmap.PortScanner().scan()
            subnet: The subnet that was scanned

        Returns:
            List of dictionaries with 'ip' and 'mac' keys
        """
        hosts = []
        for host in nmap_result.get('scan', {}):
            state = nmap_result['scan'][host].get('status', {}).get('state')
            if state == 'up':
                addresses = nmap_result['scan'][host].get('addresses', {})
                mac = addresses.get('mac', None)

                hosts.append({
                    "ip": host,
                    "mac": mac
                })

        logger.info("Parsed {} live hosts from nmap results", len(hosts))
        return hosts

    def parse_nmap_ports(self, nm: Any, ip: str) -> Dict:
        """
        Parse nmap port scan results for a single host.

        Args:
            nm: nmap.PortScanner instance with scan results
            ip: IP address of the scanned host

        Returns:
            Dict with 'ports', 'os', and 'mac' keys containing detailed scan info
        """
        result = {
            "ports": [],
            "os": "unknown",
            "mac": None
        }

        if ip not in nm.all_hosts():
            logger.warning("Host {} not found in nmap results", ip)
            return result

        try:
            # Extract MAC address
            addresses = nm[ip].get('addresses', {})
            result["mac"] = addresses.get('mac', None)

            # Extract vendor information if available
            vendor = nm[ip].get('vendor', {})
            if result["mac"] and result["mac"] in vendor:
                result["vendor"] = vendor[result["mac"]]

            # Extract port information
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                for port in ports:
                    port_info = nm[ip][proto][port]
                    result["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": port_info.get('state', 'unknown'),
                        "service": port_info.get('name', ''),
                        "product": port_info.get('product', ''),
                        "version": port_info.get('version', ''),
                        "extrainfo": port_info.get('extrainfo', '')
                    })

            # Extract OS information
            if 'osmatch' in nm[ip] and nm[ip]['osmatch']:
                # Get the best OS match
                os_match = nm[ip]['osmatch'][0]
                result["os"] = os_match.get('name', 'unknown')
                result["os_accuracy"] = os_match.get('accuracy', 0)
                logger.debug("OS detection: {} (accuracy: {}%)",
                             result["os"],
                             result["os_accuracy"])
            elif 'osclass' in nm[ip] and nm[ip]['osclass']:
                # Fallback to OS class
                os_class = nm[ip]['osclass'][0]
                os_type = os_class.get('type', '')
                os_family = os_class.get('osfamily', '')
                os_gen = os_class.get('osgen', '')
                result["os"] = f"{os_family} {os_gen}".strip() if os_family else os_type
                result["os_accuracy"] = os_class.get('accuracy', 0)
                logger.debug("OS class detection: {}", result["os"])

            logger.info("Parsed {} open ports on {} (MAC: {})",
                        len(result["ports"]), ip, result["mac"] or "N/A")

        except Exception as e:
            logger.error("Error parsing nmap results for {}: {}", ip, e)

        return result

    def merge_host_data(self, discovery_host: Dict, port_scan_result: Dict) -> Dict:
        """
        Merge discovery data with port scan results.

        Args:
            discovery_host: Host dict from discovery (with ip and mac)
            port_scan_result: Result from parse_nmap_ports

        Returns:
            Merged host dictionary with all information
        """
        merged = {
            "ip": discovery_host.get("ip"),
            "mac": port_scan_result.get("mac") or discovery_host.get("mac"),
            "vendor": port_scan_result.get("vendor", ""),
            "ports": port_scan_result.get("ports", []),
            "os": port_scan_result.get("os", "unknown"),
            "os_accuracy": port_scan_result.get("os_accuracy", 0)
        }

        return merged

    def parse(self, ans) -> List[Dict]:
        """
        Legacy method for backward compatibility.
        Alias for parse_arp().

        Args:
            ans: Answered packets from scapy srp() function

        Returns:
            List of dictionaries with 'ip' and 'mac' keys
        """
        return self.parse_arp(ans)