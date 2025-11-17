"""
ARP result parser class.
"""

from typing import List, Dict


class ARPResultParser:
    """
    Parses ARP scan results from scapy.

    Example:
        parser = ARPResultParser()
        hosts = parser.parse(ans)
    """

    def parse(self, ans) -> List[Dict]:
        """
        Parse ARP scan results.

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
        return hosts