import os
import xml.etree.ElementTree as ET
import ipaddress

class HostDiscovery:
    def __init__(self, command_executor, logger, scan_id):
        self.command_executor = command_executor
        self.logger = logger
        self.scan_id = scan_id
    
    def discover_active_hosts(self, subnet):
        """Reliable host discovery with detailed progress"""
        self.logger.log(f"🚀 Starting host discovery phase", "PHASE_START")
        self.logger.log(f"Network analysis", "NETWORK", f"subnet: {subnet}")
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            total_possible_hosts = network.num_addresses - 2
            self.logger.log(f"Network details", "NETWORK", 
                    f"size: {total_possible_hosts} hosts, range: {network[1]} - {network[-2]}")
        except Exception as e:
            self.logger.log(f"Network analysis failed", "NETWORK_ERR", str(e))
        
        temp_file = f"/tmp/nmap_discovery_{self.scan_id}.xml"
        
        cmd = f"nmap -sn -T3 --max-retries 2 --host-timeout 30s {subnet} -oX {temp_file}"
        
        self.logger.log(f"Starting Nmap discovery scan", "SCAN_START", "ping sweep (ICMP+ARP)")
        self.logger.log(f"Nmap command", "NMAP_CMD", cmd)
        
        stdout, stderr, returncode = self.command_executor.run_command(cmd, timeout=300)
        
        active_hosts = set()
        scan_details = ""
        
        try:
            if os.path.exists(temp_file):
                self.logger.log(f"Parsing Nmap XML output", "PARSE_START", f"file: {temp_file}")
                
                tree = ET.parse(temp_file)
                root = tree.getroot()
                
                hosts_found = 0
                hosts_checked = 0
                
                for host in root.findall('host'):
                    hosts_checked += 1
                    status = host.find('status')
                    
                    if status is not None and status.get('state') == 'up':
                        address = host.find('address')
                        if address is not None and address.get('addrtype') == 'ipv4':
                            ip = address.get('addr')
                            
                            if self._is_valid_host_ip(ip, subnet):
                                active_hosts.add(ip)
                                hosts_found += 1
                                self.logger.log(f"Host confirmed active", "HOST_UP", 
                                        f"IP: {ip}, total: {hosts_found}")
                            else:
                                self.logger.log(f"Host filtered (invalid)", "HOST_FILTER", 
                                        f"IP: {ip} - network/broadcast address")
                    else:
                        address = host.find('address')
                        if address is not None and address.get('addrtype') == 'ipv4':
                            ip = address.get('addr')
                            self.logger.log(f"Host not responding", "HOST_DOWN", f"IP: {ip}")
                
                os.remove(temp_file)
                self.logger.log(f"Nmap XML file cleaned up", "CLEANUP", temp_file)
                
                scan_details = f"scanned: {hosts_checked}, active: {hosts_found}"
                
                if hosts_found == 0:
                    self.logger.log(f"No active hosts found", "SCAN_EMPTY", 
                            "all hosts appear to be down or filtered")
                else:
                    self.logger.log(f"Host discovery successful", "SCAN_SUCCESS", 
                            f"found {hosts_found} active hosts")
                
        except Exception as e:
            self.logger.log(f"Error parsing discovery results", "PARSE_ERROR", str(e))
            if os.path.exists(temp_file):
                os.remove(temp_file)
                self.logger.log(f"Cleaned up temp file after error", "CLEANUP", temp_file)
        
        self.logger.log(f"🏁 Host discovery complete", "PHASE_END", 
                f"{len(active_hosts)} hosts | {scan_details}")
        return list(active_hosts)

    def _is_valid_host_ip(self, ip, subnet):
        """Verify IP is a valid host address with logging"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(subnet, strict=False)
            
            if ip_obj == network.network_address:
                return False
            if ip_obj == network.broadcast_address:
                return False
                
            return True
        except Exception as e:
            self.logger.log(f"IP validation error", "VALIDATION_ERR", f"IP: {ip}, error: {e}")
            return True