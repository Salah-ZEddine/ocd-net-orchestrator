import re
import socket
import time

class HostResolver:
    def __init__(self, command_executor, logger):
        self.command_executor = command_executor
        self.logger = logger
    
    def get_mac_address(self, ip):
        """Get MAC address with detailed lookup process"""
        self.logger.log(f"Starting MAC address lookup", "MAC_LOOKUP", f"IP: {ip}")
        
        try:
            cmd = f"arp -n {ip} 2>/dev/null"
            stdout, stderr, returncode = self.command_executor.run_command(cmd, timeout=5)
            
            if stdout:
                for line in stdout.split('\n'):
                    if ip in line:
                        if "incomplete" in line:
                            self.logger.log(f"MAC lookup incomplete", "MAC_INCOMPLETE", f"IP: {ip}")
                            continue
                            
                        mac_match = re.search(r'([0-9A-Fa-f:]{17})', line.upper())
                        if mac_match:
                            mac = mac_match.group(1)
                            self.logger.log(f"MAC found via ARP table", "MAC_FOUND", f"IP: {ip} -> MAC: {mac}")
                            return mac
                        else:
                            self.logger.log(f"MAC regex failed", "MAC_REGEX_FAIL", f"line: {line.strip()}")
            
            self.logger.log(f"MAC not found in ARP table", "MAC_NOT_FOUND", f"IP: {ip}")
            
        except Exception as e:
            self.logger.log(f"MAC lookup error", "MAC_ERROR", f"IP: {ip}, error: {e}")
        
        return "Unknown"

    def get_hostname(self, ip):
        """Get hostname with detailed DNS process"""
        self.logger.log(f"Starting hostname resolution", "DNS_LOOKUP", f"IP: {ip}")
        
        try:
            socket.setdefaulttimeout(2)
            self.logger.log(f"Attempting reverse DNS", "DNS_QUERY", f"IP: {ip}")
            
            start_dns = time.time()
            hostname = socket.gethostbyaddr(ip)[0]
            dns_duration = time.time() - start_dns
            
            if hostname and hostname != ip:
                self.logger.log(f"Hostname resolved", "DNS_SUCCESS", 
                        f"IP: {ip} -> {hostname} (took {dns_duration:.2f}s)")
                return hostname
            else:
                self.logger.log(f"Hostname same as IP", "DNS_SAME", f"IP: {ip}")
                
        except socket.herror as e:
            self.logger.log(f"DNS host error", "DNS_FAIL", f"IP: {ip}, error: {e}")
        except socket.timeout:
            self.logger.log(f"DNS timeout", "DNS_TIMEOUT", f"IP: {ip}")
        except socket.gaierror as e:
            self.logger.log(f"DNS address error", "DNS_FAIL", f"IP: {ip}, error: {e}")
        except Exception as e:
            self.logger.log(f"DNS unexpected error", "DNS_ERROR", f"IP: {ip}, error: {e}")
        
        return "Unknown"