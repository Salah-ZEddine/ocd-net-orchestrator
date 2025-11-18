import uuid
import time
from datetime import datetime

class HostScanner:
    def __init__(self, host_resolver, port_scanner, os_detector, logger):
        self.host_resolver = host_resolver
        self.port_scanner = port_scanner
        self.os_detector = os_detector
        self.logger = logger
    
    def scan_single_host(self, ip):
        """Complete scan for a single host by orchestrating services"""
        self.logger.log(f"🚀 Starting comprehensive host scan", "HOST_SCAN_START", f"IP: {ip}")
        host_start_time = time.time()
        
        try:
            # Get basic information
            self.logger.log(f"Phase 1: Basic host information", "HOST_PHASE", "MAC and hostname")
            mac_address = self.host_resolver.get_mac_address(ip)
            hostname = self.host_resolver.get_hostname(ip)
            
            # Port scanning
            self.logger.log(f"Phase 2: Port scanning", "HOST_PHASE", "TCP port scan")
            open_ports = self.port_scanner.scan_ports(ip)
            
            # OS detection
            self.logger.log(f"Phase 3: OS detection", "HOST_PHASE", "OS fingerprinting")
            os_info = self.os_detector.detect_os(ip)
            
            # Create host result
            host_result = {
                'id': str(uuid.uuid4())[:8],
                'scan_id': str(uuid.uuid4())[:8],
                'timestamp': datetime.now().isoformat(),
                'hostname': hostname,
                'ip_address': ip,
                'mac_address': mac_address,
                'operating_system': os_info,
                'open_ports': open_ports,
                'port_count': len(open_ports),
                'status': 'Active'
            }
            
            host_duration = time.time() - host_start_time
            self.logger.log(f"✅ Host scan completed", "HOST_SCAN_SUCCESS", 
                    f"IP: {ip}, duration: {host_duration:.2f}s, ports: {len(open_ports)}")
            
            return host_result
            
        except Exception as e:
            host_duration = time.time() - host_start_time
            self.logger.log(f"❌ Host scan failed", "HOST_SCAN_ERROR", 
                    f"IP: {ip}, duration: {host_duration:.2f}s, error: {e}")
            return None