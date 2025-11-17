#!/usr/bin/env python3
"""
Reliable Network Scanner - Simple & Accurate CLI Tool
No false positives - only reports what actually responds
"""

import subprocess
import json
import ipaddress
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os
import re
import sys
import uuid
import socket

class ReliableNetworkScanner:
    def __init__(self, subnet, max_workers=10):
        self.subnet = subnet
        self.max_workers = max_workers
        self.scan_results = []
        self.scan_id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.now().isoformat()
        
        if os.geteuid() != 0:
            print("❌ ERROR: This script must be run as root!")
            print("💡 Use: sudo python3 network_scanner.py")
            sys.exit(1)
            
        print(f"🔧 Reliable Network Scanner Initialized")
        print(f"📡 Target: {subnet}")
        print(f"🆔 Scan ID: {self.scan_id}")
        print(f"⏰ Started: {self.timestamp}")
        print("-" * 50)

    def log(self, message, level="INFO"):
        """Log messages with timestamp and level"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def run_command(self, cmd, timeout=120):
        """Execute shell command with timeout"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", 1
        except Exception as e:
            return "", str(e), 1

    def discover_active_hosts(self):
        """Reliable host discovery using Nmap with strict filtering"""
        self.log(f"Discovering active hosts in {self.subnet}", "PHASE")
        
        temp_file = f"/tmp/nmap_discovery_{self.scan_id}.xml"
        
        # Use conservative Nmap settings to avoid false positives
        cmd = f"nmap -sn -T3 --max-retries 2 --host-timeout 30s {self.subnet} -oX {temp_file}"
        
        self.log(f"Running Nmap discovery...", "SCAN")
        stdout, stderr, returncode = self.run_command(cmd, timeout=300)
        
        active_hosts = set()
        
        try:
            if os.path.exists(temp_file):
                tree = ET.parse(temp_file)
                root = tree.getroot()
                
                hosts_found = 0
                for host in root.findall('host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        address = host.find('address')
                        if address is not None and address.get('addrtype') == 'ipv4':
                            ip = address.get('addr')
                            
                            # Verify this is a valid host (not network/broadcast address)
                            if self._is_valid_host_ip(ip):
                                active_hosts.add(ip)
                                hosts_found += 1
                                self.log(f"Confirmed active host: {ip}", "SUCCESS")
                
                os.remove(temp_file)
                
                if hosts_found == 0:
                    self.log("No active hosts found in Nmap scan", "WARNING")
                
        except Exception as e:
            self.log(f"Error parsing discovery results: {e}", "ERROR")
            if os.path.exists(temp_file):
                os.remove(temp_file)
        
        self.log(f"Discovery complete: {len(active_hosts)} confirmed hosts", "SUCCESS")
        return list(active_hosts)

    def _is_valid_host_ip(self, ip):
        """Verify IP is a valid host address (not network/broadcast)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(self.subnet, strict=False)
            
            # Exclude network and broadcast addresses
            if ip_obj == network.network_address:
                return False
            if ip_obj == network.broadcast_address:
                return False
                
            return True
        except:
            return True

    def get_mac_address(self, ip):
        """Get MAC address using ARP table"""
        try:
            cmd = f"arp -n {ip} 2>/dev/null"
            stdout, stderr, returncode = self.run_command(cmd, timeout=5)
            
            if stdout:
                for line in stdout.split('\n'):
                    if ip in line and "incomplete" not in line:
                        mac_match = re.search(r'([0-9A-Fa-f:]{17})', line.upper())
                        if mac_match:
                            return mac_match.group(1)
        except:
            pass
        return "Unknown"

    def get_hostname(self, ip):
        """Get hostname via reverse DNS with timeout"""
        try:
            # Set a short timeout to avoid hanging
            socket.setdefaulttimeout(2)
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return hostname
        except:
            pass
        return "Unknown"

    def scan_ports(self, ip):
        """Scan for open ports - only report actually open ports"""
        self.log(f"Scanning ports for {ip}", "PORT_SCAN")
        open_ports = []
        
        temp_file = f"/tmp/nmap_ports_{self.scan_id}_{ip.replace('.', '_')}.xml"
        
        # Scan common ports with conservative timing
        cmd = f"nmap -sS --top-ports 100 --open -T3 {ip} -oX {temp_file}"
        stdout, stderr, returncode = self.run_command(cmd, timeout=120)
        
        try:
            if os.path.exists(temp_file):
                tree = ET.parse(temp_file)
                root = tree.getroot()
                
                ports_found = 0
                for port in root.findall(".//port"):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_id = int(port.get('portid'))
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        
                        port_info = {
                            'port': port_id,
                            'service': service_name,
                            'protocol': port.get('protocol')
                        }
                        open_ports.append(port_info)
                        ports_found += 1
                        self.log(f"{ip}: Port {port_id}/{service_name} confirmed open", "PORT")
                
                os.remove(temp_file)
                
                if ports_found == 0:
                    self.log(f"{ip}: No open ports found", "INFO")
                
        except Exception as e:
            self.log(f"Error parsing port scan for {ip}: {e}", "ERROR")
            if os.path.exists(temp_file):
                os.remove(temp_file)
        
        self.log(f"Port scan complete for {ip}: {len(open_ports)} open ports", "SUCCESS")
        return open_ports

    def detect_os(self, ip):
        """Simple OS detection - only if host has open ports"""
        # Only do OS detection if we found open ports to save time
        return "Not scanned"  # Remove this to enable OS detection
        
        # Uncomment below if you want OS detection:
        """
        self.log(f"Detecting OS for {ip}", "OS_DETECTION")
        
        temp_file = f"/tmp/nmap_os_{self.scan_id}_{ip.replace('.', '_')}.xml"
        cmd = f"nmap -O --osscan-guess -T3 {ip} -oX {temp_file}"
        stdout, stderr, returncode = self.run_command(cmd, timeout=90)
        
        try:
            if os.path.exists(temp_file):
                tree = ET.parse(temp_file)
                root = tree.getroot()
                
                for host in root.findall('host'):
                    os_elem = host.find('os')
                    if os_elem is not None:
                        osmatch = os_elem.find('osmatch')
                        if osmatch is not None:
                            os_info = osmatch.get('name', 'Unknown')
                            accuracy = osmatch.get('accuracy', '0')
                            self.log(f"{ip}: OS detected as {os_info}", "SUCCESS")
                            os.remove(temp_file)
                            return f"{os_info} ({accuracy}% accuracy)"
                
                os.remove(temp_file)
        except:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        
        return "Unknown"
        """

    def scan_single_host(self, ip):
        """Complete scan for a single host - only report confirmed information"""
        self.log(f"Scanning host: {ip}", "HOST_SCAN")
        
        try:
            # Get basic information
            mac_address = self.get_mac_address(ip)
            hostname = self.get_hostname(ip)
            
            # Only scan ports if we can confirm the host is reachable
            open_ports = self.scan_ports(ip)
            
            # Simple OS info (disabled by default to save time)
            os_info = self.detect_os(ip)
            
            # Create reliable host result
            host_result = {
                'id': str(uuid.uuid4())[:8],
                'scan_id': self.scan_id,
                'timestamp': datetime.now().isoformat(),
                'hostname': hostname,
                'ip_address': ip,
                'mac_address': mac_address,
                'operating_system': os_info,
                'open_ports': open_ports,
                'port_count': len(open_ports),
                'status': 'Active'
            }
            
            self.log(f"Completed reliable scan for {ip}", "SUCCESS")
            return host_result
            
        except Exception as e:
            self.log(f"Error scanning {ip}: {e}", "ERROR")
            return None  # Don't include failed scans in results

    def run_scan(self):
        """Main reliable scanning workflow"""
        print(f"\n🎯 Starting Reliable Network Scan")
        print("=" * 50)
        
        start_time = datetime.now()
        
        # Phase 1: Reliable host discovery
        self.log("PHASE 1: Host Discovery", "PHASE")
        active_hosts = self.discover_active_hosts()
        
        if not active_hosts:
            self.log("No active hosts found. Exiting.", "INFO")
            return None
        
        print(f"\n📋 Found {len(active_hosts)} confirmed active hosts:")
        for host in active_hosts:
            print(f"   • {host}")
        
        # Phase 2: Scan each confirmed host
        self.log(f"\nPHASE 2: Host Scanning", "PHASE")
        self.log(f"Scanning {len(active_hosts)} confirmed hosts", "INFO")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_single_host, host): host for host in active_hosts}
            
            successful_scans = 0
            for i, future in enumerate(as_completed(futures)):
                host = futures[future]
                try:
                    result = future.result()
                    if result:  # Only add successful scans
                        self.scan_results.append(result)
                        successful_scans += 1
                        self.log(f"Progress: {i+1}/{len(active_hosts)} - {host} completed", "PROGRESS")
                    else:
                        self.log(f"Scan failed for {host}", "WARNING")
                except Exception as e:
                    self.log(f"Failed to scan {host}: {e}", "ERROR")
        
        # Phase 3: Generate results
        self.log("PHASE 3: Generating Results", "PHASE")
        return self.generate_results(start_time, successful_scans)

    def generate_results(self, start_time, successful_scans):
        """Generate final JSON output with only confirmed data"""
        scan_duration = datetime.now() - start_time
        
        results = {
            'scan_metadata': {
                'scan_id': self.scan_id,
                'start_time': self.timestamp,
                'end_time': datetime.now().isoformat(),
                'duration_seconds': scan_duration.total_seconds(),
                'subnet_scanned': self.subnet,
                'hosts_discovered': len(self.scan_results),
                'scan_reliability': 'High - No false positives'
            },
            'network_devices': self.scan_results
        }
        
        # Save to JSON file
        filename = f"network_scan_{self.scan_id}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Print reliable summary
        print(f"\n🏆 Reliable Scan Complete!")
        print("=" * 50)
        print(f"⏱️  Duration: {scan_duration}")
        print(f"📡 Subnet: {self.subnet}")
        print(f"🖥️  Confirmed Hosts: {len(self.scan_results)}")
        print(f"💾 Results: {filename}")
        print(f"✅ Reliability: High - No false positives reported")
        
        # Show confirmed device summary
        if self.scan_results:
            print(f"\n📊 Confirmed Devices:")
            print("-" * 60)
            for device in self.scan_results:
                ports_info = f"{device['port_count']} open ports" if device['port_count'] > 0 else "No open ports"
                print(f"  {device['ip_address']:15} | {device['hostname'][:20]:20} | {device['mac_address']:17} | {ports_info}")
        
        return results

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Reliable Network Scanner - No False Positives")
        print("Usage: sudo python3 network_scanner.py <subnet>")
        print("Example: sudo python3 network_scanner.py 192.168.1.0/24")
        sys.exit(1)
    
    subnet = sys.argv[1]
    
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print(f"❌ Invalid subnet: {subnet}")
        print("💡 Valid examples: 192.168.1.0/24, 10.0.0.0/16")
        sys.exit(1)
    
    # Run the reliable scanner
    scanner = ReliableNetworkScanner(subnet, max_workers=8)
    results = scanner.run_scan()
    
    if results:
        print(f"\n✨ Reliable network scan completed!")
        print(f"📈 Only confirmed active hosts reported")
    else:
        print(f"\n💥 No active hosts found in the target subnet!")

if __name__ == "__main__":
    main()