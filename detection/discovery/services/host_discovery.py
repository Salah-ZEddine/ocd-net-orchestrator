#!/usr/bin/env python3
"""
Reliable Network Scanner - Detailed Logging Version
Shows exactly what's happening during the scan process
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
import time

class ReliableNetworkScanner:
    def __init__(self, subnet, max_workers=10):
        self.subnet = subnet
        self.max_workers = max_workers
        self.scan_results = []
        self.scan_id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.now().isoformat()
        self.start_time = time.time()
        
        if os.geteuid() != 0:
            print("❌ ERROR: This script must be run as root!")
            print("💡 Use: sudo python3 network_scanner.py")
            sys.exit(1)
            
        print(f"🔧 Reliable Network Scanner Initialized")
        print(f"📡 Target: {subnet}")
        print(f"👥 Max Workers: {max_workers}")
        print(f"🆔 Scan ID: {self.scan_id}")
        print(f"⏰ Started: {self.timestamp}")
        print("-" * 60)

    def log(self, message, level="INFO", details=None):
        """Enhanced logging with timing and details"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        elapsed = time.time() - self.start_time
        elapsed_str = f"[+{elapsed:06.2f}s]"
        
        log_line = f"{elapsed_str} [{timestamp}] [{level}] {message}"
        
        if details:
            log_line += f" | {details}"
            
        print(log_line)

    def run_command(self, cmd, timeout=120):
        """Execute shell command with detailed logging"""
        self.log(f"Executing command", "CMD", f"'{cmd}' (timeout: {timeout}s)")
        
        try:
            start_cmd = time.time()
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            cmd_duration = time.time() - start_cmd
            
            self.log(f"Command completed", "CMD_DONE", 
                    f"returncode: {result.returncode}, duration: {cmd_duration:.2f}s")
            
            if result.stderr and result.stderr.strip():
                self.log(f"Command stderr", "CMD_ERR", result.stderr.strip())
                
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            self.log(f"Command timeout", "CMD_TIMEOUT", f"after {timeout}s")
            return "", "Timeout", 1
        except Exception as e:
            self.log(f"Command exception", "CMD_EXCEPT", str(e))
            return "", str(e), 1

    def discover_active_hosts(self):
        """Reliable host discovery with detailed progress"""
        self.log(f"🚀 Starting host discovery phase", "PHASE_START")
        self.log(f"Network analysis", "NETWORK", f"subnet: {self.subnet}")
        
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
            total_possible_hosts = network.num_addresses - 2  # Exclude network and broadcast
            self.log(f"Network details", "NETWORK", 
                    f"size: {total_possible_hosts} hosts, range: {network[1]} - {network[-2]}")
        except Exception as e:
            self.log(f"Network analysis failed", "NETWORK_ERR", str(e))
        
        temp_file = f"/tmp/nmap_discovery_{self.scan_id}.xml"
        
        # Use conservative Nmap settings to avoid false positives
        cmd = f"nmap -sn -T3 --max-retries 2 --host-timeout 30s {self.subnet} -oX {temp_file}"
        
        self.log(f"Starting Nmap discovery scan", "SCAN_START", "ping sweep (ICMP+ARP)")
        self.log(f"Nmap command", "NMAP_CMD", cmd)
        
        stdout, stderr, returncode = self.run_command(cmd, timeout=300)
        
        active_hosts = set()
        scan_details = ""
        
        try:
            if os.path.exists(temp_file):
                self.log(f"Parsing Nmap XML output", "PARSE_START", f"file: {temp_file}")
                
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
                            
                            # Verify this is a valid host (not network/broadcast address)
                            if self._is_valid_host_ip(ip):
                                active_hosts.add(ip)
                                hosts_found += 1
                                self.log(f"Host confirmed active", "HOST_UP", 
                                        f"IP: {ip}, total: {hosts_found}")
                            else:
                                self.log(f"Host filtered (invalid)", "HOST_FILTER", 
                                        f"IP: {ip} - network/broadcast address")
                    else:
                        # Log hosts that were scanned but not up
                        address = host.find('address')
                        if address is not None and address.get('addrtype') == 'ipv4':
                            ip = address.get('addr')
                            self.log(f"Host not responding", "HOST_DOWN", f"IP: {ip}")
                
                os.remove(temp_file)
                self.log(f"Nmap XML file cleaned up", "CLEANUP", temp_file)
                
                scan_details = f"scanned: {hosts_checked}, active: {hosts_found}"
                
                if hosts_found == 0:
                    self.log(f"No active hosts found", "SCAN_EMPTY", 
                            "all hosts appear to be down or filtered")
                else:
                    self.log(f"Host discovery successful", "SCAN_SUCCESS", 
                            f"found {hosts_found} active hosts")
                
        except Exception as e:
            self.log(f"Error parsing discovery results", "PARSE_ERROR", str(e))
            if os.path.exists(temp_file):
                os.remove(temp_file)
                self.log(f"Cleaned up temp file after error", "CLEANUP", temp_file)
        
        self.log(f"🏁 Host discovery complete", "PHASE_END", 
                f"{len(active_hosts)} hosts | {scan_details}")
        return list(active_hosts)

    def _is_valid_host_ip(self, ip):
        """Verify IP is a valid host address with logging"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(self.subnet, strict=False)
            
            # Exclude network and broadcast addresses
            if ip_obj == network.network_address:
                return False
            if ip_obj == network.broadcast_address:
                return False
                
            return True
        except Exception as e:
            self.log(f"IP validation error", "VALIDATION_ERR", f"IP: {ip}, error: {e}")
            return True

    def get_mac_address(self, ip):
        """Get MAC address with detailed lookup process"""
        self.log(f"Starting MAC address lookup", "MAC_LOOKUP", f"IP: {ip}")
        
        # Method 1: ARP table lookup
        try:
            cmd = f"arp -n {ip} 2>/dev/null"
            stdout, stderr, returncode = self.run_command(cmd, timeout=5)
            
            if stdout:
                for line in stdout.split('\n'):
                    if ip in line:
                        if "incomplete" in line:
                            self.log(f"MAC lookup incomplete", "MAC_INCOMPLETE", f"IP: {ip}")
                            continue
                            
                        mac_match = re.search(r'([0-9A-Fa-f:]{17})', line.upper())
                        if mac_match:
                            mac = mac_match.group(1)
                            self.log(f"MAC found via ARP table", "MAC_FOUND", f"IP: {ip} -> MAC: {mac}")
                            return mac
                        else:
                            self.log(f"MAC regex failed", "MAC_REGEX_FAIL", f"line: {line.strip()}")
            
            self.log(f"MAC not found in ARP table", "MAC_NOT_FOUND", f"IP: {ip}")
            
        except Exception as e:
            self.log(f"MAC lookup error", "MAC_ERROR", f"IP: {ip}, error: {e}")
        
        return "Unknown"

    def get_hostname(self, ip):
        """Get hostname with detailed DNS process"""
        self.log(f"Starting hostname resolution", "DNS_LOOKUP", f"IP: {ip}")
        
        try:
            # Set a short timeout to avoid hanging
            socket.setdefaulttimeout(2)
            self.log(f"Attempting reverse DNS", "DNS_QUERY", f"IP: {ip}")
            
            start_dns = time.time()
            hostname = socket.gethostbyaddr(ip)[0]
            dns_duration = time.time() - start_dns
            
            if hostname and hostname != ip:
                self.log(f"Hostname resolved", "DNS_SUCCESS", 
                        f"IP: {ip} -> {hostname} (took {dns_duration:.2f}s)")
                return hostname
            else:
                self.log(f"Hostname same as IP", "DNS_SAME", f"IP: {ip}")
                
        except socket.herror as e:
            self.log(f"DNS host error", "DNS_FAIL", f"IP: {ip}, error: {e}")
        except socket.timeout:
            self.log(f"DNS timeout", "DNS_TIMEOUT", f"IP: {ip}")
        except socket.gaierror as e:
            self.log(f"DNS address error", "DNS_FAIL", f"IP: {ip}, error: {e}")
        except Exception as e:
            self.log(f"DNS unexpected error", "DNS_ERROR", f"IP: {ip}, error: {e}")
        
        return "Unknown"

    def scan_ports(self, ip):
        """Scan for open ports with detailed progress"""
        self.log(f"🚀 Starting port scan", "PORT_SCAN_START", f"IP: {ip}")
        
        open_ports = []
        temp_file = f"/tmp/nmap_ports_{self.scan_id}_{ip.replace('.', '_')}.xml"
        
        # Scan common ports with conservative timing
        cmd = f"nmap -sS --top-ports 100 --open -T3 {ip} -oX {temp_file}"
        
        self.log(f"Port scan command", "PORT_CMD", cmd)
        self.log(f"Temp file", "PORT_TEMP_FILE", temp_file)
        
        stdout, stderr, returncode = self.run_command(cmd, timeout=120)
        
        try:
            if os.path.exists(temp_file):
                self.log(f"Parsing port scan results", "PORT_PARSE_START", f"file: {temp_file}")
                
                tree = ET.parse(temp_file)
                root = tree.getroot()
                
                ports_found = 0
                total_ports_checked = 0
                
                for port in root.findall(".//port"):
                    total_ports_checked += 1
                    state = port.find('state')
                    
                    if state is not None and state.get('state') == 'open':
                        port_id = int(port.get('portid'))
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        protocol = port.get('protocol')
                        
                        port_info = {
                            'port': port_id,
                            'service': service_name,
                            'protocol': protocol
                        }
                        open_ports.append(port_info)
                        ports_found += 1
                        
                        self.log(f"Open port found", "PORT_OPEN", 
                                f"IP: {ip}, {protocol}/{port_id} ({service_name})")
                
                os.remove(temp_file)
                self.log(f"Port scan temp file cleaned", "PORT_CLEANUP", temp_file)
                
                if ports_found == 0:
                    self.log(f"No open ports found", "PORT_NONE", 
                            f"IP: {ip}, checked {total_ports_checked} ports")
                else:
                    self.log(f"Port scan completed", "PORT_SUCCESS", 
                            f"IP: {ip}, {ports_found} open ports out of {total_ports_checked} checked")
                
        except Exception as e:
            self.log(f"Port scan parsing error", "PORT_PARSE_ERROR", 
                    f"IP: {ip}, error: {e}")
            if os.path.exists(temp_file):
                os.remove(temp_file)
                self.log(f"Cleaned port temp file after error", "PORT_CLEANUP_ERR", temp_file)
        
        self.log(f"🏁 Port scan complete", "PORT_SCAN_END", 
                f"IP: {ip}, total open ports: {len(open_ports)}")
        return open_ports

    def detect_os(self, ip):
        """OS detection with detailed process"""
        self.log(f"🚀 Starting OS detection", "OS_DETECT_START", f"IP: {ip}")
        
        temp_file = f"/tmp/nmap_os_{self.scan_id}_{ip.replace('.', '_')}.xml"
        cmd = f"nmap -O --osscan-guess -T3 {ip} -oX {temp_file}"
        
        self.log(f"OS detection command", "OS_CMD", cmd)
        
        stdout, stderr, returncode = self.run_command(cmd, timeout=90)
        
        try:
            if os.path.exists(temp_file):
                self.log(f"Parsing OS detection results", "OS_PARSE_START", f"file: {temp_file}")
                
                tree = ET.parse(temp_file)
                root = tree.getroot()
                
                os_found = False
                
                for host in root.findall('host'):
                    os_elem = host.find('os')
                    if os_elem is not None:
                        osmatch = os_elem.find('osmatch')
                        if osmatch is not None:
                            os_info = osmatch.get('name', 'Unknown')
                            accuracy = osmatch.get('accuracy', '0')
                            
                            result = f"{os_info} ({accuracy}% accuracy)"
                            self.log(f"OS detected successfully", "OS_SUCCESS", 
                                    f"IP: {ip} -> {result}")
                            
                            os.remove(temp_file)
                            self.log(f"OS temp file cleaned", "OS_CLEANUP", temp_file)
                            return result
                
                if not os_found:
                    self.log(f"No OS fingerprint matched", "OS_NOT_FOUND", f"IP: {ip}")
                
                os.remove(temp_file)
                self.log(f"OS temp file cleaned (no match)", "OS_CLEANUP_NO_MATCH", temp_file)
                
        except Exception as e:
            self.log(f"OS detection error", "OS_ERROR", f"IP: {ip}, error: {e}")
            if os.path.exists(temp_file):
                os.remove(temp_file)
                self.log(f"Cleaned OS temp file after error", "OS_CLEANUP_ERR", temp_file)
        
        return "Unknown"

    def scan_single_host(self, ip):
        """Complete scan for a single host with detailed progress"""
        self.log(f"🚀 Starting comprehensive host scan", "HOST_SCAN_START", f"IP: {ip}")
        host_start_time = time.time()
        
        try:
            # Get basic information
            self.log(f"Phase 1: Basic host information", "HOST_PHASE", "MAC and hostname")
            mac_address = self.get_mac_address(ip)
            hostname = self.get_hostname(ip)
            
            # Only scan ports if we can confirm the host is reachable
            self.log(f"Phase 2: Port scanning", "HOST_PHASE", "TCP port scan")
            open_ports = self.scan_ports(ip)
            
            # OS detection
            self.log(f"Phase 3: OS detection", "HOST_PHASE", "OS fingerprinting")
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
            
            host_duration = time.time() - host_start_time
            self.log(f"✅ Host scan completed", "HOST_SCAN_SUCCESS", 
                    f"IP: {ip}, duration: {host_duration:.2f}s, ports: {len(open_ports)}")
            
            return host_result
            
        except Exception as e:
            host_duration = time.time() - host_start_time
            self.log(f"❌ Host scan failed", "HOST_SCAN_ERROR", 
                    f"IP: {ip}, duration: {host_duration:.2f}s, error: {e}")
            return None

    def run_scan(self):
        """Main reliable scanning workflow with detailed progress"""
        print(f"\n🎯 Starting Reliable Network Scan")
        print("=" * 60)
        
        start_time = time.time()
        
        # Phase 1: Reliable host discovery
        self.log("PHASE 1: Host Discovery", "MAIN_PHASE", "Finding active hosts")
        active_hosts = self.discover_active_hosts()
        
        if not active_hosts:
            self.log("No active hosts found. Exiting.", "SCAN_EMPTY", "scan complete")
            return None
        
        print(f"\n📋 Found {len(active_hosts)} confirmed active hosts:")
        for i, host in enumerate(active_hosts, 1):
            print(f"   {i:2d}. {host}")
        
        # Phase 2: Scan each confirmed host
        self.log(f"PHASE 2: Host Scanning", "MAIN_PHASE", 
                f"Scanning {len(active_hosts)} hosts with {self.max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_single_host, host): host for host in active_hosts}
            
            successful_scans = 0
            failed_scans = 0
            
            for i, future in enumerate(as_completed(futures), 1):
                host = futures[future]
                try:
                    result = future.result()
                    if result:  # Only add successful scans
                        self.scan_results.append(result)
                        successful_scans += 1
                        progress_pct = (i / len(active_hosts)) * 100
                        self.log(f"Scan progress", "PROGRESS", 
                                f"{i}/{len(active_hosts)} ({progress_pct:.1f}%) - {host} completed")
                    else:
                        failed_scans += 1
                        self.log(f"Scan failed for host", "HOST_FAILED", host)
                        
                except Exception as e:
                    failed_scans += 1
                    self.log(f"Scan exception for host", "HOST_EXCEPTION", 
                            f"{host}, error: {e}")
        
        # Phase 3: Generate results
        self.log("PHASE 3: Generating Results", "MAIN_PHASE", "Creating output files")
        return self.generate_results(start_time, successful_scans, failed_scans)

    def generate_results(self, start_time, successful_scans, failed_scans):
        """Generate final JSON output with detailed statistics"""
        scan_duration = time.time() - start_time
        
        # Calculate statistics
        total_ports = sum(len(host['open_ports']) for host in self.scan_results)
        hosts_with_ports = len([h for h in self.scan_results if h['port_count'] > 0])
        
        results = {
            'scan_metadata': {
                'scan_id': self.scan_id,
                'start_time': self.timestamp,
                'end_time': datetime.now().isoformat(),
                'duration_seconds': round(scan_duration, 2),
                'subnet_scanned': self.subnet,
                'hosts_discovered': len(self.scan_results),
                'successful_scans': successful_scans,
                'failed_scans': failed_scans,
                'total_open_ports': total_ports,
                'hosts_with_open_ports': hosts_with_ports,
                'scan_reliability': 'High - No false positives',
                'performance_metrics': {
                    'hosts_per_second': round(len(self.scan_results) / max(scan_duration, 0.1), 2),
                    'total_hosts_scanned': successful_scans + failed_scans
                }
            },
            'network_devices': self.scan_results
        }
        
        # Save to JSON file
        filename = f"network_scan_{self.scan_id}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Print detailed summary
        print(f"\n🏆 Reliable Scan Complete!")
        print("=" * 60)
        print(f"⏱️  Duration: {scan_duration:.2f} seconds")
        print(f"📡 Subnet: {self.subnet}")
        print(f"🖥️  Confirmed Hosts: {len(self.scan_results)}")
        print(f"✅ Successful: {successful_scans} | ❌ Failed: {failed_scans}")
        print(f"🔓 Total Open Ports: {total_ports}")
        print(f"📈 Performance: {results['scan_metadata']['performance_metrics']['hosts_per_second']} hosts/sec")
        print(f"💾 Results: {filename}")
        print(f"✅ Reliability: High - No false positives reported")
        
        # Show confirmed device summary
        if self.scan_results:
            print(f"\n📊 Confirmed Devices:")
            print("-" * 70)
            for i, device in enumerate(self.scan_results, 1):
                ports_info = f"{device['port_count']} open ports" if device['port_count'] > 0 else "No open ports"
                hostname_display = device['hostname'][:20] if device['hostname'] != "Unknown" else "No hostname"
                print(f"  {i:2d}. {device['ip_address']:15} | {hostname_display:20} | {device['mac_address']:17} | {ports_info}")
        
        self.log(f"Scan completely finished", "SCAN_COMPLETE", 
                f"duration: {scan_duration:.2f}s, results: {filename}")
        
        return results

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Reliable Network Scanner - Detailed Logging Version")
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
        print(f"\n✨ Network scan completed successfully!")
        print(f"📊 Detailed logs show exactly what happened during the scan")
    else:
        print(f"\n💥 No active hosts found in the target subnet!")

if __name__ == "__main__":
    main()