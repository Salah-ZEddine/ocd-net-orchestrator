import json
import time
from datetime import datetime
import os 
class ScanOrchestrator:
    def __init__(self, host_discovery, host_scanner, logger, scan_id, subnet):
        self.host_discovery = host_discovery
        self.host_scanner = host_scanner
        self.logger = logger
        self.scan_id = scan_id
        self.subnet = subnet
        self.scan_results = []
    
    def run_scan(self, max_workers=10):
        """Main reliable scanning workflow with detailed progress"""
        print(f"\n Starting Network Scan")
        print("=" * 60)
        
        start_time = time.time()
        
        # Phase 1: Host discovery
        self.logger.log("PHASE 1: Host Discovery", "MAIN_PHASE", "Finding active hosts")
        active_hosts = self.host_discovery.discover_active_hosts(self.subnet)
        
        if not active_hosts:
            self.logger.log("No active hosts found. Exiting.", "SCAN_EMPTY", "scan complete")
            return None
        
        print(f"\n Found {len(active_hosts)} confirmed active hosts:")
        for i, host in enumerate(active_hosts, 1):
            print(f"   {i:2d}. {host}")
        
        # Phase 2: Scan each host SEQUENTIALLY (no threads)
        self.logger.log(f"PHASE 2: Host Scanning", "MAIN_PHASE", 
                f"Scanning {len(active_hosts)} hosts SEQUENTIALLY")
        
        successful_scans = 0
        failed_scans = 0
        
        # Simple sequential loop instead of ThreadPoolExecutor
        for i, host in enumerate(active_hosts, 1):
            try:
                result = self.host_scanner.scan_single_host(host)
                if result:
                    self.scan_results.append(result)
                    successful_scans += 1
                    progress_pct = (i / len(active_hosts)) * 100
                    self.logger.log(f"Scan progress", "PROGRESS", 
                            f"{i}/{len(active_hosts)} ({progress_pct:.1f}%) - {host} completed")
                else:
                    failed_scans += 1
                    self.logger.log(f"Scan failed for host", "HOST_FAILED", host)
                    
            except Exception as e:
                failed_scans += 1
                self.logger.log(f"Scan exception for host", "HOST_EXCEPTION", 
                        f"{host}, error: {e}")
        
        # Phase 3: Generate results
        self.logger.log("PHASE 3: Generating Results", "MAIN_PHASE", "Creating output files")
        return self.generate_results(start_time, successful_scans, failed_scans)
    
    def generate_results(self, start_time, successful_scans, failed_scans):
        """Generate final JSON output with detailed statistics"""
        scan_duration = time.time() - start_time
        
        total_ports = sum(len(host['open_ports']) for host in self.scan_results)
        hosts_with_ports = len([h for h in self.scan_results if h['port_count'] > 0])
        
        results = {
            'scan_metadata': {
                'scan_id': self.scan_id,
                'start_time': datetime.now().isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': round(scan_duration, 2),
                'subnet_scanned': self.subnet,
                'hosts_discovered': len(self.scan_results),
                'successful_scans': successful_scans,
                'failed_scans': failed_scans,
                'total_open_ports': total_ports,
                'hosts_with_open_ports': hosts_with_ports,
                'total_hosts_scanned': successful_scans + failed_scans
                
            },
            'network_devices': self.scan_results
        }
        
        today = datetime.now()
        date_dir = today.strftime("%m-%d-%Y")  # Format: 11-19-2025
        timestamp = today.strftime("%H%M%S")   # Format: 143025 (2:30:25 PM)
        
        # Create directory if it doesn't exist
        logs_dir = "logs"
        full_dir_path = os.path.join(logs_dir, date_dir)        
        if not os.path.exists(full_dir_path):
            os.makedirs(full_dir_path, exist_ok=True)
            self.logger.log(f"Created directory", "DIR_CREATED", f"path: {full_dir_path}")
        
        # Generate filename with timestamp
        filename = f"scan_{timestamp}.json"
        full_path = os.path.join(full_dir_path, filename)
        with open(full_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.print_summary(scan_duration, successful_scans, failed_scans, total_ports, filename)
        return results
    
    def print_summary(self, scan_duration, successful_scans, failed_scans, total_ports, filename):
        """Print scan summary"""
        print(f"\nScan Complete!")
        print("=" * 60)
        print(f" Duration: {scan_duration:.2f} seconds")
        print(f"Subnet: {self.subnet}")
        print(f" Confirmed Hosts: {len(self.scan_results)}")
        print(f" Successful: {successful_scans} |  Failed: {failed_scans}")
        print(f"total Open Ports: {total_ports}")
        print(f" Results: {filename}")
        
        if self.scan_results:
            print(f"\n Confirmed Devices:")
            print("-" * 70)
            for i, device in enumerate(self.scan_results, 1):
                ports_info = f"{device['port_count']} open ports" if device['port_count'] > 0 else "No open ports"
                hostname_display = device['hostname'][:20] if device['hostname'] != "Unknown" else "No hostname"
                print(f"  {i:2d}. {device['ip_address']:15} | {hostname_display:20} | {device['mac_address']:17} | {ports_info}")
        
        self.logger.log(f"Scan completely finished", "SCAN_COMPLETE", 
                f"duration: {scan_duration:.2f}s, results: {filename}")