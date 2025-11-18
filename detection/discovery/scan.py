from utils.logger import Logger
import uuid
import os
import sys
from datetime import datetime
from utils.command_executor import CommandExecutor
from services import HostDiscovery, HostResolver, PortScanner, OSDetector, HostScanner, ScanOrchestrator

class ReliableNetworkScanner:
    def __init__(self, subnet):
        self.subnet = subnet
        
        self.scan_id = str(uuid.uuid4())[:8]
        
        # Check root privileges
        if os.geteuid() != 0:
            print("❌ ERROR: This script must be run as root!")
            print("💡 Use: sudo python3 network_scanner.py")
            sys.exit(1)
            
        # Initialize all services
        self.logger = Logger()
        self.command_executor = CommandExecutor(self.logger)
        
        # Core services
        self.host_discovery = HostDiscovery(self.command_executor, self.logger, self.scan_id)
        self.host_resolver = HostResolver(self.command_executor, self.logger)
        self.port_scanner = PortScanner(self.command_executor, self.logger, self.scan_id)
        self.os_detector = OSDetector(self.command_executor, self.logger, self.scan_id)
        
        # Higher level services
        self.host_scanner = HostScanner(self.host_resolver, self.port_scanner, self.os_detector, self.logger)
        self.scan_orchestrator = ScanOrchestrator(self.host_discovery, self.host_scanner, self.logger, self.scan_id, self.subnet)
        
        print(f"🔧 Reliable Network Scanner Initialized")
        print(f"📡 Target: {subnet}")
        print(f"🆔 Scan ID: {self.scan_id}")
        print(f"⏰ Started: {datetime.now().isoformat()}")
        print("-" * 60)

    def run_scan(self):
        """Main entry point - just delegates to orchestrator"""
        return self.scan_orchestrator.run_scan()

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Reliable Network Scanner - Detailed Logging Version")
        print("Usage: sudo python3 scan.py <subnet>")
        print("Example: sudo python3 scan.py 192.168.1.0/24")
        sys.exit(1)
    
    subnet = sys.argv[1]
    
    try:
        import ipaddress
        ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print(f"❌ Invalid subnet: {subnet}")
        print("💡 Valid examples: 192.168.1.0/24, 10.0.0.0/16")
        sys.exit(1)
    
    # Run the reliable scanner
    print("🚀 Starting scanner...")
    scanner = ReliableNetworkScanner(subnet)
    results = scanner.run_scan()
    
    if results:
        print(f"\n✨ Network scan completed successfully!")
    else:
        print(f"\n💥 No active hosts found in the target subnet!")

if __name__ == "__main__":
    main()