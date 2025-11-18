import os
import xml.etree.ElementTree as ET

class PortScanner:
    def __init__(self, command_executor, logger, scan_id):
        self.command_executor = command_executor
        self.logger = logger
        self.scan_id = scan_id
    
    def scan_ports(self, ip):
        """Scan for open ports with detailed progress"""
        self.logger.log(f"🚀 Starting port scan", "PORT_SCAN_START", f"IP: {ip}")
        
        open_ports = []
        temp_file = f"/tmp/nmap_ports_{self.scan_id}_{ip.replace('.', '_')}.xml"
        
        cmd = f"nmap -sS --top-ports 100 --open -T3 {ip} -oX {temp_file}"
        
        self.logger.log(f"Port scan command", "PORT_CMD", cmd)
        self.logger.log(f"Temp file", "PORT_TEMP_FILE", temp_file)
        
        stdout, stderr, returncode = self.command_executor.run_command(cmd, timeout=120)
        
        try:
            if os.path.exists(temp_file):
                self.logger.log(f"Parsing port scan results", "PORT_PARSE_START", f"file: {temp_file}")
                
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
                        
                        self.logger.log(f"Open port found", "PORT_OPEN", 
                                f"IP: {ip}, {protocol}/{port_id} ({service_name})")
                
                os.remove(temp_file)
                self.logger.log(f"Port scan temp file cleaned", "PORT_CLEANUP", temp_file)
                
                if ports_found == 0:
                    self.logger.log(f"No open ports found", "PORT_NONE", 
                            f"IP: {ip}, checked {total_ports_checked} ports")
                else:
                    self.logger.log(f"Port scan completed", "PORT_SUCCESS", 
                            f"IP: {ip}, {ports_found} open ports out of {total_ports_checked} checked")
                
        except Exception as e:
            self.logger.log(f"Port scan parsing error", "PORT_PARSE_ERROR", 
                    f"IP: {ip}, error: {e}")
            if os.path.exists(temp_file):
                os.remove(temp_file)
                self.logger.log(f"Cleaned port temp file after error", "PORT_CLEANUP_ERR", temp_file)
        
        self.logger.log(f"🏁 Port scan complete", "PORT_SCAN_END", 
                f"IP: {ip}, total open ports: {len(open_ports)}")
        return open_ports