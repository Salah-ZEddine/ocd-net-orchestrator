import os
import xml.etree.ElementTree as ET

class OSDetector:
    def __init__(self, command_executor, logger, scan_id):
        self.command_executor = command_executor
        self.logger = logger
        self.scan_id = scan_id
    
    def detect_os(self, ip):
        """OS detection with detailed process"""
        self.logger.log(f"Starting OS detection", "OS_DETECT_START", f"IP: {ip}")
        
        temp_file = f"/tmp/nmap_os_{self.scan_id}_{ip.replace('.', '_')}.xml"
        cmd = f"nmap -O --osscan-guess -T3 {ip} -oX {temp_file}"
        
        self.logger.log(f"OS detection command", "OS_CMD", cmd)
        
        stdout, stderr, returncode = self.command_executor.run_command(cmd, timeout=90)
        
        try:
            if os.path.exists(temp_file):
                self.logger.log(f"Parsing OS detection results", "OS_PARSE_START", f"file: {temp_file}")
                
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
                            self.logger.log(f"OS detected successfully", "OS_SUCCESS", 
                                    f"IP: {ip} -> {result}")
                            
                            os.remove(temp_file)
                            self.logger.log(f"OS temp file cleaned", "OS_CLEANUP", temp_file)
                            return result
                
                if not os_found:
                    self.logger.log(f"No OS fingerprint matched", "OS_NOT_FOUND", f"IP: {ip}")
                
                os.remove(temp_file)
                self.logger.log(f"OS temp file cleaned (no match)", "OS_CLEANUP_NO_MATCH", temp_file)
                
        except Exception as e:
            self.logger.log(f"OS detection error", "OS_ERROR", f"IP: {ip}, error: {e}")
            if os.path.exists(temp_file):
                os.remove(temp_file)
                self.logger.log(f"Cleaned OS temp file after error", "OS_CLEANUP_ERR", temp_file)
        
        return "Unknown"