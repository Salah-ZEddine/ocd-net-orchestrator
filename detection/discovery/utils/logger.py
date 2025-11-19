import time
from datetime import datetime

class Logger:
    def __init__(self):
        self.start_time = time.time()
    
    def log(self, message, level="INFO", details=None):
     COLOR_MAP = {
        # Success/Positive - Green
        "SUCCESS": "\033[92m",
        "MAC_FOUND": "\033[92m",
        "PORT_SUCCESS": "\033[92m",
        "PORT_OPEN": "\033[92m",
        "OS_SUCCESS": "\033[92m",
        "HOST_SCAN_SUCCESS": "\033[92m",
        "SCAN_COMPLETE": "\033[92m",
        "DIR_CREATED": "\033[92m",
        "CMD_DONE": "\033[92m",
        "PROGRESS": "\033[92m",
        "HOST_UP":"\033[92m",
        
        # Errors/Failures - Red
        "FAIL": "\033[91m",
        "ERROR": "\033[91m",
        "DNS_FAIL": "\033[91m",
        "HOST_FAILED": "\033[91m",
        "HOST_EXCEPTION": "\033[91m",
        "MAC_INCOMPLETE": "\033[91m",
        "MAC_NOT_FOUND": "\033[91m",

        "MAC_REGEX_FAIL": "\033[91m",
        "OS_NOT_FOUND": "\033[91m",
        "PORT_NONE": "\033[91m",
        "SCAN_EMPTY": "\033[91m",
        
        # Warnings/Neutral - Yellow
        "WARNING": "\033[93m",
        "OS_CLEANUP_NO_MATCH": "\033[93m",
        
        # Informational/Process - Blue
        "INFO": "\033[94m",
        "HOST_SCAN_START": "\033[94m",
        "HOST_PHASE": "\033[94m",
        "MAC_LOOKUP": "\033[94m",
        "DNS_LOOKUP": "\033[94m",
        "DNS_QUERY": "\033[94m",
        "PORT_SCAN_START": "\033[94m",
        "PORT_CMD": "\033[94m",
        "PORT_TEMP_FILE": "\033[94m",
        "PORT_PARSE_START": "\033[94m",
        "PORT_CLEANUP": "\033[94m",
        "PORT_SCAN_END": "\033[94m",
        "OS_DETECT_START": "\033[94m",
        "OS_CMD": "\033[94m",
        "OS_PARSE_START": "\033[94m",
        "OS_CLEANUP": "\033[94m",
        "CMD": "\033[94m",
        "MAIN_PHASE": "\033[94m",
        "NMAP_CMD": "\033[94m",
        
        
        # Special/Highlights - Cyan
        "SCAN_START": "\033[96m",
        "NETWORK": "\033[96m",
        "PHASE_START": "\033[96m",
        "PARSE_START":"\033[96m"
    }
    
     RESET = "\033[0m"
    
    # Get color for this level, default to white if not found
     color = COLOR_MAP.get(level, "\033[97m")
    
     log_line = f"{color}[{level}]{RESET} {message}"
    
     if details:
        log_line += f" | {details}"
        
     print(log_line)