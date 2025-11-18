import time
from datetime import datetime

class Logger:
    def __init__(self):
        self.start_time = time.time()
    
    def log(self, message, level="INFO", details=None):
        """Enhanced logging with timing and details"""
        timestamp = datetime.now().strftime("%H:%M:%S")
       
        
        log_line = f" [{level}] {message}"
        
        if details:
            log_line += f" | {details}"
            
        print(log_line)