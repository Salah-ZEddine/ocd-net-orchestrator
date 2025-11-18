import subprocess
import time

class CommandExecutor:
    def __init__(self, logger, timeout=120):
        self.logger = logger
        self.default_timeout = timeout
    
    def run_command(self, cmd, timeout=None):
        """Execute shell command with detailed logging"""
        timeout = timeout or self.default_timeout
        self.logger.log(f"Executing command", "CMD", f"'{cmd}' (timeout: {timeout}s)")
        
        try:
            start_cmd = time.time()
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            cmd_duration = time.time() - start_cmd
            
            self.logger.log(f"Command completed", "CMD_DONE", 
                    f"returncode: {result.returncode}, duration: {cmd_duration:.2f}s")
            
            if result.stderr and result.stderr.strip():
                self.logger.log(f"Command stderr", "CMD_ERR", result.stderr.strip())
                
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            self.logger.log(f"Command timeout", "CMD_TIMEOUT", f"after {timeout}s")
            return "", "Timeout", 1
        except Exception as e:
            self.logger.log(f"Command exception", "CMD_EXCEPT", str(e))
            return "", str(e), 1