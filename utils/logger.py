import sys
import time
import threading

class Colors:
    """Terminal colors for categorized logging."""
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def log_info(message):
    """General status updates."""
    print(f"{Colors.BLUE}[*]{Colors.END} {message}")

def log_success(message):
    """Task completed or positive result."""
    print(f"{Colors.GREEN}[+]{Colors.END} {message}")

def log_warn(message):
    """Informational finding or minor concern."""
    print(f"{Colors.YELLOW}[-]{Colors.END} {message}")

def log_critical(message):
    """High-risk security finding."""
    print(f"{Colors.RED}{Colors.BOLD}[!] CRITICAL: {message}{Colors.END}")

def log_error(message):
    """Script error or permission denied."""
    print(f"{Colors.RED}[X] ERROR: {message}{Colors.END}")

class Spinner:
    """
    A simple thread-based spinner to provide visual feedback 
    during long-running processes (like 'find' commands).
    """
    def __init__(self, message="Scanning..."):
        self.spinner = ['|', '/', '-', '\\']
        self.message = message
        self.running = False
        self.thread = None

    def _spin(self):
        idx = 0
        while self.running:
            sys.stdout.write(f"\r{Colors.CYAN}{self.spinner[idx % 4]}{Colors.END} {self.message}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r')

    def __enter__(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        if self.thread:
            self.thread.join()

# --- Example Usage (When run as a standalone script) ---
if __name__ == "__main__":
    log_info("Initializing Audit...")
    
    with Spinner("Searching for SUID binaries (this may take a moment)..."):
        time.sleep(3) # Simulating a search
        
    log_success("Search complete.")
    log_critical("Found writable /etc/passwd!")
    log_warn("Kernel is outdated.")
    log_error("Could not read /root/ directory (Permission Denied).")