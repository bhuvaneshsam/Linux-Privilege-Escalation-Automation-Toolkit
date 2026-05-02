import subprocess
import os
from utils.logger import log_info, log_critical, Spinner

class SUIDScanner:
    """
    Scans for SUID (Set User ID) and SGID (Set Group ID) binaries.
    Cross-references findings with GTFOBins-style dangerous binaries.
    """

    def __init__(self):
        self.findings = []
        # Common binaries that are dangerous when SUID bit is set
        self.gtfo_bins = [
            "find", "nano", "vim", "cp", "mv", "bash", "sh", "python", "perl", 
            "awk", "base64", "pkexec", "git", "screen", "tmux", "nice", 
            "zip", "tar", "nmap", "strace", "gdb"
        ]

    def scan_suid_sgid(self):
        """
        Executes a targeted search for SUID/SGID files.
        Avoids full root (/) scan to prevent permission errors and speed up execution.
        """
        log_info("Scanning for SUID/SGID binaries in system paths...")
        
        # High-value directories where exploitable SUIDs are usually found
        target_dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin", "/opt"]
        
        # Build the find command
        # -perm /6000 looks for either SUID (4000) or SGID (2000)
        search_paths = " ".join([d for d in target_dirs if os.path.exists(d)])
        cmd = f"find {search_paths} -type f -perm /6000 2>/dev/null"

        with Spinner("Hunting for privileged binaries..."):
            try:
                # Use subprocess.run with capture_output to handle exit codes manually
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                # We process output even if returncode is not 0 (e.g., partial permission denial)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    for path in lines:
                        self.analyze_binary(path)
                
            except Exception as e:
                self.findings.append({"error": f"Scanner failed: {str(e)}"})

    def analyze_binary(self, path):
        """Categorizes the risk of a found SUID/SGID binary."""
        binary_name = os.path.basename(path)
        risk = "Low"
        description = "Standard SUID/SGID binary detected."
        mitigation = "No immediate action required unless binary is non-standard."

        if binary_name in self.gtfo_bins:
            risk = "High"
            description = f"Dangerous binary '{binary_name}' has SUID/SGID bits set. Known bypass exists (GTFOBins)."
            mitigation = f"Remove SUID bit: 'chmod u-s {path}' or restrict execution."
            log_critical(f"Dangerous SUID: {path}")

        self.findings.append({
            "path": path,
            "binary": binary_name,
            "risk": risk,
            "description": description,
            "mitigation": mitigation
        })

    def run(self):
        """Main entry point for the module."""
        self.scan_suid_sgid()
        return self.findings

def scan_suid():
    """Wrapper function for main.py."""
    scanner = SUIDScanner()
    return scanner.run()

if __name__ == "__main__":
    # Test execution
    res = scan_suid()
    print(f"\nFound {len(res)} SUID/SGID binaries.")