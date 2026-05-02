import subprocess
import os
from utils.logger import log_info, log_warn, log_critical, Spinner

class CapabilityScanner:
    """
    Scans for Linux Capabilities (getcap).
    Identifies binaries that have been granted specific root-level 
    powers without needing the full SUID bit.
    """

    def __init__(self):
        self.findings = []
        # Capabilities that are frequently used for privilege escalation
        self.dangerous_caps = [
            "cap_setuid",       # Can change User ID (Equivalent to SUID)
            "cap_setgid",       # Can change Group ID
            "cap_dac_override", # Can bypass file read/write/execute checks
            "cap_sys_admin",    # The 'new root' - covers many administrative tasks
            "cap_chown",        # Can change ownership of any file
            "cap_net_raw",      # Can sniff network traffic
            "cap_sys_ptrace"    # Can debug/inject into other processes
        ]

    def is_getcap_installed(self):
        """Checks if the 'getcap' utility is available on the system."""
        try:
            subprocess.check_output("which getcap", shell=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def scan_capabilities(self):
        """
        Runs getcap recursively on common binary directories.
        Parses output to identify dangerous configurations.
        """
        if not self.is_getcap_installed():
            log_warn("'getcap' command not found. Skipping Capability scan.")
            return

        log_info("Scanning binaries for dangerous Linux Capabilities...")
        
        # Directories most likely to contain custom-capped binaries
        target_dirs = "/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt"
        
        with Spinner("Running getcap enumeration..."):
            # Command: getcap -r (recursive)
            cmd = f"getcap -r {target_dirs} 2>/dev/null"
            try:
                output = subprocess.check_output(cmd, shell=True).decode().strip()
                if not output:
                    return

                for line in output.splitlines():
                    # Format: /path/to/binary = cap_name+ep
                    parts = line.split(" = ")
                    if len(parts) != 2:
                        continue
                    
                    file_path = parts[0]
                    cap_info = parts[1]
                    
                    risk = "Low"
                    description = f"Capability '{cap_info}' assigned."

                    # Check for dangerous matches
                    for dangerous in self.dangerous_caps:
                        if dangerous in cap_info.lower():
                            risk = "High"
                            description = f"Dangerous capability '{dangerous}' found. Potential for Privilege Escalation."
                            log_critical(f"Dangerous Cap: {file_path} ({cap_info})")
                            break
                    
                    self.findings.append({
                        "path": file_path,
                        "capabilities": cap_info,
                        "risk": risk,
                        "description": description
                    })

            except subprocess.CalledProcessError:
                pass

    def run(self):
        """Main execution point for the module."""
        self.scan_capabilities()
        return self.findings

def scan_capabilities():
    """Wrapper function for main.py."""
    scanner = CapabilityScanner()
    return scanner.run()

if __name__ == "__main__":
    # Standalone test execution
    res = scan_capabilities()
    print(f"\nAudit complete. Found {len(res)} binaries with capabilities.")