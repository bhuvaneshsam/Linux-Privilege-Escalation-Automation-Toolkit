import os
import subprocess
from utils.logger import log_info, log_warn, log_critical, Spinner

class PermissionScanner:
    """
    Audits the filesystem for insecure permissions.
    Focuses on world-writable files, sensitive configuration exposure,
    and improper ownership of system-critical paths.
    """

    def __init__(self):
        self.findings = []
        # Sensitive files that should NEVER be writable by a standard user
        self.critical_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/group",
            "/etc/crontab",
            "/etc/exports",
            "/etc/fstab",
            "/root/.ssh/authorized_keys"
        ]

    def check_critical_files(self):
        """Checks if high-value system files are writable by the current user."""
        log_info("Checking integrity of critical system files...")
        for file_path in self.critical_files:
            if os.path.exists(file_path):
                # os.W_OK checks if the current process/user has write access
                if os.access(file_path, os.W_OK):
                    self.findings.append({
                        "type": "Critical File Writable",
                        "path": file_path,
                        "risk": "Critical",
                        "description": f"The sensitive file {file_path} is WRITABLE. This allows immediate privilege escalation."
                    })

    def find_world_writable_files(self):
        """
        Scans specific directories for world-writable files.
        Scanning the entire '/' is too slow; we focus on high-impact areas.
        """
        search_paths = ["/etc", "/opt", "/usr/local", "/var/www", "/tmp"]
        log_info(f"Scanning {search_paths} for world-writable files...")
        
        with Spinner("Searching for permission leaks..."):
            for path in search_paths:
                if not os.path.exists(path):
                    continue
                
                # find <path> -perm -0002 -type f (world writable)
                # We exclude /tmp specific standard files usually, but here we report all for auditing
                cmd = f"find {path} -xdev -type f -perm -0002 2>/dev/null"
                try:
                    output = subprocess.check_output(cmd, shell=True).decode().splitlines()
                    for line in output:
                        # Ignore standard temporary socket files or locks
                        if any(x in line for x in [".sock", ".lock"]):
                            continue
                            
                        self.findings.append({
                            "type": "World Writable File",
                            "path": line,
                            "risk": "Medium/High",
                            "description": "Any user on the system can modify this file."
                        })
                except Exception:
                    continue

    def check_insecure_home_dirs(self):
        """Checks if other users' home directories are readable/writable."""
        log_info("Checking for insecure Home Directory permissions...")
        try:
            # List directories in /home
            homes = os.listdir("/home")
            current_user = os.getlogin() if os.isatty(0) else ""
            
            for user_home in homes:
                full_path = os.path.join("/home", user_home)
                if user_home != current_user and os.path.isdir(full_path):
                    # Check if we can enter/read other user's home
                    if os.access(full_path, os.R_OK):
                        self.findings.append({
                            "type": "Insecure Home Directory",
                            "path": full_path,
                            "risk": "Low/Medium",
                            "description": f"Home directory of '{user_home}' is readable by others."
                        })
        except Exception:
            pass

    def run(self):
        """Orchestrates the permission audit."""
        self.check_critical_files()
        self.find_world_writable_files()
        self.check_insecure_home_dirs()
        
        # Immediate feedback for Critical findings
        for f in self.findings:
            if f['risk'] == "Critical":
                log_critical(f"{f['type']} -> {f['path']}")
                
        return self.findings

def scan_permissions():
    """Entry point for main toolkit."""
    scanner = PermissionScanner()
    return scanner.run()

if __name__ == "__main__":
    # Test block
    results = scan_permissions()
    print(f"Total findings: {len(results)}")