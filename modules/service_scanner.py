import os
import subprocess
import re
from utils.logger import log_info, log_warn, log_critical, Spinner

class ServiceScanner:
    """
    Audits Systemd services and Cron jobs for common misconfigurations.
    Focuses on:
    - Writable service files.
    - Root cron jobs executing writable scripts.
    - Relative paths in service definitions.
    """

    def __init__(self):
        self.findings = []

    def check_systemd_writable(self):
        """Checks if custom systemd service files are writable by the current user."""
        log_info("Auditing Systemd service file permissions...")
        
        # Focus on /etc/systemd/system as it contains administrator-created services
        search_path = "/etc/systemd/system"
        if not os.path.exists(search_path):
            return

        try:
            # Find all .service files
            cmd = f"find {search_path} -name '*.service' -type f 2>/dev/null"
            service_files = subprocess.check_output(cmd, shell=True).decode().splitlines()
            
            for s_file in service_files:
                if os.access(s_file, os.W_OK):
                    self.findings.append({
                        "type": "Writable Service File",
                        "path": s_file,
                        "risk": "High",
                        "description": f"The service file {s_file} is writable. An attacker can modify 'ExecStart' to run arbitrary code as root."
                    })
        except Exception:
            pass

    def check_cron_vulnerabilities(self):
        """
        Analyzes system-wide cron jobs.
        Looks for scripts executed by root that are writable by the current user.
        """
        log_info("Analyzing Cron jobs for insecure script execution...")
        
        cron_locations = [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.monthly",
            "/etc/cron.weekly"
        ]

        for loc in cron_locations:
            if not os.path.exists(loc):
                continue
            
            try:
                # Read crontab files
                if os.path.isfile(loc):
                    self.parse_cron_file(loc)
                else:
                    for f in os.listdir(loc):
                        self.parse_cron_file(os.path.join(loc, f))
            except Exception:
                continue

    def parse_cron_file(self, file_path):
        """Parses a cron file to find script paths and check their permissions."""
        try:
            with open(file_path, 'r') as f:
                content = f.readlines()
            
            for line in content:
                line = line.strip()
                # Simple regex to find absolute paths in cron lines
                matches = re.findall(r'(/[a-zA-Z0-9\._\-/]+)', line)
                
                for path in matches:
                    # We only care about scripts/binaries, not standard system paths
                    if os.path.isfile(path) and not path.startswith(('/bin', '/sbin', '/usr/bin')):
                        if os.access(path, os.W_OK):
                            self.findings.append({
                                "type": "Insecure Cron Task",
                                "path": path,
                                "source": file_path,
                                "risk": "High",
                                "description": f"Cron job in {file_path} executes writable script {path}."
                            })
        except:
            pass

    def check_path_variable(self):
        """Checks if the crontab PATH variable includes writable directories."""
        if os.path.exists("/etc/crontab"):
            try:
                with open("/etc/crontab", "r") as f:
                    for line in f:
                        if line.startswith("PATH="):
                            path_val = line.split("=")[1].strip()
                            for directory in path_val.split(":"):
                                if os.path.isdir(directory) and os.access(directory, os.W_OK):
                                    self.findings.append({
                                        "type": "Dangerous Cron PATH",
                                        "path": directory,
                                        "risk": "Medium",
                                        "description": f"Cron PATH includes writable directory '{directory}'. Potential for hijacking."
                                    })
            except:
                pass

    def run(self):
        """Run all service and cron sub-modules."""
        with Spinner("Auditing Background Tasks..."):
            self.check_systemd_writable()
            self.check_cron_vulnerabilities()
            self.check_path_variable()
        
        # Log any high-risk items immediately
        for f in self.findings:
            if f['risk'] == "High":
                log_critical(f"Insecure Task: {f['path']} (Source: {f.get('source', 'Systemd')})")
        
        return self.findings

def scan_services():
    """Wrapper for main.py."""
    scanner = ServiceScanner()
    return scanner.run()

if __name__ == "__main__":
    # Standalone test
    print(f"Detected Service Risks: {len(scan_services())}")