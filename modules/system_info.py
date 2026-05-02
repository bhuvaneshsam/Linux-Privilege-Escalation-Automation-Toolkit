import os
import platform
import subprocess
import re
from utils.logger import log_info, log_warn


class SystemInfoScanner:
    """
    Collects detailed system metadata for privilege escalation analysis.
    Focus: Detection, enumeration, and security awareness.
    """

    def __init__(self):
        self.sys_data = {}

    def get_cmd_output(self, cmd_list):
        """Safely execute commands without shell=True."""
        try:
            result = subprocess.check_output(
                cmd_list,
                stderr=subprocess.STDOUT
            ).decode().strip()
            return result
        except Exception:
            return "Unknown"

    def get_distro_info(self):
        """Extract Linux distribution info from /etc/os-release."""
        distro = "Unknown Linux"

        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r") as f:
                    content = f.read()

                match = re.search(r'PRETTY_NAME="(.+?)"', content)
                if match:
                    distro = match.group(1)

            except Exception:
                pass

        return distro

    def check_kernel_vulnerabilities(self, kernel_version):
        """
        Map kernel versions to known privilege escalation vulnerabilities.
        (Educational mapping only)
        """
        risks = []

        try:
            # Extract major version
            version_parts = kernel_version.split(".")
            major = int(version_parts[0])
            minor = int(version_parts[1]) if len(version_parts) > 1 else 0

            # Example mappings
            if major == 2 and minor <= 6:
                risks.append("CVE-2016-5195 (DirtyCow) - High Risk")

            if major == 4 and minor <= 4:
                risks.append("CVE-2017-1000112 - Medium Risk")

            if major == 5 and minor <= 8:
                risks.append("CVE-2022-0847 (Dirty Pipe) - Medium Risk")

        except Exception:
            risks.append("Kernel parsing error")

        return risks if risks else ["No obvious kernel CVEs detected"]

    def run(self):
        """Main execution method."""

        log_info("Gathering hardware and OS metadata...")

        # Basic System Info
        self.sys_data['hostname'] = platform.node()
        self.sys_data['os_type'] = platform.system()
        self.sys_data['distro'] = self.get_distro_info()
        self.sys_data['kernel_version'] = platform.release()
        self.sys_data['architecture'] = platform.machine()

        # User Info
        self.sys_data['current_user'] = self.get_cmd_output(["whoami"])
        self.sys_data['uid_gid'] = self.get_cmd_output(["id"])
        self.sys_data['is_root'] = (os.geteuid() == 0)

        # Environment
        self.sys_data['env_path'] = os.environ.get('PATH', 'Not Found')

        # Uptime
        self.sys_data['uptime'] = self.get_cmd_output(["uptime", "-p"])

        # Kernel Risk Mapping
        self.sys_data['potential_kernel_cves'] = self.check_kernel_vulnerabilities(
            self.sys_data['kernel_version']
        )

        # Optional Logging Summary
        log_info(f"OS: {self.sys_data['distro']}")
        log_info(f"Kernel: {self.sys_data['kernel_version']}")
        log_info(f"User: {self.sys_data['current_user']}")

        if not self.sys_data['is_root']:
            log_warn("Running without root privileges. Some checks may be limited.")

        return self.sys_data


# Wrapper for main.py
def get_sys_info():
    scanner = SystemInfoScanner()
    return scanner.run()


# Standalone testing
if __name__ == "__main__":
    import json
    print(json.dumps(get_sys_info(), indent=4))