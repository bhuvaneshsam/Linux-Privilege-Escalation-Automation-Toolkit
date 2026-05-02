import os
import sys
import argparse
from datetime import datetime
from utils.banner import print_banner
from utils.logger import log_info, log_success, log_warn
from utils.report_gen import ReportGenerator
from modules.system_info import get_sys_info
from modules.suid_scanner import scan_suid
from modules.sudo_scanner import scan_sudo
from modules.perm_scanner import scan_permissions
from modules.service_scanner import scan_services
from modules.cap_scanner import scan_capabilities

def main():
    print_banner()
    
    if os.geteuid() != 0:
        log_warn("Running as non-root. Some scans may be limited.")

    parser = argparse.ArgumentParser(description="LPE-Audit-Pro: Privilege Escalation Audit Tool")
    parser.add_argument("-o", "--output", help="Output format (txt/json)", default="txt")
    args = parser.parse_args()

    results = {}

    log_info("Starting System Enumeration...")
    results['sys_info'] = get_sys_info()
    
    log_info("Scanning for SUID/SGID Binaries...")
    results['suid'] = scan_suid()

    log_info("Checking Sudo Permissions...")
    results['sudo'] = scan_sudo()

    log_info("Checking Weak File Permissions...")
    results['permissions'] = scan_permissions()

    log_info("Auditing Services and Cron Jobs...")
    results['services'] = scan_services()

    log_info("Checking Linux Capabilities...")
    results['capabilities'] = scan_capabilities()

    # Generate Report
    report_path = f"reports/audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    rg = ReportGenerator(results)
    if args.output == "json":
        rg.generate_json(f"{report_path}.json")
    else:
        rg.generate_txt(f"{report_path}.txt")

    log_success(f"Audit Complete. Report saved to {report_path}.{args.output}")

if __name__ == "__main__":
    main()