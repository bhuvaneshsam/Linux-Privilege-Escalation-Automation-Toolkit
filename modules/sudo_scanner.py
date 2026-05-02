import subprocess

def scan_sudo():
    findings = []
    try:
        # Check sudo -l without password (only works if user has NOPASSWD or cached creds)
        cmd = "sudo -l -n 2>/dev/null"
        output = subprocess.check_output(cmd, shell=True).decode().splitlines()
        
        for line in output:
            if "NOPASSWD: ALL" in line:
                findings.append({"risk": "Critical", "description": "User can run ALL commands as root without password."})
            elif "NOPASSWD:" in line:
                findings.append({"risk": "High", "description": f"User can run specific commands as root: {line.strip()}"})
    except:
        findings.append({"info": "Could not check sudo -l without password."})
    return findings