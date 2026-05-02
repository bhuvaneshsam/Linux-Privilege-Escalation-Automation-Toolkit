import os
import sys

class Colors:
    """ANSI Escape Codes for Terminal Coloring"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """
    Displays the professional CLI banner for the toolkit.
    Includes project metadata and a safety disclaimer.
    """
    
    # ASCII Art - Stylized for Cybersecurity
    # Generated with "Standard" font
    ascii_art = f"""
{Colors.CYAN}  _      _____  ______                 _ _ _     _____           
 | |    |  __ \|  ____|               | (_) |   |  __ \          
 | |    | |__) | |__ ______ __ _ _   _| |_| |_  | |__) | __ ___  
 | |    |  ___/|  __|______/ _` | | | | | | __| |  ___/ '__/ _ \ 
 | |____| |    | |____    | (_| | |_| | | | |_  | |   | | | (_) |
 |______|_|    |______|    \__,_|\__,_|_|_|\__| |_|   |_|  \___/ 
                                                                 {Colors.END}"""

    metadata = f"""
 {Colors.BOLD}Project:{Colors.END} Linux Privilege Escalation Audit Toolkit
 {Colors.BOLD}Version:{Colors.END} 1.0.0 (Production Ready)
 {Colors.BOLD}Author: {Colors.END} Cybersecurity Final Year Project
 {Colors.BOLD}Mode:   {Colors.END} {Colors.GREEN}DETECTION & AUDIT ONLY{Colors.END}
    """

    separator = f"{Colors.BLUE}{'=' * 65}{Colors.END}"

    disclaimer = f"""
 {Colors.RED}{Colors.BOLD}[!] LEGAL DISCLAIMER:{Colors.END}
 This tool is for authorized security auditing and academic purposes 
 only. Unauthorized use on systems without prior consent is illegal.
    """

    # Clear terminal screen (optional, depends on preference)
    # os.system('clear') 

    print(separator)
    print(ascii_art)
    print(metadata)
    print(separator)
    print(disclaimer)
    print(separator + "\n")

def clear_screen():
    """Clears the terminal screen based on OS"""
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

if __name__ == "__main__":
    # Test the banner
    print_banner()