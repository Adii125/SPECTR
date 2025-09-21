"""Banner display utility for SPECTR scanner"""

from utils.colors import Colors

def display_banner():
    """Display SPECTR ASCII banner"""
    banner = f"""{Colors.CYAN}
███████╗██████╗ ███████╗ ██████╗████████╗██████╗ 
██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗
███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗
███████║██║     ███████╗╚██████╗   ██║   ██║  ██║
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝
{Colors.RESET}
{Colors.YELLOW}SPECTR - Scanner for Payloads, Endpoints, Configs,
         Traversals, and Requests{Colors.RESET}
{Colors.GREEN}Advanced Web Vulnerability Scanner{Colors.RESET}
{Colors.RED}{"=" * 50}{Colors.RESET}
"""
    print(banner)
