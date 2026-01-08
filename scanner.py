import nmap
from rich.console import Console
from rich.table import Table

console = Console()
scanner = nmap.PortScanner()

COMMON_PORTS = "21,22,23,25,53,80,110,139,143,443,445,3306,3389"

def scan_host(target):
    console.print(f"\n[bold cyan][*] Scanning {target}...[/bold cyan]")
    scanner.scan(target, COMMON_PORTS, arguments="-T4")

    open_ports = []
    warnings = []

    if target in scanner.all_hosts():
        for proto in scanner[target].all_protocols():
            for port in scanner[target][proto]:
                state = scanner[target][proto][port]['state']
                if state == "open":
                    open_ports.append(port)

                    if port == 21:
                        warnings.append("FTP service detected")
                    if port == 23:
                        warnings.append("Telnet detected (insecure)")
                    if port == 3389:
                        warnings.append("RDP exposed")

    return open_ports, warnings


def show_report(target, open_ports, warnings):
    table = Table(title=f"Scan Report for {target}")
    table.add_column("Item", style="cyan")
    table.add_column("Result", style="green")

    table.add_row("Open Ports Count", str(len(open_ports)))
    table.add_row("Open Ports", ", ".join(map(str, open_ports)) if open_ports else "None")

    if warnings:
        table.add_row("Warnings", "\n".join(warnings))
    else:
        table.add_row("Warnings", "No obvious risks detected")

    console.print(table)


if __name__ == "__main__":
    target = input("Enter target IP or range (e.g. 192.168.1.1): ")
    ports, alerts = scan_host(target)
    show_report(target, ports, alerts)
