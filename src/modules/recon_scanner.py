import subprocess
import socket
import requests

def subdomains_lookup(domain: str) -> list:
    """
    Recherche passive de sous-domaines via l'API publique et gratuite crt.sh (Certificats SSL).
    C'est totalement invisible pour la cible (OSINT).
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get("name_value")
                if name and not name.startswith("*."):
                    # Nettoyage des sous-domaines multiples sur une ligne
                    for sub in name.split("\n"):
                        subdomains.add(sub.strip())
    except Exception:
        pass
    return sorted(list(subdomains))[:15] # On limite aux 15 premiers pour Telegram

def quick_port_scan(target_ip: str) -> list:
    """
    Scan de ports rapide et asynchrone sur les ports les plus critiques en Red Team.
    """
    # Ports cibles : SSH, FTP, HTTP, HTTPS, SMB, RDP, MySQL, Postgres, WinRM
    ports_to_test = [21, 22, 80, 443, 445, 3389, 3306, 5432, 5985]
    open_ports = []
    
    for port in ports_to_test:
        # Utilisation d'un socket avec un timeout très court pour aller vite
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def run_recon(target: str) -> str:
    """
    Fonction principale appelée par le main.py pour orchestrer la reconnaissance.
    """
    target = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
    
    # 1. Résolution IP
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return f"❌ **Impossible de résoudre le domaine :** `{target}`. Vérifiez l'adresse."

    report = f"🌐 **Rapport de Reconnaissance :** `{target}` 🌐\n"
    report += f"📍 **IP Résolue :** `{target_ip}`\n\n"
    
    # 2. Collecte des sous-domaines (si ce n'est pas déjà une IP brute)
    report += "🔍 *Énumération passive des sous-domaines (OSINT)...*\n"
    subdomains = subdomains_lookup(target)
    if subdomains:
        report += "📦 **Sous-domaines découverts :**\n"
        for sub in subdomains:
            report += f"• `{sub}`\n"
    else:
        report += "ℹ️ Aucun sous-domaine public trouvé via crt.sh.\n"
    
    report += "\n---------------------------------------\n\n"
    
    # 3. Scan des ports réseau
    report += "⚡ *Scan réseau des ports critiques en cours...*\n"
    open_ports = quick_port_scan(target_ip)
    if open_ports:
        report += "🔥 **Ports OUVERTS détectés :**\n"
        port_mapping = {21: "FTP", 22: "SSH (Potentiel Bruteforce)", 80: "HTTP", 443: "HTTPS", 445: "SMB (Exploit ?)", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 5985: "WinRM"}
        for port in open_ports:
            service = port_mapping.get(port, "Inconnu")
            report += f"• Port `{port}` : **{service}**\n"
    else:
        report += "✅ Aucun port critique standard n'est ouvert ou filtré par un Pare-feu.\n"
        
    return report