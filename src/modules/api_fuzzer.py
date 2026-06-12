import socket
import requests

def grab_banner(ip: str, port: int) -> str:
    """
    Se connecte à un port ouvert pour récupérer la bannière du service (version du logiciel).
    C'est la clé pour trouver l'exploit exact.
    """
    try:
        s = socket.socket()
        s.settimeout(2.0)
        s.connect((ip, port))
        
        # Pour HTTP/HTTPS, on envoie une requête basique pour forcer la bannière Server
        if port in [80, 443]:
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        if banner:
            # Nettoyage rapide pour Telegram
            return banner.split('\n')[0][:100]
    except Exception:
        pass
    return "Pas de bannière renvoyée (Service discret ou filtré)"

def analyze_service_vulnerability(port: int, banner: str) -> str:
    """
    Analyse la bannière récupérée pour suggérer des pistes d'attaques Red Team connues.
    """
    banner_lower = banner.lower()
    
    if port == 21:
        if "vsftpd 2.3.4" in banner_lower:
            return "🔥 **CRITIQUE : Backdoor vsftpd 2.3.4 détecté !** Exploit disponible dans Metasploit (`exploit/unix/ftp/vsftpd_234_backdoor`)."
        return "💡 *Piste d'attaque :* Tentez une connexion anonyme (`anonymous:anonymous`) ou un bruteforce de dictionnaire."
        
    if port == 22:
        if "openssh" in banner_lower:
            return f"💡 *Piste d'attaque :* Version détectée (`{banner}`). Vérifiez si elle est vulnérable à l'énumération d'utilisateurs ou utilisez `Hydra` pour un bruteforce SSH."
            
    if port == 445:
        return "🔥 **HAUTE : Protocole SMB actif.** Utilisez `Nmap` avec le script `--script smb-vuln-*` pour tester EternalBlue (CVE-2017-0143) ou MS17-010."
        
    if port in [3306, 5432]:
        return "🔑 *Piste d'attaque :* Base de données accessible à distance. Tentez des accès par défaut (`root` sans mot de passe, `postgres:postgres`)."
        
    return "🔍 Analyse manuelle requise avec Searchsploit."

def run_active_fuzz(target_ip: str, open_ports: list) -> str:
    """
    Orchestre la saisie de bannières et l'analyse de vulnérabilités sur les ports trouvés.
    """
    if not open_ports:
        return "❌ Aucun port ouvert fourni pour le fuzzing actif."

    report = f"🎯 **Analyse d'Exploitation Active :** `{target_ip}` 🎯\n"
    report += "_Récupération des versions de logiciels en cours..._\n\n"
    report += "=======================================\n\n"

    for port in open_ports:
        report += f"🔌 **Port {port}**\n"
        banner = grab_banner(target_ip, port)
        report += f"📝 **Bannière :** `{banner}`\n"
        
        # Corrélation avec nos connaissances d'attaque
        attack_vector = analyze_service_vulnerability(port, banner)
        report += f"⚔️ {attack_vector}\n"
        report += "---------------------------------------\n"
        
    return report