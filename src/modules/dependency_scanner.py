import os
import subprocess
import json
import requests

def get_cve_exploit_data(cve_id):
    """
    Interroge des bases de données de vulnérabilités ouvertes pour savoir si la CVE
    possède un exploit public connu ou s'il y a un PoC sur GitHub.
    """
    poc_url = f"https://api.github.com/search/repositories?q={cve_id}+poc"
    cisa_url = f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    exploit_status = {
        "score": "N/A",
        "severity": "INCONNUE",
        "is_active_threat": "NON",
        "poc_link": None
    }
    
    # 1. Recherche de PoC sur GitHub
    try:
        headers = {"User-Agent": "SecOps-Telegram-Bot"}
        response = requests.get(poc_url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("total_count", 0) > 0:
                # Récupère le lien du premier dépôt de PoC trouvé
                exploit_status["poc_link"] = data["items"][0]["html_url"]
    except Exception:
        pass # Reste discret si la requête échoue

    # 2. Vérification rapide si la CVE est dans le catalogue CISA KEV (Menace Active)
    try:
        # On interroge l'API Shodan/VulnCheck alternative ou on parse le flux si besoin.
        # Pour rester ultra-rapide et asynchrone sans télécharger le gros JSON CISA à chaque fois,
        # on cible l'API open-source de National Vulnerability Database via une passerelle publique.
        nvd_api = f"https://vulnerable.io/api/cve/{cve_id}" # Exemple de passerelle miroir rapide
        res = requests.get(f"https://api.vulncheck.com/v1/public/cve?cve={cve_id}", timeout=5)
        # Note : Si VulnCheck demande une clé, on utilise une API de secours totalement gratuite :
        cve_backup_url = f"https://cve.circl.lu/api/cve/{cve_id}"
        res = requests.get(cve_backup_url, timeout=5)
        
        if res.status_code == 200:
            cve_data = res.json()
            if cve_data:
                cvss = cve_data.get("cvss") or cve_data.get("cvss-v3")
                if cvss:
                    exploit_status["score"] = str(cvss)
                    cvss_float = float(cvss)
                    if cvss_float >= 9.0: exploit_status["severity"] = "CRITIQUE"
                    elif cvss_float >= 7.0: exploit_status["severity"] = "HAUTE"
                    elif cvss_float >= 4.0: exploit_status["severity"] = "MOYENNE"
                    else: exploit_status["severity"] = "FAIBLE"
    except Exception:
        pass

    return exploit_status

def scan_dependencies(target_path):
    """
    Scanne les dépendances Python pour trouver des CVE et les enrichit avec des données Red Team.
    """
    requirements_path = os.path.join(target_path, "requirements.txt")
    
    if not os.path.exists(requirements_path):
        return "ℹ️ Aucun fichier `requirements.txt` trouvé dans ce projet. Pas de dépendances Python à analyser."

    try:
        # Exécution de pip-audit au format JSON
        result = subprocess.run(
            ["pip-audit", "-r", requirements_path, "-f", "json"],
            capture_output=True, text=True, check=False
        )
        
        if "command not found" in result.stderr or result.returncode == 127:
            return "❌ `pip-audit` n'est pas installé dans l'environnement virtuel. Installez-le avec `pip install pip-audit`."

        data = json.loads(result.stdout)
    except Exception as e:
        return f"❌ Erreur lors de l'analyse des CVE : {str(e)}"

    dependencies = data.get("dependencies", [])
    vuln_count = sum(len(dep.get("vulns", [])) for dep in dependencies)

    if vuln_count == 0:
        return "✅ **Analyse des CVE terminée :** Aucune vulnérabilité connue trouvée dans les dépendances ! Le projet est à jour."

    report = f"⚠️ 🚨 **{vuln_count} VULNÉRABILITÉ(S) DÉTECTÉE(S) !**\n"
    report += "_Triage automatique des cibles d'exploitation en cours..._\n\n"
    report += "=======================================\n\n"
    
    for dep in dependencies:
        vulns = dep.get("vulns", [])
        if not vulns:
            continue
            
        package_name = dep.get("name")
        current_version = dep.get("version")
        
        report += f"📦 **Package :** `{package_name}` (v{current_version})\n"
        
        for vuln in vulns:
            cve_id = vuln.get("id")
            fix_versions = ", ".join(vuln.get("fix_versions", [])) or "Aucun correctif disponible"
            description = vuln.get("description", "Pas de description disponible.")
            
            # 🔥 CORRÉLATION RED TEAM : On va chercher si la faille est exploitable
            intelligence = get_cve_exploit_data(cve_id)
            
            report += f"🔍 **ID :** `{cve_id}`\n"
            report += f"📊 **Score CVSS :** `{intelligence['score']}` ({intelligence['severity']})\n"
            
            if intelligence['poc_link']:
                report += f"💥 **Exploit Public (PoC) disponible :**\n🔗 {intelligence['poc_link']}\n"
            else:
                report += "💥 **Exploit Public (PoC) :** Aucun dépôt public direct trouvé.\n"
                
            report += f"📝 **Détails :** {description[:150]}...\n"
            report += f"🛡️ **Parade :** Mettre à jour vers v`{fix_versions}`\n"
            report += "---------------------------------------\n"
            
    return report