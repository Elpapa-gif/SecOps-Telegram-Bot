import os
import re

def analyze_single_sql_file(file_path: str) -> list:
    """
    Analyse un fichier SQL unique à la recherche de vulnérabilités statiques
    et retourne la liste des failles trouvées.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
            
            for index, line in enumerate(lines):
                # 1. Détection de concaténation brute (vulnérabilité SQLi potentielle dans les fonctions/procédures)
                if re.search(r"\blike\b\s*['\"].*%.*['\"]\s*\+\s*\w+", line, re.IGNORECASE) or \
                   re.search(r"EXEC\s*\(\s*['\"].*?\+\s*\w+", line, re.IGNORECASE):
                    findings.append({
                        "line": index + 1,
                        "type": "Injection SQL Potentielle",
                        "detail": "Concaténation brute de variables détectée dans une requête dynamique.",
                        "severity": "HAUTE"
                    })
                
                # 2. Détection d'absence de RLS (Row Level Security) sur PostgreSQL
                if "CREATE TABLE" in line.upper() and not any("ALTER TABLE" in l.upper() and "ENABLE ROW LEVEL SECURITY" in l.upper() for l in lines):
                    # Évite de dupliquer pour chaque table, on remonte l'alerte de configuration globale
                    if not any(f["type"] == "Absence de RLS" for f in findings):
                        findings.append({
                            "line": index + 1,
                            "type": "Absence de RLS",
                            "detail": "Des tables sont créées sans politique de Row Level Security (RLS) globale détectée.",
                            "severity": "MOYENNE"
                        })
    except Exception as e:
        pass
    return findings

def generate_payloads(finding_type: str) -> str:
    """
    Génère des commandes et payloads d'exploitation adaptés au type de faille.
    """
    if finding_type == "Injection SQL Potentielle":
        return (
            "🎯 **Payloads d'exploitation suggérés :**\n"
            "• *Auth Bypass:* `' OR '1'='1` ou `' OR 1=1 --`\n"
            "• *Union Based:* `' UNION SELECT username, password FROM users --`\n"
            "• *Commande automatique (sqlmap) :*\n"
            "`sqlmap -u \"URL_CIBLE\" --forms --batch --crawl=2 --dbs`"
        )
    elif finding_type == "Absence de RLS":
        return (
            "⚔️ **Vecteur Red Team :**\n"
            "L'absence de RLS permet à n'importe quel utilisateur authentifié de lire "
            "les lignes des autres utilisateurs si l'application ne filtre pas strictement l'ID en amont (vulnérabilité BOLA/IDOR)."
        )
    return "🔍 Analyse manuelle recommandée."

def scan_sql(target_path: str) -> str:
    """
    Scanne intelligemment un fichier SQL unique OU parcourt récursivement un dossier complet.
    """
    sql_files = []

    # Correction du bug "Is a directory" : Gestion dynamique du chemin passé
    if os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith('.sql'):
                    sql_files.append(os.path.join(root, file))
    elif os.path.isfile(target_path) and target_path.endswith('.sql'):
        sql_files.append(target_path)
    else:
        return "❌ Le chemin fourni n'est ni un fichier SQL valide, ni un dossier."

    if not sql_files:
        return f"ℹ️ Aucun fichier `.sql` trouvé dans `{target_path}`."

    report = f"💉 **Rapport d'Audit Smart SQL :** `{os.path.basename(target_path)}` 💉\n"
    report += f"📁 *Fichiers analysés : {len(sql_files)}*\n\n"
    report += "=======================================\n\n"

    total_vulns = 0
    for file_path in sql_files:
        relative_name = os.path.relpath(file_path, target_path) if os.path.isdir(target_path) else os.path.basename(file_path)
        findings = analyze_single_sql_file(file_path)
        
        if findings:
            total_vulns += len(findings)
            report += f"📄 **Fichier :** `{relative_name}`\n"
            for f in findings:
                report += f"• **Ligne {f['line']}** : [{f['severity']}] *{f['type']}*\n"
                report += f"  _Détail : {f['detail']}_\n\n"
                # Ajout des payloads d'attaque "On-the-Fly"
                report += f"{generate_payloads(f['type'])}\n"
                report += "---------------------------------------\n"

    if total_vulns == 0:
        return f"✅ **Audit SQL terminé :** Aucun indicateur de faille classique ou d'absence de RLS détecté dans les {len(sql_files)} fichier(s)."

    return report