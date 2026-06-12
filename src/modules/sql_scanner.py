import os
import re

def analyze_sql_file(file_path: str) -> dict:
    """
    Analyse un fichier SQL à la recherche de failles d'injection ou d'un manque de RLS.
    """
    if not os.path.exists(file_path):
        return {"status": "error", "message": f"Le fichier {file_path} n'existe pas."}

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        issues = []
        
        # 1. Détecter la création de tables
        tables = re.findall(r"create\s+table\s+(\w+)", content, re.IGNORECASE)
        
        # 2. Chercher les activations de RLS : "ALTER TABLE ... ENABLE ROW LEVEL SECURITY"
        rls_enabled_tables = re.findall(r"alter\s+table\s+(\w+)\s+enable\s+row\s+level\s+security", content, re.IGNORECASE)
        
        # Vérifier quelles tables n'ont pas la RLS activée
        for table in tables:
            if table not in rls_enabled_tables:
                issues.append({
                    "type": "RLS_MANQUANTE",
                    "severity": "HAUTE",
                    "details": f"La table `{table}` est créée mais le Row Level Security (RLS) n'est pas activé."
                })

        # 3. Détecter des patterns d'injections SQL potentiels (ex: concaténation dynamique dans des fonctions/procédures)
        # On cherche des structures suspectes comme l'exécution de chaînes assemblées avec || ou %
        injection_patterns = [
            (r"execute\s+immediate\s+.*\|\|", "Concaténation dynamique suspecte dans EXECUTE IMMEDIATE."),
            (r"query\s*:=\s*.*['\"].*\|\|", "Construction de requête SQL par concaténation de chaînes.")
        ]

        for pattern, desc in injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                issues.append({
                    "type": "INJECTION_SQL_POTENTIELLE",
                    "severity": "CRITIQUE",
                    "details": desc
                })

        return {
            "status": "success",
            "file": os.path.basename(file_path),
            "issues_count": len(issues),
            "issues": issues
        }

    except Exception as e:
        return {"status": "error", "message": f"Impossible de lire ou d'analyser le fichier : {str(e)}"}

def generate_sql_report(analysis: dict) -> str:
    """
    Génère le rapport formaté pour Telegram.
    """
    if analysis["status"] == "error":
        return f"❌ *Erreur d'analyse SQL :* {analysis['message']}"
        
    if analysis["issues_count"] == 0:
        return f"✅ *Audit SQL ({analysis['file']}) :* Aucune vulnérabilité flagrante ou absence de RLS détectée."
        
    report = f"📊 *Rapport d'Audit Base de Données ({analysis['file']}) :*\n"
    report += f"⚠️ *{analysis['issues_count']} alerte(s) de sécurité identifiée(s).*\n\n"
    
    for idx, issue in enumerate(analysis["issues"], 1):
        emoji = "🚨" if issue["severity"] == "CRITIQUE" else "🔥"
        report += f"{emoji} *{idx}. [{issue['type']}]* - Priorité : `{issue['severity']}`\n"
        report += f"💡 {issue['details']}\n\n"
        
    report += "🛠️ _Remédiation :_ Activez systématiquement la RLS (`ALTER TABLE t ENABLE ROW LEVEL SECURITY;`) et utilisez exclusivement des requêtes préparées."
    return report