import subprocess
import json
import os

def scan_local_directory(directory_path: str) -> dict:
    """
    Scanne un répertoire local à la recherche de clés API et secrets fuis.
    Retourne un dictionnaire avec le statut et les résultats.
    """
    if not os.path.exists(directory_path):
        return {"status": "error", "message": f"Le dossier {directory_path} n'existe pas."}

    try:
        # Exécution de TruffleHog en mode filesystem
        cmd = ["trufflehog", "filesystem", directory_path, "--json", "--only-verified"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode not in [0, 1]:
            return {"status": "error", "message": f"Erreur TruffleHog: {result.stderr}"}

        secrets_found = []
        lines = result.stdout.strip().split("\n")
        
        for line in lines:
            if line.strip():  # Évite les lignes vides accidentelles
                try:
                    secret_data = json.loads(line)
                    clean_secret = {
                        "detector": secret_data.get("DetectorName"),
                        "file": secret_data.get("SourceFiles", {}).get("Disk", {}).get("FilePath"),
                        "verified": secret_data.get("Verified", False)
                    }
                    secrets_found.append(clean_secret)
                except json.JSONDecodeError:
                    continue

        return {
            "status": "success",
            "count": len(secrets_found),
            "secrets": secrets_found
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Le scan a dépassé le temps limite de 2 minutes."}
    except Exception as e:
        return {"status": "error", "message": f"Erreur inattendue : {str(e)}"}

def generate_telegram_report(scan_results: dict) -> str:
    """
    Génère un texte propre formaté pour le Markdown Telegram.
    """
    if scan_results["status"] == "error":
        return f"❌ **Erreur lors du scan de clés :** {scan_results['message']}"
    
    if scan_results["count"] == 0:
        return "✅ **Scan Clés API :** Aucun secret ou clé vulnérable détecté dans ce répertoire."
    
    report = f"⚠️ 🚨 **{scan_results['count']} SECRET(S) DÉTECTÉ(S) !**\n\n"
    for idx, secret in enumerate(scan_results["secrets"], 1):
        report += f"**{idx}. Type :** `{secret['detector']}`\n"
        report += f"📂 **Fichier :** `{secret['file']}`\n"
        report += f"🔴 **Vérifié/Actif :** {'Oui (VULNÉRABLE)' if secret['verified'] else 'Potentiel (À vérifier)'}\n\n"
        
    report += "💡 _Mesure de sécurité :_ Supprimez immédiatement ces clés du code source."
    return report

def scan_api(target_path: str) -> str:
    """
    Fonction passerelle appelée par main.py.
    Exécute le scan local et retourne directement le rapport Telegram formaté.
    """
    resultats = scan_local_directory(target_path)
    return generate_telegram_report(resultats)