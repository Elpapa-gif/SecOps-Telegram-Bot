import jwt
import json
import base64

def analyze_jwt_token(token: str) -> dict:
    """
    Analyse un token JWT de manière statique pour détecter des failles de configuration
    (Algorithme 'none', clés faibles, signatures non vérifiées).
    """
    try:
        # Séparation des trois parties du JWT (Header, Payload, Signature)
        parts = token.split('.')
        if len(parts) != 3:
            return {"status": "error", "message": "Le format du token JWT est invalide (doit contenir 2 points)."}

        # Décodage du Header pour voir l'algorithme utilisé
        header_segment = parts[0]
        # Ajout du padding manquant pour base64 si nécessaire
        header_json = base64.urlsafe_b64decode(header_segment + '=' * (-len(header_segment) % 4)).decode('utf-8')
        header = json.loads(header_json)
        
        algo = header.get("alg", "").lower()
        
        # Décodage du Payload sans vérification de signature pour l'analyse statique
        payload_segment = parts[1]
        payload_json = base64.urlsafe_b64decode(payload_segment + '=' * (-len(payload_segment) % 4)).decode('utf-8')
        payload = json.loads(payload_json)

        findings = []
        is_vulnerable = False

        # 👀 Détection Faille 1 : Algorithme 'none' (Bypass critique)
        if algo == "none":
            findings.append({
                "issue": "Algorithme 'none' activé",
                "severity": "CRITIQUE",
                "poc": "Un attaquant peut modifier le payload (ex: passer admin) et reconstruire le token sans signature.",
                "remediation": "Désactivez impérativement le support de l'algorithme 'none' dans votre bibliothèque JWT backend."
            })
            is_vulnerable = True

        # 👀 Détection Faille 2 : Utilisation de clés faibles connues (Brute-force)
        # Test de décodage avec des secrets par défaut courants
        secrets_communs = ["secret", "password", "123456", "admin", "jwt"]
        for secret in secrets_communs:
            try:
                jwt.decode(token, secret, algorithms=[header.get("alg", "HS256")])
                findings.append({
                    "issue": f"Clé secrète trop faible détectée ('{secret}')",
                    "severity": "HAUTE",
                    "poc": f"Un attaquant peut brute-forcer la signature en local avec Hashcat et la clé '{secret}' pour forger de faux jetons.",
                    "remediation": "Utilisez une clé secrète forte générée aléatoirement d'au moins 256 bits (ex: `openssl rand -hex 32`)."
                })
                is_vulnerable = True
                break
            except (jwt.InvalidSignatureError, jwt.ExpiredSignatureError):
                continue

        return {
            "status": "success",
            "vulnerable": is_vulnerable,
            "algo": header.get("alg"),
            "payload": payload,
            "findings": findings
        }

    except Exception as e:
        return {"status": "error", "message": f"Erreur lors du décodage du jeton : {str(e)}"}

def generate_jwt_report(results: dict) -> str:
    """
    Formate les résultats de l'analyse JWT pour un affichage propre sur Telegram.
    """
    if results["status"] == "error":
        return f"❌ **Erreur d'analyse JWT :** {results['message']}"

    report = "🔑 **Rapport d'Analyse JWT** 🔑\n"
    report += f"📊 **Algorithme déclaré :** `{results['algo']}`\n\n"
    
    if not results["vulnerable"]:
        report += "✅ **Aucune vulnérabilité structurelle évidente détectée.**\n"
        report += "_Note : Assurez-vous tout de même que la clé secrète côté serveur ne puisse pas être devinée._"
        return report

    report += f"⚠️ 🚨 **{len(results['findings'])} FAILLE(S) DÉTECTÉE(S) !**\n\n"
    
    for idx, f in enumerate(results["findings"], 1):
        report += f"**{idx}. Faille :** {f['issue']} | 🔥 **Gravité :** `{f['severity']}`\n"
        report += f"💥 **Détails de l'attaque (PoC) :** {f['poc']}\n"
        report += f"🛡️ **Parade / Remédiation :** {f['remediation']}\n"
        report += "---------------------------------------\n"

    return report

def scan_jwt(token: str) -> str:
    """
    Fonction passerelle appelée par main.py.
    Prend le token brut, l'analyse et renvoie le rapport textuel final.
    """
    analysis_results = analyze_jwt_token(token)
    return generate_jwt_report(analysis_results)