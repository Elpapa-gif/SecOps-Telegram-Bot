import jwt

def analyze_jwt_token(token: str) -> dict:
    """
    Analyse un token JWT à la recherche de configurations dangereuses.
    """
    try:
        # 1. Inspecter le header sans valider la signature pour voir l'algorithme utilisé
        unverified_header = jwt.get_unverified_header(token)
        alg = unverified_header.get("alg", "").lower()
        
        # 2. Vérification de la faille critique "Algorithm None"
        is_none_vulnerable = (alg == "none")
            
        # 3. Récupérer le payload pour analyser sa structure temporelle
        payload = jwt.decode(token, options={"verify_signature": False})
        has_expiration = "exp" in payload

        return {
            "status": "success",
            "algorithm": alg,
            "none_vulnerable": is_none_vulnerable,
            "has_expiration": has_expiration,
            "claims": list(payload.keys())
        }
    except Exception as e:
        return {"status": "error", "message": f"Token invalide ou impossible à parser : {str(e)}"}

def generate_jwt_report(analysis: dict) -> str:
    """
    Génère un rapport textuel pour Telegram.
    """
    if analysis["status"] == "error":
        return f"❌ *Erreur d'analyse JWT :* {analysis['message']}"
        
    report = "🔐 *Rapport d'Audit Authentification (JWT) :*\n\n"
    report += f"🔹 *Algorithme détecté :* `{analysis['algorithm'].upper()}`\n"
    
    if analysis["none_vulnerable"]:
        report += "🚨 *FAILLE CRITIQUE :* L'algorithme 'none' est actif ! Un attaquant peut usurper n'importe quelle identité en modifiant simplement le header.\n"
    else:
        report += "✅ *Algorithme :* Pas de faille 'none' détectée.\n"
        
    if not analysis["has_expiration"]:
        report += "⚠️ *ATTENTION :* Ce token ne possède pas de clé d'expiration (`exp`). S'il est intercepté, il reste valide à vie.\n"
    else:
        report += "✅ *Expiration :* Le token implémente une durée de vie restrictive.\n"
        
    report += f"\n📋 *Claims identifiés :* `{', '.join(analysis['claims'])}`"
    return report