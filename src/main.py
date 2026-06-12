import os
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# Chargement automatique des variables d'environnement du fichier .env
from dotenv import load_dotenv
load_dotenv()

# Importation de tes modules de scan, reconnaissance et exploitation active
from modules.api_scanner import scan_api
from modules.jwt_scanner import scan_jwt
from modules.sql_scanner import scan_sql
from modules.dependency_scanner import scan_dependencies
from modules.recon_scanner import run_recon
from modules.api_fuzzer import run_active_fuzz  # Nouvelle brique Fuzzing active !

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Message d'accueil du bot."""
    welcome_text = (
        "🛡️ **Bienvenue sur le SecOps Telegram Bot** 🛡️\n\n"
        "Votre plateforme locale d'audit de sécurité opérationnelle.\n\n"
        "**Commandes disponibles :**\n"
        "🌐 `/recon [domaine/IP]` : Cartographie passive (sous-domaines) et scan de ports critiques.\n"
        "🎯 `/fuzz [IP] [ports]` : Grab de bannières applicatives et analyse des vecteurs d'attaque (Ex: `/fuzz 1.1.1.1 21,22,445`).\n"
        "🔍 `/scan_api [chemin]` : Recherche les clés d'API et secrets fuis avec TruffleHog.\n"
        "📦 `/scan_cve [chemin]` : Analyse les dépendances à la recherche de CVE et PoCs publics.\n"
        "💉 `/scan_sql [chemin_fichier]` : Inspecte un fichier SQL à la recherche de failles d'injection ou absence de RLS.\n"
        "🔑 `/scan_jwt [token]` : Analyse la structure et la robustesse d'un token JWT."
    )
    await update.message.reply_text(welcome_text, parse_mode="Markdown")

async def recon_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère la commande /recon pour la phase de reconnaissance active/passive."""
    if not context.args:
        await update.message.reply_text("❌ Veuillez spécifier une cible. Exemple : `/recon target.com` ou `/recon 1.1.1.1`")
        return
        
    target = context.args[0]
    await update.message.reply_text(f"🌐 Lancement de la reconnaissance sur `{target}`... Patientez.")
    
    report = run_recon(target)
    await update.message.reply_text(report, parse_mode="Markdown")

async def fuzz_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère la commande /fuzz pour récupérer les versions des services et analyser les opportunités d'exploits."""
    if len(context.args) < 2:
        await update.message.reply_text("❌ Syntaxe incorrecte. Exemple : `/fuzz 192.168.10.54 21,22,445`")
        return
        
    target_ip = context.args[0]
    ports_raw = context.args[1]
    
    try:
        # Conversion de la chaîne "21,22,445" en liste d'entiers [21, 22, 445]
        open_ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip().isdigit()]
    except Exception:
        await update.message.reply_text("❌ Le format des ports est invalide. Utilisez des chiffres séparés par des virgules.")
        return

    await update.message.reply_text(f"🎯 Lancement du Fuzzing actif (Banner Grabbing) sur `{target_ip}` pour les ports {open_ports}... Patientez.")
    
    report = run_active_fuzz(target_ip, open_ports)
    await update.message.reply_text(report, parse_mode="Markdown")

async def scan_api_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère la commande /scan_api."""
    target_path = context.args[0] if context.args else "."
    await update.message.reply_text(f"🔍 TruffleHog analyse le dossier `{target_path}`... Patientez.")
    
    report = scan_api(target_path)
    await update.message.reply_text(report, parse_mode="Markdown")

async def scan_cve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère la commande /scan_cve pour identifier les vulnérabilités publiques."""
    target_path = context.args[0] if context.args else "."
    await update.message.reply_text(f"🔍 Analyse des CVE et dépendances dans `{target_path}`... Patientez.")
    
    report = scan_dependencies(target_path)
    await update.message.reply_text(report, parse_mode="Markdown")

async def scan_sql_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère la commande /scan_sql."""
    if not context.args:
        await update.message.reply_text("❌ Veuillez spécifier le chemin d'un fichier SQL. Exemple : `/scan_sql /chemin/vers/schema.sql`")
        return
        
    target_file = context.args[0]
    await update.message.reply_text(f"💉 Analyse statique du fichier SQL `{target_file}`... Patientez.")
    
    report = scan_sql(target_file)
    await update.message.reply_text(report, parse_mode="Markdown")

async def scan_jwt_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère la commande /scan_jwt."""
    if not context.args:
        await update.message.reply_text("❌ Veuillez fournir un token JWT à analyser. Exemple : `/scan_jwt eyJhbGciOi...`")
        return
        
    jwt_token = context.args[0]
    await update.message.reply_text("🔑 Décodage et analyse du token JWT en cours... Patientez.")
    
    report = scan_jwt(jwt_token)
    await update.message.reply_text(report, parse_mode="Markdown")

def main():
    # Récupération du Token chargé par load_dotenv()
    TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    
    if not TOKEN:
        print("❌ ERREUR : La variable TELEGRAM_BOT_TOKEN est introuvable. Vérifiez votre fichier .env.")
        return

    # Initialisation de l'Application (v20+)
    application = Application.builder().token(TOKEN).build()

    # Enregistrement des commandes (Handlers)
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("recon", recon_command))
    application.add_handler(CommandHandler("fuzz", fuzz_command)) # Nouveau handler d'analyse active !
    application.add_handler(CommandHandler("scan_api", scan_api_command))
    application.add_handler(CommandHandler("scan_cve", scan_cve_command))
    application.add_handler(CommandHandler("scan_sql", scan_sql_command))
    application.add_handler(CommandHandler("scan_jwt", scan_jwt_command))

    # Démarrage du Bot
    print("🚀 Le bot SecOps est en ligne et écoute les commandes...")
    application.run_polling()

if __name__ == "__main__":
    main()