import os
import logging
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# Importations de tous nos modules d'audit
from modules.api_scanner import scan_local_directory, generate_telegram_report
from modules.jwt_scanner import analyze_jwt_token, generate_jwt_report
from modules.sql_scanner import analyze_sql_file, generate_sql_report # Nouveau module

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ALLOWED_USER_ID = int(os.getenv("MY_TELEGRAM_ID")) if os.getenv("MY_TELEGRAM_ID") else None

if not BOT_TOKEN or not ALLOWED_USER_ID:
    raise ValueError("Erreur critique : Variables d'environnement manquantes dans le fichier .env !")

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

def restricted_access(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        if update.effective_user.id != ALLOWED_USER_ID:
            logging.warning(f"Accès refusé pour l'ID non autorisé : {update.effective_user.id}")
            return 
        return await func(update, context, *args, **kwargs)
    return wrapper

@restricted_access
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🛡️ *Red Team Bot activé sur Kali Linux.* Prêt pour les audits.", parse_mode="Markdown")

@restricted_access
async def cmd_scan_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target_dir = context.args[0] if context.args else "."
    await update.message.reply_text(f"🔍 TruffleHog analyse le dossier `{target_dir}`... Patientez.")
    results = scan_local_directory(target_dir)
    clean_report = generate_telegram_report(results)
    await update.message.reply_text(clean_report, parse_mode="Markdown")

@restricted_access
async def cmd_scan_jwt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ *Usage :* `/scan_jwt <votre_token_jwt>`", parse_mode="Markdown")
        return
    token_to_test = context.args[0]
    await update.message.reply_text("🔍 Analyse de la structure du token JWT en cours...")
    analysis = analyze_jwt_token(token_to_test)
    report = generate_jwt_report(analysis)
    await update.message.reply_text(report, parse_mode="Markdown")

@restricted_access
async def cmd_scan_sql(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande : /scan_sql <chemin_du_fichier_sql>"""
    if not context.args:
        await update.message.reply_text("❌ *Usage :* `/scan_sql <chemin_du_fichier.sql>`", parse_mode="Markdown")
        return
        
    file_to_test = context.args[0]
    await update.message.reply_text(f"🔍 Analyse statique du fichier `{file_to_test}`...")
    
    # Lancement du scanner SAST SQL
    analysis = analyze_sql_file(file_to_test)
    report = generate_sql_report(analysis)
    
    await update.message.reply_text(report, parse_mode="Markdown")

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan_api", cmd_scan_api))
    app.add_handler(CommandHandler("scan_jwt", cmd_scan_jwt))
    app.add_handler(CommandHandler("scan_sql", cmd_scan_sql)) # Liaison de la commande SQL
    
    print("🚀 Le bot de sécurité tourne sur Kali Linux...")
    app.run_polling()

if __name__ == "__main__":
    main()