#!/usr/bin/env python3
"""ZeroPath Telegram Bot - Launches Mini App."""
import os
import logging
from telegram import Update, WebAppInfo, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
WEBAPP_URL = "https://zeropath.secure-dana.my.id/"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message with Mini App button."""
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton(
            "🛡️ Launch ZeroPath Scanner",
            web_app=WebAppInfo(url=WEBAPP_URL)
        )]
    ])
    
    await update.message.reply_text(
        "**🛡️ ZeroPath — Autonomous Exploit Chain Generator**\n\n"
        "AI-powered security scanner yang bisa:\n"
        "• Detect XSS, SQLi, CORS, Headers vulns\n"
        "• Auto-generate attack chains\n"
        "• Create PoC code & mitigation\n\n"
        "Klik tombol di bawah untuk mulai scan!",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )
    logger.info(f"User {update.effective_user.username} started the bot")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show help."""
    await update.message.reply_text(
        "**ZeroPath Commands:**\n\n"
        "/start — Launch scanner\n"
        "/help — Show this help\n\n"
        "Mini App terbuka langsung di Telegram. "
        "Masukkan target URL dan biarkan AI menganalisisnya."
    )

def main():
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN environment variable not set!")
        return
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    
    logger.info("🤖 ZeroPath Bot started!")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
