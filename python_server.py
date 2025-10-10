#!/usr/bin/env python3
# bot_translate_whisper_tts_copy_no_ffmpeg.py

import logging
from io import BytesIO
from uuid import uuid4
import tempfile
import os

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

from deep_translator import GoogleTranslator
import easyocr
from langdetect import detect, DetectorFactory
from gtts import gTTS
import whisper

DetectorFactory.seed = 0

# --- Логирование ---
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- Конфигурация ---
TG_BOT_TOKEN = "8309228719:AAG6pgCzfHzn_cR4ZSjd84ekcWObslA0rnY"

LANG_MAP = {
    "Русский": "ru",
    "English": "en",
    "中文": "zh-CN",
}

CODE_TO_NAME = {v: k for k, v in LANG_MAP.items()}

# --- OCR Reader ---
reader_cn = easyocr.Reader(['ch_sim', 'en'], gpu=False)
reader_ru = easyocr.Reader(['ru', 'en'], gpu=False)

# --- Whisper model ---
try:
    whisper_model = whisper.load_model("small")
    logger.info("Whisper model loaded")
except Exception as e:
    logger.exception("Failed to load Whisper model: %s", e)
    whisper_model = None

# --- Helpers ---
def detect_language_of_text(text: str) -> str:
    try:
        lang = detect(text).lower()
        if lang.startswith("zh"):
            return "zh-CN"
        if lang.startswith("ru"):
            return "ru"
        if lang.startswith("en"):
            return "en"
        return lang
    except Exception as e:
        logger.warning("langdetect failed: %s", e)
        return "en"

def build_lang_buttons(source_code: str):
    buttons = []
    for name, code in LANG_MAP.items():
        if code == source_code:
            continue
        buttons.append(InlineKeyboardButton(text=name, callback_data=f"translate_{code}"))
    return InlineKeyboardMarkup([buttons])

def build_copy_button(copy_key: str):
    return InlineKeyboardMarkup([[InlineKeyboardButton(text="Скопировать перевод", callback_data=f"copy_{copy_key}")]])

# --- Handlers ---
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Привет! Я переводчик (RU/EN/中文).\n"
        "Отправь текст, фото или голосовое сообщение — я определю язык и предложу варианты перевода."
    )

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text.strip()
    if not user_text:
        await update.message.reply_text("Пустой текст — пришлите непустой текст.")
        return

    src_code = detect_language_of_text(user_text)
    src_name = CODE_TO_NAME.get(src_code, src_code)

    context.user_data['pending_text'] = user_text
    context.user_data['pending_source'] = src_code

    keyboard = build_lang_buttons(src_code)
    await update.message.reply_text(
        f"Определил язык: {src_name} ({src_code}). На какой язык переводим?",
        reply_markup=keyboard
    )

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    if not msg.photo:
        await update.message.reply_text("Фото не обнаружено.")
        return

    photo = msg.photo[-1]
    bio = BytesIO()

    file = await photo.get_file()
    await file.download_to_memory(out=bio)
    bio.seek(0)
    image_bytes = bio.read()

    try:
        temp_text = " ".join([text for _, text, _ in reader_cn.readtext(image_bytes)])
        results = reader_cn.readtext(image_bytes) if detect_language_of_text(temp_text).startswith("zh") else reader_ru.readtext(image_bytes)
    except Exception as e:
        logger.exception("OCR error: %s", e)
        await update.message.reply_text("Ошибка OCR при обработке изображения.")
        return

    ocr_text = " ".join([text for _, text, _ in results]).strip()
    if not ocr_text:
        await update.message.reply_text("Не удалось распознать текст на фото.")
        return

    context.user_data['pending_text'] = ocr_text
    src_code = detect_language_of_text(ocr_text)
    context.user_data['pending_source'] = src_code
    src_name = CODE_TO_NAME.get(src_code, src_code)

    keyboard = build_lang_buttons(src_code)
    preview = ocr_text if len(ocr_text) <= 800 else ocr_text[:800] + "...\n\n(текст усечён в превью)"

    await update.message.reply_text(
        f"Распознанный текст (язык: {src_name}):\n\n{preview}\n\nНа какой язык переводим?",
        reply_markup=keyboard
    )

# --- Voice notes without ffmpeg ---
async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if whisper_model is None:
        await update.message.reply_text("Speech-to-text недоступно: модель Whisper не загружена на сервере.")
        return

    msg = update.message
    voice = msg.voice
    if not voice:
        await update.message.reply_text("Голосовое сообщение не обнаружено.")
        return

    bio = BytesIO()
    vf = await voice.get_file()
    await vf.download_to_memory(out=bio)
    bio.seek(0)
    ogg_bytes = bio.read()

    with tempfile.TemporaryDirectory() as tmpdir:
        ogg_path = os.path.join(tmpdir, "voice.ogg")
        with open(ogg_path, "wb") as f:
            f.write(ogg_bytes)

        try:
            res = whisper_model.transcribe(ogg_path, fp16=False)
            recognized_text = res.get("text", "").strip()
            whisper_lang = res.get("language", None)
        except Exception as e:
            logger.warning("Whisper transcription failed: %s", e)
            await update.message.reply_text(
                "Не удалось распознать голосовое сообщение (Whisper не поддерживает OGG напрямую)."
            )
            return

    if not recognized_text:
        await update.message.reply_text("Не удалось распознать речь в сообщении.")
        return

    src_code = "en"
    if whisper_lang:
        wl = whisper_lang.lower()
        if wl.startswith("ru"):
            src_code = "ru"
        elif wl.startswith("zh"):
            src_code = "zh-CN"
        elif wl.startswith("en"):
            src_code = "en"
        else:
            src_code = detect_language_of_text(recognized_text)
    else:
        src_code = detect_language_of_text(recognized_text)

    context.user_data['pending_text'] = recognized_text
    context.user_data['pending_source'] = src_code

    src_name = CODE_TO_NAME.get(src_code, src_code)
    keyboard = build_lang_buttons(src_code)
    preview = recognized_text if len(recognized_text) <= 800 else recognized_text[:800] + "...\n\n(текст усечён в превью)"

    await update.message.reply_text(
        f"Распознанный голос (язык: {src_name}):\n\n{preview}\n\nНа какой язык переводим?",
        reply_markup=keyboard
    )

# --- Callback ---
async def callback_translate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data or ""
    if data.startswith("copy_"):
        key = data[len("copy_"):]
        cache = context.user_data.get('copy_cache', {})
        text_to_copy = cache.get(key)
        if text_to_copy:
            await query.answer(text="Отправляю текст в чат", show_alert=False)
            await query.message.reply_text(text_to_copy)
            try:
                del cache[key]
                context.user_data['copy_cache'] = cache
            except Exception:
                pass
        else:
            await query.answer(text="Текст больше недоступен", show_alert=True)
        return

    if not data.startswith("translate_"):
        await query.answer()
        return

    if 'pending_text' not in context.user_data:
        await query.edit_message_text("Срок ожидания текста истёк или текста нет. Пришлите текст/фото/голос снова.")
        return

    target_code = data.replace("translate_", "", 1)
    src_code = context.user_data.get('pending_source', None)
    text = context.user_data.get('pending_text', '')

    if src_code == target_code:
        await query.edit_message_text("Исходный язык совпадает с выбранным целевым — ничего не перевожу.")
        return

    try:
        translated_text = GoogleTranslator(source='auto', target=target_code).translate(text)
    except Exception as e:
        logger.exception("Ошибка при переводе: %s", e)
        await query.edit_message_text("Ошибка при переводе. Попробуйте позже.")
        return

    preview_orig = text.strip()
    if len(preview_orig) > 800:
        preview_orig = preview_orig[:800] + "...\n\n(оригинал усечён)"
    src_name = CODE_TO_NAME.get(src_code, src_code)
    target_name = CODE_TO_NAME.get(target_code, target_code)

    copy_key = str(uuid4())
    cache = context.user_data.get('copy_cache', {})
    cache[copy_key] = translated_text
    context.user_data['copy_cache'] = cache

    try:
        await query.edit_message_text(
            f"Исходный ({src_name}):\n{preview_orig}\n\nПеревод ({target_name}):\n{translated_text}",
            reply_markup=build_copy_button(copy_key)
        )
    except Exception:
        await query.message.reply_text(
            f"Перевод ({target_name}):\n{translated_text}",
            reply_markup=build_copy_button(copy_key)
        )

    try:
        tts_lang = target_code.lower()
        tts = gTTS(text=translated_text, lang=tts_lang)
        bio = BytesIO()
        tts.write_to_fp(bio)
        bio.seek(0)
        await query.message.reply_voice(voice=bio)
    except Exception as e:
        logger.warning("Не удалось сгенерировать TTS: %s", e)

    context.user_data.pop('pending_text', None)
    context.user_data.pop('pending_source', None)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Примеры команд:\n"
        "/start - старт\n"
        "Отправьте текст, фото или голосовое сообщение — бот определит язык и предложит варианты перевода (RU/EN/中文).\n"
        "После перевода будет также отправлено голосовое сообщение и кнопка для копирования текста."
    )

# --- Main ---
def main():
    app = ApplicationBuilder().token(TG_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", help_cmd))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.VOICE, handle_voice))
    app.add_handler(CallbackQueryHandler(callback_translate))

    logger.info("Bot started without ffmpeg requirement")
    app.run_polling()

if __name__ == "__main__":
    main()
