from aiogram import Bot, Dispatcher, types
from aiogram.utils import executor

API_TOKEN = "8115570934:AAGFJFnNDo5lxDlE3XZEQ_W63WjuoYYHJJM"

bot = Bot(token=API_TOKEN)
dp = Dispatcher(bot)

@dp.message_handler(commands=['start'])
async def start_cmd(message: types.Message):
    await message.answer("старт")

if __name__ == "__main__":
    executor.start_polling(dp, skip_updates=True)
