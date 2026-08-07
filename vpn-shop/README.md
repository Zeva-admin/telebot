# VPN Shop - Сервис продажи VPN-подписок

Full-stack веб-приложение для продажи VPN-подписок с личным кабинетом пользователя, админ-панелью и интеграцией платёжных систем.

## 📁 Структура проекта

```
vpn-shop/
├── backend/
│   ├── __init__.py
│   ├── app.py                 # Главное приложение Flask
│   ├── config.py              # Конфигурация приложения
│   ├── models/
│   │   └── models.py          # Модели базы данных (User, Plan, Subscription, Payment)
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth_routes.py     # API аутентификации (/api/auth/*)
│   │   ├── plans_routes.py    # API тарифов (/api/plans/*)
│   │   ├── subscriptions_routes.py  # API подписок (/api/subscriptions/*)
│   │   ├── payments_routes.py # API платежей (/api/payments/*)
│   │   └── admin_routes.py    # API админки (/api/admin/*)
│   ├── services/
│   │   ├── __init__.py
│   │   ├── payment_service.py # Платёжный сервис (Mock/Stripe/YooKassa)
│   │   └── vpn_config_service.py  # Генерация VPN конфигов
│   └── utils/
│       └── helpers.py         # Утилиты и декораторы
├── static/
│   ├── css/
│   │   └── styles.css         # Основные стили
│   └── js/
│       └── app.js             # Клиентский JavaScript
├── templates/
│   ├── index.html             # Главная страница
│   ├── login.html             # Страница входа
│   ├── register.html          # Страница регистрации
│   ├── dashboard.html         # Личный кабинет
│   ├── plans.html             # Страница тарифов
│   ├── admin.html             # Админ-панель
│   └── error.html             # Страница ошибок
├── requirements.txt           # Зависимости Python
└── README.md                  # Этот файл
```

## 🛠 Выбор стека: Почему Flask?

**Flask выбран вместо Django по следующим причинам:**

1. **Лёгковесность**: Flask минималистичен, не навязывает избыточную структуру
2. **Гибкость**: Легко настраивается под конкретные задачи VPN-сервиса
3. **Прозрачность**: Код проще для понимания и модификации
4. **REST API**: Flask идеально подходит для создания чистых REST API эндпоинтов
5. **Быстрый старт**: Меньше boilerplate кода по сравнению с Django

## 🚀 Быстрый старт

### 1. Установка зависимостей

```bash
cd vpn-shop
pip install -r requirements.txt
```

### 2. Запуск сервера разработки

```bash
# Вариант 1: Прямой запуск
python backend/app.py

# Вариант 2: Через Flask CLI
export FLASK_APP=backend.app
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000
```

### 3. Доступ к приложению

Откройте браузер и перейдите по адресу: http://localhost:5000

### 4. Данные для входа (администратор)

- Email: `admin@vpnshop.local`
- Пароль: `admin123456`

## 📡 REST API Endpoints

### Аутентификация (`/api/auth`)
| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| POST | `/register` | Регистрация нового пользователя |
| POST | `/login` | Вход в систему |
| POST | `/logout` | Выход из системы |
| GET | `/me` | Данные текущего пользователя |
| PUT | `/me` | Обновление профиля |
| POST | `/change-password` | Смена пароля |

### Тарифные планы (`/api/plans`)
| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| GET | `/` | Список активных тарифов |
| GET | `/<id>` | Информация о тарифе |
| POST | `/` | Создание тарифа (админ) |
| PUT | `/<id>` | Обновление тарифа (админ) |
| DELETE | `/<id>` | Удаление тарифа (админ) |

### Подписки (`/api/subscriptions`)
| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| GET | `/` | Список подписок пользователя |
| GET | `/<id>` | Информация о подписке |
| POST | `/` | Создание новой подписки |
| GET | `/<id>/config` | Получить VPN конфиг |
| GET | `/<id>/config/download` | Скачать конфиг файлом |
| POST | `/<id>/cancel` | Отмена подписки |
| POST | `/<id>/renew` | Продление подписки |

### Платежи (`/api/payments`)
| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| GET | `/` | История платежей |
| GET | `/<id>` | Информация о платеже |
| POST | `/create` | Создание платежа |
| POST | `/<id>/confirm` | Подтверждение платежа |
| POST | `/<id>/refund` | Возврат средств |

### Админка (`/api/admin`)
| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| GET | `/stats` | Общая статистика |
| GET | `/users` | Список пользователей |
| GET | `/users/<id>` | Данные пользователя |
| POST | `/users/<id>/toggle-admin` | Изменение роли админа |
| GET | `/subscriptions` | Все подписки |
| GET | `/payments` | Все платежи |
| GET | `/plans` | Все тарифы (включая неактивные) |

## 💳 Платёжные провайдеры

В проекте реализована архитектура с поддержкой множественных платёжных провайдеров:

### Mock (тестовый)
Используется по умолчанию. Имитирует успешные платежи без реальных транзакций.

### Stripe (для продакшена)
```python
# В config.py или .env
PAYMENT_PROVIDER = 'stripe'
STRIPE_SECRET_KEY = 'sk_test_...'
STRIPE_PUBLISHABLE_KEY = 'pk_test_...'
```

### YooKassa (для РФ)
```python
# В config.py или .env
PAYMENT_PROVIDER = 'yookassa'
YOOKASSA_SHOP_ID = 'shop_id'
YOOKASSA_SECRET_KEY = 'secret_key'
```

Для подключения нового провайдера достаточно создать класс, наследующий `PaymentProvider`, и реализовать его методы.

## 🗄 База данных

### SQLite (разработка)
По умолчанию используется SQLite:
```
sqlite:///vpn_shop.db
```

### PostgreSQL (продакшен)
Для перехода на PostgreSQL:

1. Установите драйвер:
```bash
pip install psycopg2-binary
```

2. Измените конфигурацию в `backend/config.py`:
```python
SQLALCHEMY_DATABASE_URI = 'postgresql://user:password@localhost/vpn_shop'
```

3. Или через переменную окружения:
```bash
export DATABASE_URL=postgresql://user:password@localhost/vpn_shop
```

## 🔐 Безопасность

- Пароли хэшируются с помощью Werkzeug (PBKDF2)
- Сессии защищены с помощью SECRET_KEY
- CSRF защита через Flask-Login
- Валидация всех входных данных на бэкенде
- Разделение прав доступа (пользователь/админ)

## 🎨 Дизайн

- Минималистичный корпоративный стиль
- Сдержанная цветовая палитра (тёмно-синий + акцентный синий)
- Адаптивная вёрстка (mobile-first)
- Все иконки — inline SVG (без шрифтов и эмодзи)
- Чёткая типографика и сетка

## 📋 Переменные окружения

```bash
# Обязательные
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here

# Опциональные
DATABASE_URL=sqlite:///vpn_shop.db
FLASK_ENV=development
PAYMENT_PROVIDER=mock

# Для Stripe
STRIPE_SECRET_KEY=sk_...
STRIPE_PUBLISHABLE_KEY=pk_...

# Для YooKassa
YOOKASSA_SHOP_ID=...
YOOKASSA_SECRET_KEY=...
```

## 🧪 Тестирование API

Пример запроса на регистрацию:
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

Пример получения тарифов:
```bash
curl http://localhost:5000/api/plans
```

## 📝 Лицензия

MIT License
