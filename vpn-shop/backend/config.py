# Конфигурация приложения

import os
from datetime import timedelta

class Config:
    """Базовая конфигурация"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Настройки базы данных
    # Для SQLite (разработка):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///vpn_shop.db'
    
    # Для PostgreSQL (продакшен):
    # SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://user:password@localhost/vpn_shop'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }
    
    # Настройки сессий
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # JWT настройки (если будем использовать)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Платёжный шлюз
    PAYMENT_PROVIDER = os.environ.get('PAYMENT_PROVIDER') or 'mock'  # 'mock', 'stripe', 'yookassa'
    
    # Mock платёжка (тестовые данные)
    MOCK_PAYMENT_SUCCESS = True
    
    # Stripe настройки (для продакшена)
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY') or ''
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY') or ''
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET') or ''
    
    # YooKassa настройки (для продакшена)
    YOOKASSA_SHOP_ID = os.environ.get('YOOKASSA_SHOP_ID') or ''
    YOOKASSA_SECRET_KEY = os.environ.get('YOOKASSA_SECRET_KEY') or ''


class DevelopmentConfig(Config):
    """Конфигурация для разработки"""
    DEBUG = True


class ProductionConfig(Config):
    """Конфигурация для продакшена"""
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
