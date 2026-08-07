# Модели базы данных

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """Модель пользователя"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Связи
    subscriptions = db.relationship('Subscription', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    payments = db.relationship('Payment', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Хэширование пароля"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Проверка пароля"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Сериализация в словарь"""
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Plan(db.Model):
    """Модель тарифного плана"""
    __tablename__ = 'plans'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)  # Цена в рублях
    duration_months = db.Column(db.Integer, nullable=False)  # Срок подписки в месяцах
    max_devices = db.Column(db.Integer, nullable=False)  # Максимум устройств
    speed_limit_mbps = db.Column(db.Integer)  # Ограничение скорости (None = безлимит)
    traffic_limit_gb = db.Column(db.Integer)  # Лимит трафика (None = безлимит)
    is_active = db.Column(db.Boolean, default=True)
    is_popular = db.Column(db.Boolean, default=False)  # Пометить как популярный
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связи
    subscriptions = db.relationship('Subscription', backref='plan', lazy='dynamic')
    
    def to_dict(self):
        """Сериализация в словарь"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'duration_months': self.duration_months,
            'max_devices': self.max_devices,
            'speed_limit_mbps': self.speed_limit_mbps,
            'traffic_limit_gb': self.traffic_limit_gb,
            'is_active': self.is_active,
            'is_popular': self.is_popular
        }


class Subscription(db.Model):
    """Модель подписки пользователя"""
    __tablename__ = 'subscriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('plans.id'), nullable=False)
    status = db.Column(db.String(20), default='active')  # active, expired, cancelled
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)  # Дата окончания
    config_generated = db.Column(db.Boolean, default=False)  # Сгенерирован ли конфиг
    config_data = db.Column(db.Text)  # JSON с конфигурацией VPN
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Связи
    payments = db.relationship('Payment', backref='subscription', lazy='dynamic')
    
    def to_dict(self):
        """Сериализация в словарь"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'plan_id': self.plan_id,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'config_generated': self.config_generated,
            'plan': self.plan.to_dict() if self.plan else None
        }


class Payment(db.Model):
    """Модель платежа"""
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscriptions.id'))
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='RUB')
    status = db.Column(db.String(20), default='pending')  # pending, success, failed, refunded
    payment_method = db.Column(db.String(50))  # card, yoomoney, etc.
    transaction_id = db.Column(db.String(100))  # ID транзакции от платёжной системы
    provider_response = db.Column(db.Text)  # Полный ответ от провайдера (JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Сериализация в словарь"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'subscription_id': self.subscription_id,
            'amount': self.amount,
            'currency': self.currency,
            'status': self.status,
            'payment_method': self.payment_method,
            'transaction_id': self.transaction_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
