# Сервис оплаты - базовый интерфейс и реализации

from abc import ABC, abstractmethod
import json
import uuid
from datetime import datetime


class PaymentProvider(ABC):
    """Базовый класс для платёжных провайдеров"""
    
    @abstractmethod
    def create_payment(self, amount, currency, description, user_id, subscription_id):
        """Создание платежа"""
        pass
    
    @abstractmethod
    def confirm_payment(self, payment_id, transaction_data):
        """Подтверждение платежа"""
        pass
    
    @abstractmethod
    def get_payment_status(self, payment_id):
        """Получение статуса платежа"""
        pass
    
    @abstractmethod
    def refund_payment(self, payment_id, amount=None):
        """Возврат средств"""
        pass


class MockPaymentProvider(PaymentProvider):
    """Mock-провайдер для тестирования (имитация платёжной системы)"""
    
    def __init__(self):
        self._payments = {}  # Хранилище платежей в памяти
    
    def create_payment(self, amount, currency, description, user_id, subscription_id):
        """Создание тестового платежа"""
        payment_id = str(uuid.uuid4())
        transaction_id = f"MOCK_{uuid.uuid4().hex[:12].upper()}"
        
        payment_data = {
            'id': payment_id,
            'transaction_id': transaction_id,
            'amount': amount,
            'currency': currency,
            'description': description,
            'user_id': user_id,
            'subscription_id': subscription_id,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat(),
            'confirmation_url': f'/api/payments/mock/confirm/{payment_id}',
            'provider': 'mock'
        }
        
        self._payments[payment_id] = payment_data
        
        return {
            'success': True,
            'payment_id': payment_id,
            'transaction_id': transaction_id,
            'confirmation_url': f'/api/payments/mock/confirm/{payment_id}',
            'amount': amount,
            'currency': currency
        }
    
    def confirm_payment(self, payment_id, transaction_data=None):
        """Подтверждение тестового платежа (всегда успешно)"""
        if payment_id not in self._payments:
            return {'success': False, 'error': 'Платёж не найден'}
        
        payment = self._payments[payment_id]
        payment['status'] = 'success'
        payment['confirmed_at'] = datetime.utcnow().isoformat()
        
        return {
            'success': True,
            'payment_id': payment_id,
            'status': 'success',
            'transaction_id': payment['transaction_id']
        }
    
    def get_payment_status(self, payment_id):
        """Получение статуса платежа"""
        if payment_id not in self._payments:
            return {'success': False, 'error': 'Платёж не найден'}
        
        payment = self._payments[payment_id]
        return {
            'success': True,
            'payment_id': payment_id,
            'status': payment['status'],
            'amount': payment['amount'],
            'currency': payment['currency']
        }
    
    def refund_payment(self, payment_id, amount=None):
        """Возврат средств (для тестов всегда успешно)"""
        if payment_id not in self._payments:
            return {'success': False, 'error': 'Платёж не найден'}
        
        payment = self._payments[payment_id]
        payment['status'] = 'refunded'
        payment['refunded_at'] = datetime.utcnow().isoformat()
        
        return {
            'success': True,
            'payment_id': payment_id,
            'status': 'refunded',
            'refunded_amount': amount or payment['amount']
        }


class StripePaymentProvider(PaymentProvider):
    """Stripe провайдер (заглушка для примера)"""
    
    def __init__(self, secret_key):
        self.secret_key = secret_key
        # В реальном проекте: import stripe; stripe.api_key = secret_key
    
    def create_payment(self, amount, currency, description, user_id, subscription_id):
        """Создание платежа через Stripe"""
        # TODO: Реализовать интеграцию со Stripe
        # Пример:
        # intent = stripe.PaymentIntent.create(
        #     amount=int(amount * 100),  # Stripe работает с копейками
        #     currency=currency.lower(),
        #     description=description,
        #     metadata={'user_id': user_id, 'subscription_id': subscription_id}
        # )
        return {
            'success': False,
            'error': 'Stripe провайдер ещё не реализован'
        }
    
    def confirm_payment(self, payment_id, transaction_data):
        """Подтверждение платежа Stripe"""
        # TODO: Реализовать подтверждение
        return {'success': False, 'error': 'Не реализовано'}
    
    def get_payment_status(self, payment_id):
        """Получение статуса платежа Stripe"""
        # TODO: Реализовать получение статуса
        return {'success': False, 'error': 'Не реализовано'}
    
    def refund_payment(self, payment_id, amount=None):
        """Возврат средств через Stripe"""
        # TODO: Реализовать возврат
        return {'success': False, 'error': 'Не реализовано'}


class YooKassaPaymentProvider(PaymentProvider):
    """YooKassa провайдер (заглушка для примера)"""
    
    def __init__(self, shop_id, secret_key):
        self.shop_id = shop_id
        self.secret_key = secret_key
    
    def create_payment(self, amount, currency, description, user_id, subscription_id):
        """Создание платежа через YooKassa"""
        # TODO: Реализовать интеграцию с YooKassa
        # Пример:
        # from yookassa import Configuration, Payment
        # Configuration.account_id = self.shop_id
        # Configuration.secret_key = self.secret_key
        # payment = Payment.create({
        #     'amount': {'value': amount, 'currency': currency},
        #     'description': description,
        #     'metadata': {'user_id': user_id, 'subscription_id': subscription_id}
        # })
        return {
            'success': False,
            'error': 'YooKassa провайдер ещё не реализован'
        }
    
    def confirm_payment(self, payment_id, transaction_data):
        """Подтверждение платежа YooKassa"""
        # TODO: Реализовать подтверждение
        return {'success': False, 'error': 'Не реализовано'}
    
    def get_payment_status(self, payment_id):
        """Получение статуса платежа YooKassa"""
        # TODO: Реализовать получение статуса
        return {'success': False, 'error': 'Не реализовано'}
    
    def refund_payment(self, payment_id, amount=None):
        """Возврат средств через YooKassa"""
        # TODO: Реализовать возврат
        return {'success': False, 'error': 'Не реализовано'}


def get_payment_provider(provider_name, config):
    """Фабрика для получения нужного провайдера"""
    providers = {
        'mock': lambda: MockPaymentProvider(),
        'stripe': lambda: StripePaymentProvider(config.get('STRIPE_SECRET_KEY')),
        'yookassa': lambda: YooKassaPaymentProvider(
            config.get('YOOKASSA_SHOP_ID'),
            config.get('YOOKASSA_SECRET_KEY')
        )
    }
    
    provider_factory = providers.get(provider_name, providers['mock'])
    return provider_factory()
