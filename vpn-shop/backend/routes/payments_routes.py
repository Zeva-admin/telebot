# API маршруты для платежей

from flask import Blueprint, request, current_app
from flask_login import login_required, current_user
import json

from backend.models.models import db, Payment, Subscription
from backend.utils.helpers import api_response, api_error
from backend.services.payment_service import get_payment_provider

payments_bp = Blueprint('payments', __name__, url_prefix='/api/payments')


@payments_bp.route('', methods=['GET'])
@login_required
def get_payments():
    """Получение истории платежей текущего пользователя"""
    payments = Payment.query.filter_by(user_id=current_user.id)\
        .order_by(Payment.created_at.desc()).all()
    
    return api_response({
        'payments': [payment.to_dict() for payment in payments]
    })


@payments_bp.route('/<int:payment_id>', methods=['GET'])
@login_required
def get_payment(payment_id):
    """Получение информации о конкретном платеже"""
    payment = Payment.query.get(payment_id)
    
    if not payment:
        return api_error('Платёж не найден', 404)
    
    # Проверка прав доступа
    if payment.user_id != current_user.id and not current_user.is_admin:
        return api_error('Доступ запрещён', 403)
    
    return api_response({'payment': payment.to_dict()})


@payments_bp.route('/create', methods=['POST'])
@login_required
def create_payment():
    """Создание нового платежа"""
    data = request.get_json()
    
    subscription_id = data.get('subscription_id')
    amount = data.get('amount')
    currency = data.get('currency', 'RUB')
    description = data.get('description', 'Оплата VPN подписки')
    payment_method = data.get('payment_method', 'card')
    
    if not subscription_id and not amount:
        return api_error('Необходимо указать subscription_id или amount', 400)
    
    # Если указан subscription_id, получаем сумму из подписки
    if subscription_id:
        subscription = Subscription.query.get(subscription_id)
        if not subscription:
            return api_error('Подписка не найдена', 404)
        
        if subscription.user_id != current_user.id:
            return api_error('Доступ запрещён', 403)
        
        amount = subscription.plan.price
    
    if not amount or amount <= 0:
        return api_error('Некорректная сумма платежа', 400)
    
    # Получение платёжного провайдера
    config = current_app.config
    provider = get_payment_provider(config.get('PAYMENT_PROVIDER', 'mock'), config)
    
    # Создание платежа через провайдера
    result = provider.create_payment(
        amount=amount,
        currency=currency,
        description=description,
        user_id=current_user.id,
        subscription_id=subscription_id
    )
    
    if not result.get('success'):
        return api_error(result.get('error', 'Ошибка создания платежа'), 500)
    
    # Сохранение платежа в БД
    payment = Payment(
        user_id=current_user.id,
        subscription_id=subscription_id,
        amount=amount,
        currency=currency,
        status='pending',
        payment_method=payment_method,
        transaction_id=result.get('transaction_id'),
        provider_response=json.dumps(result)
    )
    
    try:
        db.session.add(payment)
        db.session.flush()
        
        # Обновление данных с ID из БД
        result['payment_db_id'] = payment.id
        
        db.session.commit()
        
        return api_response(result, 'Платёж создан', 201)
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при сохранении платежа: {str(e)}', 500)


@payments_bp.route('/<int:payment_id>/confirm', methods=['POST'])
@login_required
def confirm_payment(payment_id):
    """Подтверждение платежа (callback от платёжной системы)"""
    payment = Payment.query.get(payment_id)
    
    if not payment:
        return api_error('Платёж не найден', 404)
    
    # Проверка прав доступа
    if payment.user_id != current_user.id and not current_user.is_admin:
        return api_error('Доступ запрещён', 403)
    
    if payment.status != 'pending':
        return api_error(f'Платёж уже в статусе {payment.status}', 400)
    
    # Получение платёжного провайдера
    config = current_app.config
    provider = get_payment_provider(config.get('PAYMENT_PROVIDER', 'mock'), config)
    
    # Подтверждение через провайдера
    data = request.get_json() or {}
    result = provider.confirm_payment(payment_id, data)
    
    if not result.get('success'):
        return api_error(result.get('error', 'Ошибка подтверждения платежа'), 500)
    
    # Обновление статуса платежа
    payment.status = 'success'
    payment.transaction_id = result.get('transaction_id')
    
    try:
        db.session.commit()
        
        # Если есть подписка, активируем её
        if payment.subscription_id:
            subscription = Subscription.query.get(payment.subscription_id)
            if subscription:
                from datetime import datetime, timedelta
                subscription.status = 'active'
                if not subscription.started_at:
                    subscription.started_at = datetime.utcnow()
                if not subscription.expires_at:
                    plan = subscription.plan
                    subscription.expires_at = datetime.utcnow() + timedelta(days=plan.duration_months * 30)
                db.session.commit()
        
        return api_response({
            'payment': payment.to_dict(),
            'message': 'Платёж успешно подтверждён'
        })
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при подтверждении платежа: {str(e)}', 500)


@payments_bp.route('/<int:payment_id>/refund', methods=['POST'])
@login_required
def refund_payment(payment_id):
    """Возврат средств по платежу"""
    payment = Payment.query.get(payment_id)
    
    if not payment:
        return api_error('Платёж не найден', 404)
    
    # Проверка прав доступа (только админ или владелец)
    if payment.user_id != current_user.id and not current_user.is_admin:
        return api_error('Доступ запрещён', 403)
    
    if payment.status != 'success':
        return api_error('Возврат возможен только для успешных платежей', 400)
    
    data = request.get_json() or {}
    refund_amount = data.get('amount')  # Если None, то полный возврат
    
    # Получение платёжного провайдера
    config = current_app.config
    provider = get_payment_provider(config.get('PAYMENT_PROVIDER', 'mock'), config)
    
    # Возврат через провайдера
    result = provider.refund_payment(payment_id, refund_amount)
    
    if not result.get('success'):
        return api_error(result.get('error', 'Ошибка возврата средств'), 500)
    
    # Обновление статуса платежа
    payment.status = 'refunded'
    
    try:
        db.session.commit()
        
        # Если есть подписка, отменяем её
        if payment.subscription_id:
            subscription = Subscription.query.get(payment.subscription_id)
            if subscription:
                subscription.status = 'cancelled'
                db.session.commit()
        
        return api_response({
            'payment': payment.to_dict(),
            'message': 'Средства возвращены'
        })
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при возврате средств: {str(e)}', 500)


# Mock эндпоинты для тестирования платежки
@payments_bp.route('/mock/confirm/<string:payment_id>', methods=['GET', 'POST'])
def mock_confirm_payment(payment_id):
    """Mock-эндпоинт для подтверждения платежа (тестирование)"""
    config = current_app.config
    provider = get_payment_provider('mock', config)
    
    result = provider.confirm_payment(payment_id, {})
    
    if result.get('success'):
        # Обновляем в БД если это наш платёж
        payment = Payment.query.filter_by(transaction_id=f"MOCK_{payment_id.split('_')[-1]}").first()
        if payment:
            payment.status = 'success'
            db.session.commit()
    
    return api_response(result)


@payments_bp.route('/mock/status/<string:payment_id>', methods=['GET'])
def mock_payment_status(payment_id):
    """Mock-эндпоинт для получения статуса платежа"""
    config = current_app.config
    provider = get_payment_provider('mock', config)
    
    result = provider.get_payment_status(payment_id)
    return api_response(result)
