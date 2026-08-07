# API маршруты для подписок

from flask import Blueprint, request, current_app, send_file
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import json
import io

from backend.models.models import db, Subscription, Plan, Payment
from backend.utils.helpers import api_response, api_error
from backend.services.vpn_config_service import VPNConfigService

subscriptions_bp = Blueprint('subscriptions', __name__, url_prefix='/api/subscriptions')


@subscriptions_bp.route('', methods=['GET'])
@login_required
def get_subscriptions():
    """Получение всех подписок текущего пользователя"""
    status_filter = request.args.get('status')
    
    query = Subscription.query.filter_by(user_id=current_user.id)
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    subscriptions = query.order_by(Subscription.created_at.desc()).all()
    
    return api_response({
        'subscriptions': [sub.to_dict() for sub in subscriptions]
    })


@subscriptions_bp.route('/<int:subscription_id>', methods=['GET'])
@login_required
def get_subscription(subscription_id):
    """Получение информации о конкретной подписке"""
    subscription = Subscription.query.get(subscription_id)
    
    if not subscription:
        return api_error('Подписка не найдена', 404)
    
    # Проверка прав доступа
    if subscription.user_id != current_user.id and not current_user.is_admin:
        return api_error('Доступ запрещён', 403)
    
    return api_response({'subscription': subscription.to_dict()})


@subscriptions_bp.route('', methods=['POST'])
@login_required
def create_subscription():
    """Создание новой подписки (после оплаты)"""
    data = request.get_json()
    
    plan_id = data.get('plan_id')
    if not plan_id:
        return api_error('Не указан тарифный план', 400)
    
    plan = Plan.query.get(plan_id)
    if not plan or not plan.is_active:
        return api_error('Тарифный план недоступен', 404)
    
    # Создание подписки
    now = datetime.utcnow()
    expires_at = now + timedelta(days=plan.duration_months * 30)
    
    subscription = Subscription(
        user_id=current_user.id,
        plan_id=plan_id,
        status='active',
        started_at=now,
        expires_at=expires_at
    )
    
    try:
        db.session.add(subscription)
        db.session.flush()  # Получаем ID до коммита
        
        # Создание записи об оплате
        payment = Payment(
            user_id=current_user.id,
            subscription_id=subscription.id,
            amount=plan.price,
            currency='RUB',
            status='success',
            payment_method='mock',
            transaction_id=f'MOCK_{subscription.id}_{now.strftime("%Y%m%d")}'
        )
        db.session.add(payment)
        
        db.session.commit()
        
        return api_response(
            {'subscription': subscription.to_dict()},
            'Подписка успешно оформлена',
            201
        )
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при создании подписки: {str(e)}', 500)


@subscriptions_bp.route('/<int:subscription_id>/config', methods=['GET'])
@login_required
def get_subscription_config(subscription_id):
    """Получение конфигурации VPN для подписки"""
    subscription = Subscription.query.get(subscription_id)
    
    if not subscription:
        return api_error('Подписка не найдена', 404)
    
    # Проверка прав доступа
    if subscription.user_id != current_user.id and not current_user.is_admin:
        return api_error('Доступ запрещён', 403)
    
    # Проверка статуса подписки
    if subscription.status != 'active':
        return api_error('Подписка не активна', 400)
    
    # Генерация конфига если ещё не сгенерирован
    if not subscription.config_generated:
        config_service = VPNConfigService()
        config_data = config_service.generate_wireguard_config(
            user_id=current_user.id,
            subscription_id=subscription.id
        )
        
        subscription.config_data = config_data['config_text']
        subscription.config_generated = True
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return api_error(f'Ошибка при генерации конфига: {str(e)}', 500)
    
    return api_response({
        'config': subscription.config_data,
        'config_type': 'wireguard'
    })


@subscriptions_bp.route('/<int:subscription_id>/config/download', methods=['GET'])
@login_required
def download_subscription_config(subscription_id):
    """Скачивание конфигурации VPN в виде файла"""
    subscription = Subscription.query.get(subscription_id)
    
    if not subscription:
        return api_error('Подписка не найдена', 404)
    
    # Проверка прав доступа
    if subscription.user_id != current_user.id and not current_user.is_admin:
        return api_error('Доступ запрещён', 403)
    
    # Проверка статуса подписки
    if subscription.status != 'active':
        return api_error('Подписка не активна', 400)
    
    # Генерация конфига если ещё не сгенерирован
    if not subscription.config_generated:
        config_service = VPNConfigService()
        config_data = config_service.generate_wireguard_config(
            user_id=current_user.id,
            subscription_id=subscription.id
        )
        
        subscription.config_data = config_data['config_text']
        subscription.config_generated = True
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return api_error(f'Ошибка при генерации конфига: {str(e)}', 500)
    
    # Создание файла для скачивания
    config_bytes = subscription.config_data.encode('utf-8')
    config_io = io.BytesIO(config_bytes)
    config_io.seek(0)
    
    filename = f'vpn_subscription_{subscription_id}.conf'
    
    return send_file(
        config_io,
        mimetype='text/plain',
        as_attachment=True,
        download_name=filename
    )


@subscriptions_bp.route('/<int:subscription_id>/cancel', methods=['POST'])
@login_required
def cancel_subscription(subscription_id):
    """Отмена подписки"""
    subscription = Subscription.query.get(subscription_id)
    
    if not subscription:
        return api_error('Подписка не найдена', 404)
    
    # Проверка прав доступа
    if subscription.user_id != current_user.id and not current_user.is_admin:
        return api_error('Доступ запрещён', 403)
    
    # Нельзя отменить уже истёкшую или отменённую подписку
    if subscription.status in ['expired', 'cancelled']:
        return api_error('Подписка уже не активна', 400)
    
    subscription.status = 'cancelled'
    
    try:
        db.session.commit()
        return api_response({}, 'Подписка отменена')
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при отмене подписки: {str(e)}', 500)


@subscriptions_bp.route('/<int:subscription_id>/renew', methods=['POST'])
@login_required
def renew_subscription(subscription_id):
    """Продление подписки"""
    subscription = Subscription.query.get(subscription_id)
    
    if not subscription:
        return api_error('Подписка не найдена', 404)
    
    # Проверка прав доступа
    if subscription.user_id != current_user.id and not current_user.is_admin:
        return api_error('Доступ запрещён', 403)
    
    plan = subscription.plan
    if not plan or not plan.is_active:
        return api_error('Тарифный план недоступен', 404)
    
    # Продление срока действия
    now = datetime.utcnow()
    if subscription.expires_at and subscription.expires_at > now:
        # Если подписка активна, продлеваем от текущей даты окончания
        new_expires_at = subscription.expires_at + timedelta(days=plan.duration_months * 30)
    else:
        # Если подписка истекла, продлеваем от текущей даты
        new_expires_at = now + timedelta(days=plan.duration_months * 30)
    
    subscription.expires_at = new_expires_at
    subscription.status = 'active'
    
    # Создание записи об оплате
    payment = Payment(
        user_id=current_user.id,
        subscription_id=subscription.id,
        amount=plan.price,
        currency='RUB',
        status='success',
        payment_method='mock',
        transaction_id=f'MOCK_RENEW_{subscription.id}_{now.strftime("%Y%m%d")}'
    )
    
    try:
        db.session.add(payment)
        db.session.commit()
        return api_response(
            {'subscription': subscription.to_dict()},
            'Подписка продлена'
        )
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при продлении подписки: {str(e)}', 500)
