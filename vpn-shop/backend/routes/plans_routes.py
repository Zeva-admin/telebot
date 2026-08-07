# API маршруты для тарифных планов

from flask import Blueprint, request
from flask_login import login_required
from backend.models.models import db, Plan
from backend.utils.helpers import api_response, api_error, admin_required

plans_bp = Blueprint('plans', __name__, url_prefix='/api/plans')


@plans_bp.route('', methods=['GET'])
def get_plans():
    """Получение списка всех активных тарифных планов"""
    is_active = request.args.get('active', 'true').lower() == 'true'
    
    query = Plan.query
    if is_active:
        query = query.filter_by(is_active=True)
    
    plans = query.order_by(Plan.price).all()
    
    return api_response({
        'plans': [plan.to_dict() for plan in plans]
    })


@plans_bp.route('/<int:plan_id>', methods=['GET'])
def get_plan(plan_id):
    """Получение информации о конкретном тарифном плане"""
    plan = Plan.query.get(plan_id)
    
    if not plan:
        return api_error('Тарифный план не найден', 404)
    
    return api_response({'plan': plan.to_dict()})


@plans_bp.route('', methods=['POST'])
@login_required
@admin_required
def create_plan():
    """Создание нового тарифного плана (только админ)"""
    data = request.get_json()
    
    required_fields = ['name', 'price', 'duration_months', 'max_devices']
    missing_fields = [f for f in required_fields if f not in data]
    
    if missing_fields:
        return api_error(f'Отсутствуют обязательные поля: {", ".join(missing_fields)}', 400)
    
    plan = Plan(
        name=data['name'],
        description=data.get('description', ''),
        price=float(data['price']),
        duration_months=int(data['duration_months']),
        max_devices=int(data['max_devices']),
        speed_limit_mbps=data.get('speed_limit_mbps'),
        traffic_limit_gb=data.get('traffic_limit_gb'),
        is_popular=data.get('is_popular', False)
    )
    
    try:
        db.session.add(plan)
        db.session.commit()
        return api_response({'plan': plan.to_dict()}, 'Тарифный план создан', 201)
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при создании: {str(e)}', 500)


@plans_bp.route('/<int:plan_id>', methods=['PUT'])
@login_required
@admin_required
def update_plan(plan_id):
    """Обновление тарифного плана (только админ)"""
    plan = Plan.query.get(plan_id)
    
    if not plan:
        return api_error('Тарифный план не найден', 404)
    
    data = request.get_json()
    
    if 'name' in data:
        plan.name = data['name']
    if 'description' in data:
        plan.description = data['description']
    if 'price' in data:
        plan.price = float(data['price'])
    if 'duration_months' in data:
        plan.duration_months = int(data['duration_months'])
    if 'max_devices' in data:
        plan.max_devices = int(data['max_devices'])
    if 'speed_limit_mbps' in data:
        plan.speed_limit_mbps = data['speed_limit_mbps']
    if 'traffic_limit_gb' in data:
        plan.traffic_limit_gb = data['traffic_limit_gb']
    if 'is_active' in data:
        plan.is_active = data['is_active']
    if 'is_popular' in data:
        plan.is_popular = data['is_popular']
    
    try:
        db.session.commit()
        return api_response({'plan': plan.to_dict()}, 'Тарифный план обновлён')
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при обновлении: {str(e)}', 500)


@plans_bp.route('/<int:plan_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_plan(plan_id):
    """Удаление тарифного плана (только админ)"""
    plan = Plan.query.get(plan_id)
    
    if not plan:
        return api_error('Тарифный план не найден', 404)
    
    # Проверка наличия активных подписок
    active_subscriptions = plan.subscriptions.filter_by(status='active').count()
    if active_subscriptions > 0:
        return api_error(
            f'Нельзя удалить план с активными подписками ({active_subscriptions})',
            400
        )
    
    try:
        db.session.delete(plan)
        db.session.commit()
        return api_response({}, 'Тарифный план удалён')
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при удалении: {str(e)}', 500)
