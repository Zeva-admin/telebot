# API маршруты для админ-панели

from flask import Blueprint, request
from flask_login import login_required, current_user
from backend.models.models import db, User, Subscription, Payment, Plan
from backend.utils.helpers import api_response, api_error, admin_required, paginate_query

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


@admin_bp.route('/stats', methods=['GET'])
@login_required
@admin_required
def get_stats():
    """Получение общей статистики (только админ)"""
    stats = {
        'total_users': User.query.count(),
        'total_subscriptions': Subscription.query.count(),
        'active_subscriptions': Subscription.query.filter_by(status='active').count(),
        'total_payments': Payment.query.count(),
        'successful_payments': Payment.query.filter_by(status='success').count(),
        'total_revenue': db.session.query(db.func.sum(Payment.amount))\
            .filter_by(status='success').scalar() or 0
    }
    
    return api_response({'stats': stats})


@admin_bp.route('/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    """Получение списка пользователей с пагинацией (только админ)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = User.query.order_by(User.created_at.desc())
    result = paginate_query(query, page, per_page)
    
    return api_response(result)


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user(user_id):
    """Получение информации о пользователе (только админ)"""
    user = User.query.get(user_id)
    
    if not user:
        return api_error('Пользователь не найден', 404)
    
    user_data = user.to_dict()
    user_data['subscriptions'] = [sub.to_dict() for sub in user.subscriptions.all()]
    user_data['payments'] = [p.to_dict() for p in user.payments.all()]
    
    return api_response({'user': user_data})


@admin_bp.route('/users/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def toggle_user_admin(user_id):
    """Переключение прав администратора у пользователя (только админ)"""
    user = User.query.get(user_id)
    
    if not user:
        return api_error('Пользователь не найден', 404)
    
    # Нельзя снять права с единственного админа
    if user.is_admin:
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count <= 1:
            return api_error('Нельзя снять права с последнего администратора', 400)
    
    user.is_admin = not user.is_admin
    
    try:
        db.session.commit()
        return api_response(
            {'user': user.to_dict()},
            f'Пользователь {"стал" if user.is_admin else "перестал быть"} администратором'
        )
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка: {str(e)}', 500)


@admin_bp.route('/subscriptions', methods=['GET'])
@login_required
@admin_required
def get_subscriptions():
    """Получение списка всех подписок с пагинацией (только админ)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status')
    
    query = Subscription.query.order_by(Subscription.created_at.desc())
    if status:
        query = query.filter_by(status=status)
    
    result = paginate_query(query, page, per_page)
    
    return api_response(result)


@admin_bp.route('/payments', methods=['GET'])
@login_required
@admin_required
def get_payments():
    """Получение списка всех платежей с пагинацией (только админ)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status')
    
    query = Payment.query.order_by(Payment.created_at.desc())
    if status:
        query = query.filter_by(status=status)
    
    result = paginate_query(query, page, per_page)
    
    return api_response(result)


@admin_bp.route('/plans', methods=['GET'])
@login_required
@admin_required
def get_all_plans():
    """Получение списка всех тарифных планов включая неактивные (только админ)"""
    plans = Plan.query.order_by(Plan.price).all()
    return api_response({'plans': [plan.to_dict() for plan in plans]})
