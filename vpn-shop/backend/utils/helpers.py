# Декораторы и утилиты

from functools import wraps
from flask import jsonify, request, current_app
from flask_login import current_user


def api_response(data=None, message='OK', status_code=200):
    """Стандартный формат ответа API"""
    response = {
        'success': True,
        'message': message,
        'data': data if data is not None else {}
    }
    return jsonify(response), status_code


def api_error(message='Error', status_code=400, errors=None):
    """Стандартный формат ошибки API"""
    response = {
        'success': False,
        'message': message,
        'errors': errors
    }
    return jsonify(response), status_code


def admin_required(f):
    """Декоратор для ограничения доступа администраторам"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return api_error('Требуется авторизация', 401)
        
        if not current_user.is_admin:
            return api_error('Требуется права администратора', 403)
        
        return f(*args, **kwargs)
    
    return decorated_function


def validate_json(*required_fields):
    """Декоратор для валидации JSON в запросе"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return api_error('Content-Type должен быть application/json', 400)
            
            data = request.get_json()
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                return api_error(
                    f'Отсутствуют обязательные поля: {", ".join(missing_fields)}',
                    400,
                    {'missing_fields': missing_fields}
                )
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_email(email):
    """Простая валидация email"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """Валидация пароля (минимум 8 символов)"""
    if len(password) < 8:
        return False, 'Пароль должен содержать минимум 8 символов'
    return True, None


def paginate_query(query, page=1, per_page=20):
    """Пагинация SQLAlchemy запроса"""
    page = max(1, page)
    per_page = min(100, per_page)  # Максимум 100 записей на страницу
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return {
        'items': [item.to_dict() if hasattr(item, 'to_dict') else item for item in pagination.items],
        'page': page,
        'per_page': per_page,
        'total': pagination.total,
        'pages': pagination.pages,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    }
