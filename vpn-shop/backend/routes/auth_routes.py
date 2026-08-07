# API маршруты для аутентификации

from flask import Blueprint, request, session
from flask_login import login_user, logout_user, login_required, current_user
from backend.models.models import db, User
from backend.utils.helpers import api_response, api_error, validate_json, validate_email, validate_password

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
@validate_json('email', 'password')
def register():
    """Регистрация нового пользователя"""
    data = request.get_json()
    
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    
    # Валидация email
    if not validate_email(email):
        return api_error('Некорректный email адрес', 400)
    
    # Проверка существования пользователя
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return api_error('Пользователь с таким email уже существует', 409)
    
    # Валидация пароля
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return api_error(error_msg, 400)
    
    # Создание пользователя
    user = User(
        email=email,
        first_name=first_name or None,
        last_name=last_name or None
    )
    user.set_password(password)
    
    try:
        db.session.add(user)
        db.session.commit()
        
        # Автоматический вход после регистрации
        login_user(user, remember=True)
        
        return api_response(
            {'user': user.to_dict()},
            'Пользователь успешно зарегистрирован',
            201
        )
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при регистрации: {str(e)}', 500)


@auth_bp.route('/login', methods=['POST'])
@validate_json('email', 'password')
def login():
    """Вход пользователя"""
    data = request.get_json()
    
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    remember = data.get('remember', True)
    
    # Поиск пользователя
    user = User.query.filter_by(email=email).first()
    
    if not user or not user.check_password(password):
        return api_error('Неверный email или пароль', 401)
    
    # Вход
    login_user(user, remember=remember)
    
    return api_response(
        {'user': user.to_dict()},
        'Успешный вход'
    )


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Выход пользователя"""
    logout_user()
    return api_response({}, 'Успешный выход')


@auth_bp.route('/me', methods=['GET'])
@login_required
def get_current_user():
    """Получение данных текущего пользователя"""
    return api_response({'user': current_user.to_dict()})


@auth_bp.route('/me', methods=['PUT'])
@login_required
@validate_json('email')
def update_current_user():
    """Обновление данных текущего пользователя"""
    data = request.get_json()
    
    email = data.get('email', '').lower().strip()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    
    # Валидация email
    if email and not validate_email(email):
        return api_error('Некорректный email адрес', 400)
    
    # Проверка уникальности email (если меняем)
    if email != current_user.email:
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return api_error('Пользователь с таким email уже существует', 409)
        current_user.email = email
    
    if first_name:
        current_user.first_name = first_name
    if last_name:
        current_user.last_name = last_name
    
    try:
        db.session.commit()
        return api_response({'user': current_user.to_dict()}, 'Данные обновлены')
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при обновлении: {str(e)}', 500)


@auth_bp.route('/change-password', methods=['POST'])
@login_required
@validate_json('current_password', 'new_password')
def change_password():
    """Смена пароля"""
    data = request.get_json()
    
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    # Проверка текущего пароля
    if not current_user.check_password(current_password):
        return api_error('Неверный текущий пароль', 400)
    
    # Валидация нового пароля
    is_valid, error_msg = validate_password(new_password)
    if not is_valid:
        return api_error(error_msg, 400)
    
    # Установка нового пароля
    current_user.set_password(new_password)
    
    try:
        db.session.commit()
        return api_response({}, 'Пароль успешно изменён')
    except Exception as e:
        db.session.rollback()
        return api_error(f'Ошибка при смене пароля: {str(e)}', 500)
