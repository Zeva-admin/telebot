# Главное приложение Flask

import os
from flask import Flask, render_template, send_from_directory
from flask_login import LoginManager, current_user
from flask_cors import CORS

from backend.config import config
from backend.models.models import db, User, Plan
from backend.routes.auth_routes import auth_bp
from backend.routes.plans_routes import plans_bp
from backend.routes.subscriptions_routes import subscriptions_bp
from backend.routes.payments_routes import payments_bp
from backend.routes.admin_routes import admin_bp


def create_app(config_name=None):
    """Фабрика приложений Flask"""
    
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Инициализация расширений
    db.init_app(app)
    CORS(app, supports_credentials=True)
    
    # Настройка Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.session_protection = 'strong'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    @login_manager.request_loader
    def load_user_from_request(request):
        # Можно добавить поддержку JWT или API ключей
        return None
    
    # Регистрация blueprint'ов
    app.register_blueprint(auth_bp)
    app.register_blueprint(plans_bp)
    app.register_blueprint(subscriptions_bp)
    app.register_blueprint(payments_bp)
    app.register_blueprint(admin_bp)
    
    # Маршруты для фронтенда
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/login')
    def login_page():
        return render_template('login.html')
    
    @app.route('/register')
    def register_page():
        return render_template('register.html')
    
    @app.route('/dashboard')
    def dashboard_page():
        if not current_user.is_authenticated:
            return render_template('login.html')
        return render_template('dashboard.html')
    
    @app.route('/plans')
    def plans_page():
        return render_template('plans.html')
    
    @app.route('/admin')
    def admin_page():
        if not current_user.is_authenticated or not current_user.is_admin:
            return render_template('login.html')
        return render_template('admin.html')
    
    # Раздача статики
    @app.route('/static/<path:filename>')
    def static_files(filename):
        return send_from_directory('static', filename)
    
    # Обработка ошибок API
    @app.errorhandler(400)
    def bad_request(error):
        if request.path.startswith('/api/'):
            from backend.utils.helpers import api_error
            return api_error('Некорректный запрос', 400)
        return render_template('error.html', error_code=400), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        if request.path.startswith('/api/'):
            from backend.utils.helpers import api_error
            return api_error('Требуется авторизация', 401)
        return render_template('error.html', error_code=401), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        if request.path.startswith('/api/'):
            from backend.utils.helpers import api_error
            return api_error('Доступ запрещён', 403)
        return render_template('error.html', error_code=403), 403
    
    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith('/api/'):
            from backend.utils.helpers import api_error
            return api_error('Ресурс не найден', 404)
        return render_template('error.html', error_code=404), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        if request.path.startswith('/api/'):
            from backend.utils.helpers import api_error
            return api_error('Внутренняя ошибка сервера', 500)
        return render_template('error.html', error_code=500), 500
    
    # Создание таблиц БД
    with app.app_context():
        db.create_all()
        
        # Создание тестовых тарифных планов если их нет
        if Plan.query.count() == 0:
            create_default_plans(app)
        
        # Создание администратора по умолчанию если нет
        if User.query.filter_by(is_admin=True).count() == 0:
            create_default_admin(app)
    
    return app


def create_default_plans(app):
    """Создание тарифных планов по умолчанию"""
    with app.app_context():
        plans_data = [
            {
                'name': 'Старт',
                'description': 'Базовый план для ознакомления с сервисом',
                'price': 299,
                'duration_months': 1,
                'max_devices': 2,
                'speed_limit_mbps': 50,
                'traffic_limit_gb': None,
                'is_popular': False
            },
            {
                'name': 'Оптима',
                'description': 'Оптимальный выбор для повседневного использования',
                'price': 799,
                'duration_months': 3,
                'max_devices': 5,
                'speed_limit_mbps': 100,
                'traffic_limit_gb': None,
                'is_popular': True
            },
            {
                'name': 'Премиум',
                'description': 'Максимальная скорость и количество устройств',
                'price': 1499,
                'duration_months': 6,
                'max_devices': 10,
                'speed_limit_mbps': None,
                'traffic_limit_gb': None,
                'is_popular': False
            },
            {
                'name': 'Годовой',
                'description': 'Выгодное предложение на целый год',
                'price': 2499,
                'duration_months': 12,
                'max_devices': 10,
                'speed_limit_mbps': None,
                'traffic_limit_gb': None,
                'is_popular': True
            }
        ]
        
        for plan_data in plans_data:
            plan = Plan(**plan_data)
            db.session.add(plan)
        
        db.session.commit()


def create_default_admin(app):
    """Создание администратора по умолчанию"""
    with app.app_context():
        admin = User(
            email='admin@vpnshop.local',
            first_name='Admin',
            last_name='User',
            is_admin=True
        )
        admin.set_password('admin123456')  # Пароль по умолчанию
        db.session.add(admin)
        db.session.commit()


# Для запуска через gunicorn / wsgi
app = create_app()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
