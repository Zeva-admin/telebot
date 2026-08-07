// Основной JavaScript для VPN Shop

/**
 * API клиент для взаимодействия с бэкендом
 */
const API = {
    baseURL: '/api',
    
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        };
        
        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Ошибка запроса');
            }
            
            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },
    
    // Auth endpoints
    auth: {
        register(data) {
            return API.request('/auth/register', {
                method: 'POST',
                body: JSON.stringify(data)
            });
        },
        login(data) {
            return API.request('/auth/login', {
                method: 'POST',
                body: JSON.stringify(data)
            });
        },
        logout() {
            return API.request('/auth/logout', { method: 'POST' });
        },
        getCurrentUser() {
            return API.request('/auth/me');
        },
        updateProfile(data) {
            return API.request('/auth/me', {
                method: 'PUT',
                body: JSON.stringify(data)
            });
        },
        changePassword(data) {
            return API.request('/auth/change-password', {
                method: 'POST',
                body: JSON.stringify(data)
            });
        }
    },
    
    // Plans endpoints
    plans: {
        getAll(active = true) {
            return API.request(`/plans?active=${active}`);
        },
        getById(id) {
            return API.request(`/plans/${id}`);
        }
    },
    
    // Subscriptions endpoints
    subscriptions: {
        getAll(status = '') {
            const query = status ? `?status=${status}` : '';
            return API.request(`/subscriptions${query}`);
        },
        getById(id) {
            return API.request(`/subscriptions/${id}`);
        },
        create(data) {
            return API.request('/subscriptions', {
                method: 'POST',
                body: JSON.stringify(data)
            });
        },
        getConfig(id) {
            return API.request(`/subscriptions/${id}/config`);
        },
        cancel(id) {
            return API.request(`/subscriptions/${id}/cancel`, {
                method: 'POST'
            });
        },
        renew(id) {
            return API.request(`/subscriptions/${id}/renew`, {
                method: 'POST'
            });
        }
    },
    
    // Payments endpoints
    payments: {
        getAll() {
            return API.request('/payments');
        },
        create(data) {
            return API.request('/payments/create', {
                method: 'POST',
                body: JSON.stringify(data)
            });
        },
        confirm(id, data = {}) {
            return API.request(`/payments/${id}/confirm`, {
                method: 'POST',
                body: JSON.stringify(data)
            });
        }
    },
    
    // Admin endpoints
    admin: {
        getStats() {
            return API.request('/admin/stats');
        },
        getUsers(page = 1, perPage = 20) {
            return API.request(`/admin/users?page=${page}&per_page=${perPage}`);
        },
        getSubscriptions(page = 1, perPage = 20, status = '') {
            let query = `?page=${page}&per_page=${perPage}`;
            if (status) query += `&status=${status}`;
            return API.request(`/admin/subscriptions${query}`);
        },
        getPayments(page = 1, perPage = 20, status = '') {
            let query = `?page=${page}&per_page=${perPage}`;
            if (status) query += `&status=${status}`;
            return API.request(`/admin/payments${query}`);
        }
    }
};


/**
 * Утилиты для работы с UI
 */
const UI = {
    // Показать уведомление
    showNotification(message, type = 'info') {
        const alertClass = {
            'success': 'alert-success',
            'error': 'alert-error',
            'warning': 'alert-warning',
            'info': 'alert-info'
        }[type] || 'alert-info';
        
        const alertHTML = `
            <div class="alert ${alertClass}" role="alert">
                ${this.escapeHtml(message)}
            </div>
        `;
        
        const container = document.querySelector('.notifications-container') || this.createNotificationsContainer();
        container.insertAdjacentHTML('beforeend', alertHTML);
        
        // Автоудаление через 5 секунд
        setTimeout(() => {
            const alert = container.lastElementChild;
            if (alert) {
                alert.style.opacity = '0';
                setTimeout(() => alert.remove(), 300);
            }
        }, 5000);
    },
    
    createNotificationsContainer() {
        const container = document.createElement('div');
        container.className = 'notifications-container';
        container.style.cssText = 'position: fixed; top: 80px; right: 20px; z-index: 3000;';
        document.body.appendChild(container);
        return container;
    },
    
    // Экранирование HTML
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },
    
    // Форматирование даты
    formatDate(dateString) {
        if (!dateString) return '—';
        const date = new Date(dateString);
        return date.toLocaleDateString('ru-RU', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    },
    
    // Форматирование цены
    formatPrice(price, currency = 'RUB') {
        return new Intl.NumberFormat('ru-RU', {
            style: 'currency',
            currency: currency,
            minimumFractionDigits: 0
        }).format(price);
    },
    
    // Показ модального окна
    showModal(content) {
        const modal = document.getElementById('modal-overlay');
        const modalContent = document.getElementById('modal-content');
        
        if (typeof content === 'string') {
            modalContent.innerHTML = content;
        } else {
            modalContent.innerHTML = '';
            modalContent.appendChild(content);
        }
        
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    },
    
    // Закрытие модального окна
    hideModal() {
        const modal = document.getElementById('modal-overlay');
        modal.classList.remove('active');
        document.body.style.overflow = '';
    },
    
    // Показ загрузки на кнопке
    setButtonLoading(button, loading = true) {
        if (loading) {
            button.disabled = true;
            button.dataset.originalText = button.textContent;
            button.innerHTML = '<span class="spinner"></span> Загрузка...';
        } else {
            button.disabled = false;
            button.textContent = button.dataset.originalText || 'Готово';
        }
    },
    
    // Скрытие элемента
    hide(element) {
        if (element) element.classList.add('hidden');
    },
    
    // Показ элемента
    show(element) {
        if (element) element.classList.remove('hidden');
    }
};


/**
 * Управление состоянием авторизации
 */
const Auth = {
    user: null,
    
    async init() {
        try {
            const response = await API.auth.getCurrentUser();
            this.user = response.data.user;
            this.updateUI();
        } catch (error) {
            this.user = null;
            this.updateUI();
        }
    },
    
    updateUI() {
        const loggedInElements = document.querySelectorAll('.auth-logged-in');
        const loggedOutElements = document.querySelectorAll('.auth-logged-out');
        const userNameElements = document.querySelectorAll('.user-name');
        
        if (this.user) {
            loggedInElements.forEach(el => el.classList.remove('hidden'));
            loggedOutElements.forEach(el => el.classList.add('hidden'));
            userNameElements.forEach(el => el.textContent = this.user.email);
        } else {
            loggedInElements.forEach(el => el.classList.add('hidden'));
            loggedOutElements.forEach(el => el.classList.remove('hidden'));
        }
    },
    
    async login(email, password) {
        const response = await API.auth.login({ email, password, remember: true });
        this.user = response.data.user;
        this.updateUI();
        return response;
    },
    
    async register(data) {
        const response = await API.auth.register(data);
        this.user = response.data.user;
        this.updateUI();
        return response;
    },
    
    async logout() {
        await API.auth.logout();
        this.user = null;
        this.updateUI();
        window.location.href = '/';
    },
    
    isAdmin() {
        return this.user && this.user.is_admin;
    }
};


/**
 * Инициализация при загрузке страницы
 */
document.addEventListener('DOMContentLoaded', () => {
    // Инициализация авторизации
    Auth.init();
    
    // Мобильное меню
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    const navLinks = document.querySelector('.nav-links');
    
    if (mobileMenuBtn && navLinks) {
        mobileMenuBtn.addEventListener('click', () => {
            navLinks.classList.toggle('active');
        });
    }
    
    // Обработка форм
    document.querySelectorAll('form[data-api]').forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const submitBtn = form.querySelector('[type="submit"]');
            UI.setButtonLoading(submitBtn, true);
            
            try {
                const formData = new FormData(form);
                const data = Object.fromEntries(formData.entries());
                
                const endpoint = form.dataset.api;
                const method = form.dataset.method || 'POST';
                
                const response = await API.request(endpoint, {
                    method,
                    body: JSON.stringify(data)
                });
                
                UI.showNotification(response.message, 'success');
                
                if (form.dataset.redirect) {
                    window.location.href = form.dataset.redirect;
                }
            } catch (error) {
                UI.showNotification(error.message, 'error');
            } finally {
                UI.setButtonLoading(submitBtn, false);
            }
        });
    });
    
    // Модальные окна
    document.querySelectorAll('[data-modal]').forEach(trigger => {
        trigger.addEventListener('click', () => {
            const modalId = trigger.dataset.modal;
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.add('active');
                document.body.style.overflow = 'hidden';
            }
        });
    });
    
    document.querySelectorAll('.modal-close, .modal-overlay').forEach(closeBtn => {
        closeBtn.addEventListener('click', (e) => {
            if (e.target === closeBtn || closeBtn.classList.contains('modal-overlay')) {
                closeBtn.closest('.modal-overlay').classList.remove('active');
                document.body.style.overflow = '';
            }
        });
    });
});
