# Сервис для генерации VPN конфигов

import json
import uuid
import secrets
from datetime import datetime


class VPNConfigService:
    """Сервис для генерации конфигураций VPN"""
    
    def __init__(self):
        pass
    
    def generate_wireguard_config(self, user_id, subscription_id, server_ip='10.0.0.1', private_key=None):
        """
        Генерация конфигурации WireGuard
        
        В реальном проекте здесь будет интеграция с WG-сервером через API
        или прямое добавление пиров в конфиг сервера
        """
        # Генерация ключей (в реальности нужно использовать wg genkey)
        if private_key is None:
            private_key = self._generate_private_key()
        
        public_key = self._derive_public_key(private_key)
        preshared_key = secrets.token_urlsafe(32)
        
        # Генерация IP адреса для клиента
        client_ip = self._generate_client_ip(user_id)
        
        config = {
            'interface': {
                'private_key': private_key,
                'address': f'{client_ip}/32',
                'dns': ['1.1.1.1', '1.0.0.1']
            },
            'peer': {
                'public_key': public_key,  # Публичный ключ сервера
                'endpoint': f'{server_ip}:51820',
                'preshared_key': preshared_key,
                'allowed_ips': ['0.0.0.0/0', '::/0'],
                'persistent_keepalive': 25
            }
        }
        
        # Формирование текстового конфига для WireGuard
        config_text = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/32
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = {public_key}
Endpoint = {server_ip}:51820
PresharedKey = {preshared_key}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
        
        return {
            'config_json': json.dumps(config, indent=2),
            'config_text': config_text,
            'client_ip': client_ip,
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def generate_openvpn_config(self, user_id, subscription_id, server_ip='vpn.example.com'):
        """
        Генерация конфигурации OpenVPN
        
        В реальном проекте здесь будет генерация сертификатов через easy-rsa
        и создание .ovpn файла
        """
        # В реальности здесь нужно генерировать сертификаты
        ca_cert = "-----BEGIN CERTIFICATE-----\n... CA Certificate ...\n-----END CERTIFICATE-----"
        client_cert = "-----BEGIN CERTIFICATE-----\n... Client Certificate ...\n-----END CERTIFICATE-----"
        client_key = "-----BEGIN PRIVATE KEY-----\n... Client Private Key ...\n-----END PRIVATE KEY-----"
        ta_key = "# OpenVPN Static key V1\n..."
        
        config_text = f"""client
dev tun
proto udp
remote {server_ip} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
{ca_cert}
</ca>

<cert>
{client_cert}
</cert>

<key>
{client_key}
</key>

<tls-auth>
{ta_key}
</tls-auth>
"""
        
        return {
            'config_text': config_text,
            'config_format': 'ovpn',
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _generate_private_key(self):
        """Генерация приватного ключа (упрощённо)"""
        # В реальности использовать криптографически безопасную генерацию
        return secrets.token_urlsafe(44)[:44]
    
    def _derive_public_key(self, private_key):
        """Получение публичного ключа из приватного (упрощённо)"""
        # В реальности это делается через криптографические функции Curve25519
        return secrets.token_urlsafe(44)[:44]
    
    def _generate_client_ip(self, user_id):
        """Генерация IP адреса для клиента в подсети VPN"""
        # Простая детерминированная генерация на основе user_id
        last_octet = (user_id % 254) + 2  # Избегаем .0 и .1
        return f'10.0.0.{last_octet}'
    
    def validate_config(self, config_text, config_type='wireguard'):
        """Валидация конфигурации"""
        if not config_text:
            return {'valid': False, 'error': 'Конфигурация пустая'}
        
        if config_type == 'wireguard':
            if '[Interface]' not in config_text or '[Peer]' not in config_text:
                return {'valid': False, 'error': 'Неверный формат WireGuard конфига'}
            if 'PrivateKey' not in config_text:
                return {'valid': False, 'error': 'Отсутствует приватный ключ'}
        
        elif config_type == 'openvpn':
            if 'client' not in config_text or 'remote' not in config_text:
                return {'valid': False, 'error': 'Неверный формат OpenVPN конфига'}
        
        return {'valid': True}
