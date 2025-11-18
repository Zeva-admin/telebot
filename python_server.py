# bot_vpn_diag_plus.py
# Сверхглубокая диагностика VPN-ключей (SS, VLESS, HTTPS subscriptions) на aiogram 3.x
# Многорезолверный DNS (A/AAAA), DoH, TCP многократные пробы, TLS (SNI/без SNI, ALPN, cipher, cert),
# HTTP-зонды, публичный IP + Geo/ASN, PTR, эвристики блокировок, итоговый рейтинг и понятный вердикт.
# Один файл, без .env.

import asyncio
import base64
import ipaddress
import json
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Tuple

import aiohttp
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import Message
import dns.asyncresolver
import dns.reversename

# =========================
# Конфиг
# =========================

BOT_TOKEN = "8115570934:AAGFJFnNDo5lxDlE3XZEQ_W63WjuoYYHJJM"

# Таймауты (сек)
DNS_TIMEOUT = 3.5
TCP_TIMEOUT = 4.0
TLS_TIMEOUT = 7.0
HTTP_TIMEOUT = 8.0

# Параллелизм
MAX_PARALLEL_HOSTS = 8
MAX_PARALLEL_DNS = 6
TCP_TRIES_PER_IP = 3  # многократные пробы для метрик

# Резолверы для DNS (A/AAAA)
DNS_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Google", "8.8.4.4"),
    ("Cloudflare", "1.1.1.1"),
    ("Cloudflare", "1.0.0.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("OpenDNS", "208.67.220.220"),
    ("Yandex", "77.88.8.8"),
    ("Yandex", "77.88.8.1"),
]

# DoH (DNS over HTTPS) — JSON API
DOH_PROVIDERS = [
    ("Google DoH", "https://dns.google/resolve"),
    ("Cloudflare DoH", "https://cloudflare-dns.com/dns-query"),
]

# Публичный IP и Geo/ASN источники
IP_ECHO_ENDPOINTS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.co/json",
    "https://ipinfo.io/json",
    "https://icanhazip.com",  # текст
]
GEO_ENDPOINTS = [
    "https://ipapi.co/json/",
    "https://ipwho.is/",
    "https://ipinfo.io/json",
]

# HTTP цели (разные AS/CDN)
HTTP_PROBE_TARGETS = [
    "https://example.com",
    "https://www.cloudflare.com",
    "https://www.google.com",
    "https://httpbin.org/get",
]

# =========================
# Модели
# =========================

@dataclass
class DNSAnswer:
    rrtype: str  # A | AAAA
    values: List[str]
    ttl: Optional[int]

@dataclass
class DNSResult:
    resolver_name: str
    resolver_ip: str
    status: str  # ok | nxdomain | timeout | error:Type
    latency_ms: float
    answers: List[DNSAnswer]

@dataclass
class DoHResult:
    provider_name: str
    status: str  # ok | error
    latency_ms: float
    answers: List[DNSAnswer]

@dataclass
class TCPProbe:
    ip: str
    port: int
    attempt: int
    status: str  # ok | timeout | refused | error:Type
    latency_ms: Optional[float]
    errno: Optional[str]

@dataclass
class TCPStats:
    ip: str
    port: int
    attempts: int
    ok_count: int
    avg_latency_ms: Optional[float]
    min_latency_ms: Optional[float]
    max_latency_ms: Optional[float]
    statuses: List[str]

@dataclass
class TLSResult:
    ip: str
    server_name: Optional[str]
    status: str  # ok | timeout | cert_error | error:Type
    latency_ms: Optional[float]
    protocol: Optional[str]  # TLSv1.3/1.2...
    cipher: Optional[str]
    alpn_protocol: Optional[str]  # h2/http/1.1/None
    cert_subject: Optional[str]
    cert_issuer: Optional[str]
    errno: Optional[str]

@dataclass
class HTTPResult:
    url: str
    status_code: Optional[int]
    status: str  # ok | timeout | error:Type
    latency_ms: Optional[float]
    server: Optional[str]
    via: Optional[str]

@dataclass
class GeoInfo:
    ip: Optional[str]
    country: Optional[str]
    city: Optional[str]
    lat: Optional[float]
    lon: Optional[float]
    org: Optional[str]
    asn: Optional[str]

@dataclass
class PTRInfo:
    ip: str
    ptr: Optional[str]
    status: str  # ok | nxdomain | timeout | error

@dataclass
class HostDiag:
    name: str
    host: str
    port: int
    protocol: str  # ss | vless | https | raw
    dns: List[DNSResult]
    doh: List[DoHResult]
    ptr: List[PTRInfo]
    tcp: List[TCPStats]
    tls: List[TLSResult]
    http: List[HTTPResult]
    geo: Optional[GeoInfo]
    score: int
    verdict: str
    notes: List[str]

# =========================
# Утилиты
# =========================

def now_ms() -> float:
    return time.perf_counter() * 1000.0

def safe_hostname(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(re.match(r"^[A-Za-z0-9.-]+$", h))

def parse_port(p: Optional[str], default: int) -> int:
    try:
        return int(p) if p else default
    except:
        return default

def pct(n: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return (n / total) * 100.0

# =========================
# Парсинг ключей
# =========================

def parse_ss(uri: str) -> Optional[Tuple[str, int, str, Optional[str]]]:
    try:
        if not uri.startswith("ss://"):
            return None
        body = uri[5:]
        if "@" in body and ":" in body:
            creds, rest = body.split("@", 1)
            host_port = rest.split("#")[0]
            host, port = host_port.split(":")
            return host, int(port), "ss", None
        else:
            if "#" in body:
                body_no_tag = body.split("#")[0]
            else:
                body_no_tag = body
            decoded = base64.urlsafe_b64decode(body_no_tag + "===")
            decoded = decoded.decode("utf-8")
            if "@" not in decoded:
                return None
            _, host_port = decoded.split("@", 1)
            host, port = host_port.split(":")
            return host, int(port), "ss", None
    except:
        return None

def parse_vless(uri: str) -> Optional[Tuple[str, int, str, Optional[str]]]:
    try:
        if not uri.startswith("vless://"):
            return None
        after = uri[len("vless://"):]
        if "@" not in after or ":" not in after:
            return None
        _, host_port_and = after.split("@", 1)
        host_port = host_port_and.split("?")[0]
        host, port = host_port.split(":")
        return host, int(port), "vless", None
    except:
        return None

def parse_https(uri: str) -> Optional[Tuple[str, int, str, Optional[str]]]:
    try:
        if not uri.startswith("https://"):
            return None
        m = re.match(r"^https://([^/]+)", uri)
        if not m:
            return None
        hostport = m.group(1)
        if ":" in hostport:
            host, port = hostport.split(":")
            return host, int(port), "https", uri
        else:
            return hostport, 443, "https", uri
    except:
        return None

def parse_raw_host(s: str) -> Optional[Tuple[str, int, str, Optional[str]]]:
    try:
        if "://" in s:
            return None
        if ":" in s:
            host, port = s.split(":", 1)
            return host, int(port), "raw", None
        else:
            return s, 443, "raw", None
    except:
        return None

def parse_input(text: str) -> List[Tuple[str, int, str, Optional[str]]]:
    items = []
    for line in text.split():
        line = line.strip()
        if not line:
            continue
        for parser in (parse_ss, parse_vless, parse_https, parse_raw_host):
            res = parser(line)
            if res:
                host, port, proto, url = res
                if safe_hostname(host):
                    items.append(res)
                break
    return items

# =========================
# DNS классический (A и AAAA) и PTR
# =========================

async def resolve_rr(resolver_name: str, resolver_ip: str, host: str, rrtype: str) -> DNSAnswer:
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = [resolver_ip]
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    try:
        ans = await r.resolve(host, rrtype, lifetime=DNS_TIMEOUT)
        values = []
        ttl = None
        for a in ans:
            v = getattr(a, 'address', None)
            if v is None:
                v = str(a)
            values.append(v)
        try:
            ttl = ans.rrset.ttl
        except:
            ttl = None
        return DNSAnswer(rrtype=rrtype, values=sorted(values), ttl=ttl)
    except dns.resolver.NXDOMAIN:
        return DNSAnswer(rrtype=rrtype, values=[], ttl=None)
    except asyncio.TimeoutError:
        return DNSAnswer(rrtype=rrtype, values=[], ttl=None)
    except Exception:
        return DNSAnswer(rrtype=rrtype, values=[], ttl=None)

async def resolve_with(resolver_name: str, resolver_ip: str, host: str) -> DNSResult:
    start = now_ms()
    answers: List[DNSAnswer] = []
    status = "ok"
    try:
        a = await resolve_rr(resolver_name, resolver_ip, host, "A")
        aaaa = await resolve_rr(resolver_name, resolver_ip, host, "AAAA")
        answers = []
        if a.values:
            answers.append(a)
        if aaaa.values:
            answers.append(aaaa)
        if not a.values and not aaaa.values:
            status = "nxdomain"
    except asyncio.TimeoutError:
        status = "timeout"
    except Exception as e:
        status = f"error:{type(e).__name__}"
    latency_ms = now_ms() - start
    return DNSResult(resolver_name, resolver_ip, status, latency_ms, answers)

async def multi_resolve(host: str) -> List[DNSResult]:
    tasks = [resolve_with(name, ip, host) for name, ip in DNS_RESOLVERS]
    results = []
    for i in range(0, len(tasks), MAX_PARALLEL_DNS):
        chunk = tasks[i:i+MAX_PARALLEL_DNS]
        results += await asyncio.gather(*chunk)
    return results

async def ptr_lookup(ip: str) -> PTRInfo:
    r = dns.asyncresolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    try:
        rev = dns.reversename.from_address(ip)
        ans = await r.resolve(rev, "PTR", lifetime=DNS_TIMEOUT)
        ptr = str(ans[0]) if ans and len(ans) > 0 else None
        return PTRInfo(ip=ip, ptr=ptr, status="ok")
    except dns.resolver.NXDOMAIN:
        return PTRInfo(ip=ip, ptr=None, status="nxdomain")
    except asyncio.TimeoutError:
        return PTRInfo(ip=ip, ptr=None, status="timeout")
    except Exception:
        return PTRInfo(ip=ip, ptr=None, status="error")

# =========================
# DoH (DNS over HTTPS)
# =========================

async def doh_query(session: aiohttp.ClientSession, provider_name: str, base_url: str, host: str, rrtype: str) -> DNSAnswer:
    start = now_ms()
    try:
        params = {"name": host, "type": rrtype}
        headers = {"accept": "application/dns-json"}
        async with session.get(base_url, params=params, headers=headers, timeout=HTTP_TIMEOUT) as resp:
            if resp.status != 200:
                raise Exception("DoH HTTP error")
            j = await resp.json()
            answers = []
            ttl = None
            for a in j.get("Answer", []) or []:
                if a.get("type") in (1, 28):  # A or AAAA
                    answers.append(a.get("data"))
                    ttl = a.get("TTL", ttl)
            return DNSAnswer(rrtype=rrtype, values=sorted(answers), ttl=ttl)
    except:
        return DNSAnswer(rrtype=rrtype, values=[], ttl=None)

async def doh_resolve(session: aiohttp.ClientSession, provider_name: str, base_url: str, host: str) -> DoHResult:
    start = now_ms()
    a = await doh_query(session, provider_name, base_url, host, "A")
    aaaa = await doh_query(session, provider_name, base_url, host, "AAAA")
    answers = []
    if a.values:
        answers.append(a)
    if aaaa.values:
        answers.append(aaaa)
    status = "ok" if answers else "error"
    latency_ms = now_ms() - start
    return DoHResult(provider_name=provider_name, status=status, latency_ms=latency_ms, answers=answers)

# =========================
# TCP многократные пробы + агрегированные метрики
# =========================

async def tcp_once(ip: str, port: int, attempt: int) -> TCPProbe:
    start = now_ms()
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
        latency_ms = now_ms() - start
        writer.close()
        if hasattr(writer, "wait_closed"):
            await writer.wait_closed()
        return TCPProbe(ip, port, attempt, "ok", latency_ms, None)
    except asyncio.TimeoutError:
        return TCPProbe(ip, port, attempt, "timeout", None, None)
    except ConnectionRefusedError as e:
        return TCPProbe(ip, port, attempt, "refused", None, repr(e))
    except Exception as e:
        return TCPProbe(ip, port, attempt, f"error:{type(e).__name__}", None, repr(e))

async def tcp_stats_for_ip(ip: str, port: int) -> TCPStats:
    probes: List[TCPProbe] = []
    for i in range(1, TCP_TRIES_PER_IP + 1):
        probes.append(await tcp_once(ip, port, i))
    oks = [p for p in probes if p.status == "ok" and p.latency_ms is not None]
    latencies = [p.latency_ms for p in oks]
    avg = (sum(latencies) / len(latencies)) if latencies else None
    mn = min(latencies) if latencies else None
    mx = max(latencies) if latencies else None
    statuses = [p.status for p in probes]
    return TCPStats(
        ip=ip, port=port, attempts=len(probes),
        ok_count=len(oks),
        avg_latency_ms=avg, min_latency_ms=mn, max_latency_ms=mx,
        statuses=statuses
    )

# =========================
# TLS (SNI/без SNI, ALPN, cipher, cert)
# =========================

async def tls_handshake(ip: str, server_name: Optional[str], port: int) -> TLSResult:
    start = now_ms()
    ctx = ssl.create_default_context()
    # Включим ALPN для проверки h2/http/1.1
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    # Для теста без проверки хоста можно ослабить — но оставим проверку сертификата (по умолчанию)
    try:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TLS_TIMEOUT)
        await loop.run_in_executor(None, sock.connect, (ip, port))
        tls_sock = ctx.wrap_socket(sock, server_hostname=server_name if server_name else None)
        protocol = tls_sock.version()
        chosen_alpn = None
        try:
            chosen_alpn = tls_sock.selected_alpn_protocol()
        except Exception:
            chosen_alpn = None
        cipher = tls_sock.cipher()[0] if tls_sock.cipher() else None
        cert = tls_sock.getpeercert()
        subj = None
        issuer = None
        try:
            subject_parts = cert.get("subject", [])
            if subject_parts:
                flat = [f"{k}={v}" for tup in subject_parts for (k, v) in tup]
                subj = ", ".join(flat)
            issuer_parts = cert.get("issuer", [])
            if issuer_parts:
                flat = [f"{k}={v}" for tup in issuer_parts for (k, v) in tup]
                issuer = ", ".join(flat)
        except:
            subj = None
        tls_sock.close()
        latency_ms = now_ms() - start
        return TLSResult(ip, server_name, "ok", latency_ms, protocol, cipher, chosen_alpn, subj, issuer, None)
    except ssl.SSLError as e:
        return TLSResult(ip, server_name, "cert_error", None, None, None, None, None, repr(e))
    except socket.timeout:
        return TLSResult(ip, server_name, "timeout", None, None, None, None, None, None)
    except Exception as e:
        return TLSResult(ip, server_name, f"error:{type(e).__name__}", None, None, None, None, None, repr(e))

# =========================
# HTTP проверки
# =========================

async def http_head(session: aiohttp.ClientSession, url: str) -> HTTPResult:
    start = now_ms()
    try:
        async with session.head(url, timeout=HTTP_TIMEOUT) as resp:
            latency_ms = now_ms() - start
            server = resp.headers.get("Server")
            via = resp.headers.get("Via")
            return HTTPResult(url, resp.status, "ok", latency_ms, server, via)
    except asyncio.TimeoutError:
        return HTTPResult(url, None, "timeout", None, None, None)
    except Exception as e:
        return HTTPResult(url, None, f"error:{type(e).__name__}", None, None, None)

async def http_get(session: aiohttp.ClientSession, url: str) -> HTTPResult:
    start = now_ms()
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT) as resp:
            await resp.read()
            latency_ms = now_ms() - start
            server = resp.headers.get("Server")
            via = resp.headers.get("Via")
            return HTTPResult(url, resp.status, "ok", latency_ms, server, via)
    except asyncio.TimeoutError:
        return HTTPResult(url, None, "timeout", None, None, None)
    except Exception as e:
        return HTTPResult(url, None, f"error:{type(e).__name__}", None, None, None)

# =========================
# Публичный IP, Geo/ASN
# =========================

async def fetch_json(session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT) as resp:
            # icanhazip.com может быть текстом
            ctype = resp.headers.get("Content-Type", "")
            if "text/plain" in ctype:
                txt = (await resp.text()).strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", txt):
                    return {"ip": txt}
                return None
            if resp.status == 200:
                return await resp.json(content_type=None)
            return None
    except:
        return None

async def get_public_ip(session: aiohttp.ClientSession) -> Optional[str]:
    for url in IP_ECHO_ENDPOINTS:
        j = await fetch_json(session, url)
        if j:
            if "ip" in j and isinstance(j["ip"], str):
                return j["ip"].strip()
            if "ip_address" in j:
                return str(j["ip_address"]).strip()
            if "query" in j:
                return str(j["query"]).strip()
    return None

async def geo_lookup(session: aiohttp.ClientSession, ip: Optional[str]) -> Optional[GeoInfo]:
    for url in GEO_ENDPOINTS:
        j = await fetch_json(session, url)
        if j:
            country = j.get("country_name") or j.get("country") or j.get("countryCode")
            city = j.get("city")
            lat = j.get("latitude") or j.get("lat")
            lon = j.get("longitude") or j.get("lon")
            org = j.get("org") or j.get("org_name") or j.get("asn")
            asn = j.get("asn") or j.get("org") or j.get("org_name")
            ip_val = j.get("ip") or j.get("query") or ip
            try:
                lat = float(lat) if lat is not None else None
                lon = float(lon) if lon is not None else None
            except:
                lat, lon = None, None
            return GeoInfo(ip_val, country, city, lat, lon, org, asn)
    return None

# =========================
# Эвристики и рейтинг
# =========================

def heuristic_verdict(
    protocol: str,
    dns: List[DNSResult],
    doh: List[DoHResult],
    tcp: List[TCPStats],
    tls: List[TLSResult],
    http: List[HTTPResult]
) -> Tuple[int, str, List[str]]:
    notes = []
    score = 0

    # DNS согласованность
    def collect_ip_sets(results: List[DNSResult]) -> List[Tuple[str, Tuple[str, ...]]]:
        sets = []
        for r in results:
            vals = []
            for ans in r.answers:
                vals.extend(ans.values)
            if vals:
                sets.append((r.resolver_name, tuple(sorted(vals))))
        return sets

    classical_sets = collect_ip_sets(dns)
    unique_sets = set([s for _, s in classical_sets])
    if len(unique_sets) > 1:
        notes.append("DNS: разные ответы у резолверов → возможный спуфинг/блокировка.")
        score -= 10
    elif len(unique_sets) == 1 and len(classical_sets) > 0:
        score += 10

    # DoH
    doh_good = [d for d in doh if d.status == "ok" and any(a.values for a in d.answers)]
    if not doh_good:
        notes.append("DoH: провалы или пустые ответы → возможная фильтрация DoH.")
        score -= 5
    else:
        score += 5

    # TCP — успешность и латентность
    tcp_ok_any = any(t.ok_count > 0 for t in tcp)
    if tcp_ok_any:
        score += 15
        for t in tcp:
            if t.ok_count > 0 and t.avg_latency_ms is not None:
                if t.avg_latency_ms < 60:
                    score += 5
                elif t.avg_latency_ms < 150:
                    score += 2
                else:
                    notes.append(f"TCP: высокая средняя задержка на {t.ip}:{t.port} ({t.avg_latency_ms:.0f} ms).")
    else:
        notes.append("TCP: ни один IP не отвечает → сервер недоступен/блокируется.")
        score -= 20

    # TLS
    tls_ok = [x for x in tls if x.status == "ok"]
    if tls_ok:
        score += 10
        # Проверка ALPN и протокола
        if any(x.alpn_protocol == "h2" for x in tls_ok):
            score += 3
        if any(x.protocol == "TLSv1.3" for x in tls_ok):
            score += 3
        if any(x.status == "cert_error" for x in tls):
            notes.append("TLS: ошибка сертификата → проблемы SNI/перехват/неверная конфигурация.")
            score -= 10
    else:
        if len(tls) > 0:
            notes.append("TLS: нет успешных рукопожатий.")
            score -= 10

    # HTTP — доступность целевого и внешних
    http_ok = [h for h in http if h.status == "ok" and h.status_code and 200 <= h.status_code < 400]
    if http_ok:
        score += 10
        if len(http_ok) < len(http):
            notes.append("HTTP: частичная доступность некоторых целей.")
    else:
        notes.append("HTTP: нет успешных 2xx/3xx ответов.")
        score -= 10

    # Итоговый вердикт
    # Пороговая логика (можно править)
    if score >= 20 and (tcp_ok_any or tls_ok):
        verdict = "Работает корректно"
    elif score >= 5 and (tcp_ok_any or tls_ok):
        verdict = "Работает частично/нестабильно"
    else:
        verdict = "Не работает/вероятно заблокирован"

    # Протокольная оговорка
    if protocol in ("ss", "vless"):
        notes.append("Примечание: выполнена инфраструктурная проверка (DNS/TCP/TLS/HTTP). Протокольный handshake SS/VLESS не выполнялся, но сеть/узел оценены.")

    return score, verdict, notes

# =========================
# Диагностика хоста
# =========================

async def diagnose_host(name: str, host: str, port: int, protocol: str, original_url: Optional[str]) -> HostDiag:
    # DNS
    dns_results = await multi_resolve(host)

    # Собираем IP из DNS
    ips: List[str] = []
    for r in dns_results:
        for ans in r.answers:
            for v in ans.values:
                try:
                    ipaddress.ip_address(v)
                    if v not in ips:
                        ips.append(v)
                except:
                    pass

    # Если ввод — это IP, используем его напрямую
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        pass

    # DoH
    doh_results: List[DoHResult] = []
    async with aiohttp.ClientSession() as session:
        for name_doh, base in DOH_PROVIDERS:
            doh_results.append(await doh_resolve(session, name_doh, base, host))

    # PTR для каждого IP
    ptr_results: List[PTRInfo] = []
    for ip in ips[:10]:
        try:
            ptr_results.append(await ptr_lookup(ip))
        except:
            ptr_results.append(PTRInfo(ip=ip, ptr=None, status="error"))

    # TCP многократные пробы и агрегированные метрики
    tcp_stats: List[TCPStats] = []
    tcp_tasks = [tcp_stats_for_ip(ip, port) for ip in ips[:10]]
    if tcp_tasks:
        tcp_stats = await asyncio.gather(*tcp_tasks)

    # TLS (для портов с TLS — чаще 443, но иногда и другие; протестируем только 443 и 8443)
    tls_results: List[TLSResult] = []
    tls_ports = []
    if port == 443:
        tls_ports.append(443)
    elif port == 8443:
        tls_ports.append(8443)
    # SNI: для домена — host, для IP — None
    server_name = None
    try:
        ipaddress.ip_address(host)
        server_name = None
    except ValueError:
        server_name = host
    for p in tls_ports:
        for ip in ips[:6]:
            tls_results.append(await tls_handshake(ip, server_name, p))
            # Дополнительно: проба без SNI, если есть домен
            if server_name:
                tls_results.append(await tls_handshake(ip, None, p))

    # HTTP
    http_results: List[HTTPResult] = []
    async with aiohttp.ClientSession() as session:
        # Если это https-узел (подписка или прямой хост) — попробуем прямой GET
        if protocol == "https" and original_url:
            http_results.append(await http_get(session, original_url))
        # Общие зондовые цели
        random_targets = random.sample(HTTP_PROBE_TARGETS, k=min(3, len(HTTP_PROBE_TARGETS)))
        for u in random_targets:
            http_results.append(await http_head(session, u))
        # Публичный IP + Geo
        pub_ip = await get_public_ip(session)
        geo = await geo_lookup(session, pub_ip)

    # Рейтинг/вердикт/заметки
    score, verdict, notes = heuristic_verdict(protocol, dns_results, doh_results, tcp_stats, tls_results, http_results)

    return HostDiag(
        name=name,
        host=host,
        port=port,
        protocol=protocol,
        dns=dns_results,
        doh=doh_results,
        ptr=ptr_results,
        tcp=tcp_stats,
        tls=tls_results,
        http=http_results,
        geo=geo,
        score=score,
        verdict=verdict,
        notes=notes
    )

# =========================
# Форматирование отчёта
# =========================

def fmt_dns(dns: List[DNSResult]) -> str:
    lines = []
    for r in dns:
        ans_lines = []
        for ans in r.answers:
            ttl = f", ttl={ans.ttl}" if ans.ttl is not None else ""
            ans_lines.append(f"{ans.rrtype}: {', '.join(ans.values)}{ttl}")
        ans_text = "; ".join(ans_lines) if ans_lines else "-"
        lines.append(f"- {r.resolver_name} ({r.resolver_ip}): {r.status}, {r.latency_ms:.1f} ms | {ans_text}")
    return "\n".join(lines) if lines else "-"

def fmt_doh(doh: List[DoHResult]) -> str:
    lines = []
    for d in doh:
        ans_lines = []
        for ans in d.answers:
            ttl = f", ttl={ans.ttl}" if ans.ttl is not None else ""
            ans_lines.append(f"{ans.rrtype}: {', '.join(ans.values)}{ttl}")
        ans_text = "; ".join(ans_lines) if ans_lines else "-"
        lines.append(f"- {d.provider_name}: {d.status}, {d.latency_ms:.1f} ms | {ans_text}")
    return "\n".join(lines) if lines else "-"

def fmt_ptr(ptrs: List[PTRInfo]) -> str:
    lines = []
    for p in ptrs:
        lines.append(f"- {p.ip} → PTR: {p.ptr or '-'} ({p.status})")
    return "\n".join(lines) if lines else "-"

def fmt_tcp(tcp: List[TCPStats]) -> str:
    lines = []
    for t in tcp:
        attempts = t.attempts
        ok_pct = pct(t.ok_count, attempts)
        avg = f"{t.avg_latency_ms:.1f} ms" if t.avg_latency_ms is not None else "-"
        mn = f"{t.min_latency_ms:.1f} ms" if t.min_latency_ms is not None else "-"
        mx = f"{t.max_latency_ms:.1f} ms" if t.max_latency_ms is not None else "-"
        lines.append(f"- {t.ip}:{t.port} → ok {t.ok_count}/{attempts} ({ok_pct:.0f}%), avg={avg}, min={mn}, max={mx}, statuses={', '.join(t.statuses)}")
    return "\n".join(lines) if lines else "-"

def fmt_tls(tls: List[TLSResult]) -> str:
    lines = []
    for r in tls:
        lat = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
        proto = r.protocol or "-"
        cipher = r.cipher or "-"
        alpn = r.alpn_protocol or "-"
        subj = (r.cert_subject[:100] + "...") if r.cert_subject and len(r.cert_subject) > 100 else (r.cert_subject or "-")
        issuer = (r.cert_issuer[:80] + "...") if r.cert_issuer and len(r.cert_issuer) > 80 else (r.cert_issuer or "-")
        lines.append(f"- {r.ip} SNI={r.server_name or '-'} → {r.status}, {lat}, proto={proto}, alpn={alpn}, cipher={cipher}, subject={subj}, issuer={issuer}{' ('+r.errno+')' if r.errno else ''}")
    return "\n".join(lines) if lines else "-"

def fmt_http(http: List[HTTPResult]) -> str:
    lines = []
    for r in http:
        lat = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
        sc = r.status_code if r.status_code is not None else "-"
        server = r.server or "-"
        via = r.via or "-"
        lines.append(f"- {r.url} → {r.status} (code={sc}), {lat}, server={server}, via={via}")
    return "\n".join(lines) if lines else "-"

def fmt_geo(geo: Optional[GeoInfo]) -> str:
    if not geo:
        return "-"
    return f"IP: {geo.ip or '-'} | Country: {geo.country or '-'} | City: {geo.city or '-'} | Lat/Lon: {geo.lat or '-'} / {geo.lon or '-'} | Org: {geo.org or '-'} | ASN: {geo.asn or '-'}"

def format_report(diag: HostDiag) -> str:
    header = f"Проверка: {diag.name} [{diag.protocol}] → {diag.host}:{diag.port}\n"
    verdict_line = f"Вердикт: {diag.verdict} | Рейтинг: {diag.score}\n"
    notes = ""
    if diag.notes:
        notes = "\nЗаметки/Причины:\n" + "\n".join([f"- {n}" for n in diag.notes]) + "\n"
    body = (
        "\nDNS (классический A/AAAA):\n" + fmt_dns(diag.dns) +
        "\n\nDNS over HTTPS (DoH):\n" + fmt_doh(diag.doh) +
        "\n\nPTR (reverse DNS):\n" + fmt_ptr(diag.ptr) +
        "\n\nTCP (многократные пробы):\n" + fmt_tcp(diag.tcp) +
        "\n\nTLS (SNI/без SNI, ALPN/cipher/cert):\n" + fmt_tls(diag.tls) +
        "\n\nHTTP (целевые и внешние):\n" + fmt_http(diag.http) +
        "\n\nGeo-IP/ASN:\n" + fmt_geo(diag.geo)
    )
    return header + verdict_line + notes + body

# =========================
# Бот (aiogram 3.x)
# =========================

bot = Bot(BOT_TOKEN, parse_mode=None)
dp = Dispatcher()

WELCOME_TEXT = (
    "Кинь VPN ключи/хосты для проверки.\n"
    "- Форматы: SS, VLESS, https://..., host:port, или просто host (443).\n"
    "- Я сделаю A/AAAA + DoH DNS, TCP многократные пробы, TLS (SNI/без SNI, ALPN, cipher, cert), HTTP-зонды,\n"
    "  публичный IP + Geo/ASN, PTR, эвристики блокировок, рейтинг и чёткий вердикт «работает/частично/не работает».\n\n"
    "Примеры:\n"
    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAexample.com:8388#node\n"
    "vless://uuid@example.com:443?encryption=none&security=tls#node\n"
    "https://example.com\n"
    "example.com:443\n"
)

@dp.message(Command("start"))
async def cmd_start(message: Message):
    await message.answer(WELCOME_TEXT)

@dp.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(WELCOME_TEXT)

@dp.message(F.text)
async def handle_check(message: Message):
    text = message.text.strip()
    items = parse_input(text)
    if not items:
        await message.reply("Не распознал ключ/хост. Дай SS/VLESS/HTTPS или host:port.")
        return

    # Если это HTTPS-ссылка на подписку — попробуем скачать и расширить (включая v2ray/ss url-ы)
    expanded: List[Tuple[str, int, str, Optional[str]]] = []
    async with aiohttp.ClientSession() as session:
        for host, port, proto, url in items:
            if proto == "https" and url:
                try:
                    async with session.get(url, timeout=HTTP_TIMEOUT) as resp:
                        if resp.status == 200:
                            txt = await resp.text()
                            for line in txt.splitlines():
                                line = line.strip()
                                if not line:
                                    continue
                                parsed = parse_input(line)
                                if parsed:
                                    expanded.extend(parsed)
                            # если ничего не нашли — всё равно добавим сам https-хост
                            if not expanded:
                                expanded.append((host, port, proto, url))
                        else:
                            expanded.append((host, port, proto, url))
                except:
                    expanded.append((host, port, proto, url))
            else:
                expanded.append((host, port, proto, url))

    # Дедупликация
    unique: Dict[str, Tuple[str, int, str, Optional[str]]] = {}
    for host, port, proto, url in expanded:
        key = f"{proto}:{host}:{port}:{url or ''}"
        unique[key] = (host, port, proto, url)
    expanded = list(unique.values())

    # Параллельная диагностика с ограничением
    sem = asyncio.Semaphore(MAX_PARALLEL_HOSTS)
    results: List[HostDiag] = []

    async def run_one(item: Tuple[str, int, str, Optional[str]]):
        host, port, proto, url = item
        name = f"{proto}:{host}:{port}"
        async with sem:
            try:
                res = await diagnose_host(name, host, port, proto, url)
                results.append(res)
            except Exception as e:
                results.append(HostDiag(
                    name=name, host=host, port=port, protocol=proto,
                    dns=[], doh=[], ptr=[], tcp=[], tls=[], http=[], geo=None,
                    score=-100, verdict="Ошибка проверки", notes=[f"Exception: {type(e).__name__}"]
                ))

    await asyncio.gather(*[run_one(item) for item in expanded])

    # Отчёты: соблюдаем лимиты Telegrаm ~4096 символов
    for res in results:
        report = format_report(res)
        if len(report) <= 3800:
            await message.answer(report)
        else:
            # Грубое разбиение по разделам
            sections = report.split("\n\n")
            buf = ""
            for sec in sections:
                if len(buf) + len(sec) + 2 > 3800:
                    await message.answer(buf)
                    buf = sec
                else:
                    buf = f"{buf}\n\n{sec}" if buf else sec
            if buf:
                await message.answer(buf)

    await message.answer(f"Готово. Проверено узлов: {len(results)}.")

# =========================
# Main
# =========================

def main():
    print("Starting bot...")
    try:
        import uvloop
        uvloop.install()
    except Exception:
        pass
    asyncio.run(dp.start_polling(bot))

if __name__ == "__main__":
    main()
