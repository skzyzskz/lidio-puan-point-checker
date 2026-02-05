import requests
import re
import json
import time
import random
import uuid
import urllib.parse

VERBOSE_LOGGING = False

def vprint(*args, **kwargs):
    """Conditional print - only prints if VERBOSE_LOGGING is True"""
    pass

class TchiboPaymentAutomation:
    def __init__(self, base_url="https://psp.tchibo.com.tr", main_site_url="https://www.tchibo.com.tr", proxy=None):
        self.base_url = base_url
        self.main_site_url = main_site_url
        self.proxy = proxy
        
        self.session = requests.Session()
        
        from requests.adapters import HTTPAdapter
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=0,
            pool_block=False
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        })
        
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.ctrl_key = None
        self.pg_process_key = None
        self.payment_token = None
        self.payment_secret = None
        self.payment_xcsrf = None
        
    def get_random_url_params(self):
        """Generate random URL parameters"""
        import random
        import time
        r_param = random.random()
        t_param = int(time.time() * 1000)
        return f"?r={r_param}&t={t_param}"
    
    def add_to_cart(self, item_id, quantity=1, quickbuy=True):
        """
        Add item to cart.
        Uses correct payload format: {"id": tcm, "identifierType": "tcm", "quantity": 1}
        Endpoint: POST /service/cart/api/shopping-cart/articles
        
        Args:
            item_id: Product item ID (e.g., "233722167222") - will extract tcm from product page
            quantity: Quantity to add (default: 1)
            quickbuy: Whether it's a quickbuy (default: True)
        
        Returns:
            True if successful, False otherwise
        """
        
        try:
            self.session.get(f"{self.main_site_url}/", allow_redirects=True, timeout=15)
        except Exception as e:
            pass
        
        cart_url = f"{self.main_site_url}/service/cart/api/shopping-cart/articles"
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-App-Platform': 'BROWSER',
            'X-Hunter-CSRF': 'x',
            'X-Hunter-Site': 'TR',
            'Origin': self.main_site_url,
        }
        
        payload = {"id": 487353, "identifierType": "tcm", "quantity": quantity}
        
        try:
            response = self.session.post(cart_url, json=payload, headers=headers, timeout=15)
            if response.status_code == 200:
                print(f"  ✓ Cart add successful (status 200)")
                return True
            else:
                print(f"  ⚠ Cart add returned {response.status_code}")
                return True
        except Exception as e:
            print(f"  ⚠ Cart add error: {e}")
            return False
        
        return True
        
        try:
            self.session.get(f"{self.main_site_url}/", allow_redirects=True, timeout=15)
        except Exception as e:
            pass
        
        def get_cookies_dict():
            cookies_dict = {}
            if hasattr(self.session, 'cookies'):
                if isinstance(self.session.cookies, dict):
                    cookies_dict = self.session.cookies
                else:
                    try:
                        cookies_dict = dict(self.session.cookies.items())
                    except:
                        for cookie in self.session.cookies:
                            if hasattr(cookie, 'name'):
                                cookies_dict[cookie.name] = cookie.value
                            elif isinstance(cookie, tuple) and len(cookie) >= 2:
                                cookies_dict[cookie[0]] = cookie[1]
            return cookies_dict
        
        longterm_token = None
        tcm_value = None
        try:
            print(f"  Accessing product page to get tokens and extract tcm...")
            product_url = f"{self.main_site_url}/c/kahve-espresso"
            response = self.session.get(product_url, allow_redirects=True, timeout=15)
            
            import re
            tcm_patterns = [
                r'productId["\']?\s*:\s*["\']?' + str(item_id) + r'["\']?[^}]{0,500}tcm["\']?\s*:\s*(\d+)',
                r'tcm["\']?\s*:\s*(\d+)[^}]{0,500}productId["\']?\s*:\s*["\']?' + str(item_id),
                r'\{"productId"["\']?\s*:\s*["\']?' + str(item_id) + r'["\']?[^}]{0,1000}"tcm"["\']?\s*:\s*(\d+)',
            ]
            
            for pattern in tcm_patterns:
                match = re.search(pattern, response.text, re.I | re.DOTALL)
                if match:
                    tcm_value = int(match.group(1))
                    print(f"    ✓ Found tcm: {tcm_value} for product {item_id}")
                    break
            
            if not tcm_value:
                all_tcms = re.findall(r'tcm["\']?\s*:\s*(\d+)', response.text, re.I)
                if all_tcms:
                    print(f"    Found tcm values on page: {set(all_tcms[:5])}")
                    if '487353' in all_tcms:
                        tcm_value = 487353
                        print(f"    Using tcm: {tcm_value} (from page)")
            
            if not tcm_value:
                if item_id.isdigit() and len(item_id) <= 10:
                    print(f"    Trying item_id as tcm: {item_id}")
                    tcm_value = int(item_id)
            
            if hasattr(response, 'headers'):
                set_cookie = response.headers.get('Set-Cookie') or response.headers.get('set-cookie')
                if set_cookie and 'LongtermToken' in set_cookie:
                    import re
                    match = re.search(r'LongtermToken=([^;]+)', set_cookie)
                    if match:
                        longterm_token = match.group(1)
                        print(f"    ✓ Got LongtermToken from Set-Cookie header!")
            
            cookies_dict = get_cookies_dict()
            if not longterm_token:
                longterm_token = cookies_dict.get('LongtermToken')
            
            grp_token = cookies_dict.get('grpToken')
            print(f"    Got grpToken: {'Yes' if grp_token else 'No'}")
            print(f"    Got LongtermToken: {'Yes' if longterm_token else 'No'}")
            print(f"    All cookies: {list(cookies_dict.keys())}")
            
            if not longterm_token:
                print(f"    LongtermToken not found, trying customerfrontenddata API...")
                try:
                    api_response = self.session.get(
                        f"{self.main_site_url}/service/customerfrontenddata/api/v1/psdata",
                        headers={
                            'Accept': 'application/json',
                            'X-Hunter-Site': 'TR',
                            'X-hunter-CSRF': 'x',
                        },
                        timeout=15
                    )
                    if hasattr(api_response, 'headers'):
                        set_cookie = api_response.headers.get('Set-Cookie') or api_response.headers.get('set-cookie')
                        if set_cookie and 'LongtermToken' in set_cookie:
                            import re
                            match = re.search(r'LongtermToken=([^;]+)', set_cookie)
                            if match:
                                longterm_token = match.group(1)
                                print(f"    ✓ Got LongtermToken from customerfrontenddata API!")
                    
                    if not longterm_token:
                        cookies_dict = get_cookies_dict()
                        longterm_token = cookies_dict.get('LongtermToken')
                except Exception as e:
                    print(f"    Error calling customerfrontenddata API: {e}")
        except Exception as e:
            print(f"  Warning: Error accessing product page: {e}")
            longterm_token = None
        
        cart_add_endpoints = [
            f"{self.main_site_url}/service/cart/api/shopping-cart/articles",
            f"{self.main_site_url}/service/cartfrontend/cart",
        ]
        
        cart_get_endpoint = f"{self.main_site_url}/service/cart/api/shopping-cart/carts"
        
        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Content-Type': 'application/json',
            'Origin': self.main_site_url,
            'Referer': f"{self.main_site_url}/c/kahve-espresso",
            'X-App-Platform': 'BROWSER',
            'X-Hunter-CSRF': 'x',
            'X-Hunter-Site': 'TR',
            'X-Hunter-Platform': 'BROWSER',
            'X-LongtermToken': longterm_token if longterm_token else '',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Ch-Ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Priority': 'u=1, i',
        }
        
        tcm_to_use = tcm_value if tcm_value else 487353
        payloads = [
            {"id": tcm_to_use, "identifierType": "tcm", "quantity": quantity},
        ]
        print(f"  Using tcm: {tcm_to_use} for product {item_id}")
        
        print(f"  Trying to add item {item_id} to cart...")
        
        for endpoint in cart_add_endpoints:
            for payload in payloads:
                try:
                    response = self.session.post(endpoint, json=payload, headers=headers, timeout=15)
                    if response.status_code in [200, 201]:
                        try:
                            result = response.json()
                            print(f"  ✓ Successfully added to cart via {endpoint}")
                            print(f"    Response: {json.dumps(result, indent=2, ensure_ascii=False)[:200]}...")
                            if self._verify_cart_updated_via_api(cart_get_endpoint, headers, item_id):
                                self._send_add_to_cart_tracking(item_id, quantity, quickbuy)
                                return True
                        except:
                            if len(response.text) > 10000:
                                continue
                            else:
                                print(f"  ⚠ {endpoint} returned non-JSON (likely HTML page)")
                                continue
                    elif response.status_code in [401, 403, 404, 410]:
                        continue
                except Exception as e:
                    continue
        
        print(f"  Trying GET requests with query parameters...")
        get_url = f"{self.main_site_url}/c/kahve-espresso?add={item_id}"
        try:
            response = self.session.get(get_url, headers={'Referer': f"{self.main_site_url}/c/kahve-espresso"}, timeout=15)
            if response.status_code == 200:
                if self._verify_cart_updated():
                    self._send_add_to_cart_tracking(item_id, quantity, quickbuy)
                    return True
        except:
            pass
        
        print(f"  ✗ Could not add item to cart - cart API endpoint not found")
        return False
    
    def _verify_cart_updated_via_api(self, cart_get_endpoint, headers, item_id):
        """Verify that cart was actually updated by calling GET /service/cart/api/shopping-cart/carts"""
        try:
            get_headers = {
                'Accept': 'application/json',
                'X-Hunter-Site': 'TR',
                'X-Hunter-Platform': 'BROWSER',
                'X-hunter-csrf': 'x',
                'Referer': f"{self.main_site_url}/c/kahve-espresso",
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Priority': 'u=1, i',
            }
            if headers.get('X-LongtermToken'):
                get_headers['X-LongtermToken'] = headers['X-LongtermToken']
            
            response = self.session.get(cart_get_endpoint, headers=get_headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if 'cartIdentifier' in data:
                    cart_id = data['cartIdentifier']
                    if 'articles' in data:
                        for article in data['articles']:
                            if str(article.get('productId')) == str(item_id):
                                print(f"  ✓✓✓ Cart verified! cartIdentifier: {cart_id[:30]}...")
                                print(f"  ✓✓✓ Item {item_id} found in cart!")
                                return True
                    print(f"  ✓ Got cartIdentifier: {cart_id[:30]}... but item not found yet")
            elif response.status_code in [401, 403, 404, 410]:
                pass
            return False
        except Exception as e:
            print(f"  Warning: Error verifying cart: {e}")
            return False
    
    def get_cart_identifier_from_api(self):
        """Get cartIdentifier from GET /service/cart/api/shopping-cart/carts (works WITHOUT LongtermToken!)"""
        try:
            cart_get_endpoint = f"{self.main_site_url}/service/cart/api/shopping-cart/carts"
            headers = {
                'Accept': 'application/json',
                'X-Hunter-Site': 'TR',
                'X-Hunter-Platform': 'BROWSER',
                'X-hunter-csrf': 'x',
                'Referer': f"{self.main_site_url}/c/kahve-espresso",
            }
            response = self.session.get(cart_get_endpoint, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if 'cartIdentifier' in data:
                    return data['cartIdentifier']
            return None
        except:
            return None
    
    def _verify_cart_updated(self):
        """Verify that cart was actually updated by checking checkout API"""
        try:
            checkout_api_url = f"{self.main_site_url}/service/checkout/api/checkout"
            headers = {
                'Accept': '*/*',
                'X-App-Platform': 'BROWSER',
                'X-Hunter-Site': 'TR',
                'X-Hunter-CSRF': 'x',
                'Referer': f"{self.main_site_url}/service/checkoutfrontend/checkout",
            }
            response = self.session.get(checkout_api_url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if 'checkoutData' in data:
                    cd = data['checkoutData']
                    if cd.get('cartIdentifier') and cd.get('customerIdentifier'):
                        return True
            return False
        except:
            return False
    
    def _send_add_to_cart_tracking(self, item_id, quantity=1, quickbuy=True):
        """Send add_to_cart tracking event"""
        try:
            tracking_url = f"{self.main_site_url}/service/ttruth/publish"
            tracking_data = {
                "url": f"{self.main_site_url}/c/kahve-espresso",
                "event_name": "add_to_cart",
                "hostname": "www.tchibo.com.tr",
                "page_path": "/c/kahve-espresso",
                "site_key": "tr",
                "consent": "C0001,C0002,C0003,C0004",
                "device_type": "no mobile",
                "screen_breakpoint": "XXL",
                "currency": "TRY",
                "page_type": "ccms",
                "node_level_1": "Home",
                "node_level_2": "HOMEPAGE",
                "screen_size": "1920x1080",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
                "items": [{
                    "item_name": f"Product_{item_id}",
                    "item_id": item_id,
                    "price": 999.9,
                    "quantity": quantity,
                    "quickbuy": str(quickbuy).lower(),
                    "source_level_1": "Home",
                    "source_level_2": "Espresso"
                }],
                "tcs_source": "google",
                "tcs_medium": "cpc",
                "tcs_campaign": "cpc",
                "custom_short_term_id": f"_{uuid.uuid4().hex[:12]}{int(time.time() * 1000)}",
                "language": "tr",
                "temp_data": "gtm",
                "cot_version": "5.20.4",
                "emitter": "not_provided",
                "token": json.dumps({"sub": str(uuid.uuid4()), "lid": None}),
                "scan": 6
            }
            
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'Origin': self.main_site_url,
                'Referer': f"{self.main_site_url}/c/kahve-espresso",
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'api-version': '2',
            }
            
            response = self.session.post(tracking_url, json=tracking_data, headers=headers, timeout=10)
            if response.status_code == 200:
                print(f"  ✓ Tracking event sent")
        except Exception as e:
            pass
    
    def get_checkout_data(self):
        """
        Get checkout data including cartIdentifier and customerIdentifier.
        Calls GET /service/checkout/api/checkout directly.
        
        SIMPLIFIED: Don't visit main site again - it resets session state.
        Just call the checkout API directly.
        """
        checkout_api_url = f"{self.main_site_url}/service/checkout/api/checkout"
        checkout_page_url = f"{self.main_site_url}/service/checkoutfrontend/checkout"
        
        try:
            self.session.get(checkout_page_url, timeout=15)
        except:
            pass
        
        headers = {
            'Accept': '*/*',
            'X-App-Platform': 'BROWSER',
            'X-Hunter-Site': 'TR',
            'X-Hunter-CSRF': 'x',
            'Referer': checkout_page_url,
        }
        
        print("  Calling GET /service/checkout/api/checkout...")
        try:
            api_response = self.session.get(checkout_api_url, headers=headers, timeout=15)
            print(f"  Response status: {api_response.status_code}")
            
            if api_response.status_code == 200:
                checkout_data = api_response.json()
                checkout_data_obj = checkout_data.get('checkoutData', {})
                cart_identifier = checkout_data_obj.get('cartIdentifier')
                customer_identifier = checkout_data_obj.get('customerIdentifier')
                
                if cart_identifier and customer_identifier:
                    print(f"  ✓ Got identifiers from checkout API")
                    print(f"    cartIdentifier: {cart_identifier[:30]}...")
                    print(f"    customerIdentifier: {customer_identifier[:30]}...")
                    self._checkout_data = checkout_data_obj
                    
                    if 'cartData' in checkout_data_obj:
                        cart_data = checkout_data_obj['cartData']
                        if 'loyaltyBeanData' in cart_data:
                            lbd = cart_data['loyaltyBeanData']
                            if 'ownedByUser' in lbd and lbd['ownedByUser'] > 0:
                                print(f"  ✓ Found loyalty points in checkout data: {lbd['ownedByUser']}")
                    
                    return cart_identifier, customer_identifier
                else:
                    print(f"  Warning: Checkout API response missing identifiers")
                    print(f"    Response keys: {list(checkout_data.keys())}")
                    if 'checkoutData' in checkout_data:
                        print(f"    checkoutData keys: {list(checkout_data['checkoutData'].keys())}")
            elif api_response.status_code == 401:
                print(f"  ✗ 401 Unauthorized - Need valid session with items in cart")
                print(f"    Available cookies: {list(self.session.cookies.keys()) if hasattr(self.session, 'cookies') and hasattr(self.session.cookies, 'keys') else 'N/A'}")
                print(f"    To fix: Add items to cart first, or use session cookies from browser")
            elif api_response.status_code == 403:
                print(f"  ✗ 403 Forbidden - Cloudflare protection")
                print(f"    Using httpx for bypass")
            else:
                print(f"  Warning: Checkout API returned {api_response.status_code}")
                try:
                    error_data = api_response.json()
                    print(f"    Error: {json.dumps(error_data, indent=2)[:300]}...")
                except:
                    print(f"    Response: {api_response.text[:300]}")
        except Exception as e:
            print(f"  Warning: Error calling checkout API: {e}")
            import traceback
            traceback.print_exc()
        
        return None, None
    
    def upsert_address(self, address_data, set_as_delivery_target=True):
        """
        Create or update address using PUT /service/checkout/api/upsertAddress
        """
        url = f"{self.main_site_url}/service/checkout/api/upsertAddress"
        
        payload = {
            "baseAddress": address_data,
            "setAsDeliveryTarget": set_as_delivery_target
        }
        
        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Content-Type': 'application/json',
            'Origin': self.main_site_url,
            'Referer': f"{self.main_site_url}/service/checkoutfrontend/checkout",
            'X-App-Platform': 'BROWSER',
            'X-Hunter-CSRF': 'x',
            'X-Hunter-Site': 'TR',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        
        try:
            response = self.session.put(url, json=payload, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data.get('responseStatus') == 'SUCCESS':
                    checkout_data = data.get('checkoutData', {})
                    customer_data = checkout_data.get('customerData', {})
                    selected_address_id = customer_data.get('selectedAddressId')
                    print(f"  ✓ Address created/updated: {selected_address_id[:50] if selected_address_id else 'None'}...")
                    return checkout_data
            print(f"  ✗ Failed to upsert address: {response.status_code}")
            return None
        except Exception as e:
            print(f"  ✗ Error upserting address: {e}")
            return None
    
    def set_payment_method(self, payment_method):
        """
        Set payment method - try PUT /service/checkout/api/payment endpoint
        """
        url = f"{self.main_site_url}/service/checkout/api/payment"
        
        payload = {
            "selectedMethod": payment_method
        }
        
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Origin': self.main_site_url,
            'Referer': f"{self.main_site_url}/service/checkoutfrontend/checkout",
            'X-App-Platform': 'BROWSER',
            'X-Hunter-CSRF': 'x',
            'X-Hunter-Site': 'TR',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        
        try:
            response = self.session.put(url, json=payload, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data.get('responseStatus') == 'SUCCESS':
                    print(f"  ✓ Payment method set: {payment_method}")
                    if 'checkoutData' in data:
                        self._checkout_data = data['checkoutData']
                    return True
            print(f"  ✗ Failed to set payment method: {response.status_code}")
            return False
        except Exception as e:
            print(f"  ✗ Error setting payment method: {e}")
            return False
    
    def submit_order(self, cart_identifier=None, customer_identifier=None):
        """
        Submit order on main Tchibo site to get payment redirect.
        Based on initiator chain: submitOrder -> PUT /service/checkout/api/order -> redirect
        """
        if not cart_identifier or not customer_identifier:
            print("Getting cartIdentifier and customerIdentifier from checkout API...")
            max_retries = 2
            for attempt in range(max_retries):
                cart_identifier, customer_identifier = self.get_checkout_data()
                if cart_identifier and customer_identifier:
                    break
                else:
                    print(f"  Attempt {attempt + 1} failed, retrying...")
            
            if not cart_identifier or not customer_identifier:
                print("Error: Could not get cartIdentifier and customerIdentifier after multiple attempts")
                print("  Trying to add item to cart again...")
                self.add_to_cart('233722167222', quantity=1)
                cart_identifier, customer_identifier = self.get_checkout_data()
                
                if not cart_identifier or not customer_identifier:
                    print("  ✗ Still cannot get identifiers - cart API may not be accessible")
                    return None
        
        import uuid
        email = f"test{uuid.uuid4().hex[:8]}@example.com"
        print("  Registering as guest...")
        register_url = f"{self.main_site_url}/service/checkout/api/register"
        register_payload = {
            "commonRegistrationData": {
                "salutation": "MR",
                "firstname": "Test",
                "lastname": "User",
                "email": email
            },
            "consents": {"guest": True}
        }
        
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-App-Platform': 'BROWSER',
            'X-Hunter-CSRF': 'x',
            'X-Hunter-Site': 'TR',
            'Referer': f"{self.main_site_url}/service/checkoutfrontend/checkout",
        }
        
        try:
            response = self.session.put(register_url, json=register_payload, headers=headers, timeout=15)
            if response.status_code == 200:
                print(f"  ✓ Registered as guest")
                if 'checkoutData' in response.json():
                    self._checkout_data = response.json()['checkoutData']
        except Exception as e:
            print(f"  ⚠ Register error: {e}")
        
        print("  Creating address...")
        address_id = str(uuid.uuid4())
        address_payload = {
            "baseAddress": {
                "addressId": address_id,
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
            },
            "setAsDeliveryTarget": True
        }
        
        try:
            address_url = f"{self.main_site_url}/service/checkout/api/upsertAddress"
            response = self.session.put(address_url, json=address_payload, headers=headers, timeout=15)
            if response.status_code == 200:
                print(f"  ✓ Address created")
                if 'checkoutData' in response.json():
                    self._checkout_data = response.json()['checkoutData']
        except Exception as e:
            print(f"  ⚠ Address error: {e}")
        
        if self._checkout_data:
            payment_data = self._checkout_data.get('paymentData', {})
            if not payment_data.get('selectedMethod') or payment_data.get('selectedMethod') == 'UNKNOWN':
                available_methods = self._checkout_data.get('availablePaymentMethods', [])
                default_method = self._checkout_data.get('defaultPaymentMethod')
                
                payment_method = default_method if default_method and default_method != 'UNKNOWN' else (available_methods[0] if available_methods else 'CREDITCARD')
                
                if payment_method:
                    print(f"  Setting payment method: {payment_method}...")
                    if self.set_payment_method(payment_method):
                        cart_id, cust_id = self.get_checkout_data()
        
        order_url = f"{self.main_site_url}/service/checkout/api/order"
        
        checkout_state = self._checkout_data.get('checkoutState', {}) if self._checkout_data else {}
        
        order_data = {
            "checkoutState": checkout_state,
            "cartIdentifier": cart_identifier,
            "customerIdentifier": customer_identifier,
        }
        
        checkout_url = f"{self.main_site_url}/service/checkoutfrontend/checkout"
        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Content-Type': 'application/json',
            'Origin': self.main_site_url,
            'Referer': checkout_url,
            'X-App-Platform': 'BROWSER',
            'X-Hunter-CSRF': 'x',
            'X-Hunter-Site': 'TR',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Ch-Ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        
        try:
            response = self.session.put(order_url, json=order_data, headers=headers, allow_redirects=False, timeout=15)
            print(f"Order submission response: {response.status_code}")
            
            if response.status_code in [307, 302, 301]:
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    if redirect_url.startswith('/'):
                        redirect_url = self.main_site_url + redirect_url
                    print(f"Got redirect URL: {redirect_url[:100]}...")
                    return redirect_url
            elif response.status_code == 206:
                print("206 Partial Content - checking for redirect or errors...")
                try:
                    error_data = response.json()
                    print(f"Full 206 response keys: {list(error_data.keys())}")
                    
                    if 'redirectUrl' in error_data:
                        redirect_url = error_data['redirectUrl']
                        print(f"✓ Found redirectUrl in response: {redirect_url[:100]}...")
                        return redirect_url
                    
                    redirect_url = response.headers.get('Location')
                    if redirect_url:
                        if '/VPayment/' in redirect_url or 'psp.tchibo.com.tr' in redirect_url:
                            redirect_url = redirect_url if redirect_url.startswith('http') else self.base_url + redirect_url
                        elif redirect_url.startswith('/'):
                            redirect_url = self.main_site_url + redirect_url
                        print(f"✓ Found redirect in Location header: {redirect_url[:100]}...")
                        return redirect_url
                    
                    if 'checkoutData' in error_data:
                        cd = error_data['checkoutData']
                        print(f"checkoutData keys: {list(cd.keys())}")
                        
                        status = error_data.get('status', '')
                        if status == 'CUSTOMER_DATA_HAS_CHANGED':
                            print("  Status: CUSTOMER_DATA_HAS_CHANGED - refreshing checkout data and retrying...")
                            self._checkout_data = cd
                            
                            max_retries = 3
                            for retry_num in range(max_retries):
                                cart_identifier = cd.get('cartIdentifier')
                                customer_identifier = cd.get('customerIdentifier')
                                if not cart_identifier or not customer_identifier:
                                    cart_identifier, customer_identifier = self.get_checkout_data()
                                    if self._checkout_data:
                                        cd = self._checkout_data
                                
                                order_data['checkoutState'] = cd.get('checkoutState', checkout_state)
                                order_data['cartIdentifier'] = cart_identifier
                                order_data['customerIdentifier'] = customer_identifier
                                
                                retry_response = self.session.put(order_url, json=order_data, headers=headers, allow_redirects=False, timeout=15)
                                print(f"Retry {retry_num + 1} order submission response: {retry_response.status_code}")
                                
                                if retry_response.status_code in [307, 302, 301]:
                                    redirect_url = retry_response.headers.get('Location')
                                    if redirect_url:
                                        if redirect_url.startswith('/'):
                                            redirect_url = self.main_site_url + redirect_url
                                        elif not redirect_url.startswith('http'):
                                            redirect_url = self.base_url + redirect_url if '/VPayment/' in redirect_url or 'psp.tchibo.com.tr' in redirect_url else self.main_site_url + redirect_url
                                        print(f"✓✓✓ Got redirect after retry: {redirect_url[:100]}...")
                                        return redirect_url
                                    else:
                                        try:
                                            retry_data = retry_response.json()
                                            if 'url' in retry_data:
                                                redirect_url = retry_data['url']
                                                if redirect_url:
                                                    if redirect_url.startswith('/'):
                                                        redirect_url = self.main_site_url + redirect_url
                                                    elif not redirect_url.startswith('http'):
                                                        redirect_url = self.base_url + redirect_url if '/VPayment/' in redirect_url or 'psp.tchibo.com.tr' in redirect_url else self.main_site_url + redirect_url
                                                    print(f"✓✓✓ Found redirect URL in 307 response: {redirect_url[:100]}...")
                                                    return redirect_url
                                            if 'redirectUrl' in retry_data:
                                                redirect_url = retry_data['redirectUrl']
                                                print(f"✓✓✓ Found redirectUrl in 307 response: {redirect_url[:100]}...")
                                                return redirect_url
                                            if 'checkoutData' in retry_data:
                                                retry_cd = retry_data['checkoutData']
                                                if 'redirectUrl' in retry_cd:
                                                    redirect_url = retry_cd['redirectUrl']
                                                    print(f"✓✓✓ Found redirectUrl in checkoutData: {redirect_url[:100]}...")
                                                    return redirect_url
                                        except Exception as e:
                                            print(f"  Error parsing 307 response: {e}")
                                elif retry_response.status_code == 206:
                                    try:
                                        retry_data = retry_response.json()
                                        if 'redirectUrl' in retry_data:
                                            redirect_url = retry_data['redirectUrl']
                                            print(f"✓✓✓ Found redirectUrl in retry: {redirect_url[:100]}...")
                                            return redirect_url
                                        elif retry_data.get('status') == 'CUSTOMER_DATA_HAS_CHANGED':
                                            if 'checkoutData' in retry_data:
                                                cd = retry_data['checkoutData']
                                                self._checkout_data = cd
                                            continue
                                    except:
                                        pass
                                
                                pass
                        
                        if 'redirectUrl' in cd:
                            redirect_url = cd['redirectUrl']
                            print(f"✓ Found redirectUrl in checkoutData: {redirect_url[:100]}...")
                            return redirect_url
                        
                        retry_executed = False
                        if 'errors' in cd:
                            errors = cd['errors']
                            print(f"DEBUG: errors type: {type(errors)}, value: {errors}, len: {len(errors) if errors else 0}")
                            if errors and len(errors) > 0:
                                print(f"Errors found: {json.dumps(errors, indent=2, ensure_ascii=False)[:500]}")
                                try:
                                    if 'checkoutState' in cd:
                                        order_data['checkoutState'] = cd['checkoutState']
                                        checkout_state = cd['checkoutState']
                                    
                                    customer_data = cd.get('customerData', {})
                                    payment_data = cd.get('paymentData', {})
                                    
                                    if 'selectedAddressId' in customer_data:
                                        checkout_state['selectedAddressId'] = customer_data['selectedAddressId']
                                        order_data['selectedAddressId'] = customer_data['selectedAddressId']
                                        print(f"  Setting address from customerData.selectedAddressId: {order_data['selectedAddressId'][:30]}...")
                                    elif 'addresses' in customer_data and isinstance(customer_data['addresses'], list) and len(customer_data['addresses']) > 0:
                                        first_address = customer_data['addresses'][0]
                                        address_id = first_address.get('id') if isinstance(first_address, dict) else None
                                        if address_id:
                                            checkout_state['selectedAddressId'] = address_id
                                            order_data['selectedAddressId'] = address_id
                                            print(f"  Setting address from first address in customerData.addresses: {address_id[:30]}...")
                                    
                                    if 'selectedMethod' in payment_data:
                                        checkout_state['selectedPaymentMethod'] = payment_data['selectedMethod']
                                        order_data['selectedPaymentMethod'] = payment_data['selectedMethod']
                                        print(f"  Setting payment method from paymentData.selectedMethod: {order_data['selectedPaymentMethod']}")
                                    
                                    if 'availablePaymentMethods' in cd and len(cd['availablePaymentMethods']) > 0 and not order_data.get('selectedPaymentMethod'):
                                        pm = cd['availablePaymentMethods'][0]
                                        if isinstance(pm, dict):
                                            payment_method = pm.get('id') or pm.get('code') or pm.get('method') or pm.get('paymentMethod')
                                        else:
                                            payment_method = str(pm) if pm else None
                                        if payment_method:
                                            checkout_state['selectedPaymentMethod'] = payment_method
                                            order_data['selectedPaymentMethod'] = payment_method
                                            print(f"  Setting payment method from availablePaymentMethods: {order_data['selectedPaymentMethod']}")
                                    
                                    if not order_data.get('selectedPaymentMethod') or order_data.get('selectedPaymentMethod') == 'UNKNOWN':
                                        for code in ['CREDIT_CARD', 'CREDITCARD', 'CARD', 'CC', '4']:
                                            checkout_state['selectedPaymentMethod'] = code
                                            order_data['selectedPaymentMethod'] = code
                                            print(f"  Using fallback payment method: {code}")
                                            break
                                    
                                    if 'possibleDeliveryTargets' in cd:
                                        targets = cd['possibleDeliveryTargets']
                                        if targets and isinstance(targets, list) and len(targets) > 0:
                                            dt = targets[0]
                                            address_id = dt.get('id') if isinstance(dt, dict) else None
                                            if address_id:
                                                order_data['selectedAddressId'] = address_id
                                                print(f"  Setting address ID: {order_data['selectedAddressId']}")
                                    
                                    if not order_data.get('selectedAddressId'):
                                        import uuid
                                        address_id = str(uuid.uuid4())
                                        
                                        invoice_address = {
                                            'addressId': address_id,
                                            'addressType': 'INVOICE_ADDRESS',
                                            'firstName': 'Test',
                                            'lastName': 'User',
                                            'streetAddress': 'Test Street 123',
                                            'postalCode': '34000',
                                            'postalTown': 'Istanbul',
                                            'countryCode': 'TR',
                                            'phoneNumber': order_data.get('phoneNumber', '5551234567'),
                                        }
                                        
                                        delivery_address = {
                                            'addressId': address_id,
                                            'addressType': 'DELIVERY_ADDRESS',
                                            'firstName': 'Test',
                                            'lastName': 'User',
                                            'streetAddress': 'Test Street 123',
                                            'postalCode': '34000',
                                            'postalTown': 'Istanbul',
                                            'countryCode': 'TR',
                                            'phoneNumber': order_data.get('phoneNumber', '5551234567'),
                                        }
                                        
                                        checkout_state['selectedAddressId'] = address_id
                                        checkout_state['invoiceAddress'] = invoice_address
                                        checkout_state['deliveryAddress'] = delivery_address
                                        order_data['selectedAddressId'] = address_id
                                        print(f"  Created full address objects with addressId: {address_id[:30]}...")
                                    
                                    checkout_state['phoneNumber'] = order_data.get('phoneNumber', '5551234567')
                                    checkout_state['email'] = order_data.get('email', 'test@example.com')
                                    
                                    order_data['checkoutState'] = checkout_state
                                    
                                    if 'defaultPaymentMethod' in cd and cd['defaultPaymentMethod']:
                                        dpm = cd['defaultPaymentMethod']
                                        if isinstance(dpm, dict):
                                            payment_method = dpm.get('id') or dpm.get('code') or dpm.get('method')
                                        else:
                                            payment_method = str(dpm) if dpm and str(dpm).upper() != 'UNKNOWN' else None
                                        if payment_method:
                                            order_data['selectedPaymentMethod'] = payment_method
                                    
                                    if not order_data.get('selectedPaymentMethod') or order_data.get('selectedPaymentMethod') == 'UNKNOWN':
                                        for code in ['CREDIT_CARD', 'CREDITCARD', 'CARD', 'CC', '4']:
                                            order_data['selectedPaymentMethod'] = code
                                            print(f"  Using fallback payment method: {code}")
                                            break
                                    
                                    order_data['phoneNumber'] = '5551234567'
                                    order_data['email'] = 'test@example.com'
                                    
                                    print(f"\n  Retrying with updated order_data:")
                                    print(f"    selectedPaymentMethod: {order_data.get('selectedPaymentMethod', 'None')}")
                                    print(f"    selectedAddressId: {order_data.get('selectedAddressId', 'None')}")
                                    print(f"    phoneNumber: {order_data.get('phoneNumber', 'None')}")
                                    print(f"    email: {order_data.get('email', 'None')}")
                                    
                                    retry_response = self.session.put(order_url, json=order_data, headers=headers, allow_redirects=False, timeout=15)
                                    retry_executed = True
                                    print(f"  Retry response status: {retry_response.status_code}")
                                except Exception as retry_ex:
                                    print(f"Exception in retry block: {retry_ex}")
                                    import traceback
                                    traceback.print_exc()
                                    retry_executed = False
                                
                                if retry_response.status_code in [307, 302, 301]:
                                    redirect_url = retry_response.headers.get('Location')
                                    if redirect_url:
                                        if '/VPayment/' in redirect_url or 'psp.tchibo.com.tr' in redirect_url:
                                            redirect_url = redirect_url if redirect_url.startswith('http') else self.base_url + redirect_url
                                        elif redirect_url.startswith('/'):
                                            redirect_url = self.main_site_url + redirect_url
                                        print(f"✓ Got redirect after retry: {redirect_url[:100]}...")
                                        return redirect_url
                                elif retry_response.status_code == 206:
                                    redirect_url = retry_response.headers.get('Location')
                                    if redirect_url:
                                        if '/VPayment/' in redirect_url or 'psp.tchibo.com.tr' in redirect_url:
                                            redirect_url = redirect_url if redirect_url.startswith('http') else self.base_url + redirect_url
                                        else:
                                            redirect_url = self.main_site_url + redirect_url if redirect_url.startswith('/') else redirect_url
                                        print(f"✓ Got redirect in 206 retry: {redirect_url[:100]}...")
                                        return redirect_url
                                    else:
                                        print(f"Still 206 after retry, checking response body...")
                                        try:
                                            retry_error_data = retry_response.json()
                                            if 'redirectUrl' in retry_error_data:
                                                redirect_url = retry_error_data['redirectUrl']
                                                print(f"✓ Found redirectUrl in retry response: {redirect_url[:100]}...")
                                                return redirect_url
                                            if 'checkoutData' in retry_error_data:
                                                retry_cd = retry_error_data['checkoutData']
                                                if 'redirectUrl' in retry_cd:
                                                    redirect_url = retry_cd['redirectUrl']
                                                    print(f"✓ Found redirectUrl in retry checkoutData: {redirect_url[:100]}...")
                                                    return redirect_url
                                            if 'paymentRedirectUrl' in retry_error_data:
                                                redirect_url = retry_error_data['paymentRedirectUrl']
                                                print(f"✓ Found paymentRedirectUrl: {redirect_url[:100]}...")
                                                return redirect_url
                                        except Exception as e:
                                            pass
                        
                        if not retry_executed:
                            print(f"Response: {json.dumps(error_data, indent=2, ensure_ascii=False)[:500]}...")
                except:
                    print(f"Response: {response.text[:500]}")
            elif response.status_code == 401:
                print("401 Unauthorized - may need valid cart session")
                try:
                    error_data = response.json()
                    print(f"Error details: {json.dumps(error_data, indent=2)[:300]}...")
                except:
                    print(f"Response: {response.text[:300]}")
            else:
                print(f"Unexpected status code: {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"Response: {json.dumps(error_data, indent=2)[:500]}...")
                except:
                    print(f"Response: {response.text[:500]}")
            return None
        except Exception as e:
            print(f"Error submitting order: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def follow_payment_redirect(self, redirect_url):
        """
        Follow redirect chain to get Token and Secret.
        Flow: /service/paymenthandling/api/mobilexpress/redirect -> VPayStep1.aspx -> VPayStepOptions_4
        """
        if not redirect_url:
            return None, None
        
        try:
            print(f"Following redirect: {redirect_url[:100]}...")
            
            response = self.session.get(redirect_url, allow_redirects=False, timeout=15)
            
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location')
                if location:
                    if location.startswith('/'):
                        parsed = urllib.parse.urlparse(redirect_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    elif not location.startswith('http'):
                        parsed = urllib.parse.urlparse(redirect_url)
                        base_path = '/'.join(parsed.path.split('/')[:-1])
                        location = f"{parsed.scheme}://{parsed.netloc}{base_path}/{location}"
                    
                    print(f"Redirect 1 -> {location[:100]}...")
                    
                    if 'errorResult=' in location or 'error' in location.lower():
                        error_msg = ""
                        if 'errorResult=' in location:
                            error_msg = location.split('errorResult=')[1].split('&')[0]
                        print(f"  ❌ Redirect goes to error page: {error_msg}")
                        return None, None
                    
                    response2 = self.session.get(location, allow_redirects=False, timeout=15)
                    
                    if response2.status_code in [301, 302, 303, 307, 308]:
                        location2 = response2.headers.get('Location')
                        if location2:
                            if location2.startswith('/'):
                                parsed = urllib.parse.urlparse(location)
                                location2 = f"{parsed.scheme}://{parsed.netloc}{location2}"
                            elif not location2.startswith('http'):
                                parsed = urllib.parse.urlparse(location)
                                base_path = '/'.join(parsed.path.split('/')[:-1])
                                location2 = f"{parsed.scheme}://{parsed.netloc}{base_path}/{location2}"
                            
                            print(f"Redirect 2 -> {location2[:100]}...")
                            
                            if 'Token=' in location2 and 'Secret=' in location2:
                                parsed = urllib.parse.urlparse(location2)
                                params = urllib.parse.parse_qs(parsed.query)
                                token = params.get('Token', [None])[0]
                                secret = params.get('Secret', [None])[0]
                                if token and secret:
                                    print(f"✓ Found Token/Secret!")
                                    return token, secret
                            
                            response3 = self.session.get(location2, allow_redirects=True, timeout=15)
                            final_url = response3.url
                            
                            if 'Token=' in final_url and 'Secret=' in final_url:
                                parsed = urllib.parse.urlparse(final_url)
                                params = urllib.parse.parse_qs(parsed.query)
                                token = params.get('Token', [None])[0]
                                secret = params.get('Secret', [None])[0]
                                if token and secret:
                                    print(f"✓ Found Token/Secret in final URL!")
                                    return token, secret
                    
                    if 'Token=' in location and 'Secret=' in location:
                        parsed = urllib.parse.urlparse(location)
                        params = urllib.parse.parse_qs(parsed.query)
                        token = params.get('Token', [None])[0]
                        secret = params.get('Secret', [None])[0]
                        if token and secret:
                            print(f"✓ Found Token/Secret in redirect location!")
                            return token, secret
            
            response = self.session.get(redirect_url, allow_redirects=True, timeout=15)
            final_url = response.url
            if 'Token=' in final_url and 'Secret=' in final_url:
                parsed = urllib.parse.urlparse(final_url)
                params = urllib.parse.parse_qs(parsed.query)
                token = params.get('Token', [None])[0]
                secret = params.get('Secret', [None])[0]
                if token and secret:
                    print(f"✓ Found Token/Secret (fallback)!")
                    return token, secret
                
        except Exception as e:
            print(f"Error following redirect: {e}")
            import traceback
            traceback.print_exc()
        
        return None, None
    
    def initialize_session(self, payment_token=None, payment_secret=None):
        """
        Initialize payment session.
        
        If payment_token and payment_secret are provided (from real order submission),
        use those to access the payment page. Otherwise, try to submit order.
        """
        
        if payment_token and payment_secret:
            self.payment_token = payment_token
            self.payment_secret = payment_secret
            payment_url = f"{self.base_url}/VPayment/VPayStepOptions_4?Token={payment_token}&Secret={urllib.parse.quote(payment_secret)}&dtype=4"
            response = self.session.get(payment_url, allow_redirects=True, timeout=15)
        else:
            redirect_url = self.submit_order()
            
            if not redirect_url:
                response = self.session.get(self.base_url + '/VPayment/VPayStepOptions', allow_redirects=True, timeout=15)
            else:
                self.payment_token, self.payment_secret = self.follow_payment_redirect(redirect_url)
                
                if self.payment_token and self.payment_secret:
                    payment_url = f"{self.base_url}/VPayment/VPayStepOptions_4?Token={self.payment_token}&Secret={urllib.parse.quote(self.payment_secret)}&dtype=4"
                    response = self.session.get(payment_url, allow_redirects=True, timeout=15)
                else:
                    response = self.session.get(self.base_url + '/VPayment/VPayStepOptions', allow_redirects=True, timeout=15)
        
        if response.status_code != 200:
            raise Exception(f"Failed to load payment page. Status: {response.status_code}")
        
        if 'VPayError' in response.url or 'error' in response.url.lower():
            print(f"  ⚠️  WARNING: Redirected to error page!")
            print(f"  URL: {response.url}")
            if 'erc=' in response.url:
                error_code = response.url.split('erc=')[1].split('&')[0]
                print(f"  Error code: {error_code}")
            raise Exception(f"Payment session invalid - redirected to error page: {response.url}")
        
        if 'VPayStepOptions' not in response.url:
            print(f"  ⚠️  WARNING: Not on expected payment page!")
            print(f"  Current URL: {response.url}")
            print(f"  Expected: VPayStepOptions_4")
        
        payment_page_response = response
        
        self.payment_xcsrf = None
        try:
            self.payment_xcsrf = self.session.cookies.get('PaymentXCSRF')
        except:
            for cookie in self.session.cookies:
                if hasattr(cookie, 'name') and cookie.name == 'PaymentXCSRF':
                    self.payment_xcsrf = cookie.value
                    break
        
        payment_session_id = None
        try:
            payment_session_id = self.session.cookies.get('Payment.SessionId')
        except:
            for cookie in self.session.cookies:
                if hasattr(cookie, 'name') and cookie.name == 'Payment.SessionId':
                    payment_session_id = cookie.value
                    break
        self.payment_session_id = payment_session_id
        
        ts_cookie_name = None
        ts_cookie_value = None
        
        all_cookie_names = []
        for c in self.session.cookies:
            if hasattr(c, 'name'):
                all_cookie_names.append(c.name)
            elif isinstance(c, str):
                all_cookie_names.append(str(c).split('=')[0] if '=' in str(c) else str(c))
        print(f"  All cookies in session: {all_cookie_names}")
        
        ts_cookie_names_to_try = ['TS01282d4a']
        for ts_name in ts_cookie_names_to_try:
            try:
                ts_cookie_value = self.session.cookies.get(ts_name)
                if ts_cookie_value:
                    ts_cookie_name = ts_name
                    print(f"  ✓ Found TS cookie by name: {ts_cookie_name}")
                    break
            except:
                pass
        
        if not ts_cookie_value:
            for cookie in self.session.cookies:
                cookie_name = None
                cookie_value = None
                if hasattr(cookie, 'name'):
                    cookie_name = cookie.name
                    cookie_value = cookie.value
                elif isinstance(cookie, str) and '=' in cookie:
                    parts = cookie.split('=', 1)
                    cookie_name = parts[0]
                    cookie_value = parts[1] if len(parts) > 1 else None
                
                if cookie_name and cookie_name.startswith('TS'):
                    ts_cookie_name = cookie_name
                    ts_cookie_value = cookie_value
                    print(f"  ✓ Found TS cookie by pattern: {ts_cookie_name}")
                    break
        
        if not self.payment_xcsrf:
            print("PaymentXCSRF not found, accessing payment page again...")
            retry_response = self.session.get(response.url if hasattr(response, 'url') else self.base_url + '/VPayment/VPayStepOptions_4', allow_redirects=True, timeout=15)
            try:
                self.payment_xcsrf = self.session.cookies.get('PaymentXCSRF')
            except:
                for cookie in self.session.cookies:
                    if hasattr(cookie, 'name') and cookie.name == 'PaymentXCSRF':
                        self.payment_xcsrf = cookie.value
                        break
        
        lfm_mid_cookie = self.session.cookies.get('l-fm-mid')
        if not lfm_mid_cookie:
            from datetime import datetime
            l_fm_mid_value = f"{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4()}"
            print(f"  Generating l-fm-mid cookie: {l_fm_mid_value}")
            self.session.cookies.set('l-fm-mid', l_fm_mid_value, domain='psp.tchibo.com.tr')
            lfm_mid_cookie = l_fm_mid_value
        self.l_fm_mid = lfm_mid_cookie
        
        loadbalance_cookie = self.session.cookies.get('loadbalancepsp')
        if not loadbalance_cookie:
            loadbalance_value = '!9MF3IqMk+WsOO4lIPdCIc6XRgVcK9UnfPr9SiDnOnDKHuhqcFcQK9Y63i53VHP8drPXx5vFJu73qqw=='
            print(f"  Setting loadbalancepsp cookie from known working value")
            self.session.cookies.set('loadbalancepsp', loadbalance_value, domain='psp.tchibo.com.tr')
            loadbalance_cookie = loadbalance_value
        self.loadbalancepsp = loadbalance_cookie
        
        html = response.text
        
        totp_value = None
        bdtot_value = None
        
        process_start = re.search(r'var\s+process\s*=\s*\{', html, re.IGNORECASE)
        if process_start:
            search_start = process_start.start()
            search_end = min(search_start + 50000, len(html))
            process_section = html[search_start:search_end]
            
            totp_match = re.search(r'TotP\s*:\s*([0-9]+\.?[0-9]*)', process_section, re.IGNORECASE)
            if totp_match:
                totp_value = totp_match.group(1)
        else:
            totp_match = re.search(r'TotP\s*:\s*([0-9]+\.?[0-9]*)', html, re.IGNORECASE)
            if totp_match:
                totp_value = totp_match.group(1)
                print(f"  ✓ Extracted TotP from page: {totp_value}")
            else:
                print("  ⚠ TotP not found in HTML")
        
        if process_start:
            bdtot_match = re.search(r'BDTot\s*:\s*([0-9]+\.?[0-9]*)', process_section, re.IGNORECASE)
            if bdtot_match:
                bdtot_value = bdtot_match.group(1)
                print(f"  ✓ Extracted BDTot from process object: {bdtot_value}")
        else:
            bdtot_match = re.search(r'BDTot\s*:\s*([0-9]+\.?[0-9]*)', html, re.IGNORECASE)
            if bdtot_match:
                bdtot_value = bdtot_match.group(1)
                print(f"  ✓ Extracted BDTot from page: {bdtot_value}")
        
        if totp_value:
            self.totp = float(totp_value)
            self.totp_value = self.totp
            self.totp_value_str = f"{self.totp:.10f}".rstrip('0').rstrip('.')
            print(f"  ✓ Formatted TotP value: {self.totp_value_str}")
        else:
            self.totp = None
            self.totp_value = None
            self.totp_value_str = None
        
        if bdtot_value:
            self.bdtot = float(bdtot_value)
        else:
            self.bdtot = None
        
        ctrl_inputs = re.findall(r'<input[^>]*name=["\']ctrlKey["\'][^>]*value=["\']([0-9a-f-]{36})', html, re.IGNORECASE)
        if ctrl_inputs:
            self.ctrl_key = ctrl_inputs[0].strip()
        
        pg_inputs = re.findall(r'<input[^>]*name=["\']pgProcessKey["\'][^>]*value=["\']([0-9a-f-]{36})', html, re.IGNORECASE)
        if pg_inputs:
            self.pg_process_key = pg_inputs[0].strip()
        
        if self.payment_token and not self.pg_process_key:
            self.pg_process_key = self.payment_token
            print(f"  ✓ Using Token as pgProcessKey: {self.pg_process_key}")
        
        if not self.ctrl_key:
            ctrl_matches = re.findall(r'ctrlKey["\']?\s*[:=]\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', html, re.IGNORECASE)
            if ctrl_matches:
                self.ctrl_key = ctrl_matches[0].strip()
        
        if not self.pg_process_key:
            pg_matches = re.findall(r'pgProcessKey["\']?\s*[:=]\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', html, re.IGNORECASE)
            if pg_matches:
                self.pg_process_key = pg_matches[0]
        
        process_match = re.search(r'process\s*=\s*\{[^}]*ctrlKey["\']?\s*[:=]\s*["\']([^"\']+)', html, re.IGNORECASE | re.DOTALL)
        if process_match:
            self.ctrl_key = process_match.group(1).strip()
        
        process_match2 = re.search(r'process\s*=\s*\{[^}]*pgProcessKey["\']?\s*[:=]\s*["\']([^"\']+)', html, re.IGNORECASE | re.DOTALL)
        if process_match2:
            self.pg_process_key = process_match2.group(1).strip()
        
        ctrl_inputs = re.findall(r'<input[^>]*name=["\']ctrlKey["\'][^>]*value=["\']([^"\']+)', html, re.IGNORECASE)
        if ctrl_inputs:
            self.ctrl_key = ctrl_inputs[0].strip()
        
        pg_inputs = re.findall(r'<input[^>]*name=["\']pgProcessKey["\'][^>]*value=["\']([^"\']+)', html, re.IGNORECASE)
        if pg_inputs:
            self.pg_process_key = pg_inputs[0].strip()
        
        if not self.ctrl_key:
            ctrl_id_match = re.search(r'<input[^>]*id=["\']ctrlKey["\'][^>]*value=["\']([^"\']+)', html, re.IGNORECASE)
            if ctrl_id_match:
                self.ctrl_key = ctrl_id_match.group(1).strip()
        
        if not self.pg_process_key:
            pg_id_match = re.search(r'<input[^>]*id=["\']pgProcessKey["\'][^>]*value=["\']([^"\']+)', html, re.IGNORECASE)
            if pg_id_match:
                self.pg_process_key = pg_id_match.group(1).strip()
        
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        
        if not self.ctrl_key:
            ctrl_context = re.search(r'ctrlKey["\']?\s*=\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', html, re.IGNORECASE)
            if ctrl_context:
                self.ctrl_key = ctrl_context.group(1).strip()
            else:
                ctrl_form = re.search(r'name\s*=\s*["\']ctrlKey["\'][^>]*value\s*=\s*["\']([0-9a-f-]{36})', html, re.IGNORECASE)
                if ctrl_form:
                    self.ctrl_key = ctrl_form.group(1).strip()
        
        if not self.pg_process_key:
            pg_context = re.search(r'pgProcessKey["\']?\s*=\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', html, re.IGNORECASE)
            if pg_context:
                self.pg_process_key = pg_context.group(1).strip()
            else:
                pg_form = re.search(r'name\s*=\s*["\']pgProcessKey["\'][^>]*value\s*=\s*["\']([0-9a-f-]{36})', html, re.IGNORECASE)
                if pg_form:
                    self.pg_process_key = pg_form.group(1).strip()
        
        if not self.ctrl_key or not self.pg_process_key:
            all_uuids = re.findall(uuid_pattern, html, re.IGNORECASE)
            seen = set()
            unique_uuids = []
            for uuid_val in all_uuids:
                if uuid_val not in seen:
                    seen.add(uuid_val)
                    unique_uuids.append(uuid_val)
            
            if len(unique_uuids) >= 2:
                if not self.ctrl_key:
                    self.ctrl_key = unique_uuids[0].strip()
            elif len(unique_uuids) == 1:
                if not self.ctrl_key:
                    self.ctrl_key = unique_uuids[0].strip()
        
        if not self.pg_process_key or self.pg_process_key == self.ctrl_key:
            if self.pg_process_key == self.ctrl_key:
                print(f"Warning: pgProcessKey matched ctrlKey, generating new UUID...")
            self.pg_process_key = str(uuid.uuid4())
            while self.pg_process_key == self.ctrl_key:
                self.pg_process_key = str(uuid.uuid4())
            print(f"Generated pgProcessKey: {self.pg_process_key}")
        
        return self.ctrl_key and self.pg_process_key
    
    def get_bank_of_card(self, card_number, amount_str="764.89", is_3d=True, point_usage=False):
        """Call pg_getbankofcard endpoint"""
        bin_num = card_number[:8]
        
        url_params = self.get_random_url_params()
        url = f"{self.base_url}/VPayment/AjaxCall{url_params}"
        
        try:
            csrf_token = self.session.cookies.get('PaymentXCSRF')
        except:
            csrf_token = None
            for cookie in self.session.cookies:
                if cookie.name == 'PaymentXCSRF':
                    csrf_token = cookie.value
                    break
        
        if not csrf_token:
            csrf_token = self.payment_xcsrf
        
        if not csrf_token:
            dummy_response = self.session.get(self.base_url + '/')
            try:
                csrf_token = self.session.cookies.get('PaymentXCSRF')
            except:
                for cookie in self.session.cookies:
                    if cookie.name == 'PaymentXCSRF':
                        csrf_token = cookie.value
                        break
        
        if not csrf_token:
            raise Exception("PaymentXCSRF token required but not found")
        
        from collections import OrderedDict
        
        data = OrderedDict([
            ('Shopizz_Ajax_Action_Public', 'pg_getbankofcard'),
            ('ctrlKey', self.ctrl_key),
            ('binNum', bin_num),
            ('amountStr', amount_str),
            ('is3D', str(is_3d).lower()),
            ('pointUsage', str(point_usage).lower()),
            ('pgProcessKey', self.pg_process_key),
            ('PaymentXCSRF', csrf_token)
        ])
        
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': self.base_url,
            'Pragma': 'no-cache',
            'Referer': f"{self.base_url}/",
            'Sec-Ch-Ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
        }
        
        cookie_parts = []
        
        if hasattr(self.session, 'cookies'):
            if hasattr(self.session.cookies, 'items'):
                for name, value in self.session.cookies.items():
                    cookie_parts.append(f"{name}={value}")
            else:
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
            print(f"  DEBUG: Manually set Cookie header with {len(final_cookie_parts)} cookies")
        
        print(f"  DEBUG: POST {url}")
        print(f"  DEBUG: Data keys: {list(data.keys())}")
        print(f"  DEBUG: Cookie header length: {len(headers.get('Cookie', ''))}")
        
        response = self.session.post(url, data=data, headers=headers)
        
        print(f"  DEBUG: Response status: {response.status_code}")
        if hasattr(response, 'http_version'):
            print(f"  DEBUG: HTTP version: {response.http_version}")
        
        response.raise_for_status()
        
        result_text = response.text.strip()
        if result_text.startswith('"') and result_text.endswith('"'):
            result_text = result_text[1:-1]
        
        result_text = result_text.replace('\\u0022', '"').replace('\\/', '/')
        return json.loads(result_text)
    
    def refresh_ctrl_key(self):
        """Refresh ctrlKey"""
        payment_url = f"{self.base_url}/VPayment/VPayStepOptions_4?Token={self.payment_token}&Secret={self.payment_secret}&dtype=4"
        
        response = self.session.get(payment_url, timeout=3)
        data = response.content
        
        start = data.find(b'ctrlKey" value="') + 16
        end = data.find(b'"', start)
        
        if start > 16 and end > start:
            self.ctrl_key = data[start:end].decode().strip()
            return True
        
        return False
    
    def get_loyalty_point(self, card_number, card_month, card_year, card_holder="", pos_id=0, card_id=0, sc=0):
        """Call pg_getloyaltypoint endpoint"""
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
            'pgProcessKey': self.pg_process_key,
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
        
        if hasattr(self.session, 'cookies'):
            if hasattr(self.session.cookies, 'items'):
                for name, value in self.session.cookies.items():
                    cookie_parts.append(f"{name}={value}")
            else:
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
            print(f"  DEBUG: Manually set Cookie header with {len(final_cookie_parts)} cookies")
        
        response = self.session.post(url, data=data, headers=headers)
        response.raise_for_status()
        
        result_text = response.text.strip()
        if result_text.startswith('"') and result_text.endswith('"'):
            result_text = result_text[1:-1]
        
        result_text = result_text.replace('\\u0022', '"').replace('\\/', '/')
        return json.loads(result_text)

def parse_card(card_string):
    """Parse card format: cardno|mm|yyyy|cvv"""
    parts = card_string.split('|')
    if len(parts) != 4:
        raise ValueError("Invalid card format. Expected: cardno|mm|yyyy|cvv")
    return {
        'card_number': parts[0],
        'month': int(parts[1]),
        'year': int(parts[2]),
        'cvv': parts[3]
    }

def main():
    import sys
    
    card_string = "4111111111111111|12|2030|123"
    if len(sys.argv) > 1:
        card_string = sys.argv[1]
    
    card_info = parse_card(card_string)
    
    automation = TchiboPaymentAutomation()
    
    print("=" * 60)
    print("TCHIBO PAYMENT AUTOMATION")
    print("=" * 60)
    print()
    
    token = sys.argv[2] if len(sys.argv) > 2 else None
    secret = sys.argv[3] if len(sys.argv) > 3 else None
    cart_id = sys.argv[4] if len(sys.argv) > 4 else None
    customer_id = sys.argv[5] if len(sys.argv) > 5 else None
    
    print("Step 0: Attempting to add item to cart...")
    max_retries = 3
    item_added = False
    
    for attempt in range(max_retries):
        print(f"  Attempt {attempt + 1}/{max_retries}...")
        item_added = automation.add_to_cart('233722167222', quantity=1)
        if item_added:
            print("  ✓✓✓ Successfully added item to cart!")
            break
        else:
            print(f"  ✗ Attempt {attempt + 1} failed, retrying...")
    
    if not item_added:
        print("  ⚠ Could not add item after multiple attempts")
        print("  Will try alternative methods...")
    print()
    
    print("Step 1: Initializing payment session...")
    if token and secret:
        print("  Using provided Token/Secret...")
        if not automation.initialize_session(payment_token=token, payment_secret=secret):
            print("✗ Failed to initialize session")
            return
    else:
        print("  Submitting order to get Token/Secret...")
        redirect_url = automation.submit_order(cart_identifier=cart_id, customer_identifier=customer_id)
        if not redirect_url:
            print("✗ Failed to submit order")
            print("  Need cartIdentifier and customerIdentifier")
            print("  Usage: python tchibo_automation.py [card] [token] [secret] [cart_id] [customer_id]")
            return
        
        token, secret = automation.follow_payment_redirect(redirect_url)
        if not token or not secret:
            print("✗ Failed to get Token/Secret from redirect")
            return
        
        if not automation.initialize_session(payment_token=token, payment_secret=secret):
            print("✗ Failed to initialize session")
            return
    
    print(f"✓ Session initialized")
    print(f"  ctrlKey: {automation.ctrl_key}")
    print(f"  pgProcessKey: {automation.pg_process_key}")
    if automation.payment_xcsrf:
        print(f"  PaymentXCSRF: {automation.payment_xcsrf[:50]}...")
    print()
    
    if hasattr(automation, 'totp_value_str') and automation.totp_value_str:
        amount_str = automation.totp_value_str
        print(f"Using TotP value from payment page for amountStr: {amount_str}")
    else:
        amount_str = "1694.80"
        print(f"Using fallback amountStr: {amount_str}")
    
    print("Step 2: Calling pg_getbankofcard...")
    print(f"  Using amount: {amount_str}")
    try:
        bank_result = automation.get_bank_of_card(card_info['card_number'], amount_str=amount_str)
        print(f"✓ Bank result: {json.dumps(bank_result, indent=2, ensure_ascii=False)}")
        if bank_result.get('actionResult') and bank_result.get('resultObj'):
            print("✓ Success! Bank info retrieved")
        else:
            print(f"✗ Failed: {bank_result.get('errorMsg', 'Unknown error')}")
        print()
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("Step 3: Calling pg_getloyaltypoint...")
    try:
        loyalty_result = automation.get_loyalty_point(
            card_info['card_number'],
            card_info['month'],
            card_info['year']
        )
        print(f"✓ Loyalty result: {json.dumps(loyalty_result, indent=2, ensure_ascii=False)}")
        if loyalty_result.get('actionResult') and loyalty_result.get('resultObj'):
            points = loyalty_result['resultObj'].get('Point', 0)
            point_str = loyalty_result['resultObj'].get('PointStr', '0')
            print(f"\n{'='*60}")
            print(f"✓✓✓ SUCCESS! Loyalty Points: {points} ({point_str})")
            print(f"{'='*60}")
            if points == 6665.77 or point_str == "6665,77":
                print("✓✓✓ Expected points value matched!")
        else:
            print(f"\n✗ Failed: {loyalty_result.get('errorMsg', 'Unknown error')}")
            print(f"   Error Code: {loyalty_result.get('errorCode', 'N/A')}")
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
