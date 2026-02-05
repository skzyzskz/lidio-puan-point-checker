import random
import threading
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_manager.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ProxyManager:
    def __init__(self, proxy_file='cgrrr.txt'):
        self.proxy_file = proxy_file
        self.proxies = []
        self.current_index = 0
        self.lock = threading.Lock()
        self.failed_proxies = set()
        self.proxy_stats = {}
        self.load_proxies()
    
    def load_proxies(self):
        try:
            with open(self.proxy_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            self.proxies = []
            for line in lines:
                line = line.strip()
                if line and ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 4:
                        host, port, username, password = parts[0], parts[1], parts[2], parts[3]
                        proxy_url = f"http://{username}:{password}@{host}:{port}"
                        self.proxies.append({
                            'url': proxy_url,
                            'host': host,
                            'port': port,
                            'username': username,
                            'password': password,
                            'original_line': line
                        })
            
                logger.info(f"{len(self.proxies)} proxy loaded")
            
            for proxy in self.proxies:
                key = f"{proxy['host']}:{proxy['port']}"
                self.proxy_stats[key] = {
                    'success_count': 0,
                    'fail_count': 0,
                    'last_used': None,
                    'is_active': True
                }
                
        except FileNotFoundError:
            logger.debug(f"Proxy file not found: {self.proxy_file}")
            self.proxies = []
        except Exception as e:
            logger.error(f"Proxy load error: {e}")
            self.proxies = []
    
    def get_next_proxy(self, strategy='round_robin'):
        with self.lock:
            if not self.proxies:
                logger.warning("No proxy loaded")
                return None
            
            active_proxies = [p for p in self.proxies if self.is_proxy_active(p)]
            
            if not active_proxies:
                logger.warning("No active proxy, resetting")
                self.reset_failed_proxies()
                active_proxies = self.proxies
            
            if strategy == 'round_robin':
                proxy = active_proxies[self.current_index % len(active_proxies)]
                self.current_index = (self.current_index + 1) % len(active_proxies)
            elif strategy == 'random':
                proxy = random.choice(active_proxies)
            else:
                proxy = active_proxies[0]
            
            key = f"{proxy['host']}:{proxy['port']}"
            self.proxy_stats[key]['last_used'] = datetime.now()
            
            logger.info(f"Proxy selected: {proxy['host']}:{proxy['port']}")
            return proxy
    
    def get_proxy_config(self, strategy='round_robin'):
        proxy = self.get_next_proxy(strategy)
        if not proxy:
            logger.warning("No active proxy available")
            return {'http': None, 'https': None}
        
        return {
            'http': proxy['url'],
            'https': proxy['url']
        }
    
    def mark_proxy_success(self, proxy):
        if not proxy:
            return
        
        key = f"{proxy['host']}:{proxy['port']}"
        with self.lock:
            if key in self.proxy_stats:
                self.proxy_stats[key]['success_count'] += 1
                self.proxy_stats[key]['is_active'] = True
                self.failed_proxies.discard(key)
                logger.debug(f"Proxy success: {key}")
    
    def mark_proxy_failed(self, proxy):
        if not proxy:
            return
        
        key = f"{proxy['host']}:{proxy['port']}"
        with self.lock:
            if key in self.proxy_stats:
                self.proxy_stats[key]['fail_count'] += 1
                
                if self.proxy_stats[key]['fail_count'] >= 3:
                    self.proxy_stats[key]['is_active'] = False
                    self.failed_proxies.add(key)
                    logger.warning(f"Proxy disabled: {key}")
    
    def is_proxy_active(self, proxy):
        key = f"{proxy['host']}:{proxy['port']}"
        return self.proxy_stats.get(key, {}).get('is_active', True)
    
    def reset_failed_proxies(self):
        with self.lock:
            for key in self.failed_proxies.copy():
                if key in self.proxy_stats:
                    self.proxy_stats[key]['is_active'] = True
                    self.proxy_stats[key]['fail_count'] = 0
            self.failed_proxies.clear()
            logger.info("All proxies reset")
    
    def get_proxy_stats(self):
        with self.lock:
            total_proxies = len(self.proxies)
            active_proxies = len([p for p in self.proxies if self.is_proxy_active(p)])
            failed_proxies = len(self.failed_proxies)
            
            return {
                'total': total_proxies,
                'active': active_proxies,
                'failed': failed_proxies,
                'current_index': self.current_index,
                'stats': self.proxy_stats.copy()
            }
    
    def get_random_proxy(self):
        return self.get_next_proxy('random')
    
    def get_round_robin_proxy(self):
        return self.get_next_proxy('round_robin')

proxy_manager = ProxyManager()

def get_proxy_config(strategy='round_robin'):
    return proxy_manager.get_proxy_config(strategy)

def mark_proxy_success(proxy):
    proxy_manager.mark_proxy_success(proxy)

def mark_proxy_failed(proxy):
    proxy_manager.mark_proxy_failed(proxy)

def get_proxy_stats():
    return proxy_manager.get_proxy_stats()

def reset_proxies():
    proxy_manager.reset_failed_proxies()

if __name__ == "__main__":
    pm = ProxyManager()
    print(f"Total proxies: {len(pm.proxies)}")
    
    for i in range(5):
        proxy = pm.get_next_proxy()
        if proxy:
            print(f"Proxy {i+1}: {proxy['host']}:{proxy['port']}")
    
    stats = pm.get_proxy_stats()
    print(f"\nStats: {stats['total']} total, {stats['active']} active, {stats['failed']} failed")
