from typing import Optional
from requests import Session
from requests.adapters import HTTPAdapter
try:
    from urllib3.util.retry import Retry
except ImportError:
    from requests.packages.urllib3.util.retry import Retry

try:
    import cloudscraper
    CLOUDSCRAPER_AVAILABLE = True
except ImportError:
    CLOUDSCRAPER_AVAILABLE = False


class SessionManager:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None, use_cloudscraper: bool = False, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.proxy = proxy
        self.use_cloudscraper = use_cloudscraper and CLOUDSCRAPER_AVAILABLE
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    
    def create_session(self, max_retries: int = 2) -> Session:
        if self.use_cloudscraper:
            return self._create_cloudscraper_session(max_retries)
        return self._create_requests_session(max_retries)
    
    def _create_cloudscraper_session(self, max_retries: int = 2) -> Session:
        scraper = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'windows',
                'desktop': True
            }
        )
        scraper.timeout = self.timeout
        
        if self.proxy:
            scraper.proxies = {"http": self.proxy, "https": self.proxy}
        
        return scraper
    
    def _create_requests_session(self, max_retries: int = 2) -> Session:
        session = Session()
        session.timeout = self.timeout
        
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[502, 503, 504],  # Removed 429 - don't retry on rate limit
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        
        return session

