from typing import Optional, Dict, Any
from requests import Response, Session
from requests.exceptions import SSLError, ConnectionError, Timeout, RequestException, HTTPError

from domain.http.retry_policy import RetryPolicy
from utils.logging import get_logger

logger = get_logger()


class RequestSender:
    def __init__(self, session: Session, retry_policy: RetryPolicy):
        self.session = session
        self.retry_policy = retry_policy
    
    def send_request(self, 
                    method: str, 
                    url: str, 
                    timeout: Optional[int] = None,
                    **kwargs) -> Optional[Response]:
        def make_request() -> Response:
            response = self.session.request(
                method.upper(),
                url,
                timeout=timeout or self.session.timeout,
                verify=True,
                **kwargs
            )
            return response
        
        try:
            response = self.retry_policy.execute_with_retry(make_request)
            if response and response.status_code == 403:
                content_lower = response.text.lower() if response.text else ""
                is_cloudflare = 'cloudflare' in content_lower or 'challenge' in content_lower or 'cf-ray' in str(response.headers).lower()
                if is_cloudflare:
                    logger.warning(f"Cloudflare protection detected (403) for {url}. Continuing with limited testing.")
            return response
        except HTTPError as e:
            if hasattr(e, 'response') and e.response is not None:
                response = e.response
                if response.status_code == 403:
                    content_lower = response.text.lower() if response.text else ""
                    is_cloudflare = 'cloudflare' in content_lower or 'challenge' in content_lower or 'cf-ray' in str(response.headers).lower()
                    if is_cloudflare:
                        logger.warning(f"Cloudflare protection detected (403) for {url}. Continuing with limited testing.")
                return response
            logger.error(f"HTTP error for {url}: {e}")
            return None
        except SSLError as e:
            logger.error(f"SSL certificate verification failed for {url}: {e}")
            logger.warning("This might be due to self-signed certificates or SSL configuration issues.")
            return None
        except ConnectionError as e:
            logger.error(f"Connection error for {url}: {e}")
            logger.warning("This might be due to network issues, firewall, or the server being unreachable.")
            return None
        except Timeout as e:
            logger.error(f"Request timeout for {url} (timeout: {timeout or self.session.timeout}s): {e}")
            return None
        except RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error for {url}: {e}")
            return None
    
    def get(self, url: str, **kwargs) -> Optional[Response]:
        return self.send_request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[Response]:
        return self.send_request('POST', url, **kwargs)

