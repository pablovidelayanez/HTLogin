from typing import List, Optional
from urllib.parse import urljoin, urlparse
from domain.http import HTTPClient
from utils.logging import get_logger

logger = get_logger()


class APIDiscovery:
    """Discover API endpoints for login (JSON/GraphQL)"""
    
    JSON_API_PATHS = [
        '/api/login',
        '/api/auth',
        '/api/v1/login',
        '/api/v1/auth',
        '/api/v2/login',
        '/api/v2/auth',
        '/api/authenticate',
        '/api/signin',
        '/auth/login',
        '/auth/signin',
        '/login',
        '/signin',
        '/authenticate',
        '/user/login',
        '/users/login',
        '/account/login',
        '/accounts/login',
        # Juice Shop and similar frameworks
        '/rest/user/login',
        '/rest/auth/login',
        '/rest/login',
        '/rest/authenticate',
        # Additional common patterns
        '/api/users/login',
        '/api/user/authenticate',
        '/api/sessions',
        '/api/token',
        '/oauth/token',
    ]
    
    GRAPHQL_PATHS = [
        '/graphql',
        '/api/graphql',
        '/graphql/v1',
        '/v1/graphql'
    ]
    
    def __init__(self, client: HTTPClient):
        self.client = client
    
    def discover_json_endpoints(self, base_url: str) -> List[str]:
        """Discover potential JSON API login endpoints"""
        discovered = []
        parsed_base = urlparse(base_url)
        base_path = parsed_base.path.rstrip('/')
        
        for path in self.JSON_API_PATHS:
            test_url = urljoin(base_url, path)
            if self._test_endpoint(test_url, 'json'):
                discovered.append(test_url)
                logger.debug(f"Found JSON API endpoint: {test_url}")
            
            if base_path:
                relative_path = base_path + path
                test_url = urljoin(base_url, relative_path)
                if self._test_endpoint(test_url, 'json'):
                    discovered.append(test_url)
                    logger.debug(f"Found JSON API endpoint: {test_url}")
        
        return list(set(discovered))  # Remove duplicates
    
    def discover_graphql_endpoints(self, base_url: str) -> List[str]:
        discovered = []
        
        for path in self.GRAPHQL_PATHS:
            test_url = urljoin(base_url, path)
            if self._test_endpoint(test_url, 'graphql'):
                discovered.append(test_url)
                logger.debug(f"Found GraphQL endpoint: {test_url}")
        
        return list(set(discovered))
    
    def _test_endpoint(self, url: str, endpoint_type: str) -> bool:
        try:
            if endpoint_type == 'json':
                test_response = self.client.post(
                    url,
                    data='{"test": "test"}',
                    headers={'Content-Type': 'application/json'},
                    allow_redirects=False
                )
                if test_response is not None:
                    status = test_response.status_code if hasattr(test_response, 'status_code') else 0

                    if status not in [404, 405]:
                        return True
            
            elif endpoint_type == 'graphql':
                graphql_query = '{"query": "{ __schema { queryType { name } } }"}'
                test_response = self.client.post(
                    url,
                    data=graphql_query,
                    headers={'Content-Type': 'application/json'},
                    allow_redirects=False
                )
                if test_response is not None:
                    status = test_response.status_code if hasattr(test_response, 'status_code') else 0
                    if status not in [404, 405]:
                        if hasattr(test_response, 'text') and test_response.text:
                            text_lower = test_response.text.lower()
                            if 'graphql' in text_lower or 'errors' in text_lower or 'data' in text_lower:
                                return True
            
            return False
        except Exception as e:
            logger.debug(f"Error testing endpoint {url}: {e}")
            return False
    
    def detect_api_format(self, url: str, response_text: Optional[str] = None) -> Optional[str]:
        """Detect if URL is likely a JSON API or GraphQL endpoint"""
        if not response_text:
            response = self.client.get(url)
            if not response or not hasattr(response, 'text'):
                return None
            response_text = response.text
        
        response_lower = response_text.lower()
        
        if 'graphql' in response_lower or url.endswith('/graphql'):
            return 'graphql'
        
        if 'api' in url.lower() or '/api/' in url:
            return 'json'
        
        try:
            import json
            json.loads(response_text)
            if len(response_text) < 1000:  # Small JSON responses are likely API responses
                return 'json'
        except:
            pass
        
        return None
