import json
import re
from typing import List, Optional, Tuple, Dict, Any
from domain.http import HTTPClient
from detection.success import LoginSuccessDetector
from utils.logging import get_logger

logger = get_logger()


class APITester:
    """Test login via JSON API or GraphQL"""
    
    USERNAME_FIELDS = ['username', 'user', 'email', 'login', 'account', 'userName', 'user_name']
    PASSWORD_FIELDS = ['password', 'pass', 'pwd', 'passwd', 'passWord', 'user_password']
    
    def __init__(self, client: HTTPClient, detector: LoginSuccessDetector):
        self.client = client
        self.detector = detector
        self._csrf_token = None
        self._csrf_cookies = {}
    
    def _fetch_csrf_token(self, login_page_url: str) -> Optional[str]:
        """Fetch CSRF token from login page (for Laravel/PHP/Django apps)"""
        try:
            logger.debug(f"[CSRF] Fetching CSRF token from: {login_page_url}")
            
            response = self.client.get(login_page_url, allow_redirects=True)
            
            if response is None:
                logger.debug("[CSRF] No response from login page")
                return None
            
            # Store cookies (including XSRF-TOKEN if present)
            if hasattr(response, 'cookies'):
                for cookie_name, cookie_value in response.cookies.items():
                    self._csrf_cookies[cookie_name] = cookie_value
                    logger.debug(f"[CSRF] Stored cookie: {cookie_name}={cookie_value[:50]}...")
            
            html = response.text if response.text else ""
            
            # Method 1: Look for hidden input field with CSRF token (Laravel _token)
            csrf_patterns = [
                r'<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']_token["\']',
                r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
                r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf-token["\']',
                # Django csrfmiddlewaretoken
                r'<input[^>]*name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
                r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']csrfmiddlewaretoken["\']',
            ]
            
            for pattern in csrf_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    token = match.group(1)
                    logger.debug(f"[CSRF] Found CSRF token in HTML: {token[:20]}...")
                    self._csrf_token = token
                    return token
            
            # Method 2: Check for XSRF-TOKEN cookie (Laravel API)
            xsrf_cookie = self._csrf_cookies.get('XSRF-TOKEN')
            if xsrf_cookie:
                # URL decode the cookie value
                import urllib.parse
                token = urllib.parse.unquote(xsrf_cookie)
                logger.debug(f"[CSRF] Found XSRF-TOKEN cookie: {token[:20]}...")
                self._csrf_token = token
                return token
            
            logger.debug("[CSRF] No CSRF token found")
            return None
            
        except Exception as e:
            logger.debug(f"[CSRF] Error fetching CSRF token: {e}")
            return None
    
    def _make_request_with_csrf(self, endpoint: str, payload: dict, 
                                 http_method: str, login_page_url: str) -> Optional[Any]:
        """Make a request with CSRF token handling"""
        
        # First try without CSRF
        headers = {'Content-Type': 'application/json'}
        
        if http_method == "POST":
            response = self.client.post(
                endpoint,
                data=json.dumps(payload),
                headers=headers,
                allow_redirects=False
            )
        else:
            response = self.client.get(
                endpoint,
                params=payload,
                headers=headers,
                allow_redirects=False
            )
        
        if response is None:
            return None
        
        # Check for CSRF error (419 in Laravel, 403 in Django)
        if response.status_code in [419, 403]:
            csrf_indicators = ['page expired', 'csrf', 'token mismatch', 'forbidden']
            response_text = response.text.lower() if response.text else ""
            
            if response.status_code == 419 or any(ind in response_text for ind in csrf_indicators):
                logger.debug(f"[CSRF] Detected CSRF protection (status {response.status_code})")
                
                # Fetch CSRF token
                csrf_token = self._fetch_csrf_token(login_page_url)
                
                if csrf_token:
                    logger.debug(f"[CSRF] Retrying with CSRF token")
                    
                    # Try as form data (not JSON) with CSRF token - Laravel expects this
                    form_payload = payload.copy()
                    form_payload['_token'] = csrf_token
                    
                    # Build headers with CSRF
                    csrf_headers = {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-CSRF-TOKEN': csrf_token,
                        'X-XSRF-TOKEN': csrf_token,
                    }
                    
                    # Add cookies
                    if self._csrf_cookies:
                        cookie_str = '; '.join([f"{k}={v}" for k, v in self._csrf_cookies.items()])
                        csrf_headers['Cookie'] = cookie_str
                    
                    # Retry with form data
                    if http_method == "POST":
                        response = self.client.post(
                            endpoint,
                            data=form_payload,  # Form data, not JSON
                            headers=csrf_headers,
                            allow_redirects=False
                        )
                    
                    if response is not None:
                        logger.debug(f"[CSRF] Retry response status: {response.status_code}")
        
        return response
    
    def test_json_api(self, endpoint: str, 
                     credentials_list: List[str],
                     success_keywords: List[str], 
                     failure_keywords: List[str],
                     original_content_length: int,
                     http_method: str = "POST",
                     language_keywords: Optional[Dict[str, List[str]]] = None,
                     username_field: Optional[str] = None,
                     password_field: Optional[str] = None,
                     login_page_url: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """Test login via JSON API"""
        logger.info(f"Testing JSON API endpoint: {endpoint}")
        
        # Reset CSRF state for new endpoint
        self._csrf_token = None
        self._csrf_cookies = {}
        
        # Use provided field names or detect them
        if not username_field or not password_field:
            detected_user, detected_pass = self._detect_api_fields(endpoint, http_method)
            username_field = username_field or detected_user
            password_field = password_field or detected_pass
        
        if not username_field or not password_field:
            logger.warning("Could not detect API field names, using defaults")
            username_field = username_field or 'email'
            password_field = password_field or 'password'
        
        logger.debug(f"[DEBUG] API fields: username={username_field}, password={password_field}")
        
        # Determine login page URL for CSRF token fetching
        if not login_page_url:
            # Try to derive login page from endpoint
            from urllib.parse import urlparse, urljoin
            parsed = urlparse(endpoint)
            login_page_url = f"{parsed.scheme}://{parsed.netloc}/login"
        
        successful_credential = None
        successful_details = None
        csrf_fetched = False
        
        for credential in credentials_list[:5]:  # Test max 5 credentials for API
            if ':' not in credential:
                continue
            
            username, password = credential.split(':', 1)
            
            payload = {
                username_field: username,
                password_field: password
            }
            
            logger.debug(f"[DEBUG] API payload: {json.dumps(payload)}")
            logger.debug(f"[DEBUG] API endpoint: {endpoint}")
            
            try:
                headers = {'Content-Type': 'application/json'}
                
                # Add CSRF token if we have one
                if self._csrf_token:
                    headers['X-CSRF-TOKEN'] = self._csrf_token
                    headers['X-XSRF-TOKEN'] = self._csrf_token
                
                # Add cookies if we have them
                if self._csrf_cookies:
                    cookie_str = '; '.join([f"{k}={v}" for k, v in self._csrf_cookies.items()])
                    headers['Cookie'] = cookie_str
                
                if http_method == "POST":
                    response = self.client.post(
                        endpoint,
                        data=json.dumps(payload),
                        headers=headers,
                        allow_redirects=False
                    )
                else:
                    response = self.client.get(
                        endpoint,
                        params=payload,
                        headers=headers,
                        allow_redirects=False
                    )
                
                if response is None:
                    logger.debug(f"[DEBUG] No response from API endpoint")
                    continue
                
                logger.debug(f"[DEBUG] API response status: {response.status_code}")
                logger.debug(f"[DEBUG] API response headers: {dict(response.headers)}")
                if response.text:
                    response_preview = response.text[:500] if len(response.text) > 500 else response.text
                    logger.debug(f"[DEBUG] API response body: {response_preview}")
                
                # Check for CSRF error (419 Laravel, 403 Django)
                if response.status_code in [419, 403] and not csrf_fetched:
                    csrf_indicators = ['page expired', 'csrf', 'token mismatch', 'forbidden', 'verification']
                    response_text = response.text.lower() if response.text else ""
                    
                    if response.status_code == 419 or any(ind in response_text for ind in csrf_indicators):
                        logger.debug(f"[CSRF] Detected CSRF protection (status {response.status_code}), fetching token...")
                        csrf_fetched = True
                        
                        # Fetch CSRF token from login page
                        csrf_token = self._fetch_csrf_token(login_page_url)
                        
                        if csrf_token:
                            logger.debug(f"[CSRF] Got token, retrying with form data...")
                            
                            # Retry with form data (Laravel expects form-urlencoded, not JSON)
                            form_payload = payload.copy()
                            form_payload['_token'] = csrf_token
                            
                            csrf_headers = {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'X-CSRF-TOKEN': csrf_token,
                                'X-XSRF-TOKEN': csrf_token,
                                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                                'Origin': f"{urlparse(endpoint).scheme}://{urlparse(endpoint).netloc}",
                                'Referer': login_page_url,
                            }
                            
                            if self._csrf_cookies:
                                cookie_str = '; '.join([f"{k}={v}" for k, v in self._csrf_cookies.items()])
                                csrf_headers['Cookie'] = cookie_str
                            
                            response = self.client.post(
                                endpoint,
                                data=form_payload,  # Form data, not JSON
                                headers=csrf_headers,
                                allow_redirects=False
                            )
                            
                            if response is not None:
                                logger.debug(f"[CSRF] Retry response status: {response.status_code}")
                                logger.debug(f"[CSRF] Retry response headers: {dict(response.headers)}")
                                if response.text:
                                    response_preview = response.text[:300] if len(response.text) > 300 else response.text
                                    logger.debug(f"[CSRF] Retry response body: {response_preview}")
                
                # For JSON APIs, use specialized detection
                json_success = self._detect_json_api_success(response)
                logger.debug(f"[DEBUG] JSON API detection result: {json_success}")
                
                # Also check for redirect to dashboard/home (Laravel success pattern)
                redirect_success = False
                if response.status_code in [302, 301]:
                    location = response.headers.get('Location', '').lower()
                    success_redirects = ['dashboard', 'home', 'admin', 'profile', 'account', 'welcome']
                    if any(sr in location for sr in success_redirects):
                        redirect_success = True
                        logger.debug(f"[DEBUG] Redirect success detected: {location}")
                    # Also check if NOT redirecting to login (which would indicate failure)
                    elif 'login' not in location and 'error' not in location:
                        redirect_success = True
                        logger.debug(f"[DEBUG] Possible redirect success (not to login): {location}")
                
                if json_success or redirect_success:
                    successful_credential = credential
                    successful_details = {
                        "confidence_score": 100,
                        "confidence_level": "High",
                        "endpoint": endpoint,
                        "format": "json",
                        "response_status": response.status_code
                    }
                    logger.info(f"✓ JSON API login successful: {credential}")
                    return True, successful_credential, successful_details
                    
            except Exception as e:
                logger.debug(f"Error testing JSON API with {credential}: {e}")
                continue
        
        return False, None, None
    
    def _detect_json_api_success(self, response) -> bool:
        """Detect successful login from JSON API response"""
        if response is None:
            logger.debug("[DEBUG] _detect_json_api_success: response is None")
            return False
        
        logger.debug(f"[DEBUG] _detect_json_api_success: status={response.status_code}")
        
        # Check status code - 2xx is generally success for APIs
        if response.status_code >= 400:
            logger.debug(f"[DEBUG] _detect_json_api_success: status >= 400, returning False")
            return False
        
        # Try to parse JSON response
        try:
            response_text = response.text.strip() if response.text else ""
            logger.debug(f"[DEBUG] _detect_json_api_success: response_text[:100]={response_text[:100] if response_text else 'empty'}")
            
            # Skip if response is HTML (not a JSON API response)
            if response_text.startswith('<!') or response_text.startswith('<html'):
                logger.debug("[DEBUG] _detect_json_api_success: Response is HTML, not JSON API")
                return False
            
            # Parse JSON
            if response_text.startswith('{') or response_text.startswith('['):
                data = json.loads(response_text)
                logger.debug(f"[DEBUG] _detect_json_api_success: Parsed JSON data keys={list(data.keys()) if isinstance(data, dict) else 'list'}")
                
                # Check for common success indicators in JSON
                success_keys = ['token', 'access_token', 'accessToken', 'jwt', 'authentication', 
                              'auth', 'session', 'sessionId', 'session_id', 'user', 'userId',
                              'id_token', 'refresh_token', 'bearer']
                
                # Check for error indicators
                error_keys = ['error', 'errors', 'message', 'errorMessage', 'error_message']
                error_values = ['invalid', 'incorrect', 'failed', 'unauthorized', 'wrong', 
                              'denied', 'not found', 'bad credentials', 'authentication failed']
                
                # Recursive check for keys in nested JSON
                def has_key(obj, keys):
                    if isinstance(obj, dict):
                        for key in keys:
                            if key.lower() in [k.lower() for k in obj.keys()]:
                                return True
                        for value in obj.values():
                            if has_key(value, keys):
                                return True
                    elif isinstance(obj, list):
                        for item in obj:
                            if has_key(item, keys):
                                return True
                    return False
                
                def has_error_value(obj):
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            if key.lower() in [ek.lower() for ek in error_keys]:
                                if isinstance(value, str):
                                    return True  # Error field exists with a message
                            if has_error_value(value):
                                return True
                    elif isinstance(obj, list):
                        for item in obj:
                            if has_error_value(item):
                                return True
                    elif isinstance(obj, str):
                        if any(ev.lower() in obj.lower() for ev in error_values):
                            return True
                    return False
                
                # Check if response has success tokens
                has_success = has_key(data, success_keys)
                has_error = has_error_value(data)
                
                logger.debug(f"[DEBUG] _detect_json_api_success: has_success={has_success}, has_error={has_error}")
                
                # Success if we have success tokens and no errors
                if has_success and not has_error:
                    logger.debug("[DEBUG] _detect_json_api_success: SUCCESS - has success keys and no errors")
                    return True
                
                # Also check if status is 200/201 and no error field
                if response.status_code in [200, 201] and not has_error and data:
                    # Non-empty response without errors could be success
                    if isinstance(data, dict) and len(data) > 0:
                        logger.debug("[DEBUG] _detect_json_api_success: SUCCESS - 200/201 with data and no errors")
                        return True
            else:
                logger.debug(f"[DEBUG] _detect_json_api_success: Response doesn't start with {{ or [")
                        
        except json.JSONDecodeError:
            logger.debug("[DEBUG] _detect_json_api_success: Response is not valid JSON")
            pass
        except Exception as e:
            logger.debug(f"[DEBUG] _detect_json_api_success: Error parsing JSON response: {e}")
            pass
        
        logger.debug("[DEBUG] _detect_json_api_success: returning False (end of function)")
        return False
    
    def test_graphql(self, endpoint: str,
                    credentials_list: List[str],
                    success_keywords: List[str],
                    failure_keywords: List[str],
                    original_content_length: int,
                    language_keywords: Optional[Dict[str, List[str]]] = None) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """Test login via GraphQL"""
        logger.info(f"Testing GraphQL endpoint: {endpoint}")
        
        mutation_names = ['login', 'authenticate', 'signIn', 'signin', 'userLogin']
        
        for credential in credentials_list[:3]:  # Test max 3 for GraphQL
            if ':' not in credential:
                continue
            
            username, password = credential.split(':', 1)
            
            for mutation_name in mutation_names:
                for user_field in ['username', 'email', 'user']:
                    for pass_field in ['password', 'pass']:
                        try:
                            mutation = f"""
                            mutation {{
                                {mutation_name}({user_field}: "{username}", {pass_field}: "{password}") {{
                                    token
                                    user {{
                                        id
                                        username
                                    }}
                                }}
                            }}
                            """
                            
                            payload = {"query": mutation.strip()}
                            
                            response = self.client.post(
                                endpoint,
                                data=json.dumps(payload),
                                headers={'Content-Type': 'application/json'},
                                allow_redirects=False
                            )
                            
                            if not response:
                                continue
                            
                            detection_result = self.detector.detect(
                                response, endpoint, original_content_length,
                                success_keywords, failure_keywords, self.client,
                                language_keywords=language_keywords
                            )
                            
                            if detection_result.is_successful:
                                successful_details = {
                                    "confidence_score": detection_result.confidence_score,
                                    "confidence_level": detection_result.confidence_level.value,
                                    "endpoint": endpoint,
                                    "format": "graphql",
                                    "mutation": mutation_name
                                }
                                logger.info(f"✓ GraphQL login successful: {credential}")
                                return True, credential, successful_details
                                
                        except Exception as e:
                            logger.debug(f"Error testing GraphQL: {e}")
                            continue
        
        return False, None, None
    
    def _detect_api_fields(self, endpoint: str, http_method: str) -> Tuple[Optional[str], Optional[str]]:
        """Try to detect username and password field names by testing endpoint"""
        test_payloads = [
            {'username': 'test', 'password': 'test'},
            {'user': 'test', 'password': 'test'},
            {'email': 'test', 'password': 'test'},
            {'login': 'test', 'password': 'test'},
            {'userName': 'test', 'password': 'test'},
            {'user_name': 'test', 'password': 'test'},
            {'userName': 'test', 'passWord': 'test'},
            {'email': 'test', 'pass': 'test'},
            {'email': 'test', 'pwd': 'test'},
            {'account': 'test', 'password': 'test'},
            {'account': 'test', 'pass': 'test'},
            {'login': 'test', 'pass': 'test'},
            {'user': 'test', 'passwd': 'test'},
            {'email': 'test', 'passwd': 'test'},
            {'username': 'test', 'user_password': 'test'},
        ]
        
        detected_fields = None
        
        for payload in test_payloads:
            try:
                headers = {'Content-Type': 'application/json'}
                if http_method == "POST":
                    response = self.client.post(
                        endpoint,
                        data=json.dumps(payload),
                        headers=headers,
                        allow_redirects=False
                    )
                else:
                    response = self.client.get(
                        endpoint,
                        params=payload,
                        headers=headers,
                        allow_redirects=False
                    )
                
                if response:
                    status = response.status_code if hasattr(response, 'status_code') else 0
                    
                    if status in [400, 401, 422]:
                        username_field = list(payload.keys())[0]
                        password_field = list(payload.keys())[1]
                        detected_fields = (username_field, password_field)
                        
                        if hasattr(response, 'text') and response.text:
                            try:
                                error_data = json.loads(response.text)
                                error_str = json.dumps(error_data).lower()
                                
                                for field_name in ['username', 'user', 'email', 'login', 'account', 'password', 'pass', 'pwd']:
                                    if field_name in error_str:
                                        if 'username' in error_str or 'user' in error_str or 'email' in error_str:
                                            if username_field in ['username', 'user', 'email', 'login', 'account']:
                                                break
                                        elif 'password' in error_str or 'pass' in error_str or 'pwd' in error_str:
                                            if password_field in ['password', 'pass', 'pwd', 'passwd']:
                                                break
                            except (json.JSONDecodeError, AttributeError):
                                pass
                        
                        return detected_fields
                    
                    if hasattr(response, 'text') and response.text:
                        try:
                            response_data = json.loads(response.text)
                            response_str = json.dumps(response_data).lower()
                            
                            field_patterns = {
                                'username': ['username', 'user', 'email', 'login', 'account'],
                                'password': ['password', 'pass', 'pwd', 'passwd']
                            }
                            
                            for field_type, patterns in field_patterns.items():
                                for pattern in patterns:
                                    if pattern in response_str:
                                        if field_type == 'username':
                                            for key in payload.keys():
                                                if key.lower() in patterns:
                                                    detected_fields = (key, list(payload.keys())[1])
                                                    break
                                        elif field_type == 'password':
                                            for key in payload.keys():
                                                if key.lower() in ['password', 'pass', 'pwd', 'passwd']:
                                                    detected_fields = (list(payload.keys())[0], key)
                                                    break
                                        
                                        if detected_fields:
                                            return detected_fields
                        except (json.JSONDecodeError, AttributeError, KeyError):
                            pass
            except Exception as e:
                logger.debug(f"Error detecting API fields with payload {payload}: {e}")
                continue
        
        return detected_fields if detected_fields else (None, None)
