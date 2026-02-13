import json
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
    
    def test_json_api(self, endpoint: str, 
                     credentials_list: List[str],
                     success_keywords: List[str], 
                     failure_keywords: List[str],
                     original_content_length: int,
                     http_method: str = "POST",
                     language_keywords: Optional[Dict[str, List[str]]] = None) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """Test login via JSON API"""
        logger.info(f"Testing JSON API endpoint: {endpoint}")
        
        username_field, password_field = self._detect_api_fields(endpoint, http_method)
        
        if not username_field or not password_field:
            logger.warning("Could not detect API field names, using defaults")
            username_field = 'username'
            password_field = 'password'
        
        successful_credential = None
        successful_details = None
        
        for credential in credentials_list[:5]:  # Test max 5 credentials for API
            if ':' not in credential:
                continue
            
            username, password = credential.split(':', 1)
            
            payload = {
                username_field: username,
                password_field: password
            }
            
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
                
                if not response:
                    continue
                
                detection_result = self.detector.detect(
                    response, endpoint, original_content_length,
                    success_keywords, failure_keywords, self.client,
                    language_keywords=language_keywords
                )
                
                if detection_result.is_successful:
                    successful_credential = credential
                    successful_details = {
                        "confidence_score": detection_result.confidence_score,
                        "confidence_level": detection_result.confidence_level.value,
                        "endpoint": endpoint,
                        "format": "json"
                    }
                    logger.info(f"✓ JSON API login successful: {credential}")
                    return True, successful_credential, successful_details
                    
            except Exception as e:
                logger.debug(f"Error testing JSON API with {credential}: {e}")
                continue
        
        return False, None, None
    
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
