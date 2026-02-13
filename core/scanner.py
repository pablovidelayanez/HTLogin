from datetime import datetime
from typing import Dict, List, Optional, Any
from tqdm import tqdm

from domain.http import HTTPClient
from domain.auth import CredentialProviderProtocol, DefaultCredentialProvider
from utils.logging import get_logger
from core.form_parser import FormParser
from core.discovery import LoginPageDiscovery
from core.tester import CredentialTester, InjectionTester
from core.user_enumeration import UsernameEnumerationTester
from core.api_discovery import APIDiscovery
from core.api_tester import APITester
from detection.success import LoginSuccessDetector
from payloads.injections import INJECTION_PAYLOADS
from config.settings import Config
from core.rate_limit_auditor import RateLimitAuditor

logger = get_logger()


class LoginScanner:
    def __init__(self, 
                 config: Config, 
                 language_keywords: Dict[str, List[str]],
                 credential_provider: Optional[CredentialProviderProtocol] = None):
        self.config = config
        self.language_keywords = language_keywords
        
        self.client = HTTPClient(
            timeout=config.timeout,
            max_retries=config.max_retries,
            proxy=config.proxy,
            user_agent=config.user_agent
        )
        
        self.detector = LoginSuccessDetector(
            threshold_low=config.confidence_threshold_low,
            threshold_medium=config.confidence_threshold_medium,
            threshold_high=config.confidence_threshold_high
        )
        
        self.form_parser = FormParser()
        self.discovery = LoginPageDiscovery(self.client, language_keywords)
        self.credential_tester = CredentialTester(self.client, self.detector)
        self.injection_tester = InjectionTester(self.client, self.detector)
        self.rate_limit_auditor = RateLimitAuditor(
            max_requests=config.rate_limit_requests,
            concurrency=config.rate_limit_threads,
            timeout=config.timeout,
        )
        self.user_enumeration_tester = UsernameEnumerationTester(self.client)
        self.api_discovery = APIDiscovery(self.client)
        self.api_tester = APITester(self.client, self.detector)
        
        self.credential_provider = credential_provider or DefaultCredentialProvider()
    
    def _is_registration_page(self, url: str, content: Optional[str] = None) -> bool:
        """Check if the URL is a registration/signup page, not a login page"""
        url_lower = url.lower()
        registration_keywords = ['register', 'signup', 'sign-up', 'sign.up', 'signup', 'create.account', 'create-account']
        
        if any(keyword in url_lower for keyword in registration_keywords):
            return True
        
        if content:
            content_lower = content.lower()
            registration_indicators = [
                'create account', 'sign up', 'register', 'registration', 
                'new account', 'create your account', 'join us', 'signup',
                'confirm password', 'password confirmation'
            ]
            if any(indicator in content_lower for indicator in registration_indicators):
                login_indicators = ['login', 'sign in', 'signin']
                has_login_indicator = any(indicator in content_lower for indicator in login_indicators)
                if not has_login_indicator or content_lower.count('register') > content_lower.count('login'):
                    return True
        
        return False
    
    def _test_baseline_login(self, form_data: FormData, url: str,
                            username: str, password: str,
                            success_keywords: List[str], failure_keywords: List[str],
                            original_content_length: int) -> Optional[Dict[str, Any]]:
        """Test baseline login with provided test account"""
        try:
            username_field = form_data.username_input.get('name')
            if not username_field:
                username_field = form_data.username_input.get('id')
            
            password_field = form_data.password_input.get('name')
            if not password_field:
                password_field = form_data.password_input.get('id')
            
            if not username_field or not password_field:
                logger.warning("Cannot perform baseline login: field names not found")
                return None
            
            payload_data = {
                username_field: username,
                password_field: password
            }
            
            if form_data.csrf_input:
                csrf_name = form_data.csrf_input.get('name')
                csrf_value = form_data.csrf_input.get('value')
                if csrf_name and csrf_value:
                    payload_data[csrf_name] = csrf_value
            
            for other_input in form_data.other_inputs:
                other_name = other_input.get('name')
                other_value = other_input.get('value')
                if other_name and other_value:
                    payload_data[other_name] = other_value
            
            if self.config.http_method == "POST":
                response = self.client.post(form_data.action, data=payload_data, allow_redirects=False)
            else:
                response = self.client.get(form_data.action, params=payload_data, allow_redirects=False)
            
            if not response:
                return None
            
            detection_result = self.detector.detect(
                response, url, original_content_length,
                success_keywords, failure_keywords, self.client,
                language_keywords=self.language_keywords
            )
            
            if detection_result.is_successful:
                return {
                    "success": True,
                    "confidence_score": detection_result.confidence_score,
                    "confidence_level": detection_result.confidence_level.value,
                    "status_code": response.status_code if hasattr(response, 'status_code') else 0,
                    "indicators": detection_result.details.get("indicators", []),
                    "redirect_url": detection_result.details.get("redirect_url"),
                    "session_cookie": detection_result.details.get("session_cookie_name"),
                    "response_length": len(response.text) if hasattr(response, 'text') and response.text else 0
                }
            else:
                return {
                    "success": False,
                    "confidence_score": detection_result.confidence_score,
                    "reason": "Login failed with test account"
                }
        except Exception as e:
            logger.error(f"Error during baseline login test: {e}")
            return None
    
    def scan(self, 
             url: str, 
             credential_provider: Optional[CredentialProviderProtocol] = None) -> Dict[str, Any]:
        start_time = datetime.now()
        results = {
            "url": url,
            "start_time": start_time.isoformat(),
            "tests": {},
            "summary": {}
        }
        
        try:
            logger.info(f"Starting tests for URL: {url}")
            
            response = self.client.get(url)
            if response is None:
                logger.error("No response received from server")
                results["error"] = "No response received from server. Possible reasons: SSL certificate issues, firewall/WAF protection (e.g., Cloudflare), network connectivity, or server unreachable."
                return results
            
            if response.status_code == 403:
                content_lower = response.text.lower() if response.text else ""
                is_cloudflare = 'cloudflare' in content_lower or 'challenge' in content_lower or 'cf-ray' in str(response.headers).lower()
                if is_cloudflare:
                    logger.warning(f"Access forbidden (403) for {url}. Cloudflare protection detected.")
                    logger.info("Attempting to bypass Cloudflare using cloudscraper...")
                    if self.client._switch_to_cloudscraper():
                        response = self.client.get(url)
                        if response and response.status_code == 200:
                            logger.info("Successfully bypassed Cloudflare protection!")
                        elif response and response.status_code != 403:
                            logger.info(f"Cloudflare bypass attempt returned status {response.status_code}")
                        else:
                            logger.warning("Cloudflare bypass failed. Tool will attempt to continue with limited testing.")
                    else:
                        logger.warning("cloudscraper not available. Tool will attempt to continue with limited testing.")
                else:
                    logger.warning(f"Access forbidden (403) for {url}. This might be due to WAF protection or IP blocking.")
                
                if response and len(response.text) == 0:
                    results["error"] = f"Access forbidden (403) with empty response. Possible WAF protection or IP blocking."
                    results["status_code"] = 403
                    return results
                
                if response is None:
                    results["error"] = f"Access forbidden (403) with no response. Possible WAF protection or IP blocking."
                    results["status_code"] = 403
                    return results
            
            if response.status_code == 429:
                logger.warning("Rate limit detected on initial request (429). Skipping all tests for this URL.")
                results["error"] = "Rate limit detected (429) on initial request"
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                results["end_time"] = end_time.isoformat()
                results["duration_seconds"] = duration
                results["summary"] = {
                    "total_requests": 1
                }
                return results
            
            if response.status_code not in [200, 403]:
                try:
                    response.raise_for_status()
                except Exception as e:
                    raise
            
            if not hasattr(response, 'text') or not response.text:
                logger.error("Response has no text content")
                results["error"] = "Response has no text content"
                return results
            
            if self._is_registration_page(url, response.text):
                logger.warning(f"Registration page detected: {url}")
                logger.info("Skipping injection tests on registration pages to avoid false positives.")
                logger.info("Registration pages use different success indicators than login pages.")
                results["note"] = "Registration page detected - injection tests skipped to avoid false positives"
                results["tests"]["registration_page"] = {
                    "status": "Skipped",
                    "reason": "Registration pages use different authentication flow than login pages"
                }
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                results["end_time"] = end_time.isoformat()
                results["duration_seconds"] = duration
                results["summary"] = {
                    "total_requests": 1
                }
                return results
            
            original_content_length = len(response.text)
            logger.debug(f"Original page content length: {original_content_length} bytes")
            
            form_data = self.form_parser.parse(
                response.text, 
                url, 
                use_selenium=self.config.use_selenium,
                selenium_wait_time=self.config.selenium_wait_time,
                user_agent=self.config.user_agent
            )
            
            if not form_data:
                logger.warning("Login form not found. Attempting alternative detection methods...")
                
                if not self.config.use_selenium:
                    try:
                        logger.info("Form not found in static HTML. Trying Selenium to render JavaScript (SPA detection)...")
                        form_data = self.form_parser.parse(
                            response.text,
                            url,
                            use_selenium=True,
                            selenium_wait_time=self.config.selenium_wait_time,
                            user_agent=self.config.user_agent
                        )
                        if form_data:
                            logger.info("✓ Form found after Selenium rendering!")
                        else:
                            logger.debug("Form still not found after Selenium rendering.")
                    except Exception as e:
                        logger.debug(f"Selenium auto-detection failed: {e}")
                        logger.info("Tip: Install Selenium and ChromeDriver, then use --use-selenium flag for better SPA support.")
            
            if not form_data:
                    discovered_urls = self.discovery.discover(
                        url, 
                        verify=self.config.discovery_verify_pages,
                        verbose=self.config.verbose
                    )
                    
                    if discovered_urls:
                        logger.info(f"Found {len(discovered_urls)} HTML login page(s)")
                        for discovered_url in discovered_urls:
                            logger.debug(f"Discovered login page: {discovered_url}")
                        
                        results["discovered_pages"] = discovered_urls
                        results["note"] = "Login form not found on main page, but login pages were discovered"
                        return results
                    
                    logger.info("No HTML forms found. Attempting to discover API endpoints...")
                    json_endpoints = self.api_discovery.discover_json_endpoints(url)
                    graphql_endpoints = self.api_discovery.discover_graphql_endpoints(url)
                    
                    if json_endpoints or graphql_endpoints:
                        logger.info(f"Found {len(json_endpoints)} JSON API endpoint(s) and {len(graphql_endpoints)} GraphQL endpoint(s)")
                        results["api_endpoints"] = {
                            "json": json_endpoints,
                            "graphql": graphql_endpoints
                        }
                        results["note"] = "No HTML forms found, but API endpoints discovered. Testing API endpoints..."
                        
                        provider = credential_provider or self.credential_provider
                        credentials_list = provider.get_credentials()
                        success_keywords = self.language_keywords.get("success", [])
                        failure_keywords = self.language_keywords.get("failure", [])
                        
                        for endpoint in json_endpoints[:3]:
                            logger.info(f"Testing JSON API endpoint: {endpoint}")
                            success, credential, details = self.api_tester.test_json_api(
                                endpoint, credentials_list[:5],  # Test max 5 credentials
                                success_keywords, failure_keywords,
                                original_content_length,
                                self.config.http_method,
                                self.language_keywords
                            )
                            if success:
                                results["tests"]["JSON API Login"] = {
                                    "status": "Successful",
                                    "endpoint": endpoint,
                                    "credential": credential,
                                    "details": details
                                }
                                logger.info(f"✓ JSON API login successful at {endpoint}")
                        
                        for endpoint in graphql_endpoints[:2]:
                            logger.info(f"Testing GraphQL endpoint: {endpoint}")
                            success, credential, details = self.api_tester.test_graphql(
                                endpoint, credentials_list[:3],  # Test max 3 credentials
                                success_keywords, failure_keywords,
                                original_content_length,
                                self.language_keywords
                            )
                            if success:
                                results["tests"]["GraphQL Login"] = {
                                    "status": "Successful",
                                    "endpoint": endpoint,
                                    "credential": credential,
                                    "details": details
                                }
                                logger.info(f"✓ GraphQL login successful at {endpoint}")
                        
                        if not results.get("tests"):
                            results["note"] = "API endpoints found but login tests were unsuccessful"
                        
                        api_total_requests = 1
                        api_total_requests += len(json_endpoints[:3]) * 5
                        api_total_requests += len(graphql_endpoints[:2]) * 5
                        api_total_requests += len(json_endpoints[:3]) * min(5, len(credentials_list))
                        api_total_requests += len(graphql_endpoints[:2]) * min(3, len(credentials_list))
                        
                        end_time = datetime.now()
                        duration = (end_time - start_time).total_seconds()
                        results["end_time"] = end_time.isoformat()
                        results["duration_seconds"] = duration
                        results["summary"] = {
                            "total_requests": api_total_requests
                        }
                        
                        return results
                    else:
                        logger.error("No login form, HTML pages, or API endpoints found.")
                        results["error"] = "No login form, HTML pages, or API endpoints found"
                        return results
            
            if not form_data.username_input or not form_data.password_input:
                logger.warning("Form found but username/password fields not detected. Trying API endpoints...")
                
                json_endpoints = self.api_discovery.discover_json_endpoints(url)
                if json_endpoints:
                    logger.info(f"Found {len(json_endpoints)} JSON API endpoint(s) as fallback")
                    results["api_endpoints"] = {"json": json_endpoints}
                    results["note"] = "Form fields not detected, testing API endpoints..."
                    
                    provider = credential_provider or self.credential_provider
                    credentials_list = provider.get_credentials()
                    success_keywords = self.language_keywords.get("success", [])
                    failure_keywords = self.language_keywords.get("failure", [])
                    
                    for endpoint in json_endpoints[:2]:
                        success, credential, details = self.api_tester.test_json_api(
                            endpoint, credentials_list[:3],
                            success_keywords, failure_keywords,
                            original_content_length,
                            self.config.http_method,
                            self.language_keywords
                        )
                        if success:
                            results["tests"]["JSON API Login"] = {
                                "status": "Successful",
                                "endpoint": endpoint,
                                "credential": credential,
                                "details": details
                            }
                            fallback_total_requests = 1
                            fallback_total_requests += len(json_endpoints[:2]) * 5
                            fallback_total_requests += len(json_endpoints[:2]) * min(3, len(credentials_list))
                            
                            end_time = datetime.now()
                            duration = (end_time - start_time).total_seconds()
                            results["end_time"] = end_time.isoformat()
                            results["duration_seconds"] = duration
                            results["summary"] = {
                                "total_requests": fallback_total_requests
                            }
                            return results
                
                logger.error("Form fields not detected and no API endpoints found.")
                results["error"] = "Form fields not detected and no API endpoints found"
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                results["end_time"] = end_time.isoformat()
                results["duration_seconds"] = duration
                results["summary"] = {
                    "total_requests": 1
                }
                return results
            
            username_field = form_data.username_input.get('name', 'N/A')
            password_field = form_data.password_input.get('name', 'N/A')
            
            logger.info(f"Username input found: {username_field}")
            logger.info(f"Password input found: {password_field}")
            
            csrf_found = form_data.csrf_input is not None
            if csrf_found:
                logger.info("CSRF token found")
            else:
                logger.warning("CSRF token not found. The form might be vulnerable to CSRF attacks.")
            
            captcha_found = form_data.captcha_input is not None
            if captcha_found:
                logger.warning("⚠ CAPTCHA detected! Automated testing may be limited. Manual verification recommended.")
                results["captcha_detected"] = True
                results["captcha_warning"] = "CAPTCHA protection detected. Some tests may fail or be skipped."
            else:
                logger.info("No CAPTCHA detected")
                results["captcha_detected"] = False
            
            results["form_info"] = {
                "username_field": username_field,
                "password_field": password_field,
                "csrf_found": csrf_found,
                "csrf_field": form_data.csrf_input.get('name') if form_data.csrf_input else None,
                "captcha_found": captcha_found
            }
            
            success_keywords = self.language_keywords.get("success", [])
            failure_keywords = self.language_keywords.get("failure", [])
            
            baseline_result = None
            if self.config.test_account_username and self.config.test_account_password:
                logger.info("Test account provided. Performing baseline login test...")
                baseline_result = self._test_baseline_login(
                    form_data, url, 
                    self.config.test_account_username,
                    self.config.test_account_password,
                    success_keywords, failure_keywords,
                    original_content_length
                )
                if baseline_result:
                    results["baseline_login"] = baseline_result
                    logger.info(f"✓ Baseline login successful. Using this as reference for confidence scoring.")
                else:
                    logger.warning("Baseline login failed. Continuing with normal testing...")
            
            if not captcha_found:
                enum_vulnerable, enum_username, enum_details = self.user_enumeration_tester.test(
                    form_data, url,
                    test_usernames=None,  # Use default test usernames
                    http_method=self.config.http_method,
                    language_keywords=self.language_keywords
                )
                if enum_vulnerable:
                    results["username_enumeration"] = {
                        "vulnerable": True,
                        "details": enum_details
                    }
                    logger.warning(f"⚠ Username enumeration vulnerability detected! "
                                 f"Test username: {enum_username}")
                else:
                    results["username_enumeration"] = {
                        "vulnerable": False
                    }
            else:
                logger.info("Skipping username enumeration test (CAPTCHA detected)")
                results["username_enumeration"] = {
                    "vulnerable": None,
                    "skipped": True,
                    "reason": "CAPTCHA detected"
                }
            
            provider = credential_provider or self.credential_provider
            credentials_list = provider.get_credentials()
            
            if provider.is_empty():
                logger.warning("No credentials available for testing")
            
            total_payloads = sum(len(payloads) for payloads in INJECTION_PAYLOADS.values())
            
            total_tests = total_payloads + len(credentials_list)
            
            pbar = None
            if self.config.show_progress:
                pbar = tqdm(total=total_tests, desc="Testing", unit="test", disable=False)
            for injection_type, payloads in INJECTION_PAYLOADS.items():
                success, payload, details, rate_limited_at = self.injection_tester.test(
                    form_data, url, injection_type, payloads,
                    success_keywords, failure_keywords,
                    self.config.http_method, original_content_length,
                    self.config.verbose, pbar,
                    nosql_progressive_mode=getattr(self.config, 'nosql_progressive_mode', True),
                    nosql_admin_patterns=getattr(self.config, 'nosql_admin_patterns', None),
                    language_keywords=self.language_keywords
                )
                
                if success:
                    results["tests"][injection_type] = {
                        "status": "Successful",
                        "payload": payload,
                        "confidence_score": details.get("confidence_score", 0),
                        "confidence_level": details.get("confidence_level", "Unknown"),
                        "manual_verification_recommended": details.get("manual_verification_recommended", False),
                        "details": details
                    }
                else:
                    results["tests"][injection_type] = {
                        "status": "Failed",
                        "rate_limited_at": rate_limited_at
                    }
            
            cred_success, cred_rate_limit, successful_cred, cred_details = self.credential_tester.test(
                form_data, url, credentials_list,
                success_keywords, failure_keywords,
                self.config.http_method, original_content_length,
                self.config.verbose, pbar,
                language_keywords=self.language_keywords
            )
            
            if cred_success:
                results["tests"]["Default Credentials"] = {
                    "status": "Successful",
                    "credential": successful_cred,
                    "confidence_score": cred_details.get("confidence_score", 0) if cred_details else 0,
                    "confidence_level": cred_details.get("confidence_level", "Unknown") if cred_details else "Unknown",
                    "manual_verification_recommended": cred_details.get("manual_verification_recommended", False) if cred_details else False,
                    "details": cred_details
                }
            else:
                results["tests"]["Default Credentials"] = {
                    "status": "Failed",
                    "rate_limited_at": cred_rate_limit
                }
            
            try:
                if self.config.rate_limit_requests > 0:
                    logger.info(f"Testing rate limiting (sending {self.config.rate_limit_requests} requests)...")
                    rl_payload = {}
                    username_field = form_data.username_input.get('name') if form_data.username_input else None
                    if not username_field and form_data.username_input:
                        username_field = form_data.username_input.get('id')
                    password_field = form_data.password_input.get('name') if form_data.password_input else None
                    if not password_field and form_data.password_input:
                        password_field = form_data.password_input.get('id')
                    
                    if username_field and password_field:
                        rl_payload = {
                            username_field: "htlogin_ratelimit_user",
                            password_field: "htlogin_ratelimit_pass",
                        }
                    
                    rl_result = self.rate_limit_auditor.audit(
                        url,
                        method=self.config.http_method,
                        payload=rl_payload or None,
                    )
                    
                    if rl_result.get("is_vulnerable"):
                        status_text = f"No rate limit after {rl_result.get('total_requests_sent', 0)} requests"
                        logger.warning(f"⚠ Rate limit test: {status_text}")
                    else:
                        blocked_at = rl_result.get("blocked_at_request_count")
                        if blocked_at:
                            status_text = f"Rate limited at request #{blocked_at}"
                        else:
                            status_text = "Rate limiting detected"
                        logger.info(f"✓ Rate limit test: {status_text}")
                    
                    results["tests"]["Rate Limit Test"] = {
                        "status": status_text,
                        "details": rl_result,
                    }
            except Exception as e:
                logger.debug(f"Error during rate limit audit: {e}")
            
            if pbar:
                pbar.close()
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            results["end_time"] = end_time.isoformat()
            results["duration_seconds"] = duration
            
            successful_tests = [k for k, v in results["tests"].items() 
                              if v.get("status") == "Successful"]
            
            total_requests = 1
            
            if self.config.test_account_username and self.config.test_account_password:
                total_requests += 1
            
            if not captcha_found:
                total_requests += min(5, len(self.user_enumeration_tester.USERNAME_NOT_FOUND_INDICATORS) if hasattr(self.user_enumeration_tester, 'USERNAME_NOT_FOUND_INDICATORS') else 5)
            
            total_requests += total_payloads
            total_requests += len(credentials_list)
            
            if self.config.rate_limit_requests > 0 and "Rate Limit Test" in results.get("tests", {}):
                rl_details = results["tests"]["Rate Limit Test"].get("details", {})
                rl_requests_sent = rl_details.get("total_requests_sent", 0)
                if rl_requests_sent > 0:
                    total_requests += rl_requests_sent
            
            results["summary"] = {
                "total_tests": len(results["tests"]),
                "successful": len(successful_tests),
                "failed": len(results["tests"]) - len(successful_tests),
                "successful_tests": successful_tests,
                "duration_seconds": duration,
                "total_requests": total_requests
            }
            
            return results
            
        except KeyError as e:
            logger.error(f"Key error: {e}")
            results["error"] = f"Missing required data: {str(e)}"
            return results
        except AttributeError as e:
            logger.error(f"Attribute error: {e}")
            results["error"] = f"Invalid object attribute: {str(e)}"
            return results
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}", exc_info=True)
            results["error"] = f"Unexpected error: {str(e)}"
            return results

