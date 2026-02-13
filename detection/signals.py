from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


class SignalType(Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"


@dataclass
class Signal:
    signal_type: SignalType
    name: str
    value: Any
    confidence: int
    description: str


class SignalCollector:
    def __init__(self, response, original_url: str, original_content_length: int, 
                 success_keywords: List[str], failure_keywords: List[str], client=None,
                 error_indicators: Optional[List[str]] = None,
                 login_indicators: Optional[List[str]] = None,
                 generic_indicators: Optional[List[str]] = None,
                 specific_indicators: Optional[List[str]] = None):
        self.response = response
        self.original_url = original_url
        self.original_content_length = original_content_length
        self.success_keywords = success_keywords
        self.failure_keywords = failure_keywords
        self.client = client
        self.signals: List[Signal] = []
        
        self.error_indicators = error_indicators or [
            'missing parameter', 'error', 'invalid', 'bad request', 'unauthorized', 'forbidden',
            'incorrect', 'failed', 'try again', 'wrong', 'denied', 'access denied', 'not found',
            'bad credentials', 'authentication failed', 'login failed', 'invalid credentials'
        ]
        self.login_indicators = login_indicators or ['login', 'sign in', 'authenticate']
        self.generic_indicators = generic_indicators or [
            'welcome', 'success', 'logged in', 'authenticated'
        ]
        self.specific_indicators = specific_indicators or [
            'admin', 'administrator', 'user:', 'username:', 'account:'
        ]
    
    def collect_all(self) -> List[Signal]:
        self.signals = []
        
        self._check_redirect()
        self._check_session_cookie()
        self._check_success_keywords()
        self._check_content_length_change()
        self._check_response_format_change()
        self._check_response_time()
        self._check_failure_keywords()
        self._check_error_messages()
        self._check_stay_on_login_page()
        self._check_multiple_users()
        
        return self.signals
    
    def _check_redirect(self) -> None:
        if not self.response or not hasattr(self.response, 'status_code'):
            return
        
        if self.response.status_code == 302:
            if not hasattr(self.response, 'headers'):
                return
            redirect_url = self.response.headers.get('Location')
            if redirect_url:
                from urllib.parse import urljoin, urlparse
                full_redirect_url = urljoin(self.original_url, redirect_url)
                
                def normalize_url(url: str) -> str:
                    parsed = urlparse(url)
                    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if parsed.query:
                        normalized += f"?{parsed.query}"
                    return normalized.lower()
                
                original_normalized = normalize_url(self.original_url)
                redirect_normalized = normalize_url(full_redirect_url)
                
                if redirect_normalized == original_normalized:
                    self.signals.append(Signal(
                        signal_type=SignalType.NEGATIVE,
                        name="redirect_loop",
                        value=full_redirect_url,
                        confidence=25,
                        description="Redirect loop detected (redirects back to original URL)"
                    ))
                    return
                
                redirect_chain = [original_normalized]
                current_url = full_redirect_url
                max_redirects = 5
                redirect_count = 0
                
                try:
                    cookies = self.response.cookies if hasattr(self.response, 'cookies') else None
                    final_response = None
                    
                    while redirect_count < max_redirects:
                        redirect_count += 1
                        current_normalized = normalize_url(current_url)
                        
                        if current_normalized in redirect_chain:
                            self.signals.append(Signal(
                                signal_type=SignalType.NEGATIVE,
                                name="redirect_loop",
                                value=current_url,
                                confidence=25,
                                description=f"Redirect loop detected in chain (redirect #{redirect_count})"
                            ))
                            return
                        
                        redirect_chain.append(current_normalized)
                        
                        if self.client:
                            redirect_response = self.client.get(current_url, cookies=cookies, allow_redirects=False)
                        else:
                            import requests
                            redirect_response = requests.get(current_url, cookies=cookies, timeout=5, allow_redirects=False)
                        
                        if not redirect_response:
                            break
                        
                        if redirect_response.status_code in [301, 302, 303, 307, 308]:
                            next_location = redirect_response.headers.get('Location')
                            if next_location:
                                current_url = urljoin(current_url, next_location)
                                cookies = redirect_response.cookies if hasattr(redirect_response, 'cookies') else cookies
                                continue
                        
                        final_response = redirect_response
                        break
                    
                    if redirect_count >= max_redirects:
                        self.signals.append(Signal(
                            signal_type=SignalType.NEGATIVE,
                            name="redirect_limit_exceeded",
                            value=current_url,
                            confidence=15,
                            description=f"Redirect chain too long (>{max_redirects} redirects)"
                        ))
                        return
                    
                    if final_response and hasattr(final_response, 'text') and final_response.text:
                        if len(final_response.text) != self.original_content_length:
                            final_url = final_response.url if (hasattr(final_response, 'url') and final_response.url) else current_url
                            redirect_text_lower = final_response.text.lower()
                            redirect_url_lower = final_url.lower() if final_url else ""
                            is_not_login_page = not any(
                                indicator.lower() in redirect_url_lower or indicator.lower() in redirect_text_lower
                                for indicator in self.login_indicators
                            )
                            
                            has_error_indicators = any(
                                indicator.lower() in redirect_text_lower or indicator.lower() in redirect_url_lower
                                for indicator in self.error_indicators
                            )
                            
                            has_failure_keywords = any(
                                kw.lower() in redirect_text_lower for kw in self.failure_keywords
                            )
                            
                            if final_url and is_not_login_page and not has_error_indicators and not has_failure_keywords:
                                redirect_final_url = final_response.url if hasattr(final_response, 'url') else current_url
                                self.signals.append(Signal(
                                    signal_type=SignalType.POSITIVE,
                                    name="302_redirect_to_non_login",
                                    value=redirect_final_url,
                                    confidence=40,
                                    description=f"302 redirect to non-login page (chain length: {redirect_count})"
                                ))
                except Exception:
                    pass
    
    def _check_session_cookie(self) -> None:
        if not self.response or not hasattr(self.response, 'headers'):
            return
        
        set_cookie_headers = self.response.headers.get_list('Set-Cookie') if hasattr(self.response.headers, 'get_list') else []
        if not set_cookie_headers and 'set-cookie' in self.response.headers:
            set_cookie_headers = [self.response.headers.get('set-cookie')]
        
        if not set_cookie_headers and hasattr(self.response, 'cookies'):
            for cookie in self.response.cookies:
                cookie_name_lower = cookie.name.lower()
                if any(keyword in cookie_name_lower for keyword in ['session', 'auth', 'token']):
                    cookie_value = getattr(cookie, 'value', '')
                    if not cookie_value or cookie_value.strip() == '':
                        continue
                    
                    has_httponly = getattr(cookie, 'has_nonstandard_attr', lambda x: False)('HttpOnly')
                    has_secure = getattr(cookie, 'secure', False)
                    
                    confidence = 35
                    description_parts = [f"Session cookie found: {cookie.name}"]
                    
                    if has_httponly:
                        confidence += 5
                        description_parts.append("HttpOnly")
                    if has_secure:
                        confidence += 5
                        description_parts.append("Secure")
                    
                    self.signals.append(Signal(
                        signal_type=SignalType.POSITIVE,
                        name="session_cookie",
                        value=cookie.name,
                        confidence=confidence,
                        description=", ".join(description_parts)
                    ))
                    break
            return
        
        for set_cookie_header in set_cookie_headers:
            if not set_cookie_header:
                continue
            
            cookie_parts = set_cookie_header.split(';')
            if not cookie_parts:
                continue
            
            name_value = cookie_parts[0].strip()
            if '=' not in name_value:
                continue
            
            cookie_name = name_value.split('=', 1)[0].strip()
            cookie_value = name_value.split('=', 1)[1].strip() if len(name_value.split('=', 1)) > 1 else ''
            
            if not cookie_value or cookie_value.strip() == '':
                continue
            
            cookie_name_lower = cookie_name.lower()
            if not any(keyword in cookie_name_lower for keyword in ['session', 'auth', 'token']):
                continue
            
            has_httponly = any('httponly' in part.lower() for part in cookie_parts)
            has_secure = any('secure' in part.lower() for part in cookie_parts)
            
            has_expiration = False
            max_age = None
            for part in cookie_parts:
                part_lower = part.lower().strip()
                if part_lower.startswith('max-age='):
                    try:
                        max_age = int(part_lower.split('=', 1)[1])
                        has_expiration = True
                    except (ValueError, IndexError):
                        pass
                elif part_lower.startswith('expires='):
                    has_expiration = True
            
            confidence = 35
            description_parts = [f"Session cookie found: {cookie_name}"]
            
            if has_httponly:
                confidence += 5
                description_parts.append("HttpOnly")
            if has_secure:
                confidence += 5
                description_parts.append("Secure")
            if has_expiration:
                confidence += 3
                if max_age:
                    description_parts.append(f"Max-Age={max_age}s")
                else:
                    description_parts.append("Expires set")
            
            self.signals.append(Signal(
                signal_type=SignalType.POSITIVE,
                name="session_cookie",
                value=cookie_name,
                confidence=confidence,
                description=", ".join(description_parts)
            ))
            break
    
    def _check_success_keywords(self) -> None:
        if not self.response or not hasattr(self.response, 'text') or not self.response.text:
            return
        
        lower_content = self.response.text.lower()
        url_lower = self.response.url.lower() if hasattr(self.response, 'url') and self.response.url else ""
        original_url_lower = self.original_url.lower()
        
        success_found = any(kw.lower() in lower_content for kw in self.success_keywords)
        
        if success_found:
            is_still_on_login_page = any(
                indicator.lower() in lower_content or indicator.lower() in url_lower or indicator.lower() in original_url_lower
                for indicator in self.login_indicators
            )
            
            has_error_indicators = any(
                indicator.lower() in lower_content for indicator in self.error_indicators
            )
            
            has_failure_keywords = any(
                kw.lower() in lower_content for kw in self.failure_keywords
            )
            
            if is_still_on_login_page or has_error_indicators or has_failure_keywords:
                return
            
            short_success_found = len(self.response.text) < 200 and any(
                kw.lower() in lower_content for kw in self.success_keywords
            )
            if short_success_found:
                matched_keyword = next((kw for kw in self.success_keywords if kw.lower() in lower_content), "success")
                self.signals.append(Signal(
                    signal_type=SignalType.POSITIVE,
                    name="short_success_message",
                    value=matched_keyword,
                    confidence=30,
                    description="Short success message with success keyword found"
                ))
            else:
                self.signals.append(Signal(
                    signal_type=SignalType.POSITIVE,
                    name="success_keywords",
                    value="found",
                    confidence=20,
                    description="Success keywords found in content"
                ))
    
    def _check_failure_keywords(self) -> None:
        if not self.response or not hasattr(self.response, 'text') or not self.response.text:
            return
        
        lower_content = self.response.text.lower()
        failure_found = any(kw.lower() in lower_content for kw in self.failure_keywords)
        
        if failure_found:
            self.signals.append(Signal(
                signal_type=SignalType.NEGATIVE,
                name="failure_keywords",
                value="found",
                confidence=30,
                description="Failure keywords found in content"
            ))
    
    def _check_content_length_change(self) -> None:
        if not self.response or not hasattr(self.response, 'text') or not self.response.text:
            return
        
        if len(self.response.text) != self.original_content_length:
            size_diff = abs(len(self.response.text) - self.original_content_length)
            if size_diff > 100:
                response_lower = self.response.text.lower()
                url_lower = self.response.url.lower() if hasattr(self.response, 'url') and self.response.url else ""
                original_url_lower = self.original_url.lower()
                
                is_error_message = any(indicator.lower() in response_lower for indicator in self.error_indicators)
                has_failure_keywords = any(kw.lower() in response_lower for kw in self.failure_keywords)
                is_still_on_login_page = any(
                    indicator.lower() in response_lower or indicator.lower() in url_lower or indicator.lower() in original_url_lower
                    for indicator in self.login_indicators
                )
                
                if is_error_message or has_failure_keywords or is_still_on_login_page:
                    if len(self.response.text) < self.original_content_length * 0.5:
                        self.signals.append(Signal(
                            signal_type=SignalType.NEGATIVE,
                            name="content_significantly_shorter_error",
                            value=size_diff,
                            confidence=15,
                            description=f"Content significantly shorter ({len(self.response.text)} vs {self.original_content_length} bytes) - error/login page detected"
                        ))
                    else:
                        self.signals.append(Signal(
                            signal_type=SignalType.NEGATIVE,
                            name="content_length_changed",
                            value=size_diff,
                            confidence=10,
                            description=f"Content length changed by {size_diff} bytes (error/login page detected)"
                        ))
                elif len(self.response.text) < self.original_content_length * 0.5:
                    self.signals.append(Signal(
                        signal_type=SignalType.POSITIVE,
                        name="content_significantly_shorter",
                        value=size_diff,
                        confidence=25,
                        description=f"Content significantly shorter ({len(self.response.text)} vs {self.original_content_length} bytes) - likely success message"
                    ))
                else:
                    self.signals.append(Signal(
                        signal_type=SignalType.POSITIVE,
                        name="content_length_changed",
                        value=size_diff,
                        confidence=10,
                        description=f"Content length changed by {size_diff} bytes"
                    ))
    
    def _check_response_format_change(self) -> None:
        if not self.response or not hasattr(self.response, 'text') or not self.response.text:
            return
        
        response_is_html = any(tag in self.response.text.lower() 
                              for tag in ['<html', '<body', '<div'])
        original_is_html = self.original_content_length > 200
        
        response_lower = self.response.text.lower()
        is_error_message = any(indicator.lower() in response_lower for indicator in self.error_indicators)
        
        if original_is_html and not response_is_html and len(self.response.text) < 200:
            confidence = 5 if is_error_message else 15
            signal_type = SignalType.NEGATIVE if is_error_message else SignalType.POSITIVE
            
            self.signals.append(Signal(
                signal_type=signal_type,
                name="format_html_to_text",
                value="changed",
                confidence=confidence,
                description=f"Response format changed from HTML to plain text {'(error message)' if is_error_message else '(likely success message)'}"
            ))
    
    def _check_response_time(self) -> None:
        if not self.response:
            return
        
        if hasattr(self.response, 'elapsed') and self.response.elapsed.total_seconds() > 1:
            self.signals.append(Signal(
                signal_type=SignalType.POSITIVE,
                name="response_time_high",
                value=self.response.elapsed.total_seconds(),
                confidence=5,
                description="Response time > 1s (possible processing)"
            ))
    
    def _check_error_messages(self) -> None:
        if not self.response or not hasattr(self.response, 'text') or not self.response.text:
            return
        
        error_patterns = [
            r'error\s+\d+',
            r'exception',
            r'traceback',
            r'stack\s+trace',
        ]
        
        import re
        content_lower = self.response.text.lower()
        for pattern in error_patterns:
            if re.search(pattern, content_lower):
                self.signals.append(Signal(
                    signal_type=SignalType.NEGATIVE,
                    name="error_message",
                    value=pattern,
                    confidence=20,
                    description=f"Error message pattern found: {pattern}"
                ))
                break
    
    def _check_stay_on_login_page(self) -> None:
        if not self.response or not hasattr(self.response, 'text') or not self.response.text:
            return
        
        content_lower = self.response.text.lower()
        url_lower = self.response.url.lower() if hasattr(self.response, 'url') and self.response.url else ""
        original_url_lower = self.original_url.lower()
        
        login_indicators_found = any(
            indicator.lower() in content_lower or indicator.lower() in url_lower or indicator.lower() in original_url_lower
            for indicator in self.login_indicators
        )
        
        content_length_similar = abs(len(self.response.text) - self.original_content_length) < 200
        
        if login_indicators_found and content_length_similar:
            confidence = 25 if content_length_similar and abs(len(self.response.text) - self.original_content_length) < 50 else 15
            self.signals.append(Signal(
                signal_type=SignalType.NEGATIVE,
                name="still_on_login_page",
                value="detected",
                confidence=confidence,
                description="Still appears to be on login page"
            ))
    
    def _check_multiple_users(self) -> None:
        if not self.response or not hasattr(self.response, 'text') or not self.response.text:
            return
        
        content_lower = self.response.text.lower()
        has_generic_message = any(indicator.lower() in content_lower for indicator in self.generic_indicators)
        has_specific_user = any(indicator.lower() in content_lower for indicator in self.specific_indicators)
        
        if has_generic_message and not has_specific_user:
            length_diff = abs(len(self.response.text) - self.original_content_length)
            if length_diff > 50:
                self.signals.append(Signal(
                    signal_type=SignalType.POSITIVE,
                    name="possible_multiple_users",
                    value="detected",
                    confidence=20,
                    description="Possible multiple users selected (generic success message without specific user)"
                ))

