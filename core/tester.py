import json
from typing import List, Optional, Tuple, Dict
from tqdm import tqdm
import requests

from domain.http import HTTPClient
from utils.logging import get_logger
from detection.success import LoginSuccessDetector
from core.form_parser import FormData
from payloads.nosql_generator import NoSQLPayloadGenerator

logger = get_logger()


class CredentialTester:
    def __init__(self, client: HTTPClient, detector: LoginSuccessDetector):
        self.client = client
        self.detector = detector
    
    def test(self, form_data: FormData, url: str, credentials_list: List[str],
             success_keywords: List[str], failure_keywords: List[str],
             http_method: str, original_content_length: int,
             verbose: bool = False, progress_bar=None,
             language_keywords: Optional[Dict[str, List[str]]] = None) -> Tuple[bool, Optional[int], Optional[str], Optional[dict]]:
        if progress_bar:
            from tqdm import tqdm
            tqdm.write("INFO: Testing Default Credentials")
        else:
            logger.info("Testing Default Credentials")
        rate_limited_at = None
        successful_credential = None
        successful_details = None
        
        for i, credential in enumerate(credentials_list, 1):
            if ':' not in credential:
                logger.warning(f"Invalid credential format (skipping): {credential}")
                continue
            
            username, password = credential.split(':', 1)
            
            if not username.strip() or not password.strip():
                logger.warning(f"Empty username or password (skipping): {credential}")
                continue
            
            logger.debug(f"Trying credential {i}/{len(credentials_list)}: {username}:{password}")
            
            username_field = None
            password_field = None
            
            if form_data.username_input:
                username_field = form_data.username_input.get('name')
                if not username_field:
                    username_field = form_data.username_input.get('id')
            
            if form_data.password_input:
                password_field = form_data.password_input.get('name')
                if not password_field:
                    password_field = form_data.password_input.get('id')
            
            if not username_field or not password_field:
                logger.warning(f"Form input fields missing 'name' or 'id' attribute, skipping credential")
                continue
            
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
            
            try:
                if http_method == "POST":
                    response = self.client.post(form_data.action, data=payload_data, allow_redirects=False)
                else:
                    response = self.client.get(form_data.action, params=payload_data, allow_redirects=False)
                
                if not response:
                    if progress_bar:
                        progress_bar.update(1)
                    continue
                
                if response.status_code in [403, 429] and rate_limited_at is None:
                    logger.warning(f"Rate limit detected during default credential test. Status code: {response.status_code}")
                    rate_limited_at = i
                
                detection_result = self.detector.detect(
                    response, url, original_content_length,
                    success_keywords, failure_keywords, self.client,
                    language_keywords=language_keywords
                )
                
                if detection_result.is_successful:
                    successful_credential = f"{username}:{password}"
                    successful_details = {
                        "confidence_score": detection_result.confidence_score,
                        "confidence_level": detection_result.confidence_level.value,
                        "indicators": detection_result.details.get("indicators", []),
                        "manual_verification_recommended": detection_result.manual_verification_recommended
                    }
                    success_msg = f"✓ Default credential successful: {username}:{password} (Confidence: {detection_result.confidence_level.value} - {detection_result.confidence_score})"
                    if progress_bar:
                        tqdm.write(f"INFO: {success_msg}")
                    else:
                        logger.info(success_msg)
                    if verbose:
                        logger.debug(f"Default credential successful: {username}:{password} "
                                   f"(Confidence: {detection_result.confidence_level.value} - {detection_result.confidence_score})")
                        logger.debug(f"Response status code: {response.status_code}")
                        if 'redirect_url' in detection_result.details:
                            logger.debug(f"Redirect location: {detection_result.details['redirect_url']}")
                        logger.debug(f"Indicators: {', '.join(detection_result.details.get('indicators', []))}")
                    
                    if progress_bar:
                        progress_bar.update(1)
                    return True, rate_limited_at, successful_credential, successful_details
                else:
                    if verbose:
                        logger.debug(f"Credential {username}:{password} - not successful "
                                   f"(Confidence: {detection_result.confidence_score})")
            except requests.exceptions.RequestException as e:
                error_str = str(e).lower()
                if '429' in error_str or 'too many' in error_str:
                    if rate_limited_at is None:
                        rate_limited_at = i
                        logger.warning(f"Rate limit detected during default credential test (429). Skipping remaining credentials.")
                    if progress_bar:
                        progress_bar.update(1)
                    continue
                logger.error(f"HTTP request error while testing credential {username}:{password}: {e}")
                if progress_bar:
                    progress_bar.update(1)
            except KeyError as e:
                logger.error(f"Key error while testing credential {username}:{password}: {e}")
                if progress_bar:
                    progress_bar.update(1)
            except AttributeError as e:
                logger.error(f"Attribute error while testing credential {username}:{password}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error while testing credential {username}:{password}: {e}", exc_info=True)
            
            if progress_bar:
                progress_bar.update(1)
        
        if progress_bar:
            tqdm.write("INFO: No default credentials were successful.")
        else:
            logger.info("No default credentials were successful.")
        return False, rate_limited_at, None, None


class InjectionTester:
    def __init__(self, client: HTTPClient, detector: LoginSuccessDetector):
        self.client = client
        self.detector = detector
    
    def test(self, form_data: FormData, url: str, injection_type: str, payloads: List[str],
             success_keywords: List[str], failure_keywords: List[str],
             http_method: str, original_content_length: int,
             verbose: bool = False, progress_bar=None,
             nosql_progressive_mode: bool = True,
             nosql_admin_patterns: Optional[List[str]] = None,
             language_keywords: Optional[Dict[str, List[str]]] = None) -> Tuple[bool, Optional[str], Optional[dict], Optional[int]]:
        if progress_bar:
            from tqdm import tqdm
            tqdm.write(f"INFO: Testing {injection_type}")
        else:
            logger.info(f"Testing {injection_type}")
        
        if injection_type == "NoSQL Injection" and nosql_progressive_mode:
            return self._test_nosql_progressive(
                form_data, url, success_keywords, failure_keywords,
                http_method, original_content_length, verbose, progress_bar,
                nosql_admin_patterns, language_keywords
            )
        
        rate_limited_at = None
        successful_payload = None
        successful_details = None
        
        for i, payload in enumerate(payloads, 1):
            logger.debug(f"Trying {injection_type} payload {i}/{len(payloads)}: {payload}")
            
            username_field = None
            password_field = None
            
            if form_data.username_input:
                username_field = form_data.username_input.get('name')
                if not username_field:
                    username_field = form_data.username_input.get('id')
            
            if form_data.password_input:
                password_field = form_data.password_input.get('name')
                if not password_field:
                    password_field = form_data.password_input.get('id')
            
            if not username_field or not password_field:
                logger.warning(f"Form input fields missing 'name' or 'id' attribute, skipping payload")
                continue
            
            payload_data = {
                username_field: payload,
                password_field: payload
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
            
            try:
                if injection_type == "NoSQL Injection":
                    headers = {'Content-Type': 'application/json'}
                    if http_method == "POST":
                        response = self.client.post(form_data.action, 
                                                   data=json.dumps(payload_data),
                                                   headers=headers, 
                                                   allow_redirects=False)
                    else:
                        response = self.client.get(form_data.action,
                                                 params=payload_data,
                                                 headers=headers,
                                                 allow_redirects=False)
                else:
                    if http_method == "POST":
                        response = self.client.post(form_data.action,
                                                   data=payload_data,
                                                   allow_redirects=False)
                    else:
                        response = self.client.get(form_data.action,
                                                 params=payload_data,
                                                 allow_redirects=False)
                
                if not response:
                    if progress_bar:
                        progress_bar.update(1)
                    continue
                
                if response.status_code in [403, 429] and rate_limited_at is None:
                    logger.warning(f"Rate limit detected during {injection_type} test. Status code: {response.status_code}")
                    rate_limited_at = i
                
                detection_result = self.detector.detect(
                    response, url, original_content_length,
                    success_keywords, failure_keywords, self.client,
                    language_keywords=language_keywords
                )
                
                if detection_result.is_successful:
                    successful_payload = payload
                    successful_details = {
                        "confidence_score": detection_result.confidence_score,
                        "confidence_level": detection_result.confidence_level.value,
                        "indicators": detection_result.details.get("indicators", []),
                        "manual_verification_recommended": detection_result.manual_verification_recommended
                    }
                    success_msg = f"✓ {injection_type} successful with payload: {payload} (Confidence: {detection_result.confidence_level.value} - {detection_result.confidence_score})"
                    if progress_bar:
                        tqdm.write(f"INFO: {success_msg}")
                    else:
                        logger.info(success_msg)
                    if verbose:
                        logger.debug(f"{injection_type} successful with payload: {payload} "
                                   f"(Confidence: {detection_result.confidence_level.value} - {detection_result.confidence_score})")
                        logger.debug(f"Response status code: {response.status_code}")
                        if 'redirect_url' in detection_result.details:
                            logger.debug(f"Redirect location: {detection_result.details['redirect_url']}")
                        logger.debug(f"Indicators: {', '.join(detection_result.details.get('indicators', []))}")
                    
                    if progress_bar:
                        progress_bar.update(1)
                    break
                else:
                    if verbose:
                        logger.debug(f"Payload {payload} - not successful "
                                   f"(Confidence: {detection_result.confidence_score})")
            except requests.exceptions.RequestException as e:
                error_str = str(e).lower()
                if '429' in error_str or 'too many' in error_str:
                    if rate_limited_at is None:
                        rate_limited_at = i
                        logger.warning(f"Rate limit detected during {injection_type} test (429). Skipping remaining payloads.")
                    if progress_bar:
                        progress_bar.update(1)
                    continue
                logger.error(f"HTTP request error while testing {injection_type} with payload {payload}: {e}")
                if progress_bar:
                    progress_bar.update(1)
            except KeyError as e:
                logger.error(f"Key error while testing {injection_type} with payload {payload}: {e}")
                if progress_bar:
                    progress_bar.update(1)
            except AttributeError as e:
                logger.error(f"Attribute error while testing {injection_type} with payload {payload}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error while testing {injection_type} with payload {payload}: {e}", exc_info=True)
            
            if progress_bar:
                progress_bar.update(1)
        
        return (successful_payload is not None), successful_payload, successful_details, rate_limited_at
    
    def _test_nosql_progressive(self, form_data: FormData, url: str,
                               success_keywords: List[str], failure_keywords: List[str],
                               http_method: str, original_content_length: int,
                               verbose: bool = False, progress_bar=None,
                               admin_patterns: Optional[List[str]] = None,
                               language_keywords: Optional[Dict[str, List[str]]] = None) -> Tuple[bool, Optional[str], Optional[dict], Optional[int]]:
        if progress_bar:
            tqdm.write("INFO: Starting progressive NoSQL injection testing")
        else:
            logger.info("Starting progressive NoSQL injection testing")
        
        generator = NoSQLPayloadGenerator(admin_patterns=admin_patterns)
        sequence = generator.generate_progressive_sequence()
        
        rate_limited_at = None
        successful_payload = None
        successful_details = None
        phase_results = {}
        should_continue = True
        
        for i, nosql_payload in enumerate(sequence, 1):
            if not should_continue:
                break
            
            logger.debug(f"Phase {nosql_payload.phase}: {nosql_payload.description}")
            if verbose:
                logger.debug(f"Phase {nosql_payload.phase.upper()}: {nosql_payload.description}")
                logger.debug(f"Username: {nosql_payload.username_payload}, Password: {nosql_payload.password_payload}")
            
            try:
                payload_data = generator.build_payload_dict(nosql_payload, form_data)
            except ValueError as e:
                logger.warning(f"Form input fields missing 'name' or 'id' attribute, skipping NoSQL injection test: {e}")
                break
            
            try:
                form_payload = {}
                for key, value in payload_data.items():
                    if isinstance(value, dict):
                        form_payload[key] = json.dumps(value, ensure_ascii=False)
                    elif isinstance(value, (list, tuple)):
                        form_payload[key] = json.dumps(value, ensure_ascii=False)
                    else:
                        form_payload[key] = value
                
                headers = {}
                if http_method == "POST":
                    response = self.client.post(
                        form_data.action,
                        data=form_payload,
                        headers=headers,
                        allow_redirects=False
                    )
                else:
                    response = self.client.get(
                        form_data.action,
                        params=form_payload,
                        headers=headers,
                        allow_redirects=False
                    )
                
                if not response:
                    if progress_bar:
                        progress_bar.update(1)
                    continue
                
                if response.status_code in [400, 500] and nosql_payload.phase == "basic_bypass":
                    if not response or not hasattr(response, 'text') or not response.text:
                        continue
                    response_text_lower = response.text.lower()
                    parse_errors = ['parse', 'syntax', 'malformed', 'invalid json']
                    if any(error in response_text_lower for error in parse_errors):
                        json_payload = {}
                        for key, value in payload_data.items():
                            json_payload[key] = value
                        
                        json_headers = {'Content-Type': 'application/json'}
                        if http_method == "POST":
                            response = self.client.post(
                                form_data.action,
                                data=json.dumps(json_payload),
                                headers=json_headers,
                                allow_redirects=False
                            )
                        else:
                            response = self.client.get(
                                form_data.action,
                                params=json_payload,
                                headers=json_headers,
                                allow_redirects=False
                            )
                        if not response:
                            if progress_bar:
                                progress_bar.update(1)
                            continue
                        if verbose:
                            logger.debug(f"Tried JSON format after form-data parse error")
                
                if response.status_code in [403, 429] and rate_limited_at is None:
                    logger.warning(f"Rate limit detected during NoSQL test. Status code: {response.status_code}")
                    rate_limited_at = i
                
                if not response or not hasattr(response, 'text') or not response.text:
                    if progress_bar:
                        progress_bar.update(1)
                    continue
                
                response_text_lower = response.text.lower()
                
                detection_result = self.detector.detect(
                    response, url, original_content_length,
                    success_keywords, failure_keywords, self.client,
                    language_keywords=language_keywords
                )
                
                has_csrf_error = 'csrf' in response_text_lower or 'missing parameter' in response_text_lower
                has_content_change = abs(len(response.text) - original_content_length) > 50
                has_format_change = original_content_length > 200 and len(response.text) < 200
                
                if has_csrf_error and (has_content_change or has_format_change):
                    from detection.signals import SignalType
                    from detection.success import ConfidenceLevel
                    
                    positive_signals = [s for s in detection_result.signals if s.signal_type == SignalType.POSITIVE]
                    
                    detection_result.confidence_score = max(35, detection_result.confidence_score + 25)
                    detection_result.is_successful = True
                    
                    if detection_result.confidence_score >= 50:
                        detection_result.confidence_level = ConfidenceLevel.HIGH
                    elif detection_result.confidence_score >= 30:
                        detection_result.confidence_level = ConfidenceLevel.MEDIUM
                    else:
                        detection_result.confidence_level = ConfidenceLevel.LOW
                    
                    logger.info(f"NoSQL injection detected via CSRF error + content change pattern (confidence: {detection_result.confidence_score})")
                    if verbose:
                        logger.debug(f"NoSQL injection detected (CSRF error + content change) - confidence adjusted to {detection_result.confidence_score}")
                
                false_positive_indicators = [
                    'invalid request',
                    'malformed',
                    'parse error',
                    'syntax error'
                ]
                
                is_likely_error = any(indicator in response_text_lower for indicator in false_positive_indicators)
                
                if is_likely_error and not detection_result.is_successful and response and hasattr(response, 'status_code') and response.status_code in [400, 500]:
                    response_preview = response.text[:100] if response and hasattr(response, 'text') and response.text else ""
                    logger.debug(f"NoSQL injection false positive detected for phase '{nosql_payload.phase}': {response_preview}")
                    if verbose:
                        logger.debug(f"False positive detected (parse/syntax error)")
                    phase_result = {
                        "success": False,
                        "confidence_score": 0,
                        "confidence_level": "Very Low",
                        "status_code": response.status_code if response and hasattr(response, 'status_code') else 0,
                        "indicators": ["False positive: parse/syntax error"],
                        "false_positive": True
                    }
                    phase_results[nosql_payload.phase] = phase_result
                    
                    if nosql_payload.phase == "basic_bypass":
                        if progress_bar:
                            tqdm.write("INFO: Basic bypass failed (parse error), NoSQL injection may not be possible")
                        else:
                            logger.info("Basic bypass failed (parse error), NoSQL injection may not be possible")
                        if verbose:
                            logger.debug("Basic bypass failed (parse error), stopping progressive testing")
                        should_continue = False
                        break
                    continue
                
                phase_result = {
                    "success": detection_result.is_successful,
                    "confidence_score": detection_result.confidence_score,
                    "confidence_level": detection_result.confidence_level.value,
                    "status_code": response.status_code if response and hasattr(response, 'status_code') else 0,
                    "indicators": detection_result.details.get("indicators", [])
                }
                phase_results[nosql_payload.phase] = phase_result
                
                if detection_result.is_successful:
                    payload_str = json.dumps({
                        "username": nosql_payload.username_payload,
                        "password": nosql_payload.password_payload
                    })
                    
                    successful_payload = payload_str
                    successful_details = {
                        "confidence_score": detection_result.confidence_score,
                        "confidence_level": detection_result.confidence_level.value,
                        "indicators": detection_result.details.get("indicators", []),
                        "manual_verification_recommended": detection_result.manual_verification_recommended,
                        "phase": nosql_payload.phase,
                        "phase_results": phase_results
                    }
                    
                    logger.info(f"✓ NoSQL injection successful in phase '{nosql_payload.phase}' "
                              f"(Confidence: {detection_result.confidence_level.value} - {detection_result.confidence_score})")
                    
                    if verbose:
                        logger.debug(f"SUCCESS! (Confidence: {detection_result.confidence_level.value} - {detection_result.confidence_score})")
                        logger.debug(f"Status Code: {response.status_code}")
                        if 'redirect_url' in detection_result.details:
                            logger.debug(f"Redirect: {detection_result.details['redirect_url']}")
                        logger.debug(f"Indicators: {', '.join(detection_result.details.get('indicators', []))}")
                    
                    if nosql_payload.phase == "admin_discovery":
                        should_continue = False
                        break
                    
                    if nosql_payload.phase == "multiple_user":
                        logger.info("Multiple users detected, continuing to admin discovery...")
                        if verbose:
                            logger.debug("Multiple users detected, continuing to admin discovery...")
                        should_continue = True
                    else:
                        should_continue = True
                else:
                    if verbose:
                        logger.debug(f"Not successful (Confidence: {detection_result.confidence_score})")
                    
                    if nosql_payload.phase == "basic_bypass":
                        if progress_bar:
                            tqdm.write("INFO: Basic bypass failed, NoSQL injection may not be possible")
                        else:
                            logger.info("Basic bypass failed, NoSQL injection may not be possible")
                        if verbose:
                            logger.debug("Basic bypass failed, stopping progressive testing")
                        should_continue = False
                        break
                
                if progress_bar:
                    progress_bar.update(1)
                    
            except requests.exceptions.RequestException as e:
                error_str = str(e).lower()
                if '429' in error_str or 'too many' in error_str:
                    if rate_limited_at is None:
                        rate_limited_at = i
                        logger.warning(f"Rate limit detected during NoSQL test (429). Skipping remaining payloads.")
                    if progress_bar:
                        progress_bar.update(1)
                    continue
                logger.error(f"HTTP request error during NoSQL progressive test phase '{nosql_payload.phase}': {e}")
                if progress_bar:
                    progress_bar.update(1)
            except ValueError as e:
                logger.error(f"Value error during NoSQL progressive test phase '{nosql_payload.phase}': {e}")
                if progress_bar:
                    progress_bar.update(1)
            except Exception as e:
                logger.error(f"Unexpected error during NoSQL progressive test phase '{nosql_payload.phase}': {e}", exc_info=True)
                if progress_bar:
                    progress_bar.update(1)
        
        if verbose:
            logger.debug("Progressive Testing Summary:")
            for phase, result in phase_results.items():
                status = "✓" if result["success"] else "✗"
                logger.debug(f"  {status} {phase}: {result['confidence_level']} ({result['confidence_score']})")
        
        return (successful_payload is not None), successful_payload, successful_details, rate_limited_at

