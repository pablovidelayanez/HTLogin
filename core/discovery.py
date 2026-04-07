import re
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import requests

from domain.http import HTTPClient
from utils.logging import get_logger
from core.form_parser import FormParser

logger = get_logger()


class LoginPageDiscovery:
    def __init__(self, client: HTTPClient, language_keywords: Optional[dict] = None):
        self.client = client
        self.language_keywords = language_keywords
        self.form_parser = FormParser()

        if language_keywords and 'login_keywords' in language_keywords:
            self.login_keywords = language_keywords['login_keywords']
        else:
            self.login_keywords = [
                'login',
                'auth',
                'signin',
                'sign-in',
                'sign in',
                'signup',
                'sign-up',
                'sign up',
                'authenticate',
                'administrator',
                'admin',
                'access',
                'account',
                'register',
            ]

    def discover(self, base_url: str, verify: bool = True, verbose: bool = False) -> List[str]:
        try:
            logger.info(f"Discovering login pages from: {base_url}")
            response = self.client.get(base_url)
            if response is None:
                logger.error("No response received from server during discovery")
                return []

            if response.status_code not in [200, 403]:
                try:
                    response.raise_for_status()
                except requests.exceptions.HTTPError:
                    return []

            if not hasattr(response, 'text') or not response.text:
                logger.error("Response has no text content during discovery")
                return []

            login_urls: Set[str] = set()

            is_directory_listing = self._is_directory_listing(response.text)

            login_urls.update(self._find_links_in_html(response.text, base_url, verbose))
            login_urls.update(self._find_links_in_source(response.text, base_url, verbose))

            if is_directory_listing:
                logger.debug(f"Detected directory listing at {base_url}, collecting all links")
                all_links = self._find_all_links_in_html(response.text, base_url, verbose)
                login_urls.update(all_links)

            login_urls.update(self._check_common_paths(base_url, verbose))

            normalized_urls = self._normalize_urls(list(login_urls))

            if verify:
                verified_urls = self._verify_urls(normalized_urls, verbose)
                logger.info(f"Discovered {len(verified_urls)} verified login pages")
                return verified_urls

            logger.info(f"Discovered {len(normalized_urls)} login pages")
            return normalized_urls

        except Exception as e:
            logger.error(f"Error discovering login pages: {e}")
            return []

    def _normalize_urls(self, urls: List[str]) -> List[str]:
        seen_paths = set()
        normalized = []

        for url in urls:
            try:
                parsed = urlparse(url)
                normalized_path = parsed.path.lower()

                path_key = (parsed.netloc, normalized_path)

                if path_key not in seen_paths:
                    seen_paths.add(path_key)
                    normalized.append(url)
                else:
                    logger.debug(f"Skipping duplicate URL (case variation): {url}")
            except Exception as e:
                logger.debug(f"Error normalizing URL {url}: {e}")
                if url not in normalized:
                    normalized.append(url)

        return normalized

    def _find_links_in_html(self, html: str, base_url: str, verbose: bool) -> Set[str]:
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception as e:
            logger.debug(f"Error parsing HTML: {e}")
            return set()

        links = soup.find_all('a', href=True)
        login_urls: Set[str] = set()

        for link in links:
            href = link.get('href', '')
            link_text = link.get_text(strip=True).lower()

            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue

            href_lower = href.lower()
            if any(keyword.lower() in href_lower for keyword in self.login_keywords):
                full_url = urljoin(base_url, href)
                login_urls.add(full_url)
                if verbose:
                    logger.debug(f"Found login link in href: {full_url}")

            if any(keyword.lower() in link_text for keyword in self.login_keywords):
                full_url = urljoin(base_url, href)
                login_urls.add(full_url)
                if verbose:
                    logger.debug(f"Found login link in text: {full_url}")

        return login_urls

    def _find_all_links_in_html(self, html: str, base_url: str, verbose: bool) -> Set[str]:
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception as e:
            logger.debug(f"Error parsing HTML: {e}")
            return set()

        links = soup.find_all('a', href=True)
        all_urls: Set[str] = set()
        parsed_base = urlparse(base_url)
        base_path = parsed_base.path.rstrip('/')

        for link in links:
            href = link.get('href', '')

            if (href.startswith('#') or
                href.startswith('javascript:') or
                href.startswith('mailto:') or
                href in ['../', '..', '/', ''] or
                href.endswith('/') and href.count('/') == 1):
                continue

            full_url = urljoin(base_url, href)
            parsed_link = urlparse(full_url)

            if parsed_link.netloc == parsed_base.netloc:
                link_path = parsed_link.path.rstrip('/')
                if base_path and link_path.startswith(base_path):
                    all_urls.add(full_url)
                    if verbose:
                        logger.debug(f"Found link in directory listing: {full_url}")
                elif not base_path or base_path == '/':
                    if not link_path.startswith('http') and not link_path.startswith('//'):
                        all_urls.add(full_url)
                        if verbose:
                            logger.debug(f"Found link in directory listing: {full_url}")

        return all_urls

    def _is_directory_listing(self, html: str) -> bool:
        html_lower = html.lower()

        indicators = [
            'index of',
            'directory listing',
            'parent directory',
            '<title>index of',
            'name</a>',
            'last modified',
            'size</a>',
            'description</a>'
        ]

        try:
            soup = BeautifulSoup(html, 'html.parser')
            links = soup.find_all('a', href=True)
            relative_links = 0

            for link in links:
                href = link.get('href', '')
                if (href and
                    not href.startswith('#') and
                    not href.startswith('javascript:') and
                    not href.startswith('http') and
                    not href.startswith('mailto:') and
                    href not in ['../', '..', '/']):
                    relative_links += 1
                    if relative_links >= 3:
                        return True
        except Exception:
            pass

        for indicator in indicators:
            if indicator in html_lower:
                return True

        return False

    def _find_links_in_source(self, page_source: str, base_url: str, verbose: bool) -> Set[str]:
        login_urls: Set[str] = set()

        href_patterns = []
        for keyword in self.login_keywords:
            pattern = rf'href=["\']([^"\']*{re.escape(keyword)}[^"\']*)["\']'
            href_patterns.append(pattern)

        for pattern in href_patterns:
            matches = re.finditer(pattern, page_source, re.IGNORECASE)
            for match in matches:
                href_value = match.group(1)
                if href_value.startswith('#') or href_value.startswith('javascript:'):
                    continue
                full_url = urljoin(base_url, href_value)
                login_urls.add(full_url)
                if verbose:
                    logger.debug(f"Found login link in page source: {full_url}")

        return login_urls

    def _check_common_paths(self, base_url: str, verbose: bool) -> Set[str]:
        login_urls: Set[str] = set()
        common_paths = set()

        for keyword in self.login_keywords:
            common_paths.add(f'/{keyword.lower()}')

            if 'administrator' in keyword.lower() or 'admin' in keyword.lower():
                common_paths.add(f'/{keyword.lower()}/login')
                common_paths.add(f'/{keyword.lower()}/login.aspx')

        common_paths.update([
            '/signin', '/sign-in',
            '/authenticate',
        ])

        for path in common_paths:
            test_url = urljoin(base_url, path)
            try:
                test_response = self.client.get(test_url)
                if test_response and hasattr(test_response, 'status_code') and test_response.status_code == 200:
                    if not hasattr(test_response, 'text') or not test_response.text:
                        continue
                    form_data = self.form_parser.parse(test_response.text, test_url)
                    if form_data:
                        login_urls.add(test_url)
                        if verbose:
                            logger.debug(f"Found login page at common path: {test_url}")
            except Exception as e:
                logger.debug(f"Error checking common path {test_url}: {e}")
                pass

        return login_urls

    def _verify_urls(self, urls: List[str], verbose: bool) -> List[str]:
        verified_urls = []
        seen_urls = set()

        for url in urls:
            try:
                verify_response = self.client.get(url)
                if verify_response is None:
                    if verbose:
                        logger.debug(f"No response for {url}")
                    continue

                final_url = verify_response.url if hasattr(verify_response, 'url') else url

                parsed_final = urlparse(final_url)
                final_path_normalized = (parsed_final.netloc, parsed_final.path.lower())

                if final_path_normalized in seen_urls:
                    if verbose:
                        logger.debug(f"Skipping {url} - redirects to already seen URL: {final_url}")
                    continue

                parsed_original = urlparse(url)
                original_path_normalized = (parsed_original.netloc, parsed_original.path.lower())
                seen_urls.add(original_path_normalized)
                seen_urls.add(final_path_normalized)

                if verify_response and hasattr(verify_response, 'status_code') and verify_response.status_code in [200, 403]:
                    if not hasattr(verify_response, 'text') or not verify_response.text:
                        continue
                    form_data = self.form_parser.parse(verify_response.text, final_url)
                    if form_data:
                        if final_url != url:
                            if verbose:
                                logger.debug(f"{url} redirects to {final_url}")
                            verified_urls.append(final_url)
                        else:
                            verified_urls.append(url)
                        if verbose:
                            logger.debug(f"Verified login page: {final_url}")
                    elif verbose:
                        logger.debug(f"Skipping {url} - no login form found")
            except requests.exceptions.RequestException as e:
                if verbose:
                    logger.debug(f"HTTP error verifying {url}: {e}")
                parsed = urlparse(url)
                path_normalized = (parsed.netloc, parsed.path.lower())
                if path_normalized not in seen_urls:
                    seen_urls.add(path_normalized)
            except Exception as e:
                if verbose:
                    logger.debug(f"Unexpected error verifying {url}: {e}")

        return self._normalize_urls(verified_urls)

