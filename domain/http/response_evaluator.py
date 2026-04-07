from typing import Optional, Dict, Any
from requests import Response
from urllib.parse import urljoin


class ResponseEvaluator:
    @staticmethod
    def is_successful(response: Optional[Response]) -> bool:
        if not response:
            return False
        return 200 <= response.status_code < 300

    @staticmethod
    def is_redirect(response: Optional[Response]) -> bool:
        if not response:
            return False
        return 300 <= response.status_code < 400

    @staticmethod
    def is_client_error(response: Optional[Response]) -> bool:
        if not response:
            return False
        return 400 <= response.status_code < 500

    @staticmethod
    def is_server_error(response: Optional[Response]) -> bool:
        if not response:
            return False
        return 500 <= response.status_code < 600

    @staticmethod
    def is_rate_limited(response: Optional[Response]) -> bool:
        if not response:
            return False
        return response.status_code in [403, 429]

    @staticmethod
    def get_redirect_location(response: Optional[Response],
                              base_url: Optional[str] = None) -> Optional[str]:
        if not response or not ResponseEvaluator.is_redirect(response):
            return None

        location = response.headers.get('Location')
        if not location:
            return None

        if base_url:
            return urljoin(base_url, location)
        return location

    @staticmethod
    def get_content_length(response: Optional[Response]) -> int:
        if not response or not hasattr(response, 'text') or not response.text:
            return 0
        return len(response.text)

    @staticmethod
    def has_header(response: Optional[Response], header_name: str) -> bool:
        if not response or not hasattr(response, 'headers'):
            return False
        return header_name.lower() in (h.lower() for h in response.headers)

    @staticmethod
    def get_header(response: Optional[Response], header_name: str) -> Optional[str]:
        if not response or not hasattr(response, 'headers'):
            return None
        return response.headers.get(header_name)

