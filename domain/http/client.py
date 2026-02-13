from typing import Protocol, Optional, Dict, Any
from requests import Response


class HTTPClientProtocol(Protocol):
    def get(self, url: str, **kwargs) -> Optional[Response]:
        ...
    
    def post(self, url: str, **kwargs) -> Optional[Response]:
        ...
    
    def request(self, method: str, url: str, **kwargs) -> Optional[Response]:
        ...

