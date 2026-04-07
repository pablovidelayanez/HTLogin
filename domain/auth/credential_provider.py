from typing import Protocol, List, Optional


class CredentialProviderProtocol(Protocol):
    def get_credentials(self) -> List[str]:
        ...

    def is_empty(self) -> bool:
        ...


class CredentialProvider:
    def __init__(self, credentials: List[str]):
        self._credentials = credentials

    def get_credentials(self) -> List[str]:
        return self._credentials.copy()

    def is_empty(self) -> bool:
        return len(self._credentials) == 0

    def count(self) -> int:
        return len(self._credentials)

