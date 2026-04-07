from typing import List

from domain.auth.credential_provider import CredentialProvider


class DefaultCredentialProvider(CredentialProvider):
    DEFAULT_CREDENTIALS = [
        "admin:admin",
        "admin:password",
        "admin:password1",
        "admin:password123",
        "admin:passw0rd",
        "admin:",
        "admin:12345",
        "administrator:password",
        "administrator:password1",
        "administrator:password123",
        "administrator:passw0rd",
        "administrator:",
        "administrator:12345"
    ]

    def __init__(self):
        super().__init__(self.DEFAULT_CREDENTIALS)

