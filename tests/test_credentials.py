import pytest
import tempfile
import os
from domain.auth.credential_provider import CredentialProvider
from domain.auth.default_credentials import DefaultCredentialProvider
from domain.auth.custom_credentials import CustomCredentialProvider


class TestCredentialProvider:

    def test_credential_provider_initialization(self):
        credentials = ["admin:admin", "user:password"]
        provider = CredentialProvider(credentials)
        assert provider.count() == 2

    def test_get_credentials(self):
        credentials = ["admin:admin", "user:password", "test:test123"]
        provider = CredentialProvider(credentials)
        retrieved = provider.get_credentials()

        assert len(retrieved) == 3
        assert "admin:admin" in retrieved
        assert "user:password" in retrieved
        assert retrieved == credentials

    def test_get_credentials_returns_copy(self):
        credentials = ["admin:admin"]
        provider = CredentialProvider(credentials)
        retrieved = provider.get_credentials()


        retrieved.append("new:credential")
        assert provider.count() == 1
        assert len(retrieved) == 2

    def test_is_empty_true(self):
        provider = CredentialProvider([])
        assert provider.is_empty() is True

    def test_is_empty_false(self):
        provider = CredentialProvider(["admin:admin"])
        assert provider.is_empty() is False

    def test_count(self):
        credentials = ["admin:admin", "user:password", "test:test"]
        provider = CredentialProvider(credentials)
        assert provider.count() == 3


class TestDefaultCredentialProvider:

    def test_default_credential_provider_initialization(self):
        provider = DefaultCredentialProvider()
        assert not provider.is_empty()
        assert provider.count() > 0

    def test_default_credentials_content(self):
        provider = DefaultCredentialProvider()
        credentials = provider.get_credentials()

        assert "admin:admin" in credentials
        assert "admin:password" in credentials
        assert "administrator:password" in credentials

    def test_default_credentials_format(self):
        provider = DefaultCredentialProvider()
        credentials = provider.get_credentials()

        for cred in credentials:
            assert ':' in cred, f"Credential '{cred}' should contain ':' separator"
            parts = cred.split(':', 1)
            assert len(parts) == 2, f"Credential '{cred}' should have exactly one ':' separator"


class TestCustomCredentialProvider:

    def test_custom_credential_provider_from_file(self):
        credentials_content = "admin:admin\nuser:password\ntest:test123\n"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(credentials_content)
            temp_path = f.name

        try:
            provider = CustomCredentialProvider(temp_path)
            credentials = provider.get_credentials()

            assert len(credentials) == 3
            assert "admin:admin" in credentials
            assert "user:password" in credentials
            assert "test:test123" in credentials
        finally:
            os.unlink(temp_path)

    def test_custom_credential_provider_empty_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            temp_path = f.name

        try:
            provider = CustomCredentialProvider(temp_path)
            assert provider.is_empty()
            assert provider.count() == 0
        finally:
            os.unlink(temp_path)

    def test_custom_credential_provider_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            CustomCredentialProvider("nonexistent_file.txt")

    def test_custom_credential_provider_skips_empty_lines(self):
        credentials_content = "admin:admin\n\nuser:password\n  \ntest:test123\n"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(credentials_content)
            temp_path = f.name

        try:
            provider = CustomCredentialProvider(temp_path)
            credentials = provider.get_credentials()


            assert len(credentials) == 3
            assert "admin:admin" in credentials
            assert "user:password" in credentials
            assert "test:test123" in credentials
        finally:
            os.unlink(temp_path)

    def test_custom_credential_provider_strips_whitespace(self):
        credentials_content = "  admin:admin  \n  user:password  \n"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(credentials_content)
            temp_path = f.name

        try:
            provider = CustomCredentialProvider(temp_path)
            credentials = provider.get_credentials()

            assert len(credentials) == 2
            assert "admin:admin" in credentials
            assert "user:password" in credentials

            for cred in credentials:
                assert cred == cred.strip()
        finally:
            os.unlink(temp_path)

    def test_custom_credential_provider_utf8_encoding(self):
        credentials_content = "admin:admin\nüser:şifre\ntest:пароль\n"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(credentials_content)
            temp_path = f.name

        try:
            provider = CustomCredentialProvider(temp_path)
            credentials = provider.get_credentials()

            assert len(credentials) == 3
            assert "admin:admin" in credentials
            assert "üser:şifre" in credentials
            assert "test:пароль" in credentials
        finally:
            os.unlink(temp_path)
