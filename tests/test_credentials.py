import pytest
import tempfile
import os
from domain.auth.credential_provider import CredentialProvider
from domain.auth.default_credentials import DefaultCredentialProvider
from domain.auth.custom_credentials import CustomCredentialProvider


class TestCredentialProvider:
    """Test cases for CredentialProvider base class"""
    
    def test_credential_provider_initialization(self):
        """Test CredentialProvider initialization"""
        credentials = ["admin:admin", "user:password"]
        provider = CredentialProvider(credentials)
        assert provider.count() == 2
    
    def test_get_credentials(self):
        """Test getting credentials list"""
        credentials = ["admin:admin", "user:password", "test:test123"]
        provider = CredentialProvider(credentials)
        retrieved = provider.get_credentials()
        
        assert len(retrieved) == 3
        assert "admin:admin" in retrieved
        assert "user:password" in retrieved
        assert retrieved == credentials
    
    def test_get_credentials_returns_copy(self):
        """Test that get_credentials returns a copy, not reference"""
        credentials = ["admin:admin"]
        provider = CredentialProvider(credentials)
        retrieved = provider.get_credentials()
        
        # Modifying retrieved should not affect original
        retrieved.append("new:credential")
        assert provider.count() == 1
        assert len(retrieved) == 2
    
    def test_is_empty_true(self):
        """Test is_empty returns True for empty credentials"""
        provider = CredentialProvider([])
        assert provider.is_empty() is True
    
    def test_is_empty_false(self):
        """Test is_empty returns False for non-empty credentials"""
        provider = CredentialProvider(["admin:admin"])
        assert provider.is_empty() is False
    
    def test_count(self):
        """Test credential count"""
        credentials = ["admin:admin", "user:password", "test:test"]
        provider = CredentialProvider(credentials)
        assert provider.count() == 3


class TestDefaultCredentialProvider:
    """Test cases for DefaultCredentialProvider class"""
    
    def test_default_credential_provider_initialization(self):
        """Test DefaultCredentialProvider initialization"""
        provider = DefaultCredentialProvider()
        assert not provider.is_empty()
        assert provider.count() > 0
    
    def test_default_credentials_content(self):
        """Test that default credentials contain expected values"""
        provider = DefaultCredentialProvider()
        credentials = provider.get_credentials()
        
        assert "admin:admin" in credentials
        assert "admin:password" in credentials
        assert "administrator:password" in credentials
    
    def test_default_credentials_format(self):
        """Test that all default credentials are in username:password format"""
        provider = DefaultCredentialProvider()
        credentials = provider.get_credentials()
        
        for cred in credentials:
            assert ':' in cred, f"Credential '{cred}' should contain ':' separator"
            parts = cred.split(':', 1)
            assert len(parts) == 2, f"Credential '{cred}' should have exactly one ':' separator"


class TestCustomCredentialProvider:
    """Test cases for CustomCredentialProvider class"""
    
    def test_custom_credential_provider_from_file(self):
        """Test loading credentials from file"""
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
        """Test loading credentials from empty file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            temp_path = f.name
        
        try:
            provider = CustomCredentialProvider(temp_path)
            assert provider.is_empty()
            assert provider.count() == 0
        finally:
            os.unlink(temp_path)
    
    def test_custom_credential_provider_file_not_found(self):
        """Test CustomCredentialProvider raises error for missing file"""
        with pytest.raises(FileNotFoundError):
            CustomCredentialProvider("nonexistent_file.txt")
    
    def test_custom_credential_provider_skips_empty_lines(self):
        """Test that empty lines in credential file are skipped"""
        credentials_content = "admin:admin\n\nuser:password\n  \ntest:test123\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(credentials_content)
            temp_path = f.name
        
        try:
            provider = CustomCredentialProvider(temp_path)
            credentials = provider.get_credentials()
            
            # Should only have 3 credentials, empty lines skipped
            assert len(credentials) == 3
            assert "admin:admin" in credentials
            assert "user:password" in credentials
            assert "test:test123" in credentials
        finally:
            os.unlink(temp_path)
    
    def test_custom_credential_provider_strips_whitespace(self):
        """Test that whitespace is stripped from credentials"""
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
            # Ensure no leading/trailing whitespace
            for cred in credentials:
                assert cred == cred.strip()
        finally:
            os.unlink(temp_path)
    
    def test_custom_credential_provider_utf8_encoding(self):
        """Test loading credentials with UTF-8 characters"""
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
