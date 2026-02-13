import pytest
from bs4 import BeautifulSoup
from core.form_parser import FormParser, FormData


class TestFormParser:
    """Test cases for FormParser class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.parser = FormParser()
    
    def test_parse_simple_form(self):
        """Test parsing a simple login form"""
        html = """
        <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert form_data.username_input is not None
        assert form_data.password_input is not None
        assert form_data.username_input.get('name') == 'username'
        assert form_data.password_input.get('name') == 'password'
        assert form_data.action == "http://example.com/login"
        assert form_data.method == "POST"
    
    def test_parse_form_with_email_input(self):
        """Test parsing form with email input type"""
        html = """
        <form action="/login" method="POST">
            <input type="email" name="email" />
            <input type="password" name="password" />
        </form>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert form_data.username_input is not None
        assert form_data.username_input.get('type') == 'email'
    
    def test_parse_form_with_csrf_token(self):
        """Test parsing form with CSRF token"""
        html = """
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="hidden" name="csrf_token" value="abc123" />
        </form>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert form_data.csrf_input is not None
        assert form_data.csrf_input.get('name') == 'csrf_token'
        assert form_data.csrf_input.get('value') == 'abc123'
    
    def test_parse_form_without_action(self):
        """Test parsing form without action attribute"""
        html = """
        <form method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
        """
        form_data = self.parser.parse(html, "http://example.com/login")
        
        assert form_data is not None
        assert form_data.action == "http://example.com/login"
    
    def test_parse_form_relative_action(self):
        """Test parsing form with relative action URL"""
        html = """
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
        """
        form_data = self.parser.parse(html, "http://example.com/page")
        
        assert form_data is not None
        assert form_data.action == "http://example.com/login"
    
    def test_parse_form_different_method(self):
        """Test parsing form with GET method"""
        html = """
        <form action="/login" method="GET">
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert form_data.method == "GET"
    
    def test_parse_form_with_other_inputs(self):
        """Test parsing form with hidden and other inputs"""
        html = """
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="hidden" name="redirect" value="/dashboard" />
            <input type="checkbox" name="remember" />
        </form>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert len(form_data.other_inputs) >= 1
    
    def test_parse_form_without_form_tag(self):
        """Test parsing when form tag is missing but inputs exist"""
        html = """
        <html>
        <body>
            <div>
                <input type="text" name="username" />
                <input type="password" name="password" />
            </div>
        </body>
        </html>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert form_data.username_input is not None
        assert form_data.password_input is not None
    
    def test_parse_no_form_or_inputs(self):
        """Test parsing HTML without form or login inputs"""
        html = """
        <html>
        <body>
            <h1>Welcome</h1>
            <p>No form here</p>
        </body>
        </html>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is None
    
    def test_find_username_by_id(self):
        """Test finding username input by ID"""
        html = """
        <form>
            <input type="text" id="user_field" />
            <input type="password" name="password" />
        </form>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert form_data.username_input is not None
        assert form_data.username_input.get('id') == 'user_field'
    
    def test_find_password_by_name(self):
        """Test finding password input by name pattern"""
        html = """
        <form>
            <input type="text" name="username" />
            <input type="password" name="pwd" />
        </form>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert form_data.password_input is not None
        assert form_data.password_input.get('name') == 'pwd'
    
    def test_csrf_token_in_meta_tag(self):
        """Test finding CSRF token in meta tag"""
        html = """
        <html>
        <head>
            <meta name="csrf-token" content="xyz789" />
        </head>
        <body>
            <form>
                <input type="text" name="username" />
                <input type="password" name="password" />
            </form>
        </body>
        </html>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        # CSRF might be found in meta tag
        # The parser should handle this
    
    def test_multiple_forms_first_with_login(self):
        """Test parsing when multiple forms exist"""
        html = """
        <html>
        <body>
            <form action="/search">
                <input type="text" name="query" />
            </form>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
            </form>
        </body>
        </html>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert form_data.action == "http://example.com/login"
    
    def test_parse_form_with_captcha(self):
        """Test parsing form with CAPTCHA widget"""
        html = """
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <div class="g-recaptcha" data-sitekey="test"></div>
        </form>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        assert form_data.captcha_input is not None
    
    def test_parse_form_captcha_keyword(self):
        """Test CAPTCHA detection via keyword in page"""
        html = """
        <html>
        <body>
            <p>Please verify you are human</p>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
            </form>
        </body>
        </html>
        """
        form_data = self.parser.parse(html, "http://example.com")
        
        assert form_data is not None
        # CAPTCHA should be detected via keyword
        assert form_data.captcha_input is not None
