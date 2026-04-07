import pytest
from bs4 import BeautifulSoup
from core.form_parser import FormParser, FormData


class TestFormParser:

    def setup_method(self):
        self.parser = FormParser()

    def test_parse_simple_form(self):
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



    def test_multiple_forms_first_with_login(self):
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

        assert form_data.captcha_input is not None
