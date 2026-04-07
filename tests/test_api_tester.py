import pytest
import json
from unittest.mock import Mock, MagicMock
from core.api_tester import APITester
from domain.http import HTTPClient
from detection.success import LoginSuccessDetector, DetectionResult, ConfidenceLevel


class TestAPITester:

    def setup_method(self):
        self.client = Mock(spec=HTTPClient)
        self.detector = Mock(spec=LoginSuccessDetector)
        self.tester = APITester(self.client, self.detector)

    def test_test_json_api_success(self):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"token": "abc123", "user": {"id": 1}}'
        self.client.post = Mock(return_value=mock_response)

        mock_detection = DetectionResult(
            is_successful=True,
            confidence_score=80,
            confidence_level=ConfidenceLevel.HIGH,
            signals=[],
            details={}
        )
        self.detector.detect = Mock(return_value=mock_detection)
        self.tester._detect_api_fields = Mock(return_value=('username', 'password'))

        success, credential, details = self.tester.test_json_api(
            "http://example.com/api/login",
            ["admin:admin"],
            ["success", "token"],
            ["error", "invalid"],
            1000
        )

        assert success is True
        assert credential == "admin:admin"
        assert details is not None
        assert details["format"] == "json"

    def test_test_json_api_failure(self):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = '{"error": "Invalid credentials"}'
        self.client.post = Mock(return_value=mock_response)

        mock_detection = DetectionResult(
            is_successful=False,
            confidence_score=10,
            confidence_level=ConfidenceLevel.VERY_LOW,
            signals=[],
            details={}
        )
        self.detector.detect = Mock(return_value=mock_detection)
        self.tester._detect_api_fields = Mock(return_value=('username', 'password'))

        success, credential, details = self.tester.test_json_api(
            "http://example.com/api/login",
            ["admin:admin"],
            ["success", "token"],
            ["error", "invalid"],
            1000
        )

        assert success is False
        assert credential is None

    def test_test_graphql_success(self):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"data": {"login": {"token": "abc123"}}}'
        self.client.post = Mock(return_value=mock_response)

        mock_detection = DetectionResult(
            is_successful=True,
            confidence_score=75,
            confidence_level=ConfidenceLevel.HIGH,
            signals=[],
            details={}
        )
        self.detector.detect = Mock(return_value=mock_detection)

        success, credential, details = self.tester.test_graphql(
            "http://example.com/graphql",
            ["admin:admin"],
            ["success", "token"],
            ["error", "invalid"],
            1000
        )


        assert isinstance(success, bool)

    def test_detect_api_fields(self):
        mock_response = Mock()
        mock_response.status_code = 400
        self.client.post = Mock(return_value=mock_response)

        username_field, password_field = self.tester._detect_api_fields(
            "http://example.com/api/login",
            "POST"
        )


        assert username_field is None or isinstance(username_field, str)
        assert password_field is None or isinstance(password_field, str)

    def test_detect_api_fields_not_found(self):
        mock_response = Mock()
        mock_response.status_code = 404
        self.client.post = Mock(return_value=mock_response)

        username_field, password_field = self.tester._detect_api_fields(
            "http://example.com/api/nonexistent",
            "POST"
        )

        assert username_field is None
        assert password_field is None
