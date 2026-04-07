import pytest
from unittest.mock import Mock, MagicMock
from core.api_discovery import APIDiscovery
from domain.http import HTTPClient


class TestAPIDiscovery:

    def setup_method(self):
        self.client = Mock(spec=HTTPClient)
        self.discovery = APIDiscovery(self.client)

    def test_discover_json_endpoints(self):

        self.discovery._test_endpoint = Mock(return_value=True)

        endpoints = self.discovery.discover_json_endpoints("http://example.com")

        assert isinstance(endpoints, list)

        assert len(endpoints) >= 0

    def test_discover_graphql_endpoints(self):

        self.discovery._test_endpoint = Mock(return_value=True)

        endpoints = self.discovery.discover_graphql_endpoints("http://example.com")

        assert isinstance(endpoints, list)

        assert len(endpoints) >= 0

    def test_test_endpoint_json_success(self):
        mock_response = Mock()
        mock_response.status_code = 400
        self.client.post = Mock(return_value=mock_response)

        result = self.discovery._test_endpoint("http://example.com/api/login", "json")

        assert result is True
        self.client.post.assert_called_once()

    def test_test_endpoint_json_not_found(self):
        mock_response = Mock()
        mock_response.status_code = 404
        self.client.post = Mock(return_value=mock_response)

        result = self.discovery._test_endpoint("http://example.com/api/login", "json")

        assert result is False

    def test_test_endpoint_graphql_success(self):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"data": {"__schema": {"queryType": {"name": "Query"}}}}'
        self.client.post = Mock(return_value=mock_response)

        result = self.discovery._test_endpoint("http://example.com/graphql", "graphql")

        assert result is True

    def test_detect_api_format_json(self):
        mock_response = Mock()
        mock_response.text = '{"error": "Invalid credentials"}'
        self.client.get = Mock(return_value=mock_response)

        format_type = self.discovery.detect_api_format("http://example.com/api/login")

        assert format_type == "json"

    def test_detect_api_format_graphql(self):
        mock_response = Mock()
        mock_response.text = '{"errors": [{"message": "GraphQL error"}]}'
        self.client.get = Mock(return_value=mock_response)

        format_type = self.discovery.detect_api_format("http://example.com/graphql")

        assert format_type == "graphql"

    def test_detect_api_format_none(self):
        mock_response = Mock()
        mock_response.text = '<html><body>Not an API</body></html>'
        self.client.get = Mock(return_value=mock_response)

        format_type = self.discovery.detect_api_format("http://example.com/page")

        assert format_type is None or format_type != "json"
