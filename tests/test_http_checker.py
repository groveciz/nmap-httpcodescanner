"""
Unit tests for nmap-httpcodescanner
"""
import pytest
from unittest.mock import patch, Mock
import sys
import os

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.http_checker import (
    check_status,
    check_default_page,
    normalize_error,
    DEFAULT_PAGE_PATTERNS
)


class TestNormalizeError:
    """Tests for error message normalization."""
    
    def test_connection_reset(self):
        assert normalize_error("ConnectionResetError: reset") == "Connection Reset"
        assert normalize_error("RemoteDisconnected error") == "Connection Reset"
        assert normalize_error("Failed to establish connection") == "Connection Reset"
    
    def test_certificate_errors(self):
        assert normalize_error("DH key too weak") == "invalid certificate"
        assert normalize_error("self signed certificate") == "invalid certificate"
        assert normalize_error("certificate has expired") == "expired certificate"
    
    def test_timeout(self):
        assert normalize_error("Connection timeout") == "timeout"
    
    def test_local_error(self):
        assert normalize_error("unable to get local issuer") == "manual check required"
    
    def test_passthrough(self):
        assert normalize_error("200") == "200"
        assert normalize_error("404") == "404"
    
    def test_none(self):
        assert normalize_error(None) is None


class TestDefaultPagePatterns:
    """Tests for default page detection."""
    
    def test_patterns_exist(self):
        assert isinstance(DEFAULT_PAGE_PATTERNS, list)
        assert len(DEFAULT_PAGE_PATTERNS) > 10
    
    def test_common_patterns_included(self):
        assert "welcome to nginx" in DEFAULT_PAGE_PATTERNS
        assert "apache2 ubuntu default page" in DEFAULT_PAGE_PATTERNS
        assert "coming soon" in DEFAULT_PAGE_PATTERNS
        assert "under construction" in DEFAULT_PAGE_PATTERNS


class TestCheckDefaultPage:
    """Tests for check_default_page function."""
    
    @patch('app.http_checker.requests.get')
    def test_nginx_default(self, mock_get):
        mock_response = Mock()
        mock_response.text = "<html><head><title>Welcome to nginx!</title></head></html>"
        mock_get.return_value = mock_response
        
        result = check_default_page("http://example.com")
        assert result == "True"
    
    @patch('app.http_checker.requests.get')
    def test_real_website(self, mock_get):
        mock_response = Mock()
        mock_response.text = "<html><head><title>Coral Travel - Book Your Vacation</title></head></html>"
        mock_get.return_value = mock_response
        
        result = check_default_page("http://coraltravel.com")
        assert result == "False"
    
    @patch('app.http_checker.requests.get')
    def test_no_title(self, mock_get):
        mock_response = Mock()
        mock_response.text = "<html><body>No title here</body></html>"
        mock_get.return_value = mock_response
        
        result = check_default_page("http://example.com")
        assert result == "True"
    
    @patch('app.http_checker.requests.get')
    def test_exception(self, mock_get):
        mock_get.side_effect = Exception("Connection failed")
        
        result = check_default_page("http://example.com")
        assert result is None


class TestCheckStatus:
    """Tests for check_status function."""
    
    @patch('app.http_checker.requests.get')
    def test_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = check_status("http://example.com")
        assert result == "200"
    
    @patch('app.http_checker.requests.get')
    def test_404(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = check_status("http://example.com/notfound")
        assert result == "404"
    
    @patch('app.http_checker.requests.get')
    def test_timeout(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.Timeout("Timed out")
        
        result = check_status("http://slow-server.com")
        assert "Timed out" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
