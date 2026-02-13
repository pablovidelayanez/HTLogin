import pytest
from unittest.mock import Mock
from detection.success import LoginSuccessDetector, DetectionResult, ConfidenceLevel
from detection.signals import Signal, SignalType


class TestLoginSuccessDetector:
    """Test cases for LoginSuccessDetector class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.detector = LoginSuccessDetector(
            threshold_low=20,
            threshold_medium=30,
            threshold_high=50
        )
    
    def test_detector_initialization(self):
        """Test detector initialization with custom thresholds"""
        detector = LoginSuccessDetector(
            threshold_low=10,
            threshold_medium=25,
            threshold_high=60
        )
        assert detector.threshold_low == 10
        assert detector.threshold_medium == 25
        assert detector.threshold_high == 60
    
    def test_determine_level_high(self):
        """Test confidence level determination for high score"""
        level = self.detector._determine_level(60)
        assert level == ConfidenceLevel.HIGH
        
        level = self.detector._determine_level(50)
        assert level == ConfidenceLevel.HIGH
    
    def test_determine_level_medium(self):
        """Test confidence level determination for medium score"""
        level = self.detector._determine_level(40)
        assert level == ConfidenceLevel.MEDIUM
        
        level = self.detector._determine_level(30)
        assert level == ConfidenceLevel.MEDIUM
    
    def test_determine_level_low(self):
        """Test confidence level determination for low score"""
        level = self.detector._determine_level(25)
        assert level == ConfidenceLevel.LOW
        
        level = self.detector._determine_level(20)
        assert level == ConfidenceLevel.LOW
    
    def test_determine_level_very_low(self):
        """Test confidence level determination for very low score"""
        level = self.detector._determine_level(15)
        assert level == ConfidenceLevel.VERY_LOW
        
        level = self.detector._determine_level(0)
        assert level == ConfidenceLevel.VERY_LOW
    
    def test_calculate_score_positive_signals(self):
        """Test score calculation with positive signals"""
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
            Signal(SignalType.POSITIVE, "session", "session_id", 35, "Session cookie found"),
        ]
        score = self.detector._calculate_score(signals)
        assert score == 75
    
    def test_calculate_score_negative_signals(self):
        """Test score calculation with negative signals"""
        signals = [
            Signal(SignalType.NEGATIVE, "failure", "invalid", 30, "Failure keyword found"),
            Signal(SignalType.NEGATIVE, "error", "error", 20, "Error message detected"),
        ]
        score = self.detector._calculate_score(signals)
        assert score == -50
    
    def test_calculate_score_mixed_signals(self):
        """Test score calculation with mixed positive and negative signals"""
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
            Signal(SignalType.NEGATIVE, "failure", "invalid", 30, "Failure keyword found"),
        ]
        score = self.detector._calculate_score(signals)
        assert score == 10
    
    def test_calculate_score_empty_signals(self):
        """Test score calculation with no signals"""
        signals = []
        score = self.detector._calculate_score(signals)
        assert score == 0
    
    def test_should_recommend_manual_verification_medium_range(self):
        """Test manual verification recommendation for medium confidence"""
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
        ]
        # Score of 40 is between medium (30) and high (50)
        should_recommend = self.detector._should_recommend_manual_verification(40, signals)
        assert should_recommend is True
    
    def test_should_recommend_manual_verification_mixed_signals(self):
        """Test manual verification recommendation with mixed signals"""
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
            Signal(SignalType.NEGATIVE, "failure", "invalid", 30, "Failure keyword found"),
        ]
        should_recommend = self.detector._should_recommend_manual_verification(10, signals)
        assert should_recommend is True
    
    def test_should_recommend_manual_verification_low_with_positive(self):
        """Test manual verification recommendation for low score with positive signals"""
        signals = [
            Signal(SignalType.POSITIVE, "session", "session_id", 35, "Session cookie found"),
        ]
        should_recommend = self.detector._should_recommend_manual_verification(15, signals)
        assert should_recommend is True
    
    def test_should_recommend_manual_verification_high_confidence(self):
        """Test no manual verification recommendation for high confidence"""
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
            Signal(SignalType.POSITIVE, "session", "session_id", 35, "Session cookie found"),
        ]
        should_recommend = self.detector._should_recommend_manual_verification(75, signals)
        assert should_recommend is False
    
    def test_detect_successful_login(self):
        """Test detection of successful login"""
        # Mock response with redirect
        response = Mock()
        response.status_code = 302
        response.headers = {'Location': 'http://example.com/dashboard'}
        response.cookies = {'session_id': 'abc123'}
        response.text = 'Welcome to dashboard'
        response.url = 'http://example.com/login'
        
        result = self.detector.detect(
            response=response,
            original_url='http://example.com/login',
            original_content_length=1000,
            success_keywords=['welcome', 'dashboard'],
            failure_keywords=['invalid', 'error']
        )
        
        assert isinstance(result, DetectionResult)
        assert result.is_successful is True
        assert result.confidence_score >= self.detector.threshold_medium
    
    def test_detect_failed_login(self):
        """Test detection of failed login"""
        # Mock response with error message
        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.cookies = {}
        response.text = 'Invalid username or password. Please try again.'
        response.url = 'http://example.com/login'
        
        result = self.detector.detect(
            response=response,
            original_url='http://example.com/login',
            original_content_length=500,
            success_keywords=['welcome', 'dashboard'],
            failure_keywords=['invalid', 'error']
        )
        
        assert isinstance(result, DetectionResult)
        assert result.is_successful is False
        assert result.confidence_score < self.detector.threshold_medium
    
    def test_detect_score_clamping(self):
        """Test that confidence score is clamped between 0 and 100"""
        # Create signals that would result in negative or >100 score
        signals = [
            Signal(SignalType.NEGATIVE, "error1", "error", 200, "Multiple errors"),
        ]
        score = self.detector._calculate_score(signals)
        # Score should be clamped in detect method
        assert score < 0  # Before clamping
        
        # Test with very high positive signals
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "url", 200, "Strong redirect"),
        ]
        score = self.detector._calculate_score(signals)
        assert score > 100  # Before clamping
        
        # The detect method should clamp these values
        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.cookies = {}
        response.text = 'test'
        response.url = 'http://example.com'
        
        # This will use SignalCollector which handles clamping
        result = self.detector.detect(
            response=response,
            original_url='http://example.com',
            original_content_length=100,
            success_keywords=[],
            failure_keywords=[]
        )
        
        assert 0 <= result.confidence_score <= 100
