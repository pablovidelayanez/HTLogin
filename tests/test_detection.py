import pytest
from unittest.mock import Mock
from detection.success import LoginSuccessDetector, DetectionResult, ConfidenceLevel
from detection.signals import Signal, SignalType


class TestLoginSuccessDetector:

    def setup_method(self):
        self.detector = LoginSuccessDetector(
            threshold_low=20,
            threshold_medium=30,
            threshold_high=50
        )

    def test_detector_initialization(self):
        detector = LoginSuccessDetector(
            threshold_low=10,
            threshold_medium=25,
            threshold_high=60
        )
        assert detector.threshold_low == 10
        assert detector.threshold_medium == 25
        assert detector.threshold_high == 60

    def test_determine_level_high(self):
        level = self.detector._determine_level(60)
        assert level == ConfidenceLevel.HIGH

        level = self.detector._determine_level(50)
        assert level == ConfidenceLevel.HIGH

    def test_determine_level_medium(self):
        level = self.detector._determine_level(40)
        assert level == ConfidenceLevel.MEDIUM

        level = self.detector._determine_level(30)
        assert level == ConfidenceLevel.MEDIUM

    def test_determine_level_low(self):
        level = self.detector._determine_level(25)
        assert level == ConfidenceLevel.LOW

        level = self.detector._determine_level(20)
        assert level == ConfidenceLevel.LOW

    def test_determine_level_very_low(self):
        level = self.detector._determine_level(15)
        assert level == ConfidenceLevel.VERY_LOW

        level = self.detector._determine_level(0)
        assert level == ConfidenceLevel.VERY_LOW

    def test_calculate_score_positive_signals(self):
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
            Signal(SignalType.POSITIVE, "session", "session_id", 35, "Session cookie found"),
        ]
        score = self.detector._calculate_score(signals)
        assert score == 75

    def test_calculate_score_negative_signals(self):
        signals = [
            Signal(SignalType.NEGATIVE, "failure", "invalid", 30, "Failure keyword found"),
            Signal(SignalType.NEGATIVE, "error", "error", 20, "Error message detected"),
        ]
        score = self.detector._calculate_score(signals)
        assert score == -50

    def test_calculate_score_mixed_signals(self):
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
            Signal(SignalType.NEGATIVE, "failure", "invalid", 30, "Failure keyword found"),
        ]
        score = self.detector._calculate_score(signals)
        assert score == 10

    def test_calculate_score_empty_signals(self):
        signals = []
        score = self.detector._calculate_score(signals)
        assert score == 0

    def test_should_recommend_manual_verification_medium_range(self):
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
        ]

        should_recommend = self.detector._should_recommend_manual_verification(40, signals)
        assert should_recommend is True

    def test_should_recommend_manual_verification_mixed_signals(self):
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
            Signal(SignalType.NEGATIVE, "failure", "invalid", 30, "Failure keyword found"),
        ]
        should_recommend = self.detector._should_recommend_manual_verification(10, signals)
        assert should_recommend is True

    def test_should_recommend_manual_verification_low_with_positive(self):
        signals = [
            Signal(SignalType.POSITIVE, "session", "session_id", 35, "Session cookie found"),
        ]
        should_recommend = self.detector._should_recommend_manual_verification(15, signals)
        assert should_recommend is True

    def test_should_recommend_manual_verification_high_confidence(self):
        signals = [
            Signal(SignalType.POSITIVE, "redirect", "http://example.com", 40, "Redirect detected"),
            Signal(SignalType.POSITIVE, "session", "session_id", 35, "Session cookie found"),
        ]
        should_recommend = self.detector._should_recommend_manual_verification(75, signals)
        assert should_recommend is False

    def test_detect_successful_login(self):

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

        signals = [
            Signal(SignalType.NEGATIVE, "error1", "error", 200, "Multiple errors"),
        ]
        score = self.detector._calculate_score(signals)

        assert score < 0


        signals = [
            Signal(SignalType.POSITIVE, "redirect", "url", 200, "Strong redirect"),
        ]
        score = self.detector._calculate_score(signals)
        assert score > 100


        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.cookies = {}
        response.text = 'test'
        response.url = 'http://example.com'


        result = self.detector.detect(
            response=response,
            original_url='http://example.com',
            original_content_length=100,
            success_keywords=[],
            failure_keywords=[]
        )

        assert 0 <= result.confidence_score <= 100
