from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass

from .signals import SignalCollector, SignalType, Signal


class ConfidenceLevel(Enum):
    VERY_LOW = "Very Low"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class DetectionResult:
    is_successful: bool
    confidence_score: int
    confidence_level: ConfidenceLevel
    signals: List[Signal]
    details: Dict
    manual_verification_recommended: bool = False


class LoginSuccessDetector:
    def __init__(self, 
                 threshold_low: int = 20,
                 threshold_medium: int = 30,
                 threshold_high: int = 50):
        self.threshold_low = threshold_low
        self.threshold_medium = threshold_medium
        self.threshold_high = threshold_high
    
    def detect(self, response, original_url: str, original_content_length: int,
               success_keywords: List[str], failure_keywords: List[str],
               client=None, language_keywords: Optional[Dict[str, List[str]]] = None) -> DetectionResult:
        error_indicators = None
        login_indicators = None
        generic_indicators = None
        specific_indicators = None
        
        if language_keywords:
            error_indicators = language_keywords.get('error_indicators')
            login_indicators = language_keywords.get('login_indicators')
            generic_indicators = language_keywords.get('generic_indicators')
            specific_indicators = language_keywords.get('specific_indicators')
        
        collector = SignalCollector(
            response, original_url, original_content_length,
            success_keywords, failure_keywords, client,
            error_indicators=error_indicators,
            login_indicators=login_indicators,
            generic_indicators=generic_indicators,
            specific_indicators=specific_indicators
        )
        signals = collector.collect_all()
        
        confidence_score = self._calculate_score(signals)
        confidence_score = max(0, min(100, confidence_score))
        confidence_level = self._determine_level(confidence_score)
        is_successful = confidence_score >= self.threshold_high
        
        manual_verification = self._should_recommend_manual_verification(
            confidence_score, signals
        )
        
        status_code = response.status_code if response and hasattr(response, 'status_code') else 0
        details = {
            "status_code": status_code,
            "indicators": [s.description for s in signals],
            "positive_signals": len([s for s in signals if s.signal_type == SignalType.POSITIVE]),
            "negative_signals": len([s for s in signals if s.signal_type == SignalType.NEGATIVE]),
        }
        
        for signal in signals:
            if signal.name == "302_redirect_to_non_login":
                details["redirect_url"] = signal.value
            elif signal.name == "session_cookie":
                details["session_cookie_name"] = signal.value
        
        return DetectionResult(
            is_successful=is_successful,
            confidence_score=confidence_score,
            confidence_level=confidence_level,
            signals=signals,
            details=details,
            manual_verification_recommended=manual_verification
        )
    
    def _calculate_score(self, signals: List[Signal]) -> int:
        score = 0
        
        for signal in signals:
            if signal.signal_type == SignalType.POSITIVE:
                score += signal.confidence
            elif signal.signal_type == SignalType.NEGATIVE:
                score -= signal.confidence
        
        return score
    
    def _determine_level(self, score: int) -> ConfidenceLevel:
        if score >= self.threshold_high:
            return ConfidenceLevel.HIGH
        elif score >= self.threshold_medium:
            return ConfidenceLevel.MEDIUM
        elif score >= self.threshold_low:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def _should_recommend_manual_verification(self, score: int, 
                                             signals: List[Signal]) -> bool:
        if self.threshold_medium <= score < self.threshold_high:
            return True
        
        positive_count = len([s for s in signals if s.signal_type == SignalType.POSITIVE])
        negative_count = len([s for s in signals if s.signal_type == SignalType.NEGATIVE])
        
        if positive_count > 0 and negative_count > 0:
            return True
        
        if score < self.threshold_medium and positive_count > 0:
            return True
        
        return False

