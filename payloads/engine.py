import urllib.parse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class EncodingType(Enum):
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    UNICODE = "unicode"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PayloadMetadata:
    payload: str
    injection_type: str
    risk_level: RiskLevel = RiskLevel.MEDIUM
    backend_hint: Optional[str] = None
    encoding: EncodingType = EncodingType.NONE
    description: Optional[str] = None


class PayloadEngine:
    def __init__(self):
        self.payloads: Dict[str, List[PayloadMetadata]] = {}
    
    def add_payload(self, injection_type: str, payload: str, 
                   risk_level: RiskLevel = RiskLevel.MEDIUM,
                   backend_hint: Optional[str] = None,
                   description: Optional[str] = None) -> None:
        if injection_type not in self.payloads:
            self.payloads[injection_type] = []
        
        metadata = PayloadMetadata(
            payload=payload,
            injection_type=injection_type,
            risk_level=risk_level,
            backend_hint=backend_hint,
            description=description
        )
        self.payloads[injection_type].append(metadata)
    
    def encode_payload(self, payload: str, encoding: EncodingType) -> str:
        if encoding == EncodingType.NONE:
            return payload
        elif encoding == EncodingType.URL:
            return urllib.parse.quote(payload)
        elif encoding == EncodingType.DOUBLE_URL:
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == EncodingType.UNICODE:
            return payload.encode('unicode_escape').decode('ascii')
        else:
            return payload
    
    def get_payloads(self, injection_type: Optional[str] = None,
                     risk_level: Optional[RiskLevel] = None,
                     encoding: Optional[EncodingType] = None) -> List[PayloadMetadata]:
        results = []
        
        types_to_check = [injection_type] if injection_type else self.payloads.keys()
        
        for inj_type in types_to_check:
            if inj_type not in self.payloads:
                continue
            
            for metadata in self.payloads[inj_type]:
                if risk_level and metadata.risk_level != risk_level:
                    continue
                
                encoded_payload = self.encode_payload(metadata.payload, encoding or metadata.encoding)
                result = PayloadMetadata(
                    payload=encoded_payload,
                    injection_type=metadata.injection_type,
                    risk_level=metadata.risk_level,
                    backend_hint=metadata.backend_hint,
                    encoding=encoding or metadata.encoding,
                    description=metadata.description
                )
                results.append(result)
        
        return results
    
    def load_from_dict(self, payloads_dict: Dict[str, List[str]]) -> None:
        for injection_type, payload_list in payloads_dict.items():
            for payload in payload_list:
                if injection_type == "SQL Injection":
                    risk = RiskLevel.HIGH
                elif injection_type == "NoSQL Injection":
                    risk = RiskLevel.MEDIUM
                else:
                    risk = RiskLevel.MEDIUM
                
                self.add_payload(injection_type, payload, risk_level=risk)
    
    def should_chain_payload(self, metadata: PayloadMetadata, 
                            partial_indicators: List[str]) -> bool:
        if partial_indicators:
            if metadata.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                return True
        return False

