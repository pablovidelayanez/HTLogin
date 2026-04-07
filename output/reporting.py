import json
import html as html_module
from datetime import datetime
from typing import List, Dict, Any, Optional

from core.results import ScanResult
from detection.success import DetectionResult, ConfidenceLevel


class ReportGenerator:
    def __init__(self):
        pass

    def generate_json(self, results_list: List[ScanResult]) -> Dict[str, Any]:
        report = {
            "metadata": {
                "tool": "HTLogin",
                "version": "1.1.1",
                "generated_at": datetime.now().isoformat(),
                "total_targets": len(results_list)
            },
            "targets": []
        }

        for result in results_list:
            result_dict = result.to_dict() if isinstance(result, ScanResult) else result
            target_report = {
                "url": result_dict.get("url", "Unknown"),
                "start_time": result_dict.get("start_time"),
                "end_time": result_dict.get("end_time"),
                "duration_seconds": result_dict.get("duration_seconds", 0),
                "error": result_dict.get("error"),
                "summary": result_dict.get("summary", {}),
                "vulnerabilities": [],
                "tests": {}
            }

            for test_name, test_result in result_dict.get("tests", {}).items():
                test_report = {
                    "test_type": test_name,
                    "status": test_result.get("status", "Unknown"),
                    "confidence_score": test_result.get("confidence_score", 0),
                    "confidence_level": test_result.get("confidence_level", "Unknown"),
                    "manual_verification_recommended": test_result.get("manual_verification_recommended", False),
                    "details": test_result.get("details", {})
                }

                if test_result.get("status") == "Successful":
                    vulnerability = {
                        "type": test_name,
                        "severity": self._determine_severity(test_result.get("confidence_level", "Unknown")),
                        "confidence": test_result.get("confidence_level", "Unknown"),
                        "confidence_score": test_result.get("confidence_score", 0),
                        "payload": test_result.get("payload") or test_result.get("credential"),
                        "indicators": test_result.get("details", {}).get("indicators", []),
                        "manual_verification_recommended": test_result.get("manual_verification_recommended", False)
                    }
                    target_report["vulnerabilities"].append(vulnerability)

                target_report["tests"][test_name] = test_report

            report["targets"].append(target_report)

        return report

    def generate_html(self, results_list: List[ScanResult]) -> str:
        html_content = self._get_html_template()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_content = html_content.replace("{timestamp}", timestamp)

        content = ""
        for result in results_list:
            result_dict = result.to_dict() if isinstance(result, ScanResult) else result
            content += self._generate_target_html(result_dict)

        html_content = html_content.replace("{content}", content)

        return html_content

    def _generate_target_html(self, result: Dict[str, Any]) -> str:
        if "error" in result:
            error_msg = html_module.escape(str(result.get('error', '')))
            url = html_module.escape(str(result.get('url', 'Unknown URL')))
            return f"""
        <div class="test-result failed">
            <div class="test-name">Error for {url}</div>
            <div class="test-details">{error_msg}</div>
        </div>
"""

        url_escaped = html_module.escape(str(result.get('url', 'Unknown')))
        html_content = f"""
        <h2>Target: {url_escaped}</h2>
        <div class="summary">
            <div class="summary-item"><strong>Total Tests:</strong> {result['summary'].get('total_tests', 0)}</div>
            <div class="summary-item"><strong>Successful:</strong> {result['summary'].get('successful', 0)}</div>
            <div class="summary-item"><strong>Failed:</strong> {result['summary'].get('failed', 0)}</div>
            <div class="summary-item"><strong>Duration:</strong> {result.get('duration_seconds', 0):.2f} seconds</div>
        </div>
"""

        for test_name, test_result in result.get("tests", {}).items():
            html_content += self._generate_test_html(test_name, test_result)

        return html_content

    def _generate_test_html(self, test_name: str, test_result: Dict[str, Any]) -> str:
        status = test_result.get("status", "Unknown")
        css_class = 'success' if status == 'Successful' else 'failed' if status == 'Failed' else 'rate-limited'

        html_content = f"""
        <div class="test-result {css_class}">
            <div class="test-name">
                {test_name}: {status}
"""

        if 'confidence_level' in test_result:
            conf_level = test_result['confidence_level'].lower()
            conf_class = self._get_confidence_class(conf_level)
            conf_score = test_result.get('confidence_score', 0)
            html_content += f'<span class="confidence {conf_class}">Confidence: {conf_level.title()} ({conf_score})</span>'

            if test_result.get('manual_verification_recommended'):
                html_content += '<span class="manual-verify">⚠ Manual Verification Recommended</span>'

        html_content += """
            </div>
            <div class="test-details">
"""

        if 'payload' in test_result and test_result['payload']:
            payload_escaped = html_module.escape(str(test_result["payload"]))
            html_content += f'<div><strong>Payload:</strong> <code>{payload_escaped}</code></div>'
        if 'credential' in test_result and test_result['credential']:
            credential_escaped = html_module.escape(str(test_result["credential"]))
            html_content += f'<div><strong>Credential:</strong> <code>{credential_escaped}</code></div>'
        if 'total_duration' in test_result:
            html_content += f'<div><strong>Test Duration:</strong> {test_result["total_duration"]:.2f} seconds</div>'

        indicators = test_result.get('details', {}).get('indicators', [])
        if indicators:
            indicators_escaped = [html_module.escape(str(ind)) for ind in indicators]
            html_content += f'<div><strong>Indicators:</strong> {", ".join(indicators_escaped)}</div>'

        if test_result.get('limitations'):
            limitations_escaped = html_module.escape(str(test_result["limitations"]))
            html_content += f'<div class="limitations"><strong>Limitations:</strong> {limitations_escaped}</div>'

        html_content += """
            </div>
        </div>
"""
        return html_content

    def _get_confidence_class(self, level: str) -> str:
        level_lower = level.lower()
        if level_lower == 'high':
            return 'confidence-high'
        elif level_lower == 'medium':
            return 'confidence-medium'
        else:
            return 'confidence-low'

    def _determine_severity(self, confidence_level: str) -> str:
        level_lower = confidence_level.lower()
        if level_lower == 'high':
            return 'High'
        elif level_lower == 'medium':
            return 'Medium'
        else:
            return 'Low'

    def _get_html_template(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTLogin Test Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
        }
        .test-result {
            margin: 20px 0;
            padding: 15px;
            border-left: 4px solid #ddd;
            background-color: #f9f9f9;
        }
        .success {
            border-left-color: #4CAF50;
            background-color: #e8f5e9;
        }
        .failed {
            border-left-color: #f44336;
            background-color: #ffebee;
        }
        .rate-limited {
            border-left-color: #ff9800;
            background-color: #fff3e0;
        }
        .test-name {
            font-weight: bold;
            font-size: 1.1em;
            color: #333;
        }
        .test-details {
            margin-top: 10px;
            color: #666;
        }
        .confidence {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.9em;
            margin-left: 10px;
        }
        .confidence-high {
            background-color: #4CAF50;
            color: white;
        }
        .confidence-medium {
            background-color: #ff9800;
            color: white;
        }
        .confidence-low {
            background-color: #f44336;
            color: white;
        }
        .manual-verify {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.9em;
            margin-left: 10px;
            background-color: #ff9800;
            color: white;
        }
        .summary {
            background-color: #e3f2fd;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .summary-item {
            margin: 10px 0;
        }
        .timestamp {
            color: #999;
            font-size: 0.9em;
        }
        .limitations {
            margin-top: 10px;
            padding: 10px;
            background-color: #fff3cd;
            border-left: 3px solid #ffc107;
            border-radius: 3px;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>HTLogin Security Test Report</h1>
        <div class="timestamp">Generated: {timestamp}</div>
        {content}
    </div>
</body>
</html>
"""


def save_output(output: Any, filename: str, format_type: str = 'text') -> None:
    if format_type == 'json':
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
    elif format_type == 'html':
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(output)
    else:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(str(output))

