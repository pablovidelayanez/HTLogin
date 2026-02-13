import json
import os
from typing import Dict, List


def _find_languages_json() -> str:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    package_path = os.path.join(current_dir, 'languages.json')
    if os.path.exists(package_path):
        return package_path
    
    try:
        import pkg_resources
        try:
            path = pkg_resources.resource_filename('utils', 'languages.json')
            if os.path.exists(path):
                return path
        except:
            pass
        try:
            path = pkg_resources.resource_filename('htlogin.utils', 'languages.json')
            if os.path.exists(path):
                return path
        except:
            pass
    except Exception:
        pass
    
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dev_path = os.path.join(script_dir, 'languages.json')
    if os.path.exists(dev_path):
        return dev_path
    
    if os.path.exists('languages.json'):
        return os.path.abspath('languages.json')
    
    raise FileNotFoundError("languages.json file not found")


def load_language_keywords(json_path: str = None, language_code: str = None) -> Dict[str, List[str]]:
    if json_path is None:
        json_path = _find_languages_json()
    
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"languages.json file not found: {json_path}")
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"languages.json reading json error: {e}") from e
    except Exception as e:
        raise RuntimeError(f"languages.json reading error: {e}") from e
    
    if language_code is None:
        return data
    
    if language_code not in data:
        raise ValueError(f"Not Supported Language: {language_code}. Supported Languages: {', '.join(data.keys())}")
    
    return data[language_code]

