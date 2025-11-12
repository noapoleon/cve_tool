import json
from pathlib import Path

def safe_dump(
        data,
        filepath: Path|str,
        indent: int = 2,
        print_errors: bool = False,
        raise_errors: bool = False
) -> bool:
    """Dump a JSON object safely. Returns True is success, False if failed."""
    try:
        with open(filepath, "w", encoding="utf8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        return True
    except (OSError, TypeError) as e:
        if print_errors:
            print(f"[ERROR] safe_json_dump fail: {type(e).__name__} -> {e}")
        if raise_errors:
            raise e
    return False

def safe_load(
        filepath: Path|str,
        print_errors: bool = False,
        raise_errors: bool = False
) -> dict|None:
    """Load a JSON file safely. Returns object is success, None if failed or doesn't exist."""
    try:
        with open(filepath, "r", encoding="utf8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        if print_errors:
            print(f"[ERROR] safe_json_load fail: {type(e).__name__} -> {e}")
        if raise_errors:
            raise e
    return None

def normalize(obj):
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, dict):
        return {k: normalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [normalize(v) for v in obj]
    return obj
