# import json
import orjson
from pathlib import Path

def safe_dump(
        data,
        filepath: Path|str,
        indent: bool = True,
        print_errors: bool = False,
        raise_errors: bool = False
) -> bool:
    """Dump a JSON object safely. Returns True is success, False if failed."""
    try:
        opts = orjson.OPT_NON_STR_KEYS
        if indent:
            opts |= orjson.OPT_INDENT_2

        # write as bytes (faster)
        Path(filepath).write_bytes(orjson.dumps(data, option=opts))
        return True
    except (OSError, TypeError, orjson.JSONEncodeError) as e:
        if print_errors:
            print(f"[ERROR] safe_dump fail: {type(e).__name__} -> {e}")
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
        return orjson.loads(Path(filepath).read_bytes())
    except (OSError, orjson.JSONDecodeError) as e:
        if print_errors:
            print(f"[ERROR] safe_load fail: {type(e).__name__} -> {e}")
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
