from pathlib import Path
from typing import Set
import json_utils

def get_archive_name(
        data_dir: Path|str,
        remove_suffix: bool = False,
        print_errors: bool = False,
        raise_errors: bool = False,
) -> str:
    try:
        data_dir = Path(data_dir)
        with open(data_dir/"archive_latest.txt", "r", encoding="utf8") as f:
            line = f.readline().strip()
            if remove_suffix:
                return line.removesuffix(".tar.zst")
            return line
    except (FileNotFoundError, OSError) as e:
        if print_errors:
            print(f"[ERROR] Failed to get archive: {type(e).__name__} -> {e}")
        if raise_errors:
            raise e
    return ""

def get_product_status_set(norm_filepath: Path|str) -> Set|None:
    # load norm file
    norm_data = json_utils.safe_load(norm_filepath)
    if norm_data is None:
        return None
    return {
        product
        for status in norm_data.get("product_status", {}).values()
        for product in status
    }
