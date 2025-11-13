from pathlib import Path
from typing import Set
from .json_utils import safe_load

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

def get_product_status_set(
        norm_filepath: Path|str,
        exclude: set[str] | None = None
) -> Set|None:
    # load norm file
    norm_data = safe_load(norm_filepath)
    if norm_data is None:
        return None

    exclude = exclude or set()

    return {
        product
        for status, products in norm_data.get("product_status", {}).items()
        if status not in exclude
        for product in products
    }
