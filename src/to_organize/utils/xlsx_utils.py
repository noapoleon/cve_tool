import openpyxl
import pandas as pd
from pathlib import Path
from typing import Optional, List

def xlsx_to_dict(
        input_xlsx: Path | str,
        cols: List,
        skiprows: Optional[List | int] = None,
        print_errors: bool = False,
        raise_errors: bool = False,
) -> list | None:
    try:
        input_xlsx = Path(input_xlsx)
        # read input
        df = pd.read_excel(
            input_xlsx,
            usecols=cols,
            skiprows=skiprows,
            engine="openpyxl",
        )

        return df.to_dict(orient='records')
    except (FileNotFoundError, ValueError, OSError, ImportError, pd.errors.ParserError) as e:
        if print_errors:
            print(f"[ERROR] Failed to read {input_xlsx}: {type(e).__name__} -> {e}")
        if raise_errors:
            raise e
    return None
