#!/usr/bin/env python


import pandas as pd
from pathlib import Path
from typing import Optional

import async_downloader as adl
# from async_downloader import sync_downloader

def xlsx_to_dict(input_xlsx: Path, cols: list, skiprows: Optional[list] = None) -> list:
    # read input
    df = pd.read_excel(
        input_xlsx,
        usecols=cols,
        skiprows=skiprows,
        engine="openpyxl",
    )

    # # Stop if either column not in file
    # for col in cols:
    #     if col not in df.columns:
    #         raise ValueError(f"Column '{col}' not present in input file '{input_xlsx}'")

    return df.to_dict(orient='records')

input_file = Path("./test_in/PAR_List_RPM_simple.xlsx")
cols = ["Progiciel", "Version "]
prog_lst = xlsx_to_dict(input_file, cols)

# url_base = "https://access.redhat.com/hydra/rest/securitydata/cve.json?package=xorg-x11-server-common"
url_base = "https://access.redhat.com/hydra/rest/securitydata/cve.json?package="
out_dir = Path("fetcher/pkg_cve_lists/")
out_dir.mkdir(parents=True, exist_ok=True)
urls_cve_for_package = []
for prog in prog_lst:
    url = f"{url_base}{prog[cols[0]]}"
    filename = Path(f"{prog[cols[0]]}.cve_list.json")
    filename = out_dir/filename
    urls_cve_for_package.append([url, filename])

# for e in urls_cve_for_package:
#     print(e)
# print(out_dir)

stats = adl.sync_downloader(urls_cve_for_package, show_progress=True, show_stats=True)
