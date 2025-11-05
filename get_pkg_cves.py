#!/usr/bin/env python

import copy
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import async_downloader as adl

def progress(label: str, current: int, total: int, eraser: str = "\r"):
    bar_length = 30
    filled = int((current / total) * bar_length)
    bar = "#" * filled + "-" * (bar_length - filled)
    print(f"{eraser}{label}[{bar}] {current}/{total} | ",
            end="" if current != total else None)


def xlsx_to_dict(input_xlsx: Path | str, cols: list, skiprows: Optional[list | int] = None) -> list:
    input_xlsx = Path(input_xlsx)
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


def dl_pkg_csaf(pkg_lst: List[List], output_dir: Path | str, max_retries: int = 10):

    url_base = "https://access.redhat.com/hydra/rest/securitydata/csaf.json?package="
    output_dir = Path(output_dir)
    if output_dir.exists():
        print(f"Warning: output directory '{output_dir}' already existed, possible overwriting")
    output_dir.mkdir(parents=True, exist_ok=True)
    urls_csaf_for_package = []
    for i, pkg in enumerate(pkg_lst, start=1):
        url = f"{url_base}{pkg[0]}"
        filename = Path(f"{pkg[0]}.json")
        filename = output_dir/filename
        urls_csaf_for_package.append([url, filename])
    stats = adl.sync_downloader(urls_csaf_for_package, show_progress=True, show_stats=True, max_concurrent=10)
    retries = 1
    while stats.fails and retries <= max_retries:
        print(f"Retrying failed items... #{retries}")
        failed_items = copy.deepcopy(stats.failed_items)
        [item.pop() for item in failed_items]
        stats = adl.sync_downloader(failed_items, show_progress=True, show_stats=True)
        retries += 1

def make_cve_pkg_map(pkg_lst: List[List], input_dir: Path | str):
    # TODO: how big will this map be?
    # Should we slowly write to the  file one package at a time?
    input_dir = Path(input_dir)
    cve_pkg_map = {}

    for i, pkg in enumerate(pkg_lst, start=1):
        try:
            # 1. open cve_list.json file
            filename = input_dir/f"{pkg[0]}.json" # TODO: Make sure pkg here is just the package name
            with open(filename, "r", encoding="utf8") as f:
                data = json.load(f)
                # 2. get list of all cves for pkg
                if data:
                    for entry in data:
                        # 3. add cves of each entry of pkg to cve_pkg_map
                        cves = entry.get("CVEs")
                        if cves:
                            # 4. add pkg to each cve entry in cve_pkg_map
                            for cve in cves:
                                if not cve_pkg_map.get(cve):
                                    cve_pkg_map[cve] = []
                                # append name-version-release (no epoch, no arch)
                                cve_pkg_map[cve].append(f"{pkg[0]}-{pkg[1]}")

        except Exception as e: # TODO: don't catch everything
            print(f"Error: Failed to add {pkg} cves to map -> {e}")
        progress("Generating CVE package map: ", i, len(pkg_lst))
    return cve_pkg_map


def get_cve_vex_url(cve: str, url_base: Optional[str] = None) -> str:
    if not url_base:
        url_base = "https://security.access.redhat.com/data/csaf/v2/vex/"
    return f"{url_base}{cve.split('-')[1]}/{cve.lower()}.json"
def dl_cve_vex(cve_pkg_map: Dict[str,List[str]], output_dir: Path|str, max_retries: int = 10):
    output_dir = Path(output_dir)
    if output_dir.exists():
        print(f"Warning: output directory '{output_dir}' already existed, possible overwriting")
    output_dir.mkdir(parents=True, exist_ok=True)
    url_base    = "https://security.access.redhat.com/data/csaf/v2/vex/"
    urls_cve_vex = []
    for cve in cve_pkg_map:
        urls_cve_vex.append([
            get_cve_vex_url(cve),       # url
            output_dir/f"{cve}.json"    # filename
        ])
    stats = adl.sync_downloader(urls_cve_vex, show_progress=True, show_stats=True, max_concurrent=10)
    retries = 1
    while stats.fails and retries <= max_retries:
        print(f"Retrying failed items... #{retries}")
        print(stats.failed_items)
        failed_items = copy.deepcopy(stats.failed_items)
        [item.pop() for item in failed_items]
        stats = adl.sync_downloader(failed_items, show_progress=True, show_stats=True)
        retries += 1


def get_pkg_cves(input_file: Path | str, output_dir: Path | str, cols: Dict, skiprows: Optional[List[int] | int] = None):
    # generate list
    pkg_lst = xlsx_to_dict(input_file, list(cols.values()), skiprows)
    pkg_lst = [list(pkg.values()) for pkg in pkg_lst]
    output_dir = Path(output_dir)

    # get csaf data for rough cve list and write map
    dl_pkg_csaf(pkg_lst, output_dir/"pkg_csaf")
    cve_pkg_map = make_cve_pkg_map(pkg_lst, output_dir/"pkg_csaf")
    with open(output_dir/"cve_pkg_map_untrimmed.json", "w", encoding="utf8") as f:
        json.dump(cve_pkg_map, f, indent=2)

    # get vex data and trim cve list
    dl_cve_vex(cve_pkg_map, output_dir/"cve_vex")
    # trim_cves(cve_pkg_map, output_dir/"cve_vex")
    # with open(output_dir/"cve_pkg_map.json", "w", encoding="utf8") as f:
    #     json.dump(cve_pkg_map, f, indent=2)


    # dl_pkg_vex(pkg_lst, output_dir/"cve_vex") # TODO: use version field and don't forget el version
    # TODO: use vex to trim cves that don't have specific version of pkg??
    # remove package entry for cve if version doesnt't match in vex,
    # then when cve pkg list empty remove it from dict
    # trim_cves_by_version(cve_pkg_map)
    # write map to json?

    # final: map to excel file

if __name__ == "__main__":
    # TODO: use argparse
    # TODO: overwrite
    input_file = Path("./test_in/PAR_List_RPM_simple.xlsx")
    output_dir = Path("./data/")
    cols = {"package": "Progiciel", "version": "Version "}
    skiprows = [1]
    get_pkg_cves(input_file, output_dir, cols, skiprows)
