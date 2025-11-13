#!/usr/bin/env python

import sys
from argparse import ArgumentParser, Namespace
import copy
import json
from pathlib import Path
import time
from types import SimpleNamespace
from typing import Dict, List, Optional, Set
from tqdm import tqdm
import pandas as pd
import async_downloader as adl
from utils import json_utils, xlsx_utils, archive_utils


def get_pkg_cves(
        input: Path | str,
        column: str,
        output: Path | str,
        data_dir: Path | str,
        rhel_versions: List[int]|Set[int]|Set[str],
        skiprows: Optional[int] = None,
        exclude: set[str] | None = {"known_not_affected"},
):
    total_start = time.time()
    input = Path(input)
    data_dir = Path(data_dir)
    rhel_versions = {str(rhel) for rhel in rhel_versions}
    exclude = exclude or set()

    # fetch list
    pkg_set = xlsx_utils.xlsx_to_dict(input, [column], skiprows, print_errors=True)
    if pkg_set is None:
        return
    pkg_set = {pkg[column] for pkg in pkg_set}

    # get norm info
    archive_name = archive_utils.get_archive_name(data_dir, remove_suffix=True, print_errors=True)
    if not archive_name:
        return
    norm_index = json_utils.safe_load(data_dir/archive_name/"norm_index.json", print_errors=True)
    if norm_index is None:
        return

    # build name:rhel sets for each rhel version
    pkg_sets = {rhel: {f"{pkg}:{rhel}" for pkg in pkg_set} for rhel in rhel_versions}

    # check normed files for matches
    fails = []
    cve_pkg_maps = {rhel: {} for rhel in rhel_versions}
    pkg_cve_maps = {rhel: {} for rhel in rhel_versions}
    with tqdm(total=sum(len(cves) for cves in norm_index.values()), desc="Searching for cve matches") as pbar:
        for year, cves in norm_index.items():
            for cve in cves:
                pbar.update(1)
                # vex_file = json_utils.safe_load(data_dir/archive_name/year/f"{cve}.json") # for more precise data

                # make set from product status entries
                norm_filepath = data_dir/archive_name/year/f"{cve}.norm.json"
                # TODO: change exclude here for different results
                product_status_set = archive_utils.get_product_status_set(norm_filepath)
                if product_status_set is None:
                    fails.append(cve)
                    continue

                for rhel, pkgs in pkg_sets.items():
                    inter = pkgs & product_status_set
                    if inter:
                        cve_pkg_maps[rhel][cve] = {pkg.rpartition(":")[0] for pkg in inter}
                        [pkg_cve_maps[rhel].get(pkg.rpartition(":")[0], set()).add(cve) for pkg in inter]

    # write cve_pkg_maps and pkg_cve_map jsons
    filename = f"{str(output).removesuffix('.xlsx')}.maps.json"
    json_utils.safe_dump(
        json_utils.normalize({
            "cve_pkg_maps": cve_pkg_maps,
            "pkg_cve_maps": pkg_cve_maps,
        }), filename, print_errors=True
    )
    # write xlsx
    headers = ["CVE", "Product"]
    headers += [f"status RHEL {rhel}" for rhel in cve_pkg_maps]
    rows = []
    unique_cves = set().union(*[rhel_map.keys() for rhel_map in cve_pkg_maps.values()])
    with tqdm(total=len(unique_cves), desc="Processing output file") as pbar:
        for cve in unique_cves:
            pkgs = {pkg for rhel in cve_pkg_maps for pkg in cve_pkg_maps[rhel].get(cve, {})}
            for pkg in pkgs:
                row = [cve, pkg]
                for rhel in cve_pkg_maps:
                    if pkg in cve_pkg_maps[rhel].get(cve, set()): #won't work with 
                        row.append(1)
                    else:
                        row.append(0)
                rows.append(row)
            pbar.update(1)
    start = time.time()
    print("Writing output excel file...")
    df_main = pd.DataFrame(rows, columns=headers) # protect
    df_main.sort_values(by="CVE", inplace=True)
    # stats
    headers = ["Package", "CVE Count"]
    rows = []
    for pkg in pkg_set:
        rows.append([pkg, sum(len(pkg_cve_maps[rhel].get(pkg, set())) for rhel in pkg_cve_maps)])
    df_stats = pd.DataFrame(rows, columns=headers)
    df_stats.sort_values(by="Package", inplace=True)
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df_main.to_excel(writer, index=False, sheet_name="main") # protect
        df_stats.to_excel(writer, index=False, sheet_name="stats") # protect
    print(f"[INFO] Output XLSX write took {round(time.time() - start, 3)} seconds")
    print(f"[DONE] Total processing time: {round(time.time() - total_start, 3)} seconds")



def parse_args():
    parser = ArgumentParser(
        description="Fetch RedHat VEX files from packages listed in an input XLSX file.\n"
        + "For now only supports rhel8 and rhel10.",
        allow_abbrev=False,
    )
    # arguments
    parser.add_argument("-i", "--input", type=Path, required=True, help="Input XLSX file containing CVE and COTS columns")
    parser.add_argument("-o", "--output", type=Path, required=True, help="Output XLSX file where processed results will be saved")
    # parser.add_argument("--logfile", type=Path, help="Output XLSX file where processed results will be saved")
    parser.add_argument("-c", "--column", type=str, required=True, help="Header name for the package column")
    parser.add_argument("-r", "--rhel-versions", type=int, nargs="+", required=True, help="List of major rhel versions to match cve matching")
    parser.add_argument("--skiprows", type=int, nargs="+", help="List of major rhel versions to match cve matching")
    parser.add_argument("-d", "--data-dir", type=Path, default="data", help="Directory to cache and read JSONs to and from")
    # parser.add_argument("--skip-download", action="store_true", help="Redownload and overwrite CSAF and VEX jsons even if they already exist in JSONS dir")
    # parser.add_argument("--overwrite", action="store_true", help="Reprocess downloaded data even if cve maps already exist in JSONS dir")
    # TODO: implement throttling
    #parser.add_argument("-t", "--throttle-download", type=int, default=50, help="Max number of concurrent CVE JSONs download requests")
    # parser.add_argument("--disable-stats", action="store_true", help="Don't print download and process statistics")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s v0.1")

    # Parse and add vars
    args = parser.parse_args()

    # Error checking
    # maybe read docs for conflict_handler argparse
    if args.output and args.input == args.output:
        parser.error(f"Input and output files must not be the same file: {args.input}")
    if not args.input.exists():
        parser.error(f"Input file doesn't exist: '{args.input}' ")
    return args

if __name__ == "__main__":
    args = parse_args()
    get_pkg_cves(
        args.input,
        args.column,
        args.output,
        args.data_dir,
        args.rhel_versions,
        args.skiprows
    )
