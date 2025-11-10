#!/usr/bin/env python

from argparse import ArgumentParser, Namespace
import copy
import json
from pathlib import Path
import time
from types import SimpleNamespace
from typing import Dict, List, Optional
from tqdm import tqdm

import pandas as pd
import async_downloader as adl


def map_to_json(map: Dict, filename: Path|str, overwrite: bool = False):
    filename = Path(filename)
    if not filename.exists() or args.overwrite:
        if (overwrite and filename.exists()):
            print(f"Warning: overwriting {filename} with new data")
        with open(filename, "w", encoding="utf8") as f:
            json.dump(map, f, indent=2)


def dl_retry(stats: SimpleNamespace, max_retries: int):
    retries = 1
    eraser = "\r"
    while stats.fails and retries <= max_retries:
        print(f"{eraser if retries != 1 else ''}Retrying {stats.fails} failed items |",
            f"Retries {retries}/{max_retries}",
            end="" if retries != max_retries else None)
        [item.pop() for item in stats.failed_items]
        failed_items = copy.deepcopy(stats.failed_items)
        stats = adl.sync_downloader(failed_items)
        retries += 1
    return stats


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


def dl_pkg_csaf(
        pkg_lst: List[List],
        output_dir: Path | str,
        max_retries: int = 10
):

    url_base = "https://access.redhat.com/hydra/rest/securitydata/csaf.json?package="
    output_dir = Path(output_dir)
    if output_dir.exists():
        print(f"Warning: output directory '{output_dir}' already existed, possible overwriting")
    output_dir.mkdir(parents=True, exist_ok=True)
    urls_csaf_for_package = []
    for pkg in pkg_lst:
        url = f"{url_base}{pkg[0]}"
        filename = Path(f"{pkg[0]}.json")
        filename = output_dir/filename
        urls_csaf_for_package.append([url, filename])
    stats = adl.sync_downloader(urls_csaf_for_package, show_progress=True, show_stats=True, max_concurrent=10)
    stats = dl_retry(stats, max_retries)

def make_cve_pkg_map(pkg_lst: List[List], input_dir: Path | str):
    # TODO: how big will this map be?
    # Should we slowly write to the  file one package at a time?
    input_dir = Path(input_dir)
    cve_pkg_map = {}

    for i, pkg in tqdm(
        enumerate(pkg_lst, start=1),
        desc="Generating CVE package map",
        total=len(pkg_lst)
    ):
        try:
            # 1. open cve_list.json file
            filename = input_dir/f"{pkg[0]}.json" # TODO: Make sure pkg here is just the package name
            with open(filename, "r", encoding="utf8") as f:
                # FIX: too slow
                data = json.load(f)
                # 2. get list of all cves for pkg
                if data:
                    for entry in data:
                        # 3. add cves of each entry of pkg to cve_pkg_map
                        cves = entry.get("CVEs")
                        if cves:
                            # 4. add pkg to each cve entry in cve_pkg_map
                            for cve in cves:
                                cve = str(cve).lower()
                                if not cve_pkg_map.get(cve):
                                    cve_pkg_map[cve] = []
                                # append name-version-release (no epoch, no arch)
                                cve_pkg_map[cve].append(f"{pkg[0]}-{pkg[1]}")

        except Exception as e: # TODO: don't catch everything
            print(f"Error: Failed to add {pkg} cves to map -> {e}")
    return cve_pkg_map


def get_cve_vex_url(cve: str, url_base: Optional[str] = None) -> str:
    if not url_base:
        url_base = "https://security.access.redhat.com/data/csaf/v2/vex/"
    return f"{url_base}{cve.split('-')[1]}/{cve}.json"


def dl_cve_vex(
        cve_pkg_map: Dict[str,List[str]],
        output_dir: Path|str,
        args: Namespace,
        max_retries: int = 10,
) -> Dict:
    output_dir = Path(output_dir)
    if output_dir.exists():
        print(f"Warning: output directory '{output_dir}' already existed, possible overwriting")
    output_dir.mkdir(parents=True, exist_ok=True)
    urls_cve_vex = []
    for cve in cve_pkg_map:
        urls_cve_vex.append([
            get_cve_vex_url(cve),       # url
            output_dir/f"{cve}.json"    # filename
        ])
    stats = adl.sync_downloader(urls_cve_vex, show_progress=True, show_stats=True, max_concurrent=10)
    stats = dl_retry(stats, max_retries)

    failed_cves = {}
    if stats.fails:
        fails_file = output_dir/"fails.json"
        for fail in stats.failed_items:
            cve = Path(fail[1]).stem
            failed_cves[cve] = {"url": fail[0], "filename": fail[1], "error": f"{fail[2]}"}
        map_to_json(failed_cves, fails_file, args.overwrite)
        print(f"Warning: Max retries reached, failed to download {stats.fails} items.",
              f"For more info check logs in {fails_file}")
    return failed_cves


def get_vex_matched_pids(data: dict, match: List[str], cve: str, rhel: Optional[str] = None) -> List[str]:
    normed = []

    # modify match set based on rhel, otherwise just use version + release
    if rhel:
        match_set = [f"{match.rsplit('-', 2)[0]}-{rhel}" for match in match]
        match_set = set(match_set)
    else:
        match_set = set(match)

    def match_normalize_pid(pid: str, rhel: Optional[str] = None):
        try:
            parts = pid.split(":", 2)
            if len(parts) < 3:
                return None
            _, ne, vra = parts
            if not rhel:
                norm = f"{ne.rsplit('-', 1)[0]}-{vra.rsplit('.', 1)[0]}"
                return norm if norm in match_set else None
            else:
                norm_real = f"{ne.rsplit('-', 1)[0]}-{vra.rsplit('.', 1)[0]}"
                # print(vra)
                # print(vra.rsplit('.', 1)[0])
                r = vra.rsplit('.', 1)[0].rsplit('-', 1)[1]
                if rhel in r:
                    norm = f"{ne.rsplit('-', 1)[0]}-{rhel}"
                else:
                    return None
                return norm_real if norm in match_set else None
        except Exception:
            return None

    def normalize_product_status(product_status: dict):
        # only keep: name-rhel
        # no version because some vex dont have versions
        # find all formats that vex product status can have
        # - snevra
        # - sha thing
        # - rhel:name
        # - ...
        for pids, status in product_status.items():
            for pid in pids:
                norm = match_normalize_pid(pid, rhel)
                if norm is not None:
                    normed.append(norm)

    try:
        product_status = data.get("vulnerabilities", [])[0].get("product_status") #unsafe
        product_status = normalize_product_status(product_status)
    except Exception as e:
        print(f"[ERROR] Failed to normalize product status for {cve}: {e}")
    for pids in product_status.values():
        for pid in pids:
            norm = match_normalize_pid(pid, rhel)
            if norm is not None:
                normed.append(norm)
    # make normed a set? or keep as list?
    return normed


def trim_map_vex(
        cve_pkg_map: Dict[str,List[str]],
        input_dir: Path|str,
        rhel: Optional[str] = None
) -> Dict[str,List[str]]:
    input_dir = Path(input_dir)
    filtered = {}

    for cve, pkgs in tqdm(
        cve_pkg_map.items(),
        total=len(cve_pkg_map),
        desc=f"Trimming CVE Package map" if not rhel else f"Trimming CVE Package map ({rhel})"
    ):
        # TODO would async help? or multithreading
        filename = f"{cve}.json"
        try:
            with open(input_dir/filename, "r", encoding="utf8") as f:
                data = json.load(f)
                pids = get_vex_matched_pids(data, pkgs, cve, rhel)
                if not data or not pids:
                    # TODO: trimming stats
                    continue
                filtered[cve] = pids
        except (FileNotFoundError, PermissionError, json.JSONDecodeError) as e:
            print(f"Failed reading {filename}: {e}")
    print(f"[DONE] Trimmed: {len(cve_pkg_map)-len(filtered)}/{len(cve_pkg_map)} | CVEs left: {len(filtered)}/{len(cve_pkg_map)}")
    return filtered



def get_pkg_cves(
        input_file: Path | str,
        output_dir: Path | str,
        args: Namespace,
        cols: Dict,
        skiprows: Optional[List[int] | int] = None,
):
    # generate list
    pkg_lst = xlsx_to_dict(input_file, list(cols.values()), skiprows)
    pkg_lst = [list(pkg.values()) for pkg in pkg_lst]
    output_dir = Path(output_dir)

    # get csaf data for rough cve list and write map
    dl_pkg_csaf(pkg_lst, output_dir/"pkg_csaf", args)
    start = time.time()
    cve_pkg_map = make_cve_pkg_map(pkg_lst, output_dir/"pkg_csaf")
    end = time.time()
    print(f"[DONE] CVE map generation took {round(end - start, 3)} seconds")
    map_to_json(cve_pkg_map, output_dir/"cve_pkg_map_untrimmed.json", args.overwrite)

    # get vex data and trim cve list
    fails = dl_cve_vex(cve_pkg_map, output_dir/"cve_vex", args)
    # remove failed items from package map
    for fail in fails:
        del cve_pkg_map[fail]

    # trim cve list
    map_filename = output_dir/"cve_pkg_map.json"
    if not map_filename.exists() or args.overwrite:
        cve_pkg_map_trimmed = trim_map_vex(cve_pkg_map, output_dir/"cve_vex")
        map_to_json(cve_pkg_map_trimmed, output_dir/"cve_pkg_map.json", args.overwrite)
    map_filename = output_dir/f"cve_pkg_map{args.rhel}.json"
    if args.rhel:
        if not map_filename.exists() or args.overwrite:
            cve_pkg_map_trimmed_rhel = trim_map_vex(cve_pkg_map, output_dir/"cve_vex", args.rhel)
            map_to_json(cve_pkg_map_trimmed_rhel, output_dir/f"cve_pkg_map_{args.rhel}.json", args.overwrite)

    # stats compare normal and rhel version

    # final: map to excel file


def parse_args():
    parser = ArgumentParser(
        description="Fetch RedHat VEX files from packages listed in an input XLSX file.\n"
        + "For now only supports rhel8 and rhel10.",
        allow_abbrev=False,
    )
    # arguments
    parser.add_argument("-i", "--input", type=Path, required=True, help="Input XLSX file containing CVE and COTS columns")
    parser.add_argument("-o", "--output", type=Path, help="Output XLSX file where processed results will be saved")
    # parser.add_argument("--logfile", type=Path, help="Output XLSX file where processed results will be saved")
    parser.add_argument("-r", "--rhel", type=str, default=None, help="List of rhel versions to match for with processing modes")
    parser.add_argument("-j", "--data-dir", type=Path, default="data", help="Directory to cache and read JSONs to and from")
    parser.add_argument("--overwrite", action="store_true", help="Redownload and overwrite VEX jsons even if they already exist in JSONS dir")
    # parser.add_argument("--skip-download", action="store_true", help="Redownload and overwrite VEX jsons even if they already exist in JSONS dir")
    # TODO: difference between donwloading vex and csaf files and overwriting the processing
    # TODO: implement throttling
    #parser.add_argument("-t", "--throttle-download", type=int, default=50, help="Max number of concurrent CVE JSONs download requests")
    parser.add_argument("--disable-stats", action="store_true", help="Don't print download and process statistics")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s v0.1")

    # Parse and add vars
    args = parser.parse_args()

    # Error checking
    # maybe read docs for conflict_handler argparse
    if args.output and args.input == args.output:
        parser.error(f"Input and output files must not be the same file: {args.input}")
    if args.rhel and args.rhel == "":
        parser.error(f"Rhel argument cannot have empty value: {args.rhel}")
    if not args.input.exists():
        parser.error(f"Input file doesn't exist: '{args.input}' ")
    return args

if __name__ == "__main__":
    args = parse_args()

    # TODO: make sure every argument has a use
    # --disable-stats

    cols = {"package": "Progiciel", "version": "Version "} # TODO: argparse -> nargs="+", default=[]
    skiprows = [1] # TODO: argparse -> nargs="+", default=[]
    get_pkg_cves(args.input, args.data_dir, args, cols, skiprows)
