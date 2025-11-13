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
                                cve_pkg_map[cve].append(f"{pkg[0]}-{pkg[1]}") # version
                                cve_pkg_map[cve].append(pkg[0]) # no version

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
            failed_cves[cve] = {"url": fail[0], "filename": f"{fail[1]}", "error": f"{fail[2]}"}
        map_to_json(failed_cves, fails_file, args.overwrite)
        print(f"Warning: Max retries reached, failed to download {stats.fails} items.",
              f"For more info check logs in {fails_file}")
    return failed_cves


def get_vex_matched_pids(data: dict, match: List[str], cve: str, rhel: str) -> List[str]:
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

def get_pkgs_in_vex(vex_filename, rhel_ver: str) -> Set|None:
    vex_filename = Path(vex_filename)

    # Open and load data
    try:
        with open(vex_filename, "r", encoding="utf8") as f:
            data = json.load(f)
    except (FileNotFoundError, PermissionError, IsADirectoryError,
        OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] Failed to normalize product_status for {vex_filename}: {e}")
        return None

    # Extract product_status dict
    try:
        product_status = data.get("vulnerabilities", [])[0].get("product_status")
    except (AttributeError, IndexError, TypeError) as e:
        print(f"[ERROR] Failed to normalize product_status for {vex_filename}:",
              f"Unexpected structure or value in JSON file: {e}")
        return None

    # Normalize pids
    # TODO: add try except because we're gonna use either str().split or regex
    rhel_prefix = f"red_hat_enterprise_linux_{rhel_ver}"
    rhel_suffix = f"el{rhel_ver}"
    normalized = set()
    for status, pids in product_status.items():
        for pid in pids:
            try:
                parts = pid.split(":")
                name = None

                if len(parts) == 2 and parts[0] == rhel_prefix:
                    # e.g. "red_hat_enterprise_linux_8:kernel-abi-stablelists"
                    # name = parts[1]
                    # print(f"adding pid: {pid} because parts[0] -> {parts[0]}")
                    normalized.add(parts[1])
                elif len(parts) == 3 and rhel_suffix in parts[2]:
                    # e.g. "RT-9.6.0.Z.MAIN.EUS:perf-0:5.14.0-570.16.1.el9_6.x86_64"
                    # name = parts[1].rsplit("-", 1)[0]
                    # print(f"adding pid: {pid} because parts[2] -> {parts[2]}")
                    normalized.add(parts[1].rsplit("-", 1)[0])
            except (AttributeError, IndexError, TypeError, ValueError) as e:
                print(f"[WARN] Failed to parse pid '{pid}': {e}")
    # print(normalized)
    return normalized

def trim_map_vex(
        cve_pkg_map: Dict[str,List[str]],
        input_dir: Path|str,
        rhel: str,
) -> Dict[str,List[str]]:
    input_dir = Path(input_dir)
    filtered = {}

    for cve, pkgs in tqdm(
        cve_pkg_map.items(),
        total=len(cve_pkg_map),
        desc=f"Trimming CVE Package map" if not rhel else f"Trimming CVE Package map ({rhel})"
    ):
        filename = f"{cve}.json"
        # give packages to function below
        vex_pkgs = get_pkgs_in_vex(input_dir/filename, rhel)
        trimmed_pkgs = [pkg for pkg in pkgs if pkg in vex_pkgs]
        if trimmed_pkgs:
            filtered[cve] = trimmed_pkgs # careful vex_pkgs is a set
    print(f"[DONE] Trimmed: {len(cve_pkg_map)-len(filtered)}/{len(cve_pkg_map)} | CVEs left: {len(filtered)}/{len(cve_pkg_map)}")
    return filtered


def get_pkg_cves(
        input: Path | str,
        column: str,
        output: Path | str,
        data_dir: Path | str,
        rhel_versions: List[int]|Set[int]|Set[str],
        skiprows: Optional[int] = None,
):
    input = Path(input)
    data_dir = Path(data_dir)
    rhel_versions = {str(rhel) for rhel in rhel_versions}

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
    with tqdm(total=sum(len(cves) for cves in norm_index.values()), desc="Searching for cve matches") as pbar:
        for year, cves in norm_index.items():
            for cve in cves:
                pbar.update(1)
                # vex_file = json_utils.safe_load(data_dir/archive_name/year/f"{cve}.json") # for more precise data

                # make set from product status entries
                norm_filepath = data_dir/archive_name/year/f"{cve}.norm.json"
                product_status_set = archive_utils.get_product_status_set(norm_filepath)
                if product_status_set is None:
                    fails.append(cve)
                    continue

                for rhel, pkgs in pkg_sets.items():
                    inter = pkgs & product_status_set
                    if inter:
                        cve_pkg_maps[rhel][cve] = inter

    # write cve_pkg_maps
    for rhel in cve_pkg_maps:
        filename = f"{str(input).removesuffix('.xlsx')}.rhel{rhel}.json"
        json_utils.safe_dump(
            json_utils.normalize(cve_pkg_maps[rhel]),
            filename, print_errors=True
        )
    # write xlsx



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
