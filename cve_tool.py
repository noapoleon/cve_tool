#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
import sys
from pathlib import Path
from typing import Optional
import json
import pandas as pd
import asyncio
import aiohttp
import types
from types import SimpleNamespace
import time

# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# # suppress InsecureRequestWarning 
# requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

## Settings
# Parsing
CVE_COL     = "CVE"
COTS_COL    = "COTS" 
URL_BASE    = "https://security.access.redhat.com/data/csaf/v2/vex/"
# Colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"
# Logger
def _log(level, color, *args, **kwargs) -> None:
    print(f"{color}{level}:{RESET}", *args, **kwargs, file=sys.stderr)
log = types.SimpleNamespace(
    info = lambda *a, **kw: _log("info", BLUE, *a, **kw),
    warn = lambda *a, **kw: _log("warn", YELLOW, *a, **kw),
    error = lambda *a, **kw: _log("error", RED, *a, **kw),
)
# Stats
stats = SimpleNamespace(
    cve_map = None,
    dl = SimpleNamespace(done = 0, fails = [], total = 0, start = 0, end = 0)
    #process = SimpleNamespace(done = 0, fails = [], total = 0, start = 0, end = 0)
)

def get_cots_name(s: str) -> str:
    """
    Extract the package name (NEVRA name) from a COTS string.

    Example:
    xorg-x11-server-common-1.20.11-24.el8_10.x86_64  -> xorg-x11-server-common
    """
    # remove arch, release, version, keep name
    return (s.rpartition('.')[0] or s).rsplit('-', 2)[0]


#def get_cve_details(cve: str, cots: str, data: dict) -> Optional[str]:
def get_cve_remediations(cve:str, cots: str, data: dict) -> str:
    if data is None:
        return "cve_json_error"
    try:
        name = get_cots_name(cots)
        pid = "red_hat_enterprise_linux_8:" + name

        # TODO: check if safe!
        # what if no "vulnerabilities" field or smth ?
        remediations = data["vulnerabilities"][0]["remediations"]
        for rem in remediations:
            if rem["category"] == "vendor_fix":
                if any(name in e and "el8" in e for e in rem["product_ids"]):
                    return "vendor_fix"
            if rem["category"] == "workaround":
                continue
            if pid in rem["product_ids"]:
                return rem["category"]
        return "cots_not_found"
    except Exception:
        # silent fail in console but not in excel file
        return "cots_not_found"


async def download_cve_jsons(
    url_base: str,
    jsons_dir: Path,
    cve_map: dict,
) -> None:
    """Downloads all CVE JSONs from base_url and writes them to disk in jsons_dir"""
    # Construct urls
    if not url_base.endswith("/"):
        url_base = url_base + "/"
    urls = [[cve, url_base + cve.split('-')[1] + "/" + cve + ".json"] for cve in cve_map.keys()]
    # Fetch urls
    stats.dl.total = len(cve_map)
    lock = asyncio.Lock()
    def progress(eraser = "\r"):
        if not stats.dl.fails:
            print(f"{eraser}Downloading jsons [{stats.dl.done}/{stats.dl.total}]", end="")
        else:
            print(f"{eraser}Downloading jsons [{stats.dl.done}/{stats.dl.total}], " +
                f"fails [{len(stats.dl.fails)}/{stats.dl.total}]", end="")
    async def fetch_cve_json(session: aiohttp.ClientSession, cve: str, url: str, timeout: float = 10.0) -> Optional[str]:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()
                out_file = jsons_dir / f"{cve}.json"
                with open(out_file, "w", encoding="utf8") as f:
                    json.dump(data, f, indent=2)
        except Exception as e:
            async with lock:
                stats.dl.fails.append([cve, url, e])
        finally:
            async with lock:
                stats.dl.done += 1
                progress()
    # 
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_cve_json(session, url[0], url[1]) for url in urls]
        stats.dl.start = time.time()
        progress(eraser="")
        await asyncio.gather(*tasks)
        stats.dl.end = time.time()
    print()

    # sys.exit(1)
    # Fetch urls
    # async with aiohttp.ClientSession() as session:
    #    tasks = []
            

    # # download loop
    # i = 0
    # total = len(cve_map.keys())
    # fails = []
    # print(f"Downloading jsons [{i}/{total}]", end="")
    # for cve in cve_map.keys():
    #     url = url_base + cve.split('-')[1] + "/" + cve + ".json"
    #     try:
    #         data = fetch_json(url)
    #         # save each JSON to a file
    #         if data is None:
    #             raise ValueError(f"json is empty for {url}")
    #         json_file = f"{jsons_dir}/{cve}.json"
    #         with open(json_file, "w", encoding="utf-8") as f:
    #             json.dump(data, f, indent=2)
    #     except Exception as e:
    #         fails.append([cve, url, e])
    #     i += 1
    #     if not fails:
    #         print(f"\rDownloading jsons [{i}/{total}]", end="")
    #     else:
    #         print(f"\rDownloading jsons [{i}/{total}], fails [{len(fails)}/{total}]", end="")
    # print("")
    # if fails:
    #     print(f"Warning: Failed to download {len(fails)} CVE jsons:", file=sys.stderr)
    #     for fail in fails:
    #         print(f"\t{fail[0]} -> {fail[1]}:\n\t\t{fail[2]}", file=sys.stderr)

def process_jsons(jsons_dir: Path, grouped: dict, args: Namespace) -> list:
    i = 0
    fails = []
    rows = []
    total = sum(len(cotss) for cotss in grouped.values())
    print(f"Processed [{i}/{total}]", end="")
    for cve, cotss in grouped.items():
        try:
            with open(jsons_dir/f"{cve}.json", "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            data = None
            fails.append([cve, cotss, e])
        for cots in cotss:
            parsed = [cve, cots]
            for mode in args.processing_modes_used:
                parsed.append(mode["parser_func"](cve, cots, data))
            rows.append(parsed)
            i += 1
            if not fails:
                print(f"\rProcessed [{i}/{total}]", end="")
            else:
                print(f"\rProcessed [{i}/{total}], failed (CVEs) [{len(fails)}/{len(grouped)}]", end="")
    print("")
    if fails:
        print(f"Failed to process {len(fails)} CVEs" +
              f" affecting {sum(len(fail[1]) for fail in fails)} COTS:",
              file=sys.stderr)
        for fail in fails:
            print(f"\t{fail[0]}: {fail[2]}\n" + "\n".join(f"\t\t{cots}" for cots in fail[1]),
                  file=sys.stderr)

    return rows


def generate_file( input_path: Path, output_path: Path, args: Namespace):
    # TODO: doc
    # settings
    cve_col     = "CVE"
    cots_col    = "COTS" 
    url_base    = "https://security.access.redhat.com/data/csaf/v2/vex/"

    # read input
    df = pd.read_excel(
        input_path,
        usecols=[cve_col, cots_col],
        engine="openpyxl",
        converters={
            # TODO: test adding empty rows
            # | null |      |
            # |      | null |
            # | null | null |
            cve_col: lambda v: "" if pd.isna(v) else str(v).strip().lower(),
            cots_col: lambda v: "" if pd.isna(v) else str(v).strip(),
        },
    )
    # Stop if either column not in file
    if cve_col not in df.columns or cots_col not in df.columns:
        raise ValueError(f"CVE column '{cve_col}' not present in input file")
    # remove empty rows
    df = df.fillna("").astype(str)
    mask_keep = (df[cve_col] != "") & (df[cots_col] != "")
    df = df.loc[mask_keep].reset_index(drop=True)

    # unique cves with list of cots for each
    grouped = df.groupby("CVE")["COTS"].apply(list).to_dict()

    ## Download all jsons ##
    if not args.skip_download:
        asyncio.run(download_cve_jsons(url_base, args.jsons_dir, grouped))

    ## Process all jsons ##
    if args.processing_modes_used:
        new_rows = process_jsons(args.jsons_dir, grouped, args)
        headers = [cve_col, cots_col]
        # TODO change headers logic
        headers += [header for mode in args.processing_modes_used for header in mode["headers"]]
        df = pd.DataFrame(new_rows, columns=headers)

        # write output
        # TODO: pretty output
        df.to_excel(output_path, index=False)


def parse_args():
    parser = ArgumentParser(
        description="Fetch and process Red Hat CVE JSON data listed in an input XLSX file. Optional processing modes such as --remediations can be used to enrich the output.",
        allow_abbrev=False,
    )
    # arguments
    parser.add_argument("-i", "--input-xlsx", type=Path, required=True, help="Input XLSX file containing CVE and COTS columns")
    parser.add_argument("-o", "--output-xlsx", type=Path, help="Output XLSX file where processed results will be saved")
    # TODO: check if rhel argument need, could just extra rhel from cots, depends on future logic of processing modes
    # parser.add_argument("-r", "--rhel", type=int, nargs='+', help="List of rhel versions to match for with processing modes")
    parser.add_argument("-j", "--jsons-dir", type=Path, default="jsons", required=True, help="Directory to store and/or read CVE JSONs")
    parser.add_argument("-s", "--skip-download", action="store_true", help="Skip downloading CVE data, read directly from jsons_dir")
    # TODO: implement throttling
    #parser.add_argument("-t", "--throttle-download", type=int, default=50, help="Max number of concurrent CVE JSONs download requests")
    parser.add_argument("--disable-stats", action="store_true", help="Don't print download and process statistics")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s v1.1")

    # Processing modes group
    # TODO: look into subparsers if modes get more complex
    processing_group = parser.add_argument_group("processing modes", "Optional modes that process the CVE data")
    processing_modes = [
        {
            "flag": "--remediations",
            "help": "Add a 'details' column with remediation information",
            "headers": ["details"], # TODO: change code because now headers is list instead of string
            "parser_func": get_cve_remediations,
        },
        ### Add future modes here ###
        # {
        #     "flag": "--another-mode",
        #     "help": "argparse helper string",
        #     "header": ["array of headers", "needed by", "parser function", "for output xlsx"],
        #     "parser_func": my_custom_parser,
        # },
    ]
    for mode in processing_modes:
        processing_group.add_argument(mode["flag"], action="store_true", help=mode["help"])

    # Parse and add vars
    args = parser.parse_args()
    args.processing_modes_used = [
        mode for mode in processing_modes
        if getattr(args, mode["flag"].lstrip("-").replace("-", "_") , False)
    ]

    # Error checking
    if args.output_xlsx and args.input_xlsx == args.output_xlsx:
        parser.error(f"Input and output files must not be the same file: {args.input_xlsx}")
    if not args.input_xlsx.exists():
        parser.error(f"Input file doesn't exist: '{args.input_xlsx}' ")
    if args.processing_modes_used and not args.output_xlsx:
        parser.error(f"-o or --output-xlsx is required when using processing modes: {', '.join(mode['flag'] for mode in args.processing_modes_used)}")
    if args.skip_download and not args.processing_modes_used:
        parser.error(f"--skip-download requires at least one processing mode (e.g.: {', '.join(mode['flag'] for mode in processing_modes)})")
    # TODO: add explicit support for (or prevent use of) /dev/stdin, /dev/stdout and others

    return args

def make_jsons_dir(jsons_dir: Path):
    if jsons_dir.exists() and not jsons_dir.is_dir():
        log.error(f"Path for JSONs dir exists and isn't a directory: '{jsons_dir}'")
        sys.exit(1)
    jsons_dir.mkdir(parents=True, exist_ok=True)

def load_cve_map(input_xlsx: Path) -> dict:
    """Uses input file to construct a map with cve keys and a list of associated cots

    Args:
        input_xlsx (Path): input file to get cve and cots list from
    """
    # TODO: keep rhel version in dict for each cots
    # read input
    df = pd.read_excel(
        input_xlsx,
        usecols=[CVE_COL, COTS_COL],
        engine="openpyxl",
        converters={
            # TODO: test adding empty rows
            # | CVE  | COTS |
            # | null |      | (valid, just download json, make sure process_jsons won't complain tho)
            # |      | null |
            # | null | null |
            CVE_COL: lambda v: "" if pd.isna(v) else str(v).strip().lower(),
            COTS_COL: lambda v: "" if pd.isna(v) else str(v).strip(),
            # TODO: check why warning here
        },
    )
    # Stop if either column not in file
    # TODO: check with excel files if it doesn't fail earlier when collumn missing
    if CVE_COL not in df.columns or COTS_COL not in df.columns:
        raise ValueError(f"CVE column '{CVE_COL}' not present in input file")
    # Remove empty rows
    # TODO don't remove empy cots line that have a CVE. Just download cve json and do nothing with it)
    df = df.fillna("").astype(str)
    mask_keep = (df[CVE_COL] != "") & (df[COTS_COL] != "")
    df = df.loc[mask_keep].reset_index(drop=True)

    # unique cves with list of cots for each
    cve_map = df.groupby("CVE")["COTS"].apply(list).to_dict()
    stats.cve_map = cve_map
    return cve_map

def statistics(args: Namespace):
    if stats.dl.fails:
        for fail in stats.dl.fails:
            log.error(f"Failed to download: {fail[0]} from {fail[1]} because {fail[2]}")
    print("--- Statistics ---")
    print(f"Total CVEs: {len(stats.cve_map)}")
    # Downloads
    print("[CVE JSONs Downloads]")
    if args.skip_download:
        print("Skipped.")
    else:
        print(f"Success: {stats.dl.total - len(stats.dl.fails)}\n" +
            f"Fails: {len(stats.dl.fails)}\nTotal: {stats.dl.total}")
        print(f"Download duration: {round(stats.dl.end - stats.dl.start, 3)} seconds")
    print("--- Statistics ---")

def main():
    args = parse_args()

    # Prepare operations
    make_jsons_dir(args.jsons_dir)

    cve_map = load_cve_map(args.input_xlsx)
    # Download cve jsons
    if not args.skip_download:
        asyncio.run(download_cve_jsons(URL_BASE, args.jsons_dir, cve_map))
    # Run process modes 
    #if args.processing_modes_used:
    #    df = process_jsons(cve_map)

    # Stats (and errors)
    if not args.disable_stats:
        statistics(args)
    # Write processed output
    #df.writesomethinglala


if __name__ == "__main__":
    main()
