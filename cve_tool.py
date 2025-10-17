#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
import sys
from pathlib import Path
from typing import Optional
import json
import pandas as pd

import requests
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# # suppress InsecureRequestWarning 
# requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def get_cots_name(s: str) -> str:
    """
    Extract the package name (NEVRA name) from a COTS string.

    Example:
    xorg-x11-server-common-1.20.11-24.el8_10.x86_64  -> xorg-x11-server-common
    """
    # remove arch, release, version, keep name
    return (s.rpartition('.')[0] or s).rsplit('-', 2)[0]

def extract_remediation_details():
    pass

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


def download_jsons(
    url_base: str,
    jsons_dir: Path,
    grouped: dict,
) -> None:
    # TODO: doc
    # normalize base URL
    if not url_base.endswith("/"):
        url_base = url_base + "/"

    def fetch_json(url: str, timeout: float = 10.0) -> Optional[str]:
        r = requests.get(url, timeout=timeout)
        # FIX: if zscaler enabled request will fail here:
        if r.status_code == 200: # TODO: other acceptable responses? redirects?
            return r.json()
        return None

    # create jsons dir
    if not jsons_dir.exists():
        jsons_dir.mkdir()
    elif not jsons_dir.is_dir():
        print(f"Error: jsons_dir exists and isn't a directory: '{jsons_dir}'")
        sys.exit(1)
    # download loop
    i = 0
    total = len(grouped.keys())
    fails = []
    print(f"Downloading jsons [{i}/{total}]", end="")
    for cve in grouped.keys():
        url = url_base + cve.split('-')[1] + "/" + cve + ".json"
        try:
            data = fetch_json(url)
            # save each JSON to a file
            if data is None:
                raise ValueError(f"json is empty for {url}")
            json_file = f"{jsons_dir}/{cve}.json"
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            fails.append([cve, url, e])
        i += 1
        if not fails:
            print(f"\rDownloading jsons [{i}/{total}]", end="")
        else:
            print(f"\rDownloading jsons [{i}/{total}], fails [{len(fails)}/{total}]", end="")
    print("")
    if fails:
        print(f"Warning: Failed to download {len(fails)} CVE jsons:", file=sys.stderr)
        for fail in fails:
            print(f"\t{fail[0]} -> {fail[1]}:\n\t\t{fail[2]}", file=sys.stderr)

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
            for mode in args.processing_modes_used.values():
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
    # ).head(200) # testing with smaller dataset
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
        download_jsons(url_base, args.jsons_dir, grouped)

    ## Process all jsons ##
    if args.processing_modes_used:
        new_rows = process_jsons(args.jsons_dir, grouped, args)
        headers = [cve_col, cots_col]
        headers += [mode["header"] for mode in args.processing_modes_used.values()]
        df = pd.DataFrame(new_rows, columns=headers)

        # write output
        # TODO: pretty output
        df.to_excel(output_path, index=False)


def parse_args():
    parser = ArgumentParser(
        description="Fetch and process Red Hat CVE JSON data listed in an input XLSX file. Optional processing modes such as --remediations can be used to enrich the output.",
        allow_abbrev=False,
    )
    # Positional arguments
    parser.add_argument("input_xlsx", type=Path, help="Input XLSX file containing CVE and COTS columns")

    # Optional arguments
    parser.add_argument("-o", "--output-xlsx", type=Path,help="Output XLSX file where processed results will be saved")
    parser.add_argument("-j", "--jsons-dir", type=Path, default="jsons", help="Directory to store and/or read CVE JSONs")
    parser.add_argument("-s", "--skip-download", action="store_true", help="Skip downloading CVE data, read directly from jsons_dir")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s v1.0")

    # processing modes group
    processing_group = parser.add_argument_group("processing modes", "Optional modes that process the CVE data")
    processing_group.add_argument("--remediations", action="store_true", help="Add a 'details' column with remediation information")
    # future modes can be added here
    # processing_group.add_argument("--another-mode", action="store_true", help="...")
    # add processing mode name to this array for error checking
    processing_modes = {
        "remediations": {"header": "details", "parser_func": get_cve_remediations},
        # "another_mode": ["columne name", parser_function],
        }

    args = parser.parse_args()
    # add used modes details to array in args
    args.processing_modes_used = {
        mode: processing_modes[mode]
        for mode in processing_modes
        if getattr(args, mode, False)
    }

    # Error checking
    if args.skip_download and not args.processing_modes_used:
        parser.error("--skip-download requires at least one processing mode (e.g.: --remediations, etc.)")
    if args.processing_modes_used and not args.output_xlsx:
        parser.error(f"-o or --output-xlsx is required when using processing modes: {', '.join(args.processing_modes_used)}")
    assert args.input_xlsx.exists(), "Input XLSX must exist"
    assert args.input_xlsx.is_file(), "Input XLSX must be a file"


    return args


def main():
    args = parse_args()

    try:
        generate_file(args.input_xlsx, args.output_xlsx, args)
    except Exception as e:
        print(f"Error handling file '{args.input_xlsx}': {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
