import json
import pandas as pd
from pathlib import Path
import tqdm
import sys

CVE_COL     = "CVE"
COTS_COL    = "COTS" 

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
    return cve_map


def main():
    with open("./data/cve_pkg_map_rhel8.json", "r", encoding="utf8") as f:
        el8_cve_map = json.load(f)
        el8_cve_map = set(el8_cve_map.keys())
        el8_cve_map = set(cve.lower() for cve in el8_cve_map)

    with open("./data/cve_pkg_map_rhel10.json", "r", encoding="utf8") as f:
        el10_cve_map = json.load(f)
        el10_cve_map = set(el10_cve_map.keys())

    diff = {
        "common": set(),
        "el8_only": set(),
        "el10_only": set(),
    }

    for cve in el8_cve_map:
        if cve in el10_cve_map:
            diff["common"].add(cve)
        else:
            diff["el8_only"].add(cve)
    for cve in el10_cve_map:
        if cve in el8_cve_map:
            diff["common"].add(cve)
        else:
            diff["el10_only"].add(cve)
    # print(diff)
    print(f"Total vuln el8: {len(el8_cve_map)}")
    print(f"Total vuln el10: {len(el10_cve_map)}")
    print(f"Vulnerabilities in common: {len(diff['common'])}")
    print(f"Vulnerabilities only in el8: {len(diff['el8_only'])}")
    print(f"Vulnerabilities only in el10: {len(diff['el10_only'])}")

    # print()
    # for i, cve in enumerate(diff['el10_only']):
    #     print(f"vuln #{i}: {cve}")




if __name__ == "__main__":
    main()
