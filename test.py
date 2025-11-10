import copy
from pathlib import Path
import json
from tqdm import tqdm
from typing import Optional, List, Set

def get_vex_pkgs_for_rhel(vex_filename, rhel_ver: str) -> Set|None:
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
                    print(f"adding pid: {pid} because parts[0] -> {parts[0]}")
                    normalized.add(parts[1])
                elif len(parts) == 3 and rhel_suffix in parts[2]:
                    # e.g. "RT-9.6.0.Z.MAIN.EUS:perf-0:5.14.0-570.16.1.el9_6.x86_64"
                    # name = parts[1].rsplit("-", 1)[0]
                    print(f"adding pid: {pid} because parts[2] -> {parts[2]}")
                    normalized.add(parts[1].rsplit("-", 1)[0])
            except (AttributeError, IndexError, TypeError, ValueError) as e:
                print(f"[WARN] Failed to parse pid '{pid}': {e}")
    print(normalized)
    return normalized


pids_ver = get_normalized_vex_pids("./data/cve_vex/cve-2025-21927.json", "8")
pids_nover = get_normalized_vex_pids("./data/cve_vex/cve-2025-38029.json", "8")
pids_nover = get_normalized_vex_pids("./data/cve_vex/cve-2025-9900.json", "8")
