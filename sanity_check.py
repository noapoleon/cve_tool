import json
from tqdm import tqdm
import requests
import sys
import time
from pathlib import Path

# TODO
# 1. check https://security.access.redhat.com/data/csaf/v2/vex/ for newer version of archive
#   1.1 download new archive version
#   1.2 unzip new archive version
#   1.3 download index
#   1.4 check index and download missing cve jsons
# 2. 

# r = requests.get("https://access.redhat.com/hydra/rest/securitydata/csaf.json?package=xorg-x11-server-common")
# if r.status_code == 200:
#     data = r.json()
#     with open("data_full/xorg-x11-server-common_api_matches.json", "w", encoding="utf8") as f:
#         json.dump(data, f, indent=2)


# cves = set()
# with open("data_full/xorg-x11-server-common_api_matches.json", "r", encoding="utf8") as f:
#     data = json.load(f)
#     for rhsa in data:
#         for cve in rhsa.get("CVEs"):
#             cves.add(cve)
#
# print(f"cves -> {len(cves)}")


# with open("data_full/xorg-x11-server-common_grep_matches", "r", encoding="utf8") as f:
#     lines = [line.strip() for line in f if line.strip()]
#     cves = set(line.split("/", 1)[1] for line in lines)
#     print(f"cves grep -> {len(cves)}")



pkg_to_check = "xorg-x11-server-common"
data_dir = Path("./data_full")
missing_cves = set()
# create cve_index
cve_index = {}
with open(data_dir/"index.txt", "r", encoding="utf8") as f:
    for line in f:
        line = line.strip()
        if line:
            year, _, cve = line.removesuffix(".json").rpartition("/")
            if not Path(data_dir/year/f"{cve}.json").exists():
                missing_cves.add(cve)
            cve_index.setdefault(year, []).append(cve)


# dl missing cves
# for cve in tqdm(missing_cves, desc="Downloading missing vex"):
#     year = cve.split("-")[1]
#     url = f"https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve}.json"
#     r = requests.get(url, timeout=10)
#     if r.status_code == 200:
#         data = r.json()
#         with open(data_dir/year/f"{cve}.json", "w", encoding="utf8") as f:
#             json.dump(data, f, ensure_ascii=False)
# print(f"how many cves mention {pkg_to_check}? {len(cve_index)}")
print(f"Total missing cves: {len(missing_cves)}")
print(f"CVEs in index file but not in archive")
# # sys.exit(1)



# doing stuff
start = time.time()
matching_cves = []
counts = {}
all_cves = [(year, cve) for year, cves in cve_index.items() for cve in cves]
for year, cve in tqdm(all_cves):
    found = False
    filepath = data_dir/year/f"{cve}.json"
    try:
        with open(filepath, "r", encoding="utf8") as f:
            data = json.load(f)
        product_status = data.get("vulnerabilities")[0].get("product_status")
        for status, pids in product_status.items():
            for pid in pids:
                if pkg_to_check in pid:
                    if not counts.get(status):
                        counts[status] = 0
                    counts[status] += 1
                    found = True
                    matching_cves.append(cve)
                if found:
                    break
            if found:
                break
    except Exception as e:
        print(f"Skipping {cve} because {e}")

print(f"how many cves -> {len(matching_cves)}")

print(f"open all files, no processing -> {time.time() - start} seconds")
print(counts)
