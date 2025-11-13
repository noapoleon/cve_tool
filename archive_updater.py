import json
import requests
from tqdm import tqdm
from pathlib import Path
import tarfile
import zstandard as zstd
import time
import threading
import async_downloader as adl
from utils import json_utils, archive_utils
from typing import List, Set


def is_latest_archive(data_dir: Path|str) -> bool:
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    latest_file = data_dir/"archive_latest.txt"
    latest_url = "https://security.access.redhat.com/data/csaf/v2/vex/archive_latest.txt"

    try:
        r = requests.get(latest_url, timeout=10)
        r.raise_for_status()
        with open(latest_file, "w", encoding="utf8") as f:
            f.write(r.text.strip())
        # Read archive name
        archive_name = archive_utils.get_archive_name(data_dir)
        # Check if archive exists locally
        if Path(data_dir/archive_name).exists():
            return True
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Server returned error: {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Network request failed: {e}")
    except OSError as e:
        print(f"[ERROR] File operation failed: {e}")
    except ValueError as e:
        print(f"[ERROR] {e}")
    return False


def dl_archive(data_dir: Path|str, archive_name: str, overwrite: bool = True):
    """Download archive safely. Returns True if successful, False otherwise."""
    data_dir = Path(data_dir)
    archive_url = f"https://security.access.redhat.com/data/csaf/v2/vex/{archive_name}"

    if Path(data_dir/archive_name).exists() and not overwrite:
        print(f"[INFO] Skipped download because archive exists: {data_dir/archive_name}")
        return True

    try:
        with requests.get(archive_url, stream=True, timeout=10) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            with open(data_dir/archive_name, "wb") as f, tqdm(
                total=total, unit="B", unit_scale=True, desc="Downloading archive") as bar:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        bar.update(len(chunk))
            return True
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Server error while downloading {archive_name}: {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Network request failed for {archive_name}: {e}")
    except OSError as e:
        print(f"[ERROR] File operation failed for {archive_name}: {e}")
    return False


def extract_archive(data_dir: Path|str, archive_name: str) -> bool:
    data_dir = Path(data_dir)

    def _live_indicator(stop_event):
        start = time.time()
        spins = "|/-\\"
        line = f"Extracting {archive_name}..."
        idx = 0
        while not stop_event.is_set():
            char = spins[idx % len(spins)]
            print(f"\r{line} [{char}] | Elapsed: {round(time.time() - start, 3)}s", end="", flush=True)
            time.sleep(.25)
            idx += 1
        print()

    stop_event = threading.Event()
    indicator_thread = threading.Thread(target=_live_indicator, args=(stop_event,))
    indicator_thread.start()

    try:
        with open(data_dir/archive_name, "rb") as fh:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(fh) as reader:
                with tarfile.open(fileobj=reader, mode="r|*") as tar:
                    tar.extractall(path=data_dir/archive_name[:-len(".tar.zst")])
                    return True
    except (zstd.ZstdError, tarfile.TarError) as e:
        print(f"[ERROR] Failed to extract and decompress {archive_name}: {e}")
    finally:
        stop_event.set()
        indicator_thread.join()
    return False


def get_index(data_dir: Path) -> dict|None:
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    url = "https://security.access.redhat.com/data/csaf/v2/vex/index.txt"
    filename = data_dir/"index.txt"

    try:
        # Fetch index.txt
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        with open(filename, "w", encoding="utf8") as f:
            f.write(r.text.strip())
        # Read archive name
        index = {}
        with open(filename, "r", encoding="utf8") as f:
            for line in f:
                line = line.strip()
                if line:
                    year, _, cve = line.removesuffix(".json").rpartition("/")
                    index.setdefault(year, []).append(cve)
        return index
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Server returned error: {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Network request failed: {e}")
    except OSError as e:
        print(f"[ERROR] File operation failed: {e}")
    except ValueError as e:
        print(f"[ERROR] {e}")
    return None


def dl_missing_cves(data_dir: Path|str, vex_index: dict):
    url_base = "https://security.access.redhat.com/data/csaf/v2/vex"
    total_vex = sum(len(cves) for cves in vex_index.values())
    missing_vex = []
    with tqdm(total=total_vex, desc="Checking missing VEX") as pbar:
        for year, cves in vex_index.items():
            for cve in cves:
                if not Path(data_dir/year/f"{cve}.json").exists():
                    missing_vex.append((f"{url_base}/{year}/{cve}.json", str(data_dir/year/f"{cve}.json")))
                pbar.update(1)
    # missing_vex = [
    #     (f"{url_base}/{year}/{cve}.json", str(data_dir/year/f"{cve}.json"))
    #     for year, cves in tqdm(vex_index.items(), total=total_vex, desc="Checking missing VEX")
    #     for cve in cves
    #     if not Path(data_dir/year/f"{cve}.json").exists()
    # ]
    if missing_vex:
        print(f"[INFO] Downloading {len(missing_vex)} missing VEX files (not in archive)")
        stats = adl.sync_downloader(missing_vex, show_progress=True, show_stats=True)
        if stats.fails:
            print(f"[WARN] Failed to download {stats.fails} VEX files from index:")
            for fail in stats.failed_items:
                print(f"  - {fail[0]} to {fail[1]}")
    # TODO: retry missing (retries: int = 10)
    print(f"[INFO] Archive contains {sum(len(cves) for cves in vex_index.values())} CVE VEX files")


def get_norm_index(data_dir: Path|str) -> dict:
    norm_index = Path(data_dir)/"norm_index.json"
    if norm_index.exists():
        try:
            return json.loads(norm_index.read_text())
        except json.JSONDecodeError:
            pass
    norm_index.write_text("{}")
    return {}


def get_normed_vex(vex_path: Path|str, rhel_vers: Set[str]) -> dict|None:
    data = json_utils.safe_load(vex_path)
    if data is None:
        return None

    # Extract product_status dict
    try:
        product_status = data.get("vulnerabilities", [])[0].get("product_status")
    except (AttributeError, IndexError, TypeError):
        # debug here
        return None

    rhel_fixes = {rhel: (f"red_hat_enterprise_linux_{rhel}", f"el{rhel}") for rhel in rhel_vers}

    def _normalize_pid(pid: str, rhel: str) -> str|None:
        try:
            parts = pid.split(":")
            if len(parts) == 2:
                el, name = parts
                if el == rhel_fixes[rhel][0]:
                    return f"{name.rpartition('/')[2]}:{rhel}"
            elif len(parts) == 3:
                _, ne, vra = parts
                if rhel_fixes[rhel][1] in vra:
                    return f"{ne.rpartition('-')[0]}:{rhel}"
            else:
                return None
        except Exception:
            return None

    new_product_status = {}
    for status, pids in product_status.items():
        new_product_status[status] = set()
        for pid in pids:
            for rhel in rhel_vers:
                new_pid = _normalize_pid(pid, rhel)
                if new_pid:
                    new_product_status[status].add(new_pid)
                    break
    return {
        "rhel_versions": rhel_vers,
        "product_status": new_product_status
    }


def norm_archive_rhel(
        data_dir: Path|str,
        vex_index: dict,
        rhel_vers: Set[str],
):
    """Creates norm files for each Vex file, only keeps name and major rhel version"""
    data_dir = Path(data_dir)

    # get norm index
    if not Path(data_dir/"norm_index.json").exists():
        norm_index = {}
    else:
        norm_index = json_utils.safe_load(data_dir/"norm_index.json")
        if norm_index is None:
            print("[ERROR] Failed to get norm index. Cannot proceed.")
            return
    for year in vex_index:
        norm_index.setdefault(year, {})

    # remove
    def _union_norm_data(old_norm_data: dict, new_norm_data: dict) -> dict:
        old_vers = set(old_norm_data.get("rhel_versions", set()))
        new_norm_data["rhel_versions"] = old_vers | new_norm_data["rhel_versions"]
        for status, old_set in old_norm_data.get("product_status", {}).items():
            if status in new_norm_data["product_status"]:
                new_norm_data["product_status"][status] = new_norm_data["product_status"][status] | set(old_set)
            else:
                new_norm_data["product_status"][status] = set(old_set)
        return new_norm_data

    # Only norm unprocessed cves or rhel versions
    missing_vex_norm = []
    for year, cves in vex_index.items():
        for cve in cves:
            diff = rhel_vers - set(norm_index[year].get(cve, set()))
            if diff:
                missing_vex_norm.append((year, cve, diff))

    fails = []
    count = 0
    batch_size = 500
    for year, cve, rhels in tqdm(
            missing_vex_norm,
            desc=f"Updating {len(missing_vex_norm)} archive vex norms for rhel versions {', '.join(rhel_vers)}"
    ):
        norm_path = data_dir/year/f"{cve}.norm.json"

        old_norm_data = json_utils.safe_load(norm_path)
        if old_norm_data is None:
            old_norm_data = {}

        # norm vex file
        new_norm_data = get_normed_vex(data_dir/year/f"{cve}.json", rhels)
        if new_norm_data is None:
            fails.append(cve)
            continue
        _union_norm_data(old_norm_data, new_norm_data)
        new_norm_data = json_utils.normalize(new_norm_data)

        # write norm file for cve
        if not json_utils.safe_dump(new_norm_data, norm_path):
            fails.append(cve)
            continue

        # update norm_index
        old_vers = set(norm_index[year].get(cve, set()))
        norm_index[year][cve] = list(old_vers | rhel_vers)
        count += 1
        if count % batch_size == 0:
            json_utils.safe_dump(norm_index, data_dir/"norm_index.json")

    if fails:
        # TODO: log file
        print(f"[WARN] Failed to norm {len(fails)} vex files for rhel {', '.join(rhel_vers)}")
        for fail in fails:
            print(f"  - {fail}")

    # save changes to norm_index
    if not json_utils.safe_dump(norm_index, data_dir/"norm_index.json"):
        print(f"[ERROR] Failed to update norm index for rhel {', '.join(rhel_vers)}")



def update_archive(
        data_dir: Path|str,
        skip_download: bool = False,
        skip_extract: bool = False,
        norm_rhel_vers: List[str]|Set[str]|None = None,
) -> bool:
    data_dir = Path(data_dir)

    start = time.time()
    up_to_date = is_latest_archive(data_dir)
    if up_to_date:
        print("[INFO] Archive file is up-to-date")
    archive_name = archive_utils.get_archive_name(data_dir)
    archive_dir = archive_name.removesuffix(".tar.zst")
    if not skip_download:
        if not up_to_date:
            if not dl_archive(data_dir, archive_name):
                return False
    if not skip_extract:
        if not up_to_date:
            if not extract_archive(data_dir, archive_name):
                return False
    vex_index = get_index(data_dir)
    if vex_index:
        dl_missing_cves(data_dir/archive_dir, vex_index)
        if norm_rhel_vers is not None:
            norm_rhel_vers = set(norm_rhel_vers)
            norm_archive_rhel(data_dir/archive_dir, vex_index, norm_rhel_vers)
            # TODO: only renorm what needs to be renormed, check norm_index
    else:
        print("[WARN] Failed to get index. Cannot check completeness or update normed files")
    print(f"[DONE] {round(time.time() - start, 3)} seconds")
    # TODO: add deletions
    # remove_deletions(data_dir)
    return True

if __name__ == "__main__":
    data_dir = Path("./data_test2")
    if not update_archive(data_dir, norm_rhel_vers=["8", "10"]):
        print("Archive update failed.")
    # if not update_archive(data_dir, skip_download=True, skip_extract=True):
    # if not update_archive(data_dir, skip_download=True,):
