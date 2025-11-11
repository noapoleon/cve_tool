import json
import requests
from tqdm import tqdm
from pathlib import Path
import tarfile
import zstandard as zstd
import time
import threading
import sys


def get_archive_name(data_dir: Path|str) -> str:
    data_dir = Path(data_dir)
    with open(data_dir/"archive_latest.txt", "r", encoding="utf8") as f:
        return f.readline().strip()


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
        archive_name = get_archive_name(data_dir)
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
    missing_vex = {f"{data_dir/year/cve}.json"
        for year, cves in vex_index.items()
        for cve in cves
        if not Path(data_dir/year/f"{cve}.json").exists()
    }
    for vex in missing_vex:
        print(vex)
    print(f"len missingg {len(missing_vex)}")
    # for year, cves in vex_index.items():
    #     for cve in cves:
    #         print(cve)
    # missing_cves = {f"{data_dir}/{year}/{cve}" for year in vex_index for cve in year}
    # for cve in missing_cves:
    #     print(cve)
    # for cve in tqdm(missing_cves, desc="Downloading missing vex"):
    #     year = cve.split("-")[1]
    #     url = f"https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve}.json"
    #     r = requests.get(url, timeout=10)
    #     if r.status_code == 200:
    #         data = r.json()
    #         with open(data_dir/year/f"{cve}.json", "w", encoding="utf8") as f:
    #             json.dump(data, f, ensure_ascii=False)
    # print(f"how many cves mention {pkg_to_check}? {len(cve_index)}")
    # print(f"Total missing cves: {len(missing_cves)}")
    # print(f"CVEs in index file but not in archive")

def update_archive(data_dir: Path|str, skip_download: bool = False, skip_extract: bool = False) -> bool:
    data_dir = Path(data_dir)

    uptodate = is_latest_archive(data_dir)
    if uptodate:
        print("Archive is up-to-date")
    archive_name = get_archive_name(data_dir)
    if not skip_download or not uptodate:
        if not dl_archive(data_dir, archive_name):
            return False
    if not skip_extract:
        if not extract_archive(data_dir, archive_name):
            return False
    vex_index = get_index(data_dir)
    dl_missing_cves(data_dir/archive_name[:-len(".tar.zst")], vex_index)
    # remove_deletions(data_dir)
    print("Archive was updated")
    return True

if __name__ == "__main__":
    data_dir = Path("./data_test")
    if not update_archive(data_dir, skip_download=True, skip_extract=True):
        print("Archive update failed.")
    # if not update_archive(data_dir, skip_download=True,):
        print("Archive update failed.")
    # update_archive(data_dir, overwrite=True)
