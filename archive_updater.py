import json
import requests
from tqdm import tqdm
from pathlib import Path
import tarfile
import zstandard as zstd
import time
import threading
import sys
import async_downloader as adl


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
        count = 0
        with open(filename, "r", encoding="utf8") as f:
            for line in f:
                line = line.strip()
                if line:
                    year, _, cve = line.removesuffix(".json").rpartition("/")
                    index.setdefault(year, []).append(cve)
        print(f"count -> {count}")
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
    missing_vex = [
        (f"{url_base}/{year}/{cve}.json", str(data_dir/year/f"{cve}.json"))
        for year, cves in vex_index.items()
        for cve in cves
        if not Path(data_dir/year/f"{cve}.json").exists()
    ]
    if missing_vex:
        print(f"[INFO] Downloading {len(missing_vex)} missing VEX files (not in archive)")
        stats = adl.sync_downloader(missing_vex, show_progress=True, show_stats=True)
        if stats.fails:
            print(f"[WARN] Failed to download {stats.fails} VEX files from index:")
            for fail in stats.failed_items:
                print(f"  - {fail[0]} to {fail[1]}")
    print(f"[INFO] Archive contains {sum(len(cves) for cves in vex_index.values())} CVE VEX files")

def update_archive(data_dir: Path|str, skip_download: bool = False, skip_extract: bool = False) -> bool:
    data_dir = Path(data_dir)

    start = time.time()
    up_to_date = is_latest_archive(data_dir)
    if up_to_date:
        print("[INFO] Archive is up-to-date")
    archive_name = get_archive_name(data_dir)
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
        dl_missing_cves(data_dir/archive_name[:-len(".tar.zst")], vex_index)
    else:
        print("[WARN] Failed to get index. Cannot check completeness")
    print(f"[DONE] {round(time.time() - start, 3)} seconds")
    # TODO: add deletions
    # remove_deletions(data_dir)
    return True

if __name__ == "__main__":
    data_dir = Path("./data_test")
    if not update_archive(data_dir):
        print("Archive update failed.")
    # if not update_archive(data_dir, skip_download=True, skip_extract=True):
    # if not update_archive(data_dir, skip_download=True,):
