from argparse import ArgumentParser, Namespace
import sys
from pathlib import Path
from typing import Optional, Callable, List, Tuple, Protocol
import json
import pandas as pd
import asyncio
import aiohttp
import types
from types import SimpleNamespace
import time

async def async_downloader(
        url_to_filename: List[Tuple[str, str]],
        timeout: float = 10.0,
        verify: bool = False,
        show_progress: bool = False,
        show_stats: bool = False,
        max_concurrent: int = 100,
        on_fail: Optional[Callable[[str, str, Exception], None]] = None,
        # TODO: func_progress: Optional[Callable[something...]] = None,
) -> SimpleNamespace:
    """Downloads stuff kinda quick

    Args:
        on_fail: Optional callback called on download failure.
            Signature should be: on_fail(url: str, filename: str, exc: Exception)
    Returns:
        stats (SimpleNamespace): Downloads stats comprised of:
            success (int): number of successful downloads
            fails (int): number of failed downloads
            total (int): total number of attempted downloads
            failed_items (list[url: str, filename: str, exc: Exception): detailed list of errors during download
            start (float): start timestamp of the download
            end (float): end timestamp of the download
            duration (float): duration of the download
    """
    # TODO: return stats or something
    stats = SimpleNamespace(
        success = 0,
        fails = 0,
        total = len(url_to_filename),
        failed_items = [],
        start = 0,
        end = 0,
        duration = 0,
    )
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(max_concurrent)

    def _show_progress(eraser: str = "\r"):
        if not show_progress:
            return
        done = stats.success + stats.fails
        bar_length = 30
        filled = int((done / stats.total) * bar_length)
        bar = "#" * filled + "-" * (bar_length - filled)
        print(f"{eraser}[{bar}] {done}/{stats.total} | " +
            f"Success: {stats.success} | " +
            f"Fails: {stats.fails} | " +
            f"Duration: {round(time.time() - stats.start, 3)}", 
              end="" if done != stats.total else None)

    async def _fetch_one(session: aiohttp.ClientSession, url: str, filename: str) -> Optional[str]:
        async with sem:
            try:
                async with session.get(url, timeout=timeout, ssl=verify) as response:
                    response.raise_for_status()
                    # TODO: maybe implement on_success callback
                    # TODO: support multiple default modes:
                    # - write to json
                    # - get json object
                    # - write normal text file
                    # - support other types later (xml, ...)
                    data = await response.json()
                    with open(filename, "w", encoding="utf8") as f:
                        json.dump(data, f, indent=2)
                    async with lock:
                        stats.success += 1
            except Exception as exc:
                async with lock:
                    stats.fails += 1
                    stats.failed_items.append([url, filename, exc])
                if on_fail:
                    on_fail(url, filename, exc)
            finally:
                async with lock:
                    _show_progress()
                    # TODO: progress_func(stats)

    async with aiohttp.ClientSession() as session:
        tasks = [_fetch_one(session, url, filename) for url, filename in url_to_filename]
        stats.start = time.time()
        _show_progress()
            # TODO: progress_func(stats)
        await asyncio.gather(*tasks)
        stats.end = time.time()
        stats.duration = stats.end - stats.start
    if show_stats:
        print(f"[DONE] Success: {stats.success}/{stats.total} | " +
            f"Fails: {stats.fails}/{stats.total} | " +
            f"Duration: {stats.duration}")
    return stats

# TODO: Sync wrapper so you can use it without knowing async stuff
#       Should be the main function if made into a module
#def sync_downloader(args...):
def sync_downloader(
    url_to_filename: List[Tuple[str, str]],
    timeout: float = 10.0,
    verify: bool = False,
    show_progress: bool = False,
    show_stats: bool = False,
    max_concurrent: int = 100,
    on_fail: Optional[Callable[[str, str, Exception], None]] = None,
) -> SimpleNamespace:
    return asyncio.run(async_downloader(
        url_to_filename,
        timeout,
        verify,
        show_progress,
        show_stats,
        max_concurrent,
        on_fail,
    ))

def load_cve_map(input_xlsx: Path) -> dict:
    """Uses input file to construct a map with cve keys and a list of associated cots

    Args:
        input_xlsx (Path): input file to get cve and cots list from
    """
    # TODO: keep rhel version in dict for each cots
    # read input
    CVE_COL     = "CVE"
    COTS_COL    = "COTS" 
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



async def main():
    URL_BASE    = "https://security.access.redhat.com/data/csaf/v2/vex/"
    cve_map = load_cve_map(Path("./test_in/noa.xlsx"))
    out_dir = Path("jsons2")
    out_dir.mkdir(exist_ok=True)
    files = [(f"{URL_BASE}{cve.split('-')[1]}/{cve}.json", str(out_dir / f"{cve}.json")) for cve in cve_map.keys()]
    
    def show_error(url, filename, e):
        print(f"Failed to download {url} to {filename}: {e}")

    # await async_downloader(files, on_fail=show_error, show_progress=True, show_stats=True)
    stats = await async_downloader(files, show_progress=True, show_stats=True)
    for fail in stats.failed_items:
        print(fail)
        print(f"Failed to download from {fail[0]} to {fail[1]}: {fail[2]}")

    # asyncio.run(async_downloader(files))


if __name__ == "__main__":
    #main()
    asyncio.run(main())
