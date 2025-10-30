#!/usr/bin/env python

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
        progress_label: Optional[str] = "Downloading ",
        timeout: float = 10.0,
        show_stats: bool = True,
        show_errors: bool = True,
        max_concurrent: int = 100,
        on_fail: Optional[Callable[[str, str, Exception], None]] = None,
        # TODO: func_progress: Optional[Callable[something...]] = None,
) -> None:
    """Downloads stuff kinda quick

    Args:
        on_fail: Optional callback called on download failure.
            Signature should be: on_fail(url: str, filename: str, exc: Exception)
    """
    # TODO: return stats or something
    stats = SimpleNamespace(
        done = 0,
        success = 0,
        fails = [],
        total = len(url_to_filename),
        start = 0,
        end = 0
    )
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(max_concurrent)

    def progress(eraser = "\r"):
        if not stats.fails:
            print(f"{eraser}{progress_label}[{stats.done}/{stats.total}]", end="")
        else:
            print(f"{eraser}{progress_label}[{stats.done}/{stats.total}], " +
                f"fails [{len(stats.fails)}/{stats.total}]", end="")

    async def async_fetch(session: aiohttp.ClientSession, url: str, filename: str) -> Optional[str]:
        async with sem:
            try:
                async with session.get(url, timeout=timeout) as response:
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
            except Exception as e:
                if on_fail:
                    on_fail(url, filename, e)
                async with lock:
                    stats.fails.append([url, filename, e])
            finally:
                async with lock:
                    stats.done += 1
                    progress()
                    # TODO: progress_func(stats)

    async with aiohttp.ClientSession() as session:
        tasks = [async_fetch(session, url, filename) for url, filename in url_to_filename]
        stats.start = time.time()
        if progress_label is not None:
            progress("")
            # TODO: progress_func(stats)
        await asyncio.gather(*tasks)
        stats.end = time.time()
    if progress_label is not None:
        print()
    if show_errors:
        for url, filename, e in stats.fails:
            print(f"[ERROR] Failed to download {url} -> {filename}: {e}")

# TODO: Sync wrapper so you can use it without knowing async stuff
#       Should be the main function if made into a module
#def sync_downloader(args...):
def sync_downloader():
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # inside async context
        # return asyncio.create_task(async_downloader(args...))
        pass
    else:
        # sync context or inactive loop
        # return asyncio.run(async_downloader(args...))
        pass

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
    cve_map = load_cve_map(Path("./test_files/noa.xlsx"))
    out_dir = Path("jsons2")
    out_dir.mkdir(exist_ok=True)
    files = [(f"{URL_BASE}{cve.split('-')[1]}/{cve}.json", str(out_dir / f"{cve}.json")) for cve in cve_map.keys()]
    
    def show_error(url, filename, e):
        print(f"Failed to download {url} to {filename}: {e}")

    await async_downloader(files, progress_label="lalala", on_fail=show_error)
    # asyncio.run(async_downloader(files))


if __name__ == "__main__":
    #main()
    asyncio.run(main())
