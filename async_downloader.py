#!/usr/bin/env python

from argparse import ArgumentParser, Namespace
import sys
from pathlib import Path
from typing import Optional, Callable, List, Tuple
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
        show_stats: bool = True,
        show_errors: bool = True,
        # TODO: on_fail: Optional[Callable[[str, Exception], None]] = None,
        # TODO: throttle: int = -1,
        # TODO: progress_func: Optional[Callable[something...]] = None,
) -> None:
    stats = SimpleNamespace(
        done = 0,
        fails = [],
        total = len(url_to_filename),
        start = 0,
        end = 0
    )
    lock = asyncio.Lock()

    def progress(eraser = "\r"):
        if not stats.fails:
            print(f"{eraser}{progress_label}[{stats.done}/{stats.total}]", end="")
        else:
            print(f"{eraser}{progress_label}[{stats.done}/{stats.total}], " +
                f"fails [{len(stats.fails)}/{stats.total}]", end="")

    async def async_fetch(session: aiohttp.ClientSession, url: str, filename: str, timeout: float = 10.0) -> Optional[str]:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()
                # TODO: either return response here or call on_success arg, not sure yet
                with open(filename, "w", encoding="utf8") as f:
                    json.dump(data, f, indent=2)
        except Exception as e:
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

async def main():
    files = [
        ("https://security.access.redhat.com/data/csaf/v2/vex/2020/cve-2020-8694.json", f"jsons_test/test{i}")
        for i in range(200)
    ]
    await async_downloader(files)
    # asyncio.run(async_downloader(files))



if __name__ == "__main__":
    #main()
    asyncio.run(main())
