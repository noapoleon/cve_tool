
#!/usr/bin/env python3

from datetime import datetime
from argparse import ArgumentParser, Namespace
import sys
from pathlib import Path
from typing import Optional
import json
import pandas as pd
import asyncio
import aiohttp
import types
from types import SimpleNamespace
import time
import requests

# Stats
stats = SimpleNamespace(
    cve_map = None,
    dl = SimpleNamespace(done = 0, fails = [], total = 0, start = 0, end = 0)
    #process = SimpleNamespace(done = 0, fails = [], total = 0, start = 0, end = 0)
)

async def download_cpe_jsons(
    url_base: str,
    jsons_dir: Path,
    cpe_map: dict,
    download: bool = False
) -> None:
    """Downloads all CVE JSONs from base_url and writes them to disk in jsons_dir"""
    # Construct urls
    if not url_base.endswith("/"):
        url_base = url_base + "/"
    urls = [[cve, url_base + cve.split('-')[1] + "/" + cve + ".json"] for cve in cpe_map.keys()]
    # Fetch urls
    stats.dl.total = len(cpe_map)
    lock = asyncio.Lock()
    def progress(eraser = "\r"):
        if not stats.dl.fails:
            print(f"{eraser}Downloading jsons [{stats.dl.done}/{stats.dl.total}]", end="")
        else:
            print(f"{eraser}Downloading jsons [{stats.dl.done}/{stats.dl.total}], " +
                f"fails [{len(stats.dl.fails)}/{stats.dl.total}]", end="")
    async def fetch_cve_json(session: aiohttp.ClientSession, cve: str, url: str, timeout: float = 10.0) -> Optional[str]:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()
                # TODO: add to cpe map, don't download unless specified
                if download:
                    out_file = 0
                    # out_file = jsons_dir / f"cpes_{results_per_page}_{start_index}.json"
                    with open(out_file, "w", encoding="utf8") as f:
                        json.dump(data, f, indent=2)
        except Exception as e:
            async with lock:
                stats.dl.fails.append([cve, url, e])
        finally:
            async with lock:
                stats.dl.done += 1
                progress()
    # 
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_cve_json(session, url[0], url[1]) for url in urls]
        stats.dl.start = time.time()
        progress(eraser="")
        await asyncio.gather(*tasks)
        stats.dl.end = time.time()
if __name__ == "__main__":
    cpe_dir = Path("cpes_jsons")
    if cpe_dir.exists() and not cpe_dir.is_dir():
        print(f"Fail: {cpe_dir} exists and isn't directory")
        sys.exit(1)
    cpe_dir.mkdir()

    outfile = Path("cpe_concat.json")
    cpe_map = {}
    timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    start_index = 0
    file = Path(f"cpes_{timestamp}_{start_index}.json")

    if not file.exists():
        r = requests.get("https://services.nvd.nist.gov/rest/json/cpes/2.0")
        if r.status_code == 200:
            data = r.json()
            results_per_page = data.get("resultsPerPage")
            # check if i should really fetch start_index or not
            start_index = data.get("startIndex")
            if not any(item is None for item in [results_per_page, start_index]):
                with open(Path(f"cpes_{timestamp}_{start_index}.json"), "w", encoding="utf8") as f:
                    json.dump(data, f, indent=2)

    s
    # if file.exists():
    #     with open(Path(f"cpes_{timestamp}_{start_index}.json"), "r", encoding="utf8") as f:
    #         data = json.load(f)
    #     for ()

        # print(f"resultsPerPage -> {data['resultsPerPage']}")
        # with open(Path("test_out.json"), "w", encoding="utf8") as f:
        #     # json.dump(data, f, indent=2)
        #     json.dump(cpe_map, f, indent=2)

    # asyncio.run(download_cpe_jsons(
    #     url_base="https://services.nvd.nist.gov/rest/json/cpes/2.0",
    #     jsons_dir=Path("cpe_jsons"),
    #     cpe_map=cpe_map,
    #     download=True
    # ))
