import json
import sys
from typing import List, Set, Optional
from utils import json_utils
import async_downloader as adl

url_list = [
    ("https://security.access.redhat.com/data/csaf/v2/vex/2020/cve-2020-8694.json", "a"),
    ("https://security.access.redhat.com/data/csaf/v2/vex/2020/cve-2020-8695.json", "b"),
    ("https://security.access.redhat.com/data/csaf/v2/vex/2020/cve-2020-8696.json", "c"), # should fail
    ("https://security.access.redhat.com/data/csaf/v2/vex/2020/cve-2020-8697.json", "d"),
]

def my_on_fail(url, filename, error):
    print(f"url {url} | filename {filename} | error: {error}")
def my_on_success(resp):
    print(f"Response size -> {sys.getsizeof(resp)} Bytes")

adl.sync_downloader(
    url_list,
    show_progress=True,
    show_stats=True,
    on_fail=my_on_fail,
    # on_success=my_on_success
)
