import json
from typing import List, Set, Optional
from utils import json_utils

    
rhel8 = json_utils.safe_load("./test_in/PAR_List_RPM_simple.rhel8.json")
if rhel8:
    print("RHEL 8:")
    print("Stats for provided list of packages")
    print(f"CVE count -> {len(rhel8)}")

rhel10 = json_utils.safe_load("./test_in/PAR_List_RPM_simple.rhel10.json")
if rhel10:
    print("RHEL 10:")
    print("Stats for provided list of packages")
    print(f"CVE count -> {len(rhel10)}")
