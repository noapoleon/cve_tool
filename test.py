import json
from typing import List, Set, Optional
from utils import json_utils

# rhel8 = json_utils.safe_load("./test_in/PAR_List_RPM_simple.rhel8.json")
# rhel10 = json_utils.safe_load("./test_in/PAR_List_RPM_simple.rhel10.json")

rhel8 = json_utils.safe_load("./test_in/mine.rhel8.json")
rhel10 = json_utils.safe_load("./test_in/mine.rhel10.json")
if rhel8 is None or rhel10 is None:
    print("error no data")
else:
    count = sum(len(prods) for prods in rhel8.values())
    count += sum(len(prods) for prods in rhel10.values())
    print(count)
