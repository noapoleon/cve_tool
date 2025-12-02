from .source import Source

class RedHat(Source):

    feeds = {
        "cve",
        "csaf",
        "vex",
    }

    def dl_cve(self):
        print(f"Downloading {__class__.__name__} vex...")
    def dl_csaf(self):
        print(f"Downloading {__class__.__name__} csaf...")
    def dl_vex(self):
        print(f"Downloading {__class__.__name__} vex...")
