from .source import Source

class NVD(Source):

    feeds = {
        "cve",
        "csaf",
        "vex",
        "sbom"
    }

    def dl_cve(self):
        print(f"Downloading {__class__.__name__} vex...")
    def dl_csaf(self):
        print(f"Downloading {__class__.__name__} csaf...")
    def dl_vex(self):
        print(f"Downloading {__class__.__name__} vex...")
    def dl_sbom(self):
        print(f"Downloading {__class__.__name__} sbom...")


