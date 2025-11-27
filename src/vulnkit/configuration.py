from pathlib import Path

class Config:
    def __init__(self):
        self.data_dir = Path("./data")
        self.sources = {
            "redhat" : {"vex"},
            # "redhat" : {"vex", "csaf", "cve", "sboms"},
        }

    def set_data_dir(self, path: str | Path):
        self.data_dir = Path(path)
    def set_sources(self, sources: dict):
        self.sources = sources
