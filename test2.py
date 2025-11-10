from argparse import ArgumentParser

parser = ArgumentParser(
    description="Fetch RedHat VEX files from packages listed in an input XLSX file.\n"
    + "For now only supports rhel8 and rhel10.",
    allow_abbrev=False,
)

parser.add_argument("-r", "--rhel", type=int, nargs="+", required=True, help="List of rhel versions to match cve matching")

args = parser.parse_args()

print(args.rhel)
