# vulnkit (WIP)

> [!CAUTION]
> Heavy restructuring in progress...
> Nothing works yet!

Toolkit for syncing, parsing, and analyzing vulnerability/advisory data.
Currently focused on Red Hat VEX files. CSAF, RHSA, and NVD support planned.

## Todo
- Finish Red Hat sync (integrity checks, retry logic, cleanup)
- Add CSAF + RHSA sync
- Add NVD sync
- Add parsers for VEX/CSAF/CVE
- Add query functions (packages -> CVEs, summaries)
- Add XLSX/CSV export
- Clean up old scripts and unify CLI

# data structure

data
	vex
		redhat
		nvd
		github
	cve
		redhat
		nvd
	csaf
		redhat
	
data
	redhat
		vex
		cve
		csaf
	nvd
		vex
		cve
	github
		csaf
