- When trying to find a list of vulnerabilities for a specific package here's the workflow used right now:
	1. Query redhat CSAF endpoint with argument `?package=<package_name>`, it will give a list of advisories with multiples CVEs listed in each entry
		- 
	2. From the csaf jsons get the lists of CVEs for each entry in the csaf file
	3. download CVE VEX files from redhat
	4. trim down list of cves by looking in product_status for matching package name

- Notes:
	- the CVE endpoint has an argument for `?package=<package_name>` in the url but IT DOES NOT WORK, it will sometimes NOT RETURN ANYTHING for a package that clearly has multiples cves attributed to it, which is why we're going through the CSAF endpoint
	- beware `product_status` does not seem to have a consistent standard for its entries formatting
	- the `remediations` array will not have entries for all categories of `product_status`, for example if a product is "known_not_affected" in `product_status` it won't have an entry in `remediations`
	- check cve-2022-24905.json for sha256 example in `product_status`

- `product_status` has several different ways to write down a product entry:
	- "stream:name-epoch:version-release.arch"
		- "RT-9.6.0.Z.MAIN.EUS:python3-perf-debuginfo-0:5.14.0-570.16.1.el9_6.x86_64",
	- "product:name"
		- "red_hat_enterprise_linux_10:kernel-core",
	- something with a hash
		- "8Base-GitOps-1.3:openshift-gitops-1/applicationset-rhel8@sha256:6def698fb89067d2259a34bced9080d3c7b509b711fda795d73f427f9068c1ba_amd64"
	- other formats but can't remember/find them again
