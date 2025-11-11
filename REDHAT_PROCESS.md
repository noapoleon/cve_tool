# REDHAT_PROCESS.md

## Overview

Red Hat provides several endpoints for querying security data:

* **CSAF**: Provides VEX-style security advisories. Includes `product_status` and `remediations` fields.
* **CVE**: Returns CVE JSON files, but these do **not** contain `product_status` or `remediations`. Only lists CVEs as standalone entries.
* **VEX**: Contains detailed status per package. Required for a full understanding of vulnerability impact.
* **OVALSTREAMS**: Used for system-specific scanning; out of scope for package-centric queries here.

**Authoritative Documentation / References:**

* VEX archive base URL: [https://security.access.redhat.com/data/csaf/v2/vex/](https://security.access.redhat.com/data/csaf/v2/vex/)
* Red Hat CSAF/VEX guidelines: [https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/](https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/#:~:text=Red%20Hat%20has%20adopted%20the,packages%20and%20Red%20Hat%20products.)
* Red Hat Security Data API documentation: [https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/](https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/)

**Key takeaway**: If the goal is to build a list of CVEs for a specific package, **VEX/CSAF files are the authoritative source**, not the CVE endpoint.

---

## Fetching CVEs for a Package

To build a list of CVEs for a package efficiently, the recommended workflow is:

1. **Query the CSAF API first to get “fixed” CVEs**

   * Use the endpoint:

     ```
     https://access.redhat.com/hydra/rest/securitydata/csaf.json?package=<package_name>
     ```
   * This **only returns entries where `product_status = "fixed"`**.
   * Example: querying `xorg-x11-server-common` returned 95 fixed CVEs.
   * Benefit: reduces the number of files that need manual parsing later.

2. **Download and extract the VEX archive**

   * Archive URL:

     ```
     https://security.access.redhat.com/data/csaf/v2/vex/archive_latest.txt
     ```
   * The archive is `.tar.zst` compressed. Use Python with `zstandard` + `tarfile` or system tools to extract.
   * Extracted JSON files contain detailed `product_status` and `remediations` fields.

3. **Parse VEX JSON files for the package**

   * Focus only on **non-fixed entries** (usually `known_affected` and `known_not_affected`).
   * Check the `product_status` tree for the package name or its substring.
   * Include all statuses relevant to your workflow; the API may skip `known_not_affected` or `known_affected`.

4. **Build a complete CVE → package map**

   * Use `fixed` from the CSAF API (step 1)
   * Combine with non-fixed entries from the archive (step 3)
   * This produces a full set of CVEs mentioning the package, including statuses the API filters out.

---

## Observed Quirks

* **CVE endpoint is unreliable for packages**

  * Querying `?package=<package_name>` may return **nothing**, even if multiple CVEs exist for that package.
  * Always use CSAF/VEX for completeness.

* **`product_status` formatting is inconsistent**

  * May include:

    * Streamed version info:

      ```
      RT-9.6.0.Z.MAIN.EUS:python3-perf-debuginfo-0:5.14.0-570.16.1.el9_6.x86_64
      ```
    * Product:name style:

      ```
      red_hat_enterprise_linux_10:kernel-core
      ```
    * GitOps / sha256 style:

      ```
      8Base-GitOps-1.3:openshift-gitops-1/applicationset-rhel8@sha256:6def698fb89067d2259a34bced9080d3c7b509b711fda795d73f427f9068c1ba_amd64
      ```
    * Other formats may exist — never assume a single standard.

* **`remediations` is not universal**

  * Only present for certain `product_status` categories.
  * E.g., if a package is `known_not_affected`, there may be no remediation listed.

* **Archive inconsistencies**

  * Compressed VEX archive may be missing some CVE files compared to `index.txt`.
  * Always validate existence via the index first.

* **`product_status` statuses**

  * Common statuses:

    * `fixed` -> included in CSAF API query
    * `known_affected` -> may require archive parsing
    * `known_not_affected` -> may require archive parsing
    * `under_investigation` -> sometimes present

* **SHA256 references**

  * Some product entries use `@sha256:<hash>` style; see e.g., `cve-2022-24905.json`.

---

## Summary

1. **Use CSAF API first** to quickly get the “fixed” CVEs for a package.
2. **Use the VEX archive** to find all additional mentions (`known_affected`, `known_not_affected`).
3. **Do not rely on the CVE endpoint** for completeness; it may silently skip entries.
4. **Normalize your package-matching logic** to handle multiple `product_status` formats.

This approach ensures you capture **all CVEs mentioning a package**, while minimizing processing for the bulk of “fixed” CVEs that the API can give you quickly.
