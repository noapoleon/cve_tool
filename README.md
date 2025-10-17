# cve_tool

Versatile program to download and process cves in different ways.
A CLI tool to **fetch, cache, and analyze CVE data** from RedHat, using an input Excel file containing CVE identifiers and related COTS names.
It can **automatically download CVE JSONs**, **parse remediation information**, and **generate a new Excel report** linking each CVE and COTS to its associated remediation info.

## 📦 Features

- Reads CVE and COTS pairs from an input `.xlsx` file
- Fetches corresponding Red Hat CVE JSON data
- Optionally skips the download step with `--skip-download` and looks in the directory provided with `--jsons-dir` (default: `./jsons/`)
- Extracts remediation details (e.g., fixed package versions)  
- Outputs the results to a new `.xlsx` file
- Can reuse cached JSONs for offline analysis

### **Positional Arguments**

| Argument      | Description                                                   |
| ------------- | ------------------------------------------------------------- |
| `input_xlsx`  | Path to the input Excel file containing CVE and COTS columns. |

### **Optional Arguments**

| Option             | Description                                                      |
| ------------------ | ---------------------------------------------------------------- |
| `-o`, `--output_xlsx` | Path to the output Excel file where results will be saved.    |
| `-j`, `--jsons-dir PATH` | Directory to store or read CVE JSON files. Default: `jsons/`     |
| `-s`, `--skip-download`  | Skip downloading CVE JSONs. Use existing files in `--jsons-dir`. |
| `-v`, `--version`        | Show program version and exit.                                   |
| `-h`, `--help`        | Show program usage.                                   |

## 📜 Input File Format

The input Excel file **must contain two columns**:

| CVE | COTS |
| :-: | :--: |
| CVE-2020-25697 | xorg-x11-server-common-1.20.11-24.el8_10.x86_64 |
| CVE-2020-8694	| kernel-4.18.0-553.76.1.el8_10.x86_64 |
| CVE-2020-8694	| kernel-core-4.18.0-553.76.1.el8_10.x86_64 |

Each row associates a CVE with a COTS name in NEVRA format (name-version-release.arch).
The script will fetch and process remediation data for each CVE accordingly.

## ⚙️ Examples

### 0. Usage

```bash
python --help
```

### 1. Fetch and process CVE data

```bash
python rh_cve_processor.py input.xlsx output.xlsx
```

### 2. Skip downloading (use existing JSONs)

```bash
python rh_cve_processor.py input.xlsx output.xlsx --skip-download
```

### 3. Only download CVE JSONs, don’t process them

```bash
python rh_cve_processor.py input.xlsx output.xlsx --only-download
```

---

## 📂 Directory Structure Example

```
rh_cve_processor/
├── rh_cve_processor.py
├── input.xlsx
├── jsons/
│   ├── CVE-2023-12345.json
│   ├── CVE-2023-54321.json
│   └── ...
└── output.xlsx
```

---

## 🧩 How It Works

1. **Read Input:** Loads the input Excel file and parses the `cve` and `cots` columns using `pandas`.
2. **Fetch Data:** For each CVE, downloads the corresponding JSON from Red Hat’s CVE API unless `--skip-download` is specified.
3. **Cache JSONs:** All downloaded JSON files are saved in `--jsons-dir`.
4. **Parse Remediations:** Extracts relevant remediation info from `data.vulnerabilities.cve-xxxx-xxxxxx.remediations`
5. **Write Output:** Saves all processed information into a new Excel file with the associated COTS name.

## 🧰 Dependencies

| Package         | Purpose                             |
| --------------- | ----------------------------------- |
| `pandas`        | Reading and writing Excel files     |
| `requests`      | Fetching CVE JSON data from Red Hat |
| `argparse`      | Command-line argument parsing       |
| `pathlib`       | File and path handling              |
| `sys`, `typing` | Standard library utilities          |
| `json`          | Parsing Red Hat JSON responses      |
