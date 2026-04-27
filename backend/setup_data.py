import gzip
import json
from pathlib import Path
import requests
import csv

# URLs
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
EDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

DATA_DIR = Path("./data")
DATA_DIR.mkdir(exist_ok=True)

# File paths
NVD_GZ = DATA_DIR / "nvdcve.json.gz"
NVD_JSON = DATA_DIR / "nvd_cve.json"
EDB_CSV = DATA_DIR / "exploitdb.csv"


def download_file(url, path):
    print(f"Downloading {url}...")
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(path, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
    print(f"Saved to {path}")


def extract_nvd():
    print("Extracting NVD gzip...")
    with gzip.open(NVD_GZ, "rb") as f_in:
        with open(NVD_JSON, "wb") as f_out:
            f_out.write(f_in.read())


def process_nvd():
    print("Processing NVD...")
    with open(NVD_JSON, encoding="utf-8") as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])
    print(f"NVD CVE count: {len(vulns)}")

    if vulns:
        print("Sample CVE:", vulns[0]["cve"]["id"])


def process_edb():
    print("Processing Exploit-DB...")

    with open(EDB_CSV, encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"Exploit-DB entries: {len(rows)}")

    if rows:
        print("Sample exploit:", rows[0].get("id"), rows[0].get("description"))


def main():
    # Download both datasets
    download_file(NVD_URL, NVD_GZ)
    download_file(EDB_URL, EDB_CSV)

    # Process NVD
    extract_nvd()
    process_nvd()

    # Process Exploit-DB
    process_edb()


if __name__ == "__main__":
    main()
