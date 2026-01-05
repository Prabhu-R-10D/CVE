import os
import json
import requests
import zipfile
from pathlib import Path
from dotenv import load_dotenv
import pandas as pd
from packaging.version import Version, InvalidVersion
import logging
from datetime import datetime
import sys
import time

load_dotenv()

GITHUB_API_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

BASE_DIR = Path(__file__).parent
DOWNLOAD_DIR = BASE_DIR / "downloads"
EXTRACT_DIR = BASE_DIR / "extracted"
REPORT_DIR = BASE_DIR / "reports"
STATE_FILE = BASE_DIR / "state.json"
INVENTORY_FILE = BASE_DIR / "inventory.xlsx"
DEBUG_FILE = REPORT_DIR / "debug_matching.json"

for d in [DOWNLOAD_DIR, EXTRACT_DIR, REPORT_DIR]:
    d.mkdir(exist_ok=True)


if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(BASE_DIR / 'cve_scanner.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_state(state):
    with open(STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2)


def fetch_releases():
    logger.info("Fetching releases from GitHub...")
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    else:
        logger.warning("No GitHub token found - API rate limits may apply")

    r = requests.get(GITHUB_API_URL, headers=headers, timeout=30)
    r.raise_for_status()
    releases = r.json()
    logger.info(f"Found {len(releases)} releases")
    return releases

def get_latest_delta(releases):
    logger.info("Looking for latest delta file...")
    for asset in releases[0].get("assets", []):
        if "delta" in asset["name"].lower():
            logger.info(f"Found delta: {asset['name']}")
            return asset
    return None


def download_file(url, output_path):
    logger.info(f"Downloading {output_path.name}...")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        total_size = int(r.headers.get('content-length', 0))

        with open(output_path, "wb") as f:
            downloaded = 0
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)

                    if total_size > 0 and downloaded % (1024 * 1024) == 0:
                        progress = (downloaded / total_size) * 100
                        logger.info(f"Download progress: {progress:.1f}%")

    logger.info(f"Download complete: {output_path.name}")

def extract_archive(archive_path):
    logger.info(f"Extracting {archive_path.name}...")
    with zipfile.ZipFile(archive_path, "r") as z:
        members = z.namelist()
        logger.info(f"Extracting {len(members)} files...")
        z.extractall(EXTRACT_DIR)
    logger.info("Extraction complete")


def load_inventory():
    logger.info(f"Loading inventory from {INVENTORY_FILE}...")
    df = pd.read_excel(INVENTORY_FILE)
    df.columns = df.columns.str.strip()
    logger.info(f"Loaded {len(df)} inventory items")
    
    logger.info("Inventory components:")
    for idx, row in df.iterrows():
        component = row.get("Software / Component Name", "N/A")
        version = row.get("Installed Version", "N/A")
        logger.info(f"  [{idx+1}] {component} - Version: {version}")
    
    return df


def normalize_version(version_str):
    """Normalize version string for comparison"""
    try:
        cleaned = str(version_str).strip().lower()
        for prefix in ['v', 'version', 'ver']:
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):].strip()
        return Version(cleaned)
    except InvalidVersion:
        logger.debug(f"Invalid version format: {version_str}")
        return None

def is_version_affected(installed, affected_entry):
    """
    Check if installed version is affected based on CVE version ranges
    """
    installed_v = normalize_version(installed)
    if not installed_v:
        logger.debug(f"Could not normalize installed version: {installed}")
        return False

    try:
        # Exact version match
        if "version" in affected_entry:
            match_v = normalize_version(affected_entry["version"])
            if match_v and installed_v == match_v:
                logger.debug(f"Exact version match: {installed} == {affected_entry['version']}")
                return True
        
        # Range checks
        start_inclusive = affected_entry.get("versionStartIncluding")
        start_exclusive = affected_entry.get("versionStartExcluding")
        end_inclusive = affected_entry.get("versionEndIncluding")
        end_exclusive = affected_entry.get("versionEndExcluding")
        less_than = affected_entry.get("lessThan")
        less_than_equal = affected_entry.get("lessThanOrEqual")
        
        has_range = any([start_inclusive, start_exclusive, end_inclusive, end_exclusive, less_than, less_than_equal])
        
        if not has_range:
            logger.debug(f"No range constraints, no match for {installed}")
            return False
        
        # Check lower bound
        if start_inclusive:
            start_v = normalize_version(start_inclusive)
            if start_v and installed_v < start_v:
                logger.debug(f"Version {installed} below start (inclusive): {start_inclusive}")
                return False
        
        if start_exclusive:
            start_v = normalize_version(start_exclusive)
            if start_v and installed_v <= start_v:
                logger.debug(f"Version {installed} at or below start (exclusive): {start_exclusive}")
                return False
        
        # Check upper bound
        if end_inclusive:
            end_v = normalize_version(end_inclusive)
            if end_v and installed_v > end_v:
                logger.debug(f"Version {installed} above end (inclusive): {end_inclusive}")
                return False
        
        if end_exclusive:
            end_v = normalize_version(end_exclusive)
            if end_v and installed_v >= end_v:
                logger.debug(f"Version {installed} at or above end (exclusive): {end_exclusive}")
                return False
        
        if less_than:
            lt_v = normalize_version(less_than)
            if lt_v and installed_v >= lt_v:
                logger.debug(f"Version {installed} not less than: {less_than}")
                return False
        
        if less_than_equal:
            lte_v = normalize_version(less_than_equal)
            if lte_v and installed_v > lte_v:
                logger.debug(f"Version {installed} above lessThanOrEqual: {less_than_equal}")
                return False
        
        logger.debug(f"Version {installed} is within affected range")
        return True
            
    except Exception as e:
        logger.debug(f"Error comparing versions: {e}")
        return False
    
    return False


def components_match(inventory_component, cve_product, cve_vendor=None, cve_package=None):
    """
    Ultra-flexible component matching with extensive debugging
    """
    inv_comp = str(inventory_component).lower().strip()
    cve_prod = str(cve_product).lower().strip() if cve_product else ""
    cve_pkg = str(cve_package).lower().strip() if cve_package else ""
    cve_vend = str(cve_vendor).lower().strip() if cve_vendor else ""
    
    # Clean up common separators
    def tokenize(s):
        """Convert string to set of tokens"""
        return set(s.replace('-', ' ').replace('_', ' ').replace('.', ' ').split())
    
    inv_tokens = tokenize(inv_comp)
    prod_tokens = tokenize(cve_prod) if cve_prod else set()
    pkg_tokens = tokenize(cve_pkg) if cve_pkg else set()
    vend_tokens = tokenize(cve_vend) if cve_vend else set()
    
    # 1. EXACT MATCHES
    if inv_comp == cve_prod:
        logger.debug(f"✓ EXACT product match: '{inventory_component}' == '{cve_product}'")
        return True
    
    if cve_pkg and inv_comp == cve_pkg:
        logger.debug(f"✓ EXACT package match: '{inventory_component}' == '{cve_package}'")
        return True
    
    # 2. DIRECT SUBSTRING MATCHES (both directions)
    if cve_prod and cve_prod in inv_comp:
        logger.debug(f"✓ SUBSTRING match: CVE product '{cve_product}' in inventory '{inventory_component}'")
        return True
    
    if inv_comp in cve_prod and len(inv_comp) > 3:  # Avoid matching very short strings
        logger.debug(f"✓ SUBSTRING match: inventory '{inventory_component}' in CVE product '{cve_product}'")
        return True
    
    if cve_pkg and cve_pkg in inv_comp:
        logger.debug(f"✓ SUBSTRING match: CVE package '{cve_package}' in inventory '{inventory_component}'")
        return True
    
    if cve_pkg and inv_comp in cve_pkg and len(inv_comp) > 3:
        logger.debug(f"✓ SUBSTRING match: inventory '{inventory_component}' in CVE package '{cve_package}'")
        return True
    
    # 3. TOKEN-BASED MATCHING (all CVE product tokens must be in inventory)
    if prod_tokens and prod_tokens.issubset(inv_tokens):
        logger.debug(f"✓ TOKEN match: all CVE product tokens {prod_tokens} found in inventory {inv_tokens}")
        return True
    
    if pkg_tokens and pkg_tokens.issubset(inv_tokens):
        logger.debug(f"✓ TOKEN match: all CVE package tokens {pkg_tokens} found in inventory {inv_tokens}")
        return True
    
    # 4. REVERSE TOKEN MATCHING (all inventory tokens in CVE product)
    if inv_tokens and prod_tokens and inv_tokens.issubset(prod_tokens):
        logger.debug(f"✓ REVERSE TOKEN match: all inventory tokens {inv_tokens} found in CVE product {prod_tokens}")
        return True
    
    if inv_tokens and pkg_tokens and inv_tokens.issubset(pkg_tokens):
        logger.debug(f"✓ REVERSE TOKEN match: all inventory tokens {inv_tokens} found in CVE package {pkg_tokens}")
        return True
    
    # 5. PARTIAL TOKEN OVERLAP (at least 2 significant tokens match)
    significant_tokens = {t for t in inv_tokens if len(t) > 3}  # Ignore short words
    prod_significant = {t for t in prod_tokens if len(t) > 3}
    pkg_significant = {t for t in pkg_tokens if len(t) > 3}
    
    prod_overlap = significant_tokens & prod_significant
    if len(prod_overlap) >= 2:
        logger.debug(f"✓ PARTIAL TOKEN match: {len(prod_overlap)} significant tokens overlap: {prod_overlap}")
        return True
    
    pkg_overlap = significant_tokens & pkg_significant
    if len(pkg_overlap) >= 2:
        logger.debug(f"✓ PARTIAL TOKEN match: {len(pkg_overlap)} significant package tokens overlap: {pkg_overlap}")
        return True
    
    # 6. KEY PRODUCT NAME MATCHING (e.g., "tomcat" in "Apache Tomcat")
    for token in significant_tokens:
        if token in cve_prod or token in cve_pkg:
            # If a significant inventory token appears in CVE, check if it's the main product name
            if len(token) > 4:  # Only for substantial matches
                logger.debug(f"✓ KEY WORD match: significant token '{token}' found in CVE product/package")
                return True
    
    # 7. VENDOR + PRODUCT COMBINATION
    if cve_vend and vend_tokens:
        vendor_in_inv = any(vt in inv_tokens for vt in vend_tokens)
        product_in_inv = any(pt in inv_tokens for pt in prod_tokens) if prod_tokens else False
        
        if vendor_in_inv and product_in_inv:
            logger.debug(f"✓ VENDOR+PRODUCT match: vendor '{cve_vendor}' + product '{cve_product}' both in inventory")
            return True
    
    # 8. SPECIAL CASE: Version numbers or model numbers might be in inventory but not CVE
    # Extract base product name from inventory (remove version/model numbers)
    import re
    inv_base = re.sub(r'\d+', '', inv_comp).strip()
    cve_base = re.sub(r'\d+', '', cve_prod).strip() if cve_prod else ""
    
    if inv_base and cve_base and len(inv_base) > 3 and len(cve_base) > 3:
        if inv_base in cve_base or cve_base in inv_base:
            logger.debug(f"✓ BASE NAME match: '{inv_base}' ~ '{cve_base}' (after removing numbers)")
            return True
    
    logger.debug(f"✗ NO MATCH: '{inventory_component}' vs CVE(product='{cve_product}', vendor='{cve_vendor}', package='{cve_package}')")
    return False


def match_cves_to_inventory(inventory):
    findings = []
    processed_cves = 0
    failed_cves = []
    debug_info = {
        "inventory_components": [],
        "cve_products": [],
        "match_attempts": [],
        "summary": {}
    }
    
    # Store inventory info for debugging
    for idx, row in inventory.iterrows():
        debug_info["inventory_components"].append({
            "index": idx,
            "component": str(row["Software / Component Name"]),
            "version": str(row["Installed Version"])
        })
    
    cve_files = list(EXTRACT_DIR.rglob("*.json"))
    total_cves = len(cve_files)
    logger.info(f"Processing {total_cves} CVE files...")
    
    all_cve_products = set()

    for idx, cve_file in enumerate(cve_files, 1):
        if idx % 100 == 0:
            logger.info(f"Progress: {idx}/{total_cves} CVEs processed")
        
        try:
            with open(cve_file, 'r', encoding='utf-8') as f:
                cve = json.load(f)
            
            meta = cve.get("cveMetadata", {})
            cve_id = meta.get("cveId", "UNKNOWN")
            
            containers = cve.get("containers", {})
            cna = containers.get("cna", {})
            affected_list = cna.get("affected", [])

            if not affected_list:
                logger.debug(f"{cve_id}: No affected products listed")
                continue

            processed_cves += 1
            logger.info(f"\n{'='*80}")
            logger.info(f"Processing {cve_id}")
            logger.info(f"{'='*80}")

            # Log all products in this CVE
            cve_product_info = []
            for affected in affected_list:
                vendor = affected.get("vendor", "")
                product = affected.get("product", "")
                package = affected.get("packageName", "")
                
                product_key = f"{vendor}/{product}" if vendor and product else (product or package)
                all_cve_products.add(product_key)
                
                cve_product_info.append({
                    "vendor": vendor,
                    "product": product,
                    "package": package
                })
                
                logger.info(f"  CVE Product: vendor='{vendor}', product='{product}', package='{package}'")
            
            debug_info["cve_products"].append({
                "cve_id": cve_id,
                "products": cve_product_info
            })

            # Try matching against inventory
            for inv_idx, app in inventory.iterrows():
                component = str(app["Software / Component Name"])
                version = str(app["Installed Version"])
                
                logger.info(f"\n  Checking inventory [{inv_idx+1}]: {component} v{version}")

                for affected in affected_list:
                    vendor = affected.get("vendor", "")
                    product = affected.get("product", "")
                    package = affected.get("packageName", "")
                    
                    match_attempt = {
                        "cve_id": cve_id,
                        "inventory_component": component,
                        "inventory_version": version,
                        "cve_vendor": vendor,
                        "cve_product": product,
                        "cve_package": package,
                        "component_matched": False,
                        "version_matched": False
                    }
                    
                    if not components_match(component, product, vendor, package):
                        match_attempt["reason"] = "component_name_mismatch"
                        debug_info["match_attempts"].append(match_attempt)
                        continue
                    
                    match_attempt["component_matched"] = True
                    logger.info(f"    ✓ Component MATCHED: {component} ~ {product or package}")

                    for v in affected.get("versions", []):
                        status = v.get("status", "")
                        logger.info(f"      Checking version: status={status}, entry={v}")
                        
                        if status != "affected":
                            match_attempt["reason"] = f"status_not_affected: {status}"
                            continue

                        if is_version_affected(version, v):
                            match_attempt["version_matched"] = True
                            match_attempt["affected_range"] = v
                            logger.warning(f"      ✓✓✓ VULNERABILITY FOUND: {cve_id} affects {component} v{version} ✓✓✓")
                            
                            findings.append({
                                "CVE ID": cve_id,
                                "Application Name": app["Application Name"],
                                "Component": app["Software / Component Name"],
                                "Installed Version": version,
                                "Affected Version Range": json.dumps(v),
                                "Vendor": vendor,
                                "Product": product,
                                "Package": package,
                                "Environment": app["Environment"],
                                "Internet Facing": app["Internet Facing (Yes/No)"],
                                "Business Criticality": app["Business Criticality Tier"],
                                "Business Impact": app["Business Impact"],
                                "CVE State": meta.get("state", "UNKNOWN"),
                                "Published Date": meta.get("datePublished", ""),
                            })
                            break
                        else:
                            match_attempt["reason"] = "version_out_of_range"
                    
                    debug_info["match_attempts"].append(match_attempt)

        except json.JSONDecodeError as e:
            failed_cves.append({"file": str(cve_file), "error": f"JSON decode error: {str(e)}"})
            logger.error(f"Failed parsing {cve_file.name}: JSON decode error - {e}")
        except UnicodeDecodeError as e:
            failed_cves.append({"file": str(cve_file), "error": f"Unicode decode error: {str(e)}"})
            logger.error(f"Failed parsing {cve_file.name}: Unicode decode error - {e}")
        except Exception as e:
            failed_cves.append({"file": str(cve_file), "error": str(e)})
            logger.error(f"Failed parsing {cve_file.name}: {e}")

    # Generate summary
    debug_info["summary"] = {
        "total_cve_files": total_cves,
        "processed_cves": processed_cves,
        "failed_cves": len(failed_cves),
        "matches_found": len(findings),
        "unique_cve_products": sorted(list(all_cve_products)),
        "total_match_attempts": len(debug_info["match_attempts"]),
        "component_matches": sum(1 for m in debug_info["match_attempts"] if m["component_matched"]),
        "version_matches": sum(1 for m in debug_info["match_attempts"] if m["version_matched"])
    }

    logger.info(f"\n{'='*80}")
    logger.info("PROCESSING SUMMARY")
    logger.info(f"{'='*80}")
    logger.info(f"  Total CVE files: {total_cves}")
    logger.info(f"  Successfully processed: {processed_cves}")
    logger.info(f"  Failed: {len(failed_cves)}")
    logger.info(f"  Vulnerabilities found: {len(findings)}")
    logger.info(f"  Unique products in CVEs: {len(all_cve_products)}")
    logger.info(f"\n  All CVE Products found:")
    for prod in sorted(list(all_cve_products)):
        logger.info(f"    - {prod}")
    
    # Save debug info
    with open(DEBUG_FILE, 'w', encoding='utf-8') as f:
        json.dump(debug_info, f, indent=2, ensure_ascii=False)
    logger.info(f"\n  Debug info saved to: {DEBUG_FILE}")
    
    if failed_cves:
        failed_log = REPORT_DIR / "failed_cves.json"
        with open(failed_log, 'w', encoding='utf-8') as f:
            json.dump(failed_cves, f, indent=2)
        logger.warning(f"  Failed CVE details: {failed_log}")

    return findings


def write_reports(findings):
    if not findings:
        logger.info("\n[SUCCESS] No applicable CVEs found in inventory")
        return

    df = pd.DataFrame(findings)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = REPORT_DIR / f"cve_applicability_report_{timestamp}.json"
    csv_path = REPORT_DIR / f"cve_applicability_report_{timestamp}.csv"
    excel_path = REPORT_DIR / f"cve_applicability_report_{timestamp}.xlsx"

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    
    df.to_csv(csv_path, index=False, encoding='utf-8')
    df.to_excel(excel_path, index=False, engine='openpyxl')

    logger.info(f"\n[REPORT] Reports written:")
    logger.info(f"   - JSON: {json_path}")
    logger.info(f"   - CSV: {csv_path}")
    logger.info(f"   - Excel: {excel_path}")
    
    if "Business Criticality" in df.columns:
        logger.info("\n[SUMMARY] Findings by Business Criticality:")
        for crit, count in df["Business Criticality"].value_counts().items():
            logger.info(f"   - {crit}: {count} affected component(s)")
    
    if "Environment" in df.columns:
        logger.info("\n[SUMMARY] Findings by Environment:")
        for env, count in df["Environment"].value_counts().items():
            logger.info(f"   - {env}: {count} affected component(s)")


def main():
    logger.info("="*80)
    logger.info("CVE APPLICABILITY SCANNER - CONTINUOUS MODE")
    logger.info("="*80)

    POLL_INTERVAL = 60

    while True:
        try:
            state = load_state()
            releases = fetch_releases()
            delta = get_latest_delta(releases)

            if not delta:
                logger.error("No delta file found. Sleeping...")
                time.sleep(POLL_INTERVAL)
                continue

            if state.get("last_delta") == delta["name"]:
                logger.info("No new CVE delta found. Sleeping...")
                time.sleep(POLL_INTERVAL)
                continue

            logger.info(f"New CVE delta detected: {delta['name']}")

            archive = DOWNLOAD_DIR / delta["name"]
            download_file(delta["browser_download_url"], archive)
            extract_archive(archive)

            inventory = load_inventory()
            findings = match_cves_to_inventory(inventory)
            write_reports(findings)

            save_state({
                "last_delta": delta["name"],
                "last_run": datetime.now().isoformat()
            })

            logger.info("Processing complete. Sleeping until next check...")
            time.sleep(POLL_INTERVAL)

        except Exception as e:
            logger.error(f"Error in polling loop: {e}", exc_info=True)
            logger.info("Retrying after 10 minutes...")
            time.sleep(10 * 60)
if __name__ == "__main__":
    main()