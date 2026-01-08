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
import re
import smtplib
from email.message import EmailMessage
from generate_pdf_report import generate_pdf_report

load_dotenv()

GITHUB_API_URL = os.getenv("GITHUB_API_URL")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
LLM_URL = os.getenv("LLM_URL")
LLM_MODEL = os.getenv("LLM_MODEL")


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


def send_email_with_attachment(subject, body, attachment_path):
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_user = os.getenv("SMTP_USERNAME")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    to_email = os.getenv("ALERT_EMAIL_TO")

    if not all([smtp_server, smtp_user, smtp_pass, to_email]):
        logger.error("Email configuration missing. Skipping email notification.")
        return

    msg = EmailMessage()
    msg["From"] = smtp_user
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with open(attachment_path, "rb") as f:
        file_data = f.read()
        file_name = Path(attachment_path).name
        
        if attachment_path.suffix.lower() == ".pdf":
            maintype, subtype = "application", "pdf"
        else:
            maintype, subtype = "application", "json"
            
        msg.add_attachment(
            file_data,
            maintype=maintype,
            subtype=subtype,
            filename=file_name
        )

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        logger.info(f"[EMAIL] Vulnerability report sent to {to_email}")

    except Exception as e:
        logger.error(f"[EMAIL] Failed to send email: {e}", exc_info=True)


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
        for prefix in ['v', 'version', 'ver', 'release']:
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):].strip()
        cleaned = re.sub(r'^[^\d]+', '', cleaned)
        return Version(cleaned)
    except (InvalidVersion, TypeError):
        logger.debug(f"Invalid version format: {version_str}")
        return None
    
def parse_text_version_range(version_text):
    """
    Convert NVD free-text version ranges like:
    'Before v3.1.49.0' → {'lessThan': '3.1.49.0'}
    """
    if not version_text:
        return None

    text = str(version_text).lower().strip()

    patterns = [
        (r"before\s+v?([\d\.]+)", "lessThan"),
        (r"prior\s+to\s+v?([\d\.]+)", "lessThan"),
        (r"earlier\s+than\s+v?([\d\.]+)", "lessThan"),
        (r"up\s+to\s+and\s+including\s+v?([\d\.]+)", "lessThanOrEqual"),
        (r"through\s+v?([\d\.]+)", "lessThanOrEqual"),
        (r"up\s+to\s+v?([\d\.]+)", "lessThan"),
        (r"below\s+v?([\d\.]+)", "lessThan"),
        (r"<=\s*v?([\d\.]+)", "lessThanOrEqual"),
        (r"<\s*v?([\d\.]+)", "lessThan"),
    ]

    for pattern, key in patterns:
        match = re.search(pattern, text)
        if match:
            return {key: match.group(1)}

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
        version_text = affected_entry.get("version", "")
        
        range_constraints = {}
        
        if version_text:
            parsed = parse_text_version_range(version_text)
            if parsed:
                range_constraints.update(parsed)
                logger.debug(f"Parsed text range '{version_text}' → {parsed}")
        
        start_inclusive = affected_entry.get("versionStartIncluding")
        start_exclusive = affected_entry.get("versionStartExcluding")
        end_inclusive = affected_entry.get("versionEndIncluding")
        end_exclusive = affected_entry.get("versionEndExcluding")
        less_than = range_constraints.get("lessThan") or affected_entry.get("lessThan")
        less_than_equal = range_constraints.get("lessThanOrEqual") or affected_entry.get("lessThanOrEqual")
        
        has_range = any([start_inclusive, start_exclusive, end_inclusive, 
                        end_exclusive, less_than, less_than_equal])
        
        if not has_range and version_text:
            if version_text.strip() == "*":
                logger.debug(f"Wildcard match: all versions affected")
                return True
            
            version_candidates = [v.strip() for v in version_text.split(',')]
            for candidate in version_candidates:
                match_v = normalize_version(candidate)
                if match_v and installed_v == match_v:
                    logger.debug(f"Exact version match: {installed} == {candidate}")
                    return True
            
            logger.debug(f"No match in version list: {installed} not in {version_candidates}")
            return False
        
        if not has_range:
            logger.debug(f"No version constraints found in entry: {affected_entry}")
            return False
        
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
        
        logger.debug(f"Version {installed} IS AFFECTED (within range)")
        return True
        
    except Exception as e:
        logger.warning(f"Error comparing versions: {e}", exc_info=True)
        return False


def generate_llm_analysis(cve_id, description, component, version):
    """
    Generate expert security analysis.
    """
    logger.info(f"Generating LLM analysis for {cve_id}...")
    
    prompt = f"""
    As a senior cybersecurity expert, analyze the following vulnerability:
    
    CVE ID: {cve_id}
    Affected Component: {component}
    Installed Version: {version}
    Description: {description}
    
    Provide a professional security report in JSON format with the following keys. 
    IMPORTANT: All values MUST be string text, NOT nested objects or lists.
    
    1. "Issue Description": A concise technical summary (2-3 sentences).
    2. "Exposure Classification": One of [External, Internal].
    3. "Risk Severity": One of [Critical, High, Medium, Low].
    4. "Impact": A consolidated string describing business and technical impact.
    5. "Fix Recommendation": A consolidated string describing remediation steps.
    6. "Required Timeline": Recommended mitigation timeframe. 
       - Use "Immediate" for Critical risks or High risks with internet exposure.
       - Use "7 days" for High risks.
       - Use "30 days" for Medium and Low risks.

    Return ONLY the raw JSON object. Do not include markdown code blocks or additional text.
    """
    
    payload = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }
    
    try:
        response = requests.post(LLM_URL, json=payload, timeout=60)
        response.raise_for_status()
        result = response.json()
        
        analysis_text = result.get("response", "{}")
        analysis = json.loads(analysis_text)
        
        required_fields = [
            "Issue Description", "Exposure Classification", "Risk Severity", 
            "Impact", "Fix Recommendation", "Required Timeline"
        ]
        
        for field in required_fields:
            if field not in analysis:
                analysis[field] = "Analysis unavailable"
                
        return analysis
        
    except Exception as e:
        logger.error(f"LLM analysis failed for {cve_id}: {e}")
        return {
            "Issue Description": "LLM analysis failed.",
            "Exposure Classification": "Unknown",
            "Risk Severity": "Unknown",
            "Impact": "Unknown",
            "Fix Recommendation": "Manual review required.",
            "Required Timeline": "Manual review required."
        }


def normalize_component_name(name):
    """Normalize component name for matching"""
    if not name:
        return "", set()
    
    name = str(name).lower().strip()
    name = re.sub(r'\bv?\d+[\d\.]*\b', '', name)
    name = re.sub(r'[_\-./]+', ' ', name)
    stopwords = {'the', 'a', 'an', 'and', 'or', 'for', 'with'}
    
    normalized = re.sub(r'[^a-z0-9]+', ' ', name).strip()
    tokens = set(normalized.split()) - stopwords
    
    return normalized, tokens


def components_match(inventory_component, cve_product, cve_vendor=None, cve_package=None):
    """
    Improved component matching with multiple strategies
    Returns True if components match, False otherwise
    """
    inv = str(inventory_component).lower().strip()
    prod = str(cve_product).lower().strip() if cve_product else ""
    pkg = str(cve_package).lower().strip() if cve_package else ""
    vend = str(cve_vendor).lower().strip() if cve_vendor else ""
    
    inv_norm, inv_tokens = normalize_component_name(inv)
    prod_norm, prod_tokens = normalize_component_name(prod)
    pkg_norm, pkg_tokens = normalize_component_name(pkg)
    vend_norm, vend_tokens = normalize_component_name(vend)
    
    logger.debug(f"Matching: inv='{inv}' vs prod='{prod}', vendor='{vend}', pkg='{pkg}'")
    logger.debug(f"  Tokens: inv={inv_tokens}, prod={prod_tokens}, vend={vend_tokens}, pkg={pkg_tokens}")
    
    if prod_norm and inv_norm == prod_norm:
        logger.debug(f"  ✓ Exact product match")
        return True
    
    if pkg_norm and inv_norm == pkg_norm:
        logger.debug(f"  ✓ Exact package match")
        return True
    
    if pkg_tokens and len(pkg_tokens) >= 1:
        if pkg_tokens.issubset(inv_tokens):
            logger.debug(f"  ✓ Package tokens subset match")
            return True
        if inv_tokens.issubset(pkg_tokens) and len(inv_tokens) >= 1:
            logger.debug(f"  ✓ Inventory tokens subset of package")
            return True
    
    if prod_tokens and vend_tokens:
        combined_cve = vend_tokens | prod_tokens
        overlap = len(inv_tokens & combined_cve)
        overlap_ratio = overlap / len(combined_cve) if combined_cve else 0
        
        if overlap_ratio >= 0.6: 
            logger.debug(f"  ✓ Vendor+Product overlap match ({overlap_ratio:.0%})")
            return True
    
    if prod_tokens and len(prod_tokens) >= 2:
        overlap = len(inv_tokens & prod_tokens)
        overlap_ratio = overlap / len(prod_tokens)
        
        if overlap_ratio >= 0.7:
            logger.debug(f"  ✓ Strong product match ({overlap_ratio:.0%})")
            return True
    
    if prod_tokens and len(prod_tokens) == 1:
        prod_token = list(prod_tokens)[0]
        if len(prod_token) >= 3 and prod_token in inv_tokens:
            if vend_tokens:
                if vend_tokens & inv_tokens:
                    logger.debug(f"  ✓ Single token + vendor match")
                    return True
            else:
                logger.debug(f"  ✓ Single significant token match")
                return True
    
    wp_keywords = {'wordpress', 'wp'}
    if inv_tokens & wp_keywords:
        if vend_tokens & wp_keywords or 'wordpress' in vend.replace('-', '').replace('_', ''):
            if prod_tokens and (prod_tokens & inv_tokens):
                logger.debug(f"  ✓ WordPress component match")
                return True
    
    if vend_tokens and prod_tokens:
        if vend_tokens & inv_tokens:
            prod_overlap = len(prod_tokens & inv_tokens)
            if prod_overlap >= 1 and prod_overlap / len(prod_tokens) >= 0.5:
                logger.debug(f"  ✓ Vendor + partial product match")
                return True
    
    aliases = {
        'httpd': ['http', 'server', 'apache'],
        'http_server': ['httpd', 'apache'],
        'mysqld': ['mysql', 'server'],
        'postgresql': ['postgres', 'pgsql'],
        'nginx': ['nginx', 'webserver'],
    }
    
    for prod_token in prod_tokens:
        if prod_token in aliases:
            if any(alias in inv_tokens for alias in aliases[prod_token]):
                logger.debug(f"  ✓ Alias match: {prod_token}")
                return True
    
    for inv_token in inv_tokens:
        if inv_token in aliases:
            if any(alias in prod_tokens for alias in aliases[inv_token]):
                logger.debug(f"  ✓ Inverse alias match: {inv_token}")
                return True
    
    logger.debug(f"  ✗ No match")
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
            descriptions = cna.get("descriptions", [])
            full_description = descriptions[0].get("value", "No description available.") if descriptions else "No description available."
            affected_list = cna.get("affected", [])

            if not affected_list:
                logger.debug(f"{cve_id}: No affected products listed")
                continue

            processed_cves += 1
            logger.info(f"\n{'='*80}")
            logger.info(f"Processing {cve_id}")
            logger.info(f"{'='*80}")

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

            for inv_idx, app in inventory.iterrows():
                component = str(app["Software / Component Name"])
                version = str(app["Installed Version"])
                
                logger.info(f"\n  Checking inventory [{inv_idx+1}]: {component} v{version}")

                for affected in affected_list:
                    vendor = affected.get("vendor", "")
                    product_raw = affected.get("product", "")
                    package = affected.get("packageName", "")
                    
                    if product_raw and ',' in product_raw:
                        sub_products = [p.strip() for p in product_raw.split(',') if p.strip()]
                    else:
                        sub_products = [product_raw] if product_raw else [""]
                    
                    matched_product = None
                    for product in sub_products:
                        if components_match(component, product, vendor, package):
                            matched_product = product
                            break
                    
                    match_attempt = {
                        "cve_id": cve_id,
                        "inventory_component": component,
                        "inventory_version": version,
                        "cve_vendor": vendor,
                        "cve_product": product_raw,
                        "cve_package": package,
                        "component_matched": False,
                        "version_matched": False
                    }
                    
                    if not matched_product:
                        match_attempt["reason"] = "component_name_mismatch"
                        debug_info["match_attempts"].append(match_attempt)
                        continue
                    
                    product = matched_product
                    match_attempt["component_matched"] = True
                    match_attempt["matched_sub_product"] = matched_product
                    logger.info(f"    ✓ Component MATCHED: {component} ~ {matched_product}")

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
                                "Description": full_description,
                            })
                            
                            # Add LLM Analysis
                            logger.info(f"Adding LLM analysis for {findings[-1]['CVE ID']}")
                            analysis = generate_llm_analysis(
                                findings[-1]["CVE ID"],
                                full_description,
                                findings[-1]["Component"],
                                findings[-1]["Installed Version"]
                            )
                            findings[-1].update(analysis)
                            
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

    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    readable_timestamp = now.strftime("%B %d, %Y, %I:%M %p")
    json_path = REPORT_DIR / f"cve_applicability_report_{timestamp}.json"
    csv_path = REPORT_DIR / f"cve_applicability_report_{timestamp}.csv"
    excel_path = REPORT_DIR / f"cve_applicability_report_{timestamp}.xlsx"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    df.to_csv(csv_path, index=False, encoding="utf-8")
    df.to_excel(excel_path, index=False, engine="openpyxl")

    logger.info(f"\n[REPORT] Reports written:")
    logger.info(f"   - JSON: {json_path}")
    logger.info(f"   - CSV: {csv_path}")
    logger.info(f"   - Excel: {excel_path}")

    pdf_path = REPORT_DIR / f"CVE_Vulnerability_Report_{timestamp}.pdf"
    try:
        generate_pdf_report(findings, pdf_path)
        logger.info(f"   - PDF: {pdf_path}")
    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}")
        pdf_path = None

    subject = f"Security Alert: {len(findings)} CVE Vulnerabilities Detected"

    tier1_count = len(df[df["Business Criticality"].str.contains("Tier-1", na=False)]) if "Business Criticality" in df.columns else 0
    internet_count = len(df[df["Internet Facing"].str.lower() == "yes"]) if "Internet Facing" in df.columns else 0

    body = f"""
OFFICIAL VULNERABILITY ADVISORY
Generated on: {readable_timestamp}

Hello,

The Automated CVE Applicability Scanner has completed its latest assessment of the system inventory. 

CRITICAL FINDINGS SUMMARY:
------------------------------------------------------------
• Total Vulnerabilities Identified: {len(findings)}
• Tier-1 (Critical) Systems Affected: {tier1_count}
• Internet-Facing Systems Exposed: {internet_count}
------------------------------------------------------------

The attached PDF Report contains:
1. Complete Executive Summary of risks
2. Detailed technical breakdown for each affected component
3. Prioritized remediation recommendations

Please treat these findings as sensitive. We recommend reviewing the attached report immediately and initiating the remediation workflow for critical items.

Regards,

10decoders
"""

    email_attachment = pdf_path if pdf_path and pdf_path.exists() else json_path
    
    send_email_with_attachment(
        subject=subject,
        body=body,
        attachment_path=email_attachment
    )

    if "Business Criticality" in df.columns:
        logger.info("\n[SUMMARY] Findings by Business Criticality:")
        for crit, count in df["Business Criticality"].value_counts().items():
            logger.info(f"   - {crit}: {count} affected component(s)")

    if "Environment" in df.columns:
        logger.info("\n[SUMMARY] Findings by Environment:")
        for env, count in df["Environment"].value_counts().items():
            logger.info(f"   - {env}: {count} affected component(s)")


def filter_new_findings(findings, state):
    previous = set(state.get("reported_findings", []))
    new_findings = []

    for f in findings:
        key = f"{f['CVE ID']}|{f['Component']}|{f['Installed Version']}"
        if key not in previous:
            new_findings.append(f)

    return new_findings

def main():
    logger.info("="*80)
    logger.info("CVE APPLICABILITY SCANNER - CONTINUOUS MODE")
    logger.info("="*80)

    POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", 60))

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
                logger.info("Delta unchanged, but rescanning inventory for applicability...")


            logger.info(f"New CVE delta detected: {delta['name']}")

            archive = DOWNLOAD_DIR / delta["name"]
            download_file(delta["browser_download_url"], archive)
            extract_archive(archive)

            inventory = load_inventory()
            findings = match_cves_to_inventory(inventory)

            new_findings = filter_new_findings(findings, state)

            if new_findings:
                logger.info(f"[NEW] {len(new_findings)} new vulnerabilities detected")
                write_reports(new_findings)
            else:
                logger.info("[INFO] No NEW vulnerabilities detected. Skipping report & email.")


            previous = set(state.get("reported_findings", []))

            current = {
                f"{f['CVE ID']}|{f['Component']}|{f['Installed Version']}"
                for f in findings
            }

            reported_keys = sorted(previous | current)


            save_state({
                "last_delta": delta["name"],
                "last_run": datetime.now().isoformat(),
                "reported_findings": reported_keys
            })

            logger.info("Processing complete. Sleeping until next check...")
            time.sleep(POLL_INTERVAL)

        except Exception as e:
            logger.error(f"Error in polling loop: {e}", exc_info=True)
            logger.info("Retrying after 10 minutes...")
            time.sleep(10 * 60)
            
if __name__ == "__main__":
    main()