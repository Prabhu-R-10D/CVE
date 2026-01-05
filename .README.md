# CVE Applicability Scanner

A continuous vulnerability scanner that monitors the official CVE Project database for new vulnerabilities and automatically assesses their applicability to your software inventory.

## Overview

This application (`app.py`) continuously polls the [CVE Project cvelistV5](https://github.com/CVEProject/cvelistV5) GitHub repository for new delta CVE updates. When new vulnerabilities are detected, it:

1. Downloads and extracts the latest CVE delta files
2. Processes CVE data against your software inventory (`inventory.xlsx`)
3. Performs intelligent component name matching and version range analysis
4. Generates detailed vulnerability reports in JSON, CSV, and Excel formats
5. Logs all activities and maintains processing state


## Prerequisites

- Python 3.9+
- GitHub Personal Access Token (recommended to avoid rate limits)
- Software inventory file (`inventory.xlsx`)

## Setup

1. **Clone or download the repository**

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux / Mac
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**:
   Create a `.env` file in the project root:
   ```
   GITHUB_TOKEN=your_github_personal_access_token_here
   ```

5. **Prepare inventory**:
   Ensure `inventory.xlsx` exists with the following columns:
   - `Application Name`
   - `Software / Component Name`
   - `Installed Version`
   - `Environment`
   - `Internet Facing (Yes/No)`
   - `Business Criticality Tier`
   - `Business Impact`

## Usage

### Continuous Mode (Default)

Run the scanner continuously:
```bash
python app.py
```

The application will:
- Poll for new CVE deltas every 60 seconds
- Download and process new vulnerabilities automatically
- Generate reports when vulnerabilities are found
- Log all activities to `cve_scanner.log`

### One-time Scan

To perform a single scan and exit (modify the script temporarily by commenting out the while loop).

## Output

### Reports
Reports are saved in the `reports/` directory with timestamps:
- `cve_applicability_report_YYYYMMDD_HHMMSS.json`
- `cve_applicability_report_YYYYMMDD_HHMMSS.csv`
- `cve_applicability_report_YYYYMMDD_HHMMSS.xlsx`

### Logs
- Console output and file logging to `cve_scanner.log`
- Debug information saved to `reports/debug_matching.json`

### State
Processing state is maintained in `state.json` to track the last processed delta.

## Configuration

The application uses several directories:
- `downloads/` - Downloaded CVE delta archives
- `extracted/` - Extracted CVE JSON files
- `reports/` - Generated vulnerability reports

All directories are created automatically if they don't exist.

## Matching Logic

### Component Matching
The scanner uses multiple strategies to match inventory components with CVE products:
- Exact matches
- Substring matching
- Token-based matching
- Partial token overlap
- Vendor + product combinations
- Base name matching (ignoring version numbers)

### Version Analysis
Supports complex version ranges including:
- Exact versions
- Inclusive/exclusive ranges
- Less than/greater than comparisons
- Multiple version constraints per CVE
