# CVE Applicability Scanner

A continuous vulnerability scanner that monitors the official CVE Project database for new vulnerabilities and automatically assesses their applicability to your software inventory.

## Overview

This application (`app.py`) continuously polls the [CVE Project cvelistV5](https://github.com/CVEProject/cvelistV5) GitHub repository for new delta CVE updates. When new vulnerabilities are detected, it:

1. Downloads and extracts the latest CVE delta files.
2. Processes CVE data against your software inventory (`inventory.xlsx`).
3. Performs intelligent component name matching and version range analysis.
4. Generates a **PDF Report** with professional styling, company logo, and executive summary.
5. Sends an official vulnerability advisory email with the PDF report attached.
6. Maintains processing state to ensure only new vulnerabilities are reported.

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
   Create a `.env` file in the project root. See the [Environment Variables](#environment-variables) section below for details.

5. **Prepare inventory**:
   Ensure `inventory.xlsx` exists in the root directory with the following columns:
   - `Application Name`
   - `Software / Component Name`
   - `Installed Version`
   - `Environment`
   - `Internet Facing (Yes/No)`
   - `Business Criticality Tier`
   - `Business Impact`

## Usage

Run the scanner:
```bash
python app.py
```

## Environment Variables

The application requires several environment variables to be set in your `.env` file.

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `GITHUB_API_URL` | The URL for the CVE Project releases API. | `https://api.github.com/repos/CVEProject/cvelistV5/releases` |
| `GITHUB_TOKEN` | GitHub Personal Access Token to avoid rate limits. | *(None)* |
| `POLL_INTERVAL_SECONDS` | Interval in seconds between polling for new deltas. | `60` |
| `SMTP_SERVER` | SMTP server address for sending report emails. | *(None)* |
| `SMTP_PORT` | SMTP server port. | `587` |
| `SMTP_USERNAME` | SMTP username/email. | *(None)* |
| `SMTP_PASSWORD` | SMTP password or app-specific password. | *(None)* |
| `ALERT_EMAIL_TO` | The recipient email address for vulnerability alerts. | *(None)* |

### Example `.env` file structure:
```env
GITHUB_TOKEN=your_token_here
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=recipient@example.com
POLL_INTERVAL_SECONDS=60
GITHUB_API_URL=https://api.github.com/repos/CVEProject/cvelistV5/releases
```

## Output

### Reports
PDF reports are saved in the `reports/` directory:
- `CVE_Vulnerability_Report_YYYYMMDD_HHMMSS.pdf`

Standard data reports are also generated:
- `cve_applicability_report_YYYYMMDD_HHMMSS.json`
- `cve_applicability_report_YYYYMMDD_HHMMSS.csv`
- `cve_applicability_report_YYYYMMDD_HHMMSS.xlsx`

### State
The `state.json` file tracks:
- `last_delta`: The last processed ZIP filename.
- `last_run`: Timestamp of the last successful scan.
- `reported_findings`: List of CVE/Component keys already reported to avoid duplication.

## Branding

The PDF report can be branded with your company logo.
- Place your logo at `assets/logo.png`.
- The scanner will automatically include it on the cover page and in the page headers.

## Maintenance

Processing directories (created automatically):
- `downloads/` - Stores downloaded CVE ZIP archives.
- `extracted/` - Stores individual CVE JSON files for analysis.
- `reports/` - Stores generated reports and debug information.
