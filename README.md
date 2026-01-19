# EXC Analyzer

[![GitHub Release](https://img.shields.io/github/v/release/exc-analyzer/exc?label=release&labelColor=black&cacheSeconds=0)](https://github.com/exc-analyzer/exc/releases)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/exc-analyzer?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=ORANGE&left_text=downloads)](https://pepy.tech/projects/exc-analyzer)
[![Release Date](https://img.shields.io/github/release-date/exc-analyzer/exc?label=release%20date&labelColor=black&color=blue)](https://github.com/exc-analyzer/exc/releases)
[![License](https://img.shields.io/pypi/l/exc-analyzer?label=license&labelColor=black&color=blue)](https://pypi.org/project/exc-analyzer/)
[![Code Size](https://img.shields.io/github/languages/code-size/exc-analyzer/exc?label=code%20size&labelColor=black)](https://github.com/exc-analyzer/exc)
[![Socket Badge](https://badge.socket.dev/pypi/package/exc-analyzer/1.3.0?artifact_id=tar-gz)](https://badge.socket.dev/pypi/package/exc-analyzer/1.3.1?artifact_id=tar-gz)

**EXC Analyzer** is a professional command-line tool for advanced GitHub repository intelligence, security auditing, and content analysis. Designed for security researchers, penetration testers, and open-source maintainers, it bridges the gap between simple metadata and deep, actionable insights.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Authentication](#authentication)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Output & Reports](#output--reports)
- [Localization](#localization)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

*   **Intelligence Gathering:** Deep-dive into repository metadata, contributor impact, and historical anomalies.
*   **Security Auditing:** Score repository security posture, audit GitHub Actions workflows, and scan for secrets in commits/files.
*   **Dork Scanning:** Powerfully search public code using GitHub dorks to find sensitive exposures.
*   **User Profiling:** Analyze user activity patterns, potential anomalies, and contributions.
*   **Smart Rate-Limiting:** Handles API quotas automatically with intelligent pausing and retries.
*   **Localization:** Localization is currently available in English and Turkish, but the infrastructure is ready to expand to a wider range of languages ​​through community contributions.

## Installation

### Kali Linux / Debian
Download the latest `.deb` from [Releases](https://github.com/exc-analyzer/exc/releases) and run:
```bash
sudo dpkg -i exc-analyzer_1.3.0-1_all.deb
sudo apt-get install -f  # Fix dependencies if needed
```

### Windows
```bash
pip install exc-analyzer
```
*(Requires Python 3.7+)*

## Authentication

1.  **Login:**
    ```bash
    exc login
    ```
2.  **Authorize:** The tool will provide a code (and copy it to your clipboard). It will open your browser to GitHub activation.
3.  **Ready:** Paste the code, approve the permissions, and you are done!

The token behaves like a standard GitHub App connection and is stored securely in your OS credential manager.

## Quick Start

**1. Analyze a Repository:**
```bash
exc analysis torvalds/linux
```
**2. Search for Sensitive Data (Dorks) (User's responsibility):**
```bash
exc dork-scan "filename:config.php 'db_password'"
```

**3. Scan for Secrets:**
```bash
exc scan-secrets microsoft/vscode -l 20
```

### Information Gathering
*   **`analysis <owner>/<repo>`** - Get a comprehensive overview of repository health, stats, and top contributors.
*   **`user-a <username>`** - Analyze public profile, top languages, and activity summary.
*   **`contrib-impact <owner>/<repo>`** - Calculate impact scores for individual contributors to identify key maintainers.
*   **`file-history <owner>/<repo> <path>`** - View granular commit history for a specific file.

### Security & Auditing
*   **`security-score <owner>/<repo>`** - Evaluate repository security (branch protection, code scanning, security policies).
*   **`actions-audit <owner>/<repo>`** - Audit GitHub Actions workflows for dangerous triggers and insecure practices.
*   **`scan-secrets <owner>/<repo>`** - Fast scan of recent commits for credentials and tokens.
*   **`advanced-secrets <owner>/<repo>`** - Deep scan of current file contents and history for high-entropy secrets.
*   **`dork-scan <query>`** - Search GitHub for sensitive sensitive code patterns (dorks). Supports export.

### Anomaly Detection
*   **`commit-anomaly <owner>/<repo>`** - Detect suspicious commit times, mass deletions, or unusual messages.
*   **`user-anomaly <username>`** - Identify irregular activity spikes or behavioral outliers for a user.

### Content Audit
*   **`content-audit <owner>/<repo>`** - Check for essential community standards (LICENSE, CODE_OF_CONDUCT, CONTRIBUTING.md).

### Utilities
*   **`login`** - Log in with your GitHub account to start analyzing.
*   **`logout`** - Log out from your GitHub account.

## Output & Reports

Most commands support the `-o` or `--output` flag to save results to a file:

```bash
# Save to a generated filename (e.g., analysis_owner_repo_date.txt)
exc analysis owner/repo -o

# Save to a specific file
exc dork-scan "password" -o results.txt
```

## Localization

Switch languages dynamically using `--lang` or the environment variable:

*   **English (Default):** `exc --lang en analysis owner/repo`
*   **Turkish:** `exc --lang tr analysis owner/repo`

*(Selection is remembered for future commands.)*

## Troubleshooting

*   **Rate Limits:** If you hit API limits, the tool will automatically pause and retry. Using an authenticated token (`exc login`) increases your quota significantly.
*   **Colors:** If output looks strange, ensure your terminal supports ANSI colors.

## License

MIT License. See `LICENSE` file for details.
