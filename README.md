# EXC Analyzer
<<<<<<< HEAD
[![GitHub Release](https://img.shields.io/github/v/release/exc-analyzer/exc?label=release&labelColor=black&cacheSeconds=0
)](https://github.com/exc-analyzer/exc/releases)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/exc-analyzer?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=BRIGHTGREEN&left_text=downloads)](https://pepy.tech/projects/exc-analyzer)
[![Release Date](https://img.shields.io/github/release-date/exc-analyzer/exc?label=release%20date&labelColor=black&color=blue)](https://github.com/exc-analyzer/exc/releases)
[![License](https://img.shields.io/pypi/l/exc-analyzer?label=license&labelColor=black&color=blue)](https://pypi.org/project/exc-analyzer/)
[![Code Size](https://img.shields.io/github/languages/code-size/exc-analyzer/exc?label=code%20size&labelColor=black)](https://github.com/exc-analyzer/exc)
[![Socket Badge](https://badge.socket.dev/pypi/package/exc-analyzer/1.2.1?artifact_id=tar-gz)](https://badge.socket.dev/pypi/package/exc-analyzer/1.2.1?artifact_id=tar-gz)
=======

[![GitHub Release](https://img.shields.io/github/v/release/exc-analyzer/exc?label=release&labelColor=black&cacheSeconds=0)](https://github.com/exc-analyzer/exc/releases)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/exc-analyzer?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=ORANGE&left_text=downloads)](https://pepy.tech/projects/exc-analyzer)
[![Release Date](https://img.shields.io/github/release-date/exc-analyzer/exc?label=release%20date&labelColor=black&color=blue)](https://github.com/exc-analyzer/exc/releases)
[![License](https://img.shields.io/pypi/l/exc-analyzer?label=license&labelColor=black&color=blue)](https://pypi.org/project/exc-analyzer/)
[![Code Size](https://img.shields.io/github/languages/code-size/exc-analyzer/exc?label=code%20size&labelColor=black)](https://github.com/exc-analyzer/exc)
[![Socket Badge](https://badge.socket.dev/pypi/package/exc-analyzer/1.3.0?artifact_id=tar-gz)](https://badge.socket.dev/pypi/package/exc-analyzer/1.3.0?artifact_id=tar-gz)
>>>>>>> ba1aa21 (chore: prepare release v1.3.0 with automated workflow)

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

## Debian/Kali Packaging
1. Prerequisites (on Debian/Ubuntu/Kali):
  ```sh
  sudo apt update
  sudo apt install build-essential debhelper dh-python python3-all python3-build python3-setuptools python3-wheel pybuild-plugin-pyproject
  ```
2. Build the source package (tested on Ubuntu 22.04 / WSL):
  ```sh
  dpkg-buildpackage -us -uc
  ```
  This consumes the metadata under `debian/` and emits `exc-analyzer_*.deb` artifacts.
  For traceability we publish sanitized logs, e.g. `exc-analyzer_1.2.1-1_build.log`.
3. Test the resulting `.deb` locally:
  ```sh
  sudo apt install ./exc-analyzer_1.2.1-1_all.deb
  ```
4. The package is assembled via `dh --with python3 --buildsystem=pybuild`, so `pyproject.toml`, localization catalogs, and console scripts are bundled automatically. `Rules-Requires-Root: no` keeps the build user-friendly.

> Note: `dpkg-buildpackage` is only available on Debian-like systems. Use WSL, a container, or a native Kali/Ubuntu machine rather than Windows PowerShell when producing the actual `.deb` for submission.

## Testing
1. Install development dependencies:
  ```sh
  pip install -e .[dev]
  ```
2. Execute the automated suite:
  ```sh
  pytest
  ```
GitHub Actions also runs these tests on every push/PR across Linux, macOS, and Windows environments to keep the CLI stable for Kali packaging requirements.


## Command Overview
| Command                        | Purpose                                      |
|------------------------------- |----------------------------------------------|
| `key`                          | Manage GitHub API token                      |
| `analysis <owner/repo>`        | Analyze repository statistics and health      |
| `user-a <username>`            | Analyze a GitHub user's profile              |
| `scan-secrets <owner/repo>`    | Scan recent commits for secrets              |
| `file-history <owner/repo> <file>` | Show commit history for a file           |
| `dork-scan <query>`            | Search public code for sensitive patterns     |
| `advanced-secrets <owner/repo>`| Deep scan for secrets in files and commits    |
| `security-score <owner/repo>`  | Evaluate repository security posture         |
| `commit-anomaly <owner/repo>`  | Detect suspicious commit/PR activity         |
| `user-anomaly <username>`      | Detect unusual user activity                 |
| `content-audit <owner/repo>`   | Audit repo docs, policies, and content       |
| `actions-audit <owner/repo>`   | Audit GitHub Actions/CI workflows            |


## Detailed Command Reference

### 1. API Key Management

- **Set or update your GitHub API key:**
  ```sh
  exc key
  ```

- **Reset (delete) your API key:**
  ```sh
  exc key --reset
  ```

- **Migrate key to the OS credential store:**
  ```sh
  exc key --migrate
  ```
### Storage

By default, the API key is stored in the **OS credential store**.

Alternatively, if the OS credential store is not available or migration is not performed, the key can be stored in:

- **Linux:** `~/.exc/build.sec` (permissions: 0600)
- **Windows:** `%USERPROFILE%\.exc\build.sec`

### 2. Repository Analysis
- Analyze repository health, stats, and contributors:
  ```sh
  exc analysis owner/repo
  ```
  - Shows description, stars, forks, languages, top committers, contributors, issues, and PRs.

### 3. User Analysis
- Profile a GitHub user:
  ```sh
  exc user-a username
  ```
  - Displays user info, activity, and top repositories.

### 4. Secret Scanning
- Scan recent commits for secrets:
  ```sh
  exc scan-secrets owner/repo -l 20
  ```
  - Detects AWS keys, GitHub tokens, SSH keys, and generic API keys in the last N commits.
- Deep scan for secrets in files and commits:
  ```sh
  exc advanced-secrets owner/repo -l 30
  ```
  - Scans all files and recent commits for a wide range of secret patterns.

### 5. File History
- Show commit history for a specific file:
  ```sh
  exc file-history owner/repo path/to/file.py
  ```
  - Lists commit messages, authors, dates, and links for the file.

### 6. Dork Scan
- Search public GitHub code for sensitive patterns:
  ```sh
  exc dork-scan "dork query"
  ```
  - Supports advanced queries, file extension and filename filters.

### 7. Contributor Impact
- Estimate contributor impact:
  ```sh
  exc contrib-impact owner/repo
  ```
  - Ranks contributors by code additions/deletions.

### 8. Security Scoring
- Evaluate repository security posture:
  ```sh
  exc security-score owner/repo
  ```
  - Checks for branch protection, code scanning, dependabot, security.md, and more.

### 9. Commit/PR Anomaly Detection
- Detect suspicious commit/PR activity:
  ```sh
  exc commit-anomaly owner/repo
  ```
  - Flags risky commit messages and patterns.

### 10. User Anomaly Detection
- Detect unusual user activity:
  ```sh
  exc user-anomaly username
  ```
  - Highlights abnormal event timing or frequency.

### 11. Content & Workflow Auditing
- Audit repository documentation and policies:
  ```sh
  exc content-audit owner/repo
  ```
  - Checks for LICENSE, SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md, and README quality.
- Audit GitHub Actions/CI workflows:
  ```sh
  exc actions-audit owner/repo
  ```
  - Reviews workflow files for security risks and best practices.


## API Key Management
- Your GitHub token is required for all API operations.
- The token is stored securely and never transmitted except to GitHub.
- If you lose or wish to rotate your token, use `exc key --reset`.

Note on storage and security:

- EXC attempts to use the operating system's secure credential storage when available (for example, Windows Credential Manager, macOS Keychain, or Linux Secret Service) via the optional `keyring` library. This provides the strongest local protection for tokens.
- If OS credential storage is not available, EXC falls back to storing the token in a local file: `~/.exc/build.sec` (Linux/macOS) or `%USERPROFILE%\\.exc\\build.sec` (Windows). The app will attempt to set strict file permissions (0600) on Unix-like systems.
- Important: base64 is used for a simple file-obfuscation fallback and is not a replacement for proper encryption. File permission protections (0600) reduce exposure, but the most robust option is OS credential storage; EXC will prefer that when possible.

## Troubleshooting

*   **Rate Limits:** If you hit API limits, the tool will automatically pause and retry. Using an authenticated token (`exc login`) increases your quota significantly.
*   **Colors:** If output looks strange, ensure your terminal supports ANSI colors.

## License

MIT License. See `LICENSE` file for details.
