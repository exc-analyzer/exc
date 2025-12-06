# EXC Analyzer
[![GitHub Release](https://img.shields.io/github/v/release/exc-analyzer/exc?label=release&labelColor=black)](https://github.com/exc-analyzer/exc/releases)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/exc-analyzer?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=ORANGE&left_text=downloads)](https://pepy.tech/projects/exc-analyzer)
[![Release Date](https://img.shields.io/github/release-date/exc-analyzer/exc?label=release%20date&labelColor=black&color=blue)](https://github.com/exc-analyzer/exc/releases)
[![License](https://img.shields.io/pypi/l/exc-analyzer?label=license&labelColor=black&color=blue)](https://pypi.org/project/exc-analyzer/)
[![Code Size](https://img.shields.io/github/languages/code-size/exc-analyzer/exc?label=code%20size&labelColor=black)](https://github.com/exc-analyzer/exc)


EXC-Analyzer is a professional command-line tool for advanced GitHub repository and user analysis, security auditing, and secret scanning. Designed for penetration testers, security researchers, and open-source maintainers, EXC-Analyzer provides deep insights into repository health, contributor activity, and potential security risks.


## Table of Contents
- [Website](https://exc-analyzer.web.app/)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Localization](#localization)
- [Debian/Kali Packaging](#debiankali-packaging)
- [Command Overview](#command-overview)
- [Detailed Command Reference](#detailed-command-reference)
- [API Key Management](#api-key-management)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)
- [License](#license)


## Features
- Repository Analysis: Extracts repository metadata, statistics, language usage, and contributor breakdown.
- User Analysis: Profiles GitHub users, including activity, top repositories, and contribution patterns.
- Secret Scanning: Detects API keys, tokens, and sensitive data in recent commits and files.
- File History: Displays granular commit history for any file in a repository.
- Contributor Impact: Quantifies individual contributor impact based on code changes.
- Security Scoring: Evaluates repository security posture (branch protection, code scanning, etc.).
- Workflow & Content Auditing: Audits repository documentation, policies, and CI/CD workflows for best practices.
- API Key Security: Stores GitHub tokens securely with strict file permissions.
- Intelligent Rate-Limit Handling: Automatically pauses and retries when GitHub API quotas are hit.


## Installation

### On Kali Linux / Debian / Ubuntu 

**Recommended (Global) Installation:**
Install globally using [pipx](https://pypa.github.io/pipx/):

```sh
python3 -m pip install pipx
python3 -m pipx ensurepath
pipx install exc-analyzer
```

**Alternative (Local/Virtual Environment) Installation:**

If you prefer to install only in your current directory (not globally), use a Python virtual environment:

```sh
python3 -m venv env
source env/bin/activate
pip install exc-analyzer
```

### On Windows
```sh
pip install exc-analyzer
```

### On macOS
```sh
brew install python3
pip3 install exc-analyzer
```

## Quick Start
1. Obtain a GitHub Personal Access Token ([instructions](https://github.com/settings/tokens)).
   > **Note:** To avoid issues during analysis, ensure you grant all available permissions to the token. Insufficient permissions may cause errors or incomplete results.
2. Initialize your API key:
   ```sh
   exc key
   ```
3. Run your first analysis:
   ```sh
   exc analysis owner/repo
   ```

## Localization
- EXC Analyzer currently ships with English (`en`) and Turkish (`tr`) interface strings. English remains the default when no preference is set.
- Override the language per invocation (and persist the choice) with `exc --lang tr ...` or `exc -L en ...`.
- Alternatively set `EXC_LANG=tr` (or rely on your shell's `LANG` variable) to influence the default without adding CLI flags.
- Language preferences are stored in `~/.exc/settings.json`. Delete or edit this file if you want to reset the remembered language.
- Missing translations automatically fall back to English so the CLI remains usable even if a key is not localized yet.

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
  For traceability we publish sanitized logs, e.g. `exc-analyzer_1.2.0-1_build.log`.
3. Test the resulting `.deb` locally:
  ```sh
  sudo apt install ./exc-analyzer_1.1.9-1_all.deb
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
- Set or update your GitHub API key:
  ```sh
  exc key
  ```
- Reset (delete) your API key:
  ```sh
  exc key --reset
  ```
- Storage:
  - Linux: `~/.exc/build.sec` (permissions: 0600)
  - Windows: `%USERPROFILE%\.exc\build.sec`

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
- API Rate Limits: If you hit GitHub API rate limits, wait and retry later. Use a personal access token with sufficient permissions.
- Missing Output or Slow Results: Large repositories or high API usage may cause delays. Try reducing the number of results or commit range.
- Color Output Issues: If you do not see colored output, ensure your terminal supports ANSI colors (e.g., use modern terminals on Windows or Linux).
- Permission Errors: Ensure you have write access to your home directory for API key storage.


## Disclaimer
This tool is intended for professional security auditing, research, and authorized analysis only. Unauthorized use on systems or repositories you do not own or have explicit permission to analyze is strictly prohibited. The author assumes no liability for misuse or damage caused by this tool.


## License
See the [LICENSE](LICENSE) file for details.
