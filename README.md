# EXC-Analyzer
![GitHub release](https://img.shields.io/github/v/release/exc-analyzer/exc)
![Release Date](https://img.shields.io/github/release-date/exc-analyzer/exc)
![License](https://img.shields.io/pypi/l/exc-analyzer)
![Downloads](https://img.shields.io/pypi/dm/exc-analyzer)
![Code Size](https://img.shields.io/github/languages/code-size/exc-analyzer/exc)


EXC-Analyzer is a professional command-line tool for advanced GitHub repository and user analysis, security auditing, and secret scanning. Designed for penetration testers, security researchers, and open-source maintainers, EXC-Analyzer provides deep insights into repository health, contributor activity, and potential security risks.

---

## Table of Contents
- [Website](https://exc-analyzer.web.app/)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Overview](#command-overview)
- [Detailed Command Reference](#detailed-command-reference)
- [API Key Management](#api-key-management)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features
- Repository Analysis: Extracts repository metadata, statistics, language usage, and contributor breakdown.
- User Analysis: Profiles GitHub users, including activity, top repositories, and contribution patterns.
- Secret Scanning: Detects API keys, tokens, and sensitive data in recent commits and files.
- File History: Displays granular commit history for any file in a repository.
- Contributor Impact: Quantifies individual contributor impact based on code changes.
- Security Scoring: Evaluates repository security posture (branch protection, code scanning, etc.).
- Workflow & Content Auditing: Audits repository documentation, policies, and CI/CD workflows for best practices.
- API Key Security: Stores GitHub tokens securely with strict file permissions.

---

## Installation

<img width="48" height="48" src="https://img.icons8.com/color/48/kali-linux.png" alt="kali-linux"/>

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
---

<img width="48" height="48" src="https://img.icons8.com/color/48/windows-10.png" alt="windows-10"/>

### On Windows
```sh
pip install exc-analyzer
```
---

<img width="48" height="48" src="https://img.icons8.com/color/48/mac-logo.png" alt="mac-logo"/> 

### On macOS
```sh
brew install python3
pip3 install exc-analyzer
```
---

![icons8-pypi-48](https://github.com/user-attachments/assets/0df8811b-bb20-415e-a05d-b8571d76fcd8)

### To browse the PYPI page and access detailed information:
[PyPI Project Page](https://pypi.org/project/exc-analyzer/)

---

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

---

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

---

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
  - Linux: `~/.exc/apikey.sec` (permissions: 0600)
  - Windows: `%USERPROFILE%\.exc\apikey.sec`

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

---

## API Key Management
- Your GitHub token is required for all API operations.
- The token is stored securely and never transmitted except to GitHub.
- If you lose or wish to rotate your token, use `exc key --reset`.

---

## Troubleshooting
- API Rate Limits: If you hit GitHub API rate limits, wait and retry later. Use a personal access token with sufficient permissions.
- Missing Output or Slow Results: Large repositories or high API usage may cause delays. Try reducing the number of results or commit range.
- Color Output Issues: If you do not see colored output, ensure your terminal supports ANSI colors (e.g., use modern terminals on Windows or Linux).
- Permission Errors: Ensure you have write access to your home directory for API key storage.

---

## Disclaimer
This tool is intended for professional security auditing, research, and authorized analysis only. Unauthorized use on systems or repositories you do not own or have explicit permission to analyze is strictly prohibited. The author assumes no liability for misuse or damage caused by this tool.

---

## License
See the [LICENSE](LICENSE) file for details.


