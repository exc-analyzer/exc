# EXC

**EXC-Analyzer** is a command-line tool for GitHub repository and user analysis, focused on security auditing, contributor insights, and secret scanning.  
It can be installed and used on both Linux and Windows platforms.

---

## Features

- Analyze GitHub repositories: stars, forks, contributors, language usage
- Analyze GitHub user profiles and top-starred repos
- Scan the latest commits for exposed secrets (API keys, tokens, SSH keys, etc.)
- View the full commit history of a specific file
- Estimate contributor impact based on code additions/deletions
- Secure API key handling (encrypted and stored locally)

---

## Installation


```bash
pip install exc-analyzer
```

## Usage

```bash
exc [command] [arguments] [options]
```

### Commands

| Command                      | Description                                       |
|-----------------------------|---------------------------------------------------|
| `key`                       | Save or reset your GitHub API token              |
| `analysis owner/repo`       | Analyze a GitHub repository                      |
| `user-a username`           | Analyze a GitHub user's profile                  |
| `scan-secrets owner/repo`   | Scan recent commits for potential secrets        |
| `file-history owner/repo file.py` | Show commit history for a specific file |
| `contrib-impact owner/repo` | Measure contributor impact                       |

---

## API Key Setup

Before using any GitHub API features, you must provide your GitHub personal access token:

```bash
exc key
```

The token is securely stored with permissions set to 0600 under:

- Linux: `~/.exc/apikey.sec`
- Windows: `%USERPROFILE%\.exc\apikey.sec`

---

## Disclaimer

This tool is intended for **educational, research, and authorized security auditing** purposes only.  
Unauthorized use on systems or repositories you do not own or have permission to analyze is strictly prohibited.  
The author does not accept any responsibility for misuse or damage caused by this tool.

---

## License

See the [LICENSE](LICENSE) file for details.
