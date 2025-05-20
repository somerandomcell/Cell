# Cell

**CyberSleuth: Your Automated Digital Probe & Initial Access Mapper for Web Reconnaissance.**

This script automates several crucial steps in the initial reconnaissance phase of a penetration test or bug bounty, focusing on web targets. It helps discover subdomains, identify live hosts, fuzz for directories and files, uncover historical URLs, and pinpoint potential entry points.

## ✨ Features

*   **Subdomain Enumeration:** Leverages `sublist3r` to discover subdomains.
*   **Live Host Probing:** Uses `httpx` to identify live web servers from the discovered subdomains.
*   **Directory & File Fuzzing:** Employs `ffuf` for aggressive content discovery on live hosts.
    *   Configurable threading, status codes, recursion, and timeouts.
    *   Intelligent FFUF job monitoring: Stops jobs that yield no new results for a configured duration or exceed max job time.
*   **Historical URL Discovery:** Utilizes `waybackurls` to fetch URLs from the Wayback Machine for all live hostnames.
*   **Entry Point Identification:**
    *   Basic parameter identification from historical URLs (`grep`).
    *   Liveness check for URLs with parameters (filters out 404s).
    *   Advanced pattern matching using `gf` (if installed) for common vulnerabilities like XSS, SQLi, SSRF, LFI, IDOR, etc., on live parameter URLs.
*   **Automated Wordlist Download:** Downloads the specified FFUF wordlist (`raft-medium-directories.txt` from SecLists by default) if not found locally.
*   **Configurable Parameters:** Easily adjust tool paths, FFUF settings, and output directories within the script.
*   **Organized Output:** Saves results in a structured directory format per target, including logs for each tool.
*   **Progress Indicators:** Provides visual feedback for long-running processes.

## 📋 Prerequisites

Make sure you have the following tools installed and available in your `$PATH`. The script will check for their presence.

**Required:**

*   **`sublist3r`**: For subdomain enumeration.
    *   Installation: `git clone https://github.com/aboul3la/Sublist3r.git; cd Sublist3r; sudo pip install -r requirements.txt`
*   **`httpx` (ProjectDiscovery)**: For probing live hosts.
    *   Installation: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
*   **`ffuf`**: For directory and file fuzzing.
    *   Installation: `go install -v github.com/ffuf/ffuf/v2@latest`
*   **`waybackurls`**: For fetching historical URLs.
    *   Installation: `go install -v github.com/tomnomnom/waybackurls@latest`
*   **`curl`**: Standard command-line tool for transferring data. (Usually pre-installed)
*   **`jq`**: Command-line JSON processor (used for FFUF result counting and summary).
    *   Installation: `sudo apt install jq` or `brew install jq`

**Optional (for enhanced entry point identification):**

*   **`gf` (grep-filter)**: For advanced pattern matching.
    *   Installation: `go install -v github.com/tomnomnom/gf@latest`
    *   **Important:** You also need to install `gf` patterns:
        ```bash
        mkdir ~/.gf
        git clone https://github.com/1ndianl33t/Gf-Patterns.git ~/.gf/1ndianl33t-patterns
        # Optionally, copy specific patterns or all to ~/.gf
        cp ~/.gf/1ndianl33t-patterns/*.json ~/.gf/
        # Add more pattern repositories if desired
        ```
*   **`anew`**: Appends unique lines to a file (used with `gf`).
    *   Installation: `go install -v github.com/tomnomnom/anew@latest`

**Wordlists:**

*   The script attempts to download `raft-medium-directories.txt` from SecLists if not found. By default, it tries to save it to:
    *   `/usr/share/seclists/Discovery/Web-Content/` (if running as root)
    *   `$HOME/wordlists/` (if running as a regular user)
    *   You can pre-download SecLists or modify `FFUF_WORDLIST_DIR_EFFECTIVE` and `FFUF_WORDLIST_FILENAME` in the script.

## ⚙️ Installation & Setup

1.  **Clone the repository (or save the script):**
    ```bash
    git clone https://github.com/yourusername/cybersleuth.git # Replace with your actual repo
    cd cybersleuth
    ```
    Or simply save the script content as `cybersleuth.sh`.

2.  **Make the script executable:**
    ```bash
    chmod +x cybersleuth.sh
    ```

3.  **Install Prerequisites:** Ensure all tools listed in the "Prerequisites" section are installed.

4.  **(Optional) Configure Tool Paths & Settings:**
    Open `cybersleuth.sh` in a text editor and modify the variables under the `# --- User Configuration ---` section if needed (e.g., if your tools are not in the default PATH, or to change FFUF settings).

## 🚀 Usage

Run the script with the target domain as an argument:

```bash
./cybersleuth.sh <target_domain>
