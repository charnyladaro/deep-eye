# Deep Eye Installation Guide

Complete installation instructions for Deep Eye security scanner across different platforms.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
- [Platform-Specific Setup](#platform-specific-setup)
- [Dependency Installation](#dependency-installation)
- [Configuration](#configuration)
- [MCP Server Setup](#mcp-server-setup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

- **Python**: 3.8 or higher
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 500MB for installation + space for scan results
- **Network**: Internet connection for AI providers and reconnaissance
- **OS**: Windows 10+, macOS 10.15+, Linux (any modern distro)

### Recommended Requirements

- **Python**: 3.10 or higher
- **RAM**: 8GB or more
- **Storage**: 2GB+ SSD
- **Network**: Stable broadband connection
- **OS**: Latest stable release of your platform

## Installation Methods

### Method 1: Standard Installation (Recommended)

**Step 1: Clone the Repository**

```bash
# Clone from GitHub
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye
```

**Step 2: Install Python Dependencies**

```bash
# Install all required packages
pip install -r requirements.txt

# For MCP integration (optional)
pip install mcp
```

**Step 3: Configure Deep Eye**

```bash
# Copy example configuration
cp config/config.example.yaml config/config.yaml

# Edit configuration with your preferred editor
nano config/config.yaml
# or
vim config/config.yaml
# or
code config/config.yaml
```

**Step 4: Verify Installation**

```bash
# Check version
python deep_eye.py --version

# View help
python deep_eye.py --help
```

---

### Method 2: Python Package Installation (Coming Soon)

```bash
# This will be available in future releases
pip install deep-eye
```

---

### Method 3: Docker Installation (Coming Soon)

```bash
# This will be available in future releases
docker pull deepeye/scanner
docker run -it deepeye/scanner
```

---

## Platform-Specific Setup

### Windows

**Prerequisites:**
```powershell
# Ensure Python is in PATH
python --version

# Install pip if not available
python -m ensurepip --upgrade
```

**Installation:**
```powershell
# Clone repository
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye

# Install dependencies
pip install -r requirements.txt

# For MCP
pip install mcp

# Copy config
copy config\config.example.yaml config\config.yaml
```

**Optional: Add to PATH**
```powershell
# Add Deep Eye to PATH for easy access
$env:Path += ";C:\path\to\deep-eye"
```

---

### macOS

**Prerequisites:**
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.11

# Verify installation
python3 --version
```

**Installation:**
```bash
# Clone repository
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye

# Install dependencies
pip3 install -r requirements.txt

# For MCP
pip3 install mcp

# Copy config
cp config/config.example.yaml config/config.yaml
```

---

### Linux

**Debian/Ubuntu:**
```bash
# Update package list
sudo apt update

# Install Python and dependencies
sudo apt install python3 python3-pip git

# Clone repository
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye

# Install Python dependencies
pip3 install -r requirements.txt

# For MCP
pip3 install mcp

# Copy config
cp config/config.example.yaml config/config.yaml
```

**Fedora/RHEL:**
```bash
# Install dependencies
sudo dnf install python3 python3-pip git

# Clone repository
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye

# Install Python dependencies
pip3 install -r requirements.txt

# For MCP
pip3 install mcp

# Copy config
cp config/config.example.yaml config/config.yaml
```

**Arch Linux:**
```bash
# Install dependencies
sudo pacman -S python python-pip git

# Clone repository
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye

# Install Python dependencies
pip install -r requirements.txt

# For MCP
pip install mcp

# Copy config
cp config/config.example.yaml config/config.yaml
```

---

### WSL (Windows Subsystem for Linux)

**Setup WSL:**
```powershell
# In PowerShell (Admin)
wsl --install -d Ubuntu
# or for Kali Linux
wsl --install -d kali-linux
```

**Install Deep Eye in WSL:**
```bash
# Inside WSL terminal
cd ~

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install python3 python3-pip git -y

# Clone repository
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye

# Install Python dependencies
pip3 install -r requirements.txt

# For MCP
pip3 install mcp

# Copy config
cp config/config.example.yaml config/config.yaml
```

**Access from Windows:**
- WSL files are accessible at: `\\wsl$\<distro-name>\home\<username>\deep-eye`
- Example: `\\wsl$\Ubuntu\home\user\deep-eye`

---

## Dependency Installation

### Core Dependencies

Deep Eye requires several Python packages. Here's what each one does:

**Web & HTTP:**
- `requests` - HTTP client for making requests
- `beautifulsoup4` - HTML/XML parsing
- `lxml` - XML/HTML processing
- `httpx` - Async HTTP client
- `aiohttp` - Async HTTP framework

**AI Providers:**
- `openai` - OpenAI API client
- `anthropic` - Claude API client
- `ollama` - Ollama API client

**Security Testing:**
- `selenium` - Browser automation
- `webdriver-manager` - Automatic webdriver management
- `dnspython` - DNS toolkit
- `python-whois` - WHOIS client
- `shodan` - Shodan API client

**Reporting:**
- `reportlab` - PDF generation
- `jinja2` - Template engine
- `markdown` - Markdown processing

**Data Processing:**
- `pyyaml` - YAML parser
- `python-dotenv` - Environment variable management
- `pandas` - Data analysis
- `numpy` - Numerical computing

**MCP Integration:**
- `mcp` - Model Context Protocol

### Optional Dependencies

**For PDF Generation (Linux):**
```bash
# Install system dependencies for WeasyPrint
sudo apt install python3-cffi python3-brotli libpango-1.0-0 libpangoft2-1.0-0
pip install weasyprint
```

**For Advanced Features:**
```bash
# Machine learning features
pip install scikit-learn

# WebSocket testing
pip install websocket-client

# Database support
pip install sqlalchemy
```

---

## Configuration

### Basic Configuration

Edit `config/config.yaml`:

**1. Set Target URL (Optional):**
```yaml
scanner:
  target_url: ""  # Can be set via CLI instead
```

**2. Configure AI Provider (Choose One):**

**Option A: OpenAI**
```yaml
ai_providers:
  openai:
    enabled: true
    api_key: "sk-your-api-key-here"
    model: "gpt-4"
```

**Option B: Claude (Anthropic)**
```yaml
ai_providers:
  claude:
    enabled: true
    api_key: "sk-ant-your-api-key-here"
    model: "claude-3-5-sonnet-20241022"
```

**Option C: Ollama (Local/Free)**
```yaml
ai_providers:
  ollama:
    enabled: true
    base_url: "http://localhost:11434"
    model: "llama2"
```

**Option D: MCP (Claude Desktop)**
```yaml
# No API key needed - uses Claude Desktop
# See MCP Server Setup section below
```

**3. Scanner Settings:**
```yaml
scanner:
  default_threads: 5
  default_depth: 2
  max_urls: 1000
  timeout: 10
  enable_recon: false
  full_scan: false
  quick_scan: false
```

**4. Select Vulnerability Checks:**
```yaml
vulnerability_scanner:
  enabled_checks:
    - sql_injection
    - xss
    - command_injection
    - ssrf
    - xxe
    - path_traversal
    # ... add more as needed
```

---

## MCP Server Setup

MCP (Model Context Protocol) allows you to use Deep Eye through Claude Desktop without API costs.

### Prerequisites

- Claude Desktop installed ([Download here](https://claude.ai/download))
- Deep Eye installed and configured
- MCP package: `pip install mcp`

### Configuration Steps

**1. Install MCP Package**

```bash
cd /path/to/deep-eye
pip install mcp
```

**2. Configure Claude Desktop**

Edit the Claude Desktop configuration file:

**Configuration File Locations:**
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

**3. Add Deep Eye MCP Server**

**For Standard Installation:**
```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "python",
      "args": ["/absolute/path/to/deep-eye/mcp_server/server.py"]
    }
  }
}
```

**For WSL (Windows with Linux subsystem):**
```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "wsl.exe",
      "args": [
        "-d", "distro-name",
        "--",
        "python3",
        "/path/in/wsl/to/deep-eye/mcp_server/server.py"
      ]
    }
  }
}
```

**Examples:**

**Windows:**
```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "python",
      "args": ["C:\\Users\\Username\\deep-eye\\mcp_server\\server.py"]
    }
  }
}
```

**macOS/Linux:**
```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "python3",
      "args": ["/home/username/deep-eye/mcp_server/server.py"]
    }
  }
}
```

**WSL:**
```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "wsl.exe",
      "args": [
        "-d", "Ubuntu",
        "--",
        "python3",
        "/home/username/deep-eye/mcp_server/server.py"
      ]
    }
  }
}
```

**4. Restart Claude Desktop**

1. Completely quit Claude Desktop
2. Start it again
3. Look for 🔌 icon (MCP connected)

**5. Verify MCP Connection**

In Claude Desktop, ask:
```
List available Deep Eye security tools
```

You should see 7 tools available!

For detailed MCP usage, see [MCP_QUICKSTART.md](MCP_QUICKSTART.md)

---

## Verification

### Test Basic Functionality

**1. Check Version:**
```bash
python deep_eye.py --version
# Expected: Deep Eye v1.3.0 (Hestia)
```

**2. View Help:**
```bash
python deep_eye.py --help
```

**3. Test Scan (Optional):**
```bash
# Test with a safe target
python deep_eye.py -u https://testphp.vulnweb.com
```

**4. Verify Configuration:**
```bash
# Check if config loads without errors
python -c "from utils.config_loader import ConfigLoader; print('Config OK')"
```

**5. Test AI Provider (if configured):**
```bash
# This will test AI connectivity
python deep_eye.py -u https://example.com --quick-scan
```

---

## Troubleshooting

### Common Issues

#### Import Errors

**Problem:** `ModuleNotFoundError: No module named 'X'`

**Solution:**
```bash
# Reinstall dependencies
pip install -r requirements.txt --upgrade

# Or install specific package
pip install package-name
```

#### Python Version Issues

**Problem:** Incompatible Python version

**Solution:**
```bash
# Check Python version
python --version

# Use Python 3.8+
python3.11 -m pip install -r requirements.txt
```

#### Permission Denied

**Problem:** Cannot execute `deep_eye.py`

**Solution:**
```bash
# Make executable (Linux/macOS)
chmod +x deep_eye.py

# Or run with python
python deep_eye.py
```

#### SSL Certificate Errors

**Problem:** SSL verification fails

**Solution:**
```bash
# Temporary fix (not recommended for production)
python deep_eye.py -u https://example.com --no-verify-ssl

# Better: Update certificates
pip install --upgrade certifi
```

#### Configuration Not Found

**Problem:** `Config file not found: config/config.yaml`

**Solution:**
```bash
# Ensure you're in the deep-eye directory
cd /path/to/deep-eye

# Copy example config
cp config/config.example.yaml config/config.yaml
```

#### MCP Server Not Starting

**Problem:** Claude Desktop can't connect to MCP server

**Solutions:**

1. **Check Python path:**
   ```bash
   # Find Python path
   which python3
   # Use this path in claude_desktop_config.json
   ```

2. **Verify file paths are absolute:**
   ```json
   {
     "command": "/usr/bin/python3",
     "args": ["/home/user/deep-eye/mcp_server/server.py"]
   }
   ```

3. **Check logs:**
   - Windows: `%APPDATA%\Claude\logs`
   - macOS: `~/Library/Logs/Claude`
   - Linux: `~/.config/Claude/logs`

4. **Test MCP server manually:**
   ```bash
   cd /path/to/deep-eye
   python3 mcp_server/server.py
   # Should start without errors
   ```

#### Dependencies Conflict

**Problem:** Package version conflicts

**Solution:**
```bash
# Use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Virtual Environment (Recommended)

Using a virtual environment prevents conflicts with system packages:

**Create Virtual Environment:**
```bash
# Navigate to deep-eye directory
cd /path/to/deep-eye

# Create venv
python -m venv venv

# Activate it
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# When done
deactivate
```

**Use with MCP:**

Update Claude Desktop config to use venv Python:
```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "/path/to/deep-eye/venv/bin/python",
      "args": ["/path/to/deep-eye/mcp_server/server.py"]
    }
  }
}
```

---

## Next Steps

After installation:

1. **Configure AI Provider** - Choose OpenAI, Claude, Ollama, or MCP
2. **Read Documentation** - Check [README.md](README.md) for features
3. **Try MCP Mode** - See [MCP_QUICKSTART.md](MCP_QUICKSTART.md)
4. **Run Your First Scan** - Start with a test target
5. **Customize Settings** - Adjust `config/config.yaml` for your needs

---

## Getting Help

- **Documentation**: [README.md](README.md)
- **MCP Guide**: [MCP_QUICKSTART.md](MCP_QUICKSTART.md)
- **AI Integration**: [AI_INTEGRATION_SUMMARY.md](AI_INTEGRATION_SUMMARY.md)
- **Issues**: [GitHub Issues](https://github.com/zakirkun/deep-eye/issues)
- **Discussions**: [GitHub Discussions](https://github.com/zakirkun/deep-eye/discussions)

---

## Security Reminder

⚠️ **Only test systems you own or have explicit permission to test.**

Unauthorized security testing is illegal. Use Deep Eye responsibly and ethically.

---

**Installation complete! Happy (ethical) hacking! 🔒**