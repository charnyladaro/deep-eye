<center>
<img src="./assets/Screenshot 2025-10-20 150312.png" height="400">
</center>

# Deep Eye 🔍

An advanced AI-driven vulnerability scanner and penetration testing tool that integrates multiple AI providers (OpenAI, Grok, OLLAMA, Claude) with comprehensive security testing modules for automated bug hunting, intelligent payload generation, and professional reporting.

![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

## 🚀 Features

### Core Capabilities
- **Multi-AI Provider Support**: Dynamic switching between OpenAI, Grok, OLLAMA, and Claude
- **Intelligent Payload Generation**: AI-powered, CVE-aware, context-sensitive payloads
- **Comprehensive Scanning**: 45+ attack methods with framework-specific tests
- **Advanced Reconnaissance**: Passive OSINT, DNS enumeration, subdomain discovery
- **Professional Reporting**: PDF/HTML/JSON reports with OSINT intelligence and executive summaries
- **Collaborative Scanning**: Team-based distributed scanning with session management
- **Custom Plugin System**: Extend Deep Eye with your own vulnerability scanners
- **Multi-Channel Notifications**: Real-time alerts via Email, Slack, and Discord
- **MCP Integration**: Use with Claude Desktop for interactive security testing

### Vulnerability Detection (45+ Types)

#### Core Vulnerabilities
- SQL Injection (Error-based, Blind, Time-based)
- Cross-Site Scripting (XSS) - Reflected, Stored, DOM-based
- Command Injection
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- Path Traversal
- CSRF (Cross-Site Request Forgery)
- Open Redirect
- CORS Misconfiguration
- Security Headers Analysis

#### Advanced Vulnerabilities
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Server-Side Template Injection (SSTI)
- CRLF Injection
- Host Header Injection
- LDAP Injection
- XML Injection
- Insecure Deserialization
- Authentication Bypass
- Information Disclosure
- Sensitive Data Exposure
- JWT Vulnerabilities
- API Security Issues
- GraphQL Vulnerabilities
- WebSocket Vulnerabilities
- Business Logic Flaws
- File Upload Vulnerabilities

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye

# Install dependencies
pip install -r requirements.txt

# Copy example configuration
cp config/config.example.yaml config/config.yaml

# Edit configuration with your settings
nano config/config.yaml
```

### Quick Start

```bash
# Basic scan
python deep_eye.py -u https://example.com

# Scan with custom config
python deep_eye.py -u https://example.com -c custom_config.yaml

# Verbose output
python deep_eye.py -u https://example.com -v
```

## 🔌 MCP Integration for Claude Desktop

Deep Eye can be used as an MCP (Model Context Protocol) server, allowing you to interact with it directly through Claude Desktop using natural conversation instead of API calls.

### Why Use MCP Mode?

- **Cost-Effective**: Uses your Claude Desktop subscription (free or Pro) instead of API credits
- **Interactive**: Conversational security testing workflow
- **Context-Aware**: Claude remembers scan context across the conversation
- **Flexible**: Combine automated scanning with manual analysis
- **Learning-Friendly**: Claude can explain vulnerabilities and suggest fixes

### MCP Setup Guide

#### Prerequisites

- Claude Desktop installed ([Download here](https://claude.ai/download))
- Python 3.8+ with Deep Eye dependencies installed
- MCP package: `pip install mcp`

#### Installation Steps

**1. Install MCP Package**

```bash
cd /path/to/deep-eye
pip install mcp
```

**2. Configure Claude Desktop**

Edit your Claude Desktop configuration file:

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Add the following configuration:

##### For Standard Installation:

```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "python",
      "args": ["/path/to/deep-eye/mcp_server/server.py"]
    }
  }
}
```

##### For WSL (Windows Subsystem for Linux):

```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "wsl.exe",
      "args": [
        "-d", "your-distro-name",
        "--",
        "python3",
        "/path/to/deep-eye/mcp_server/server.py"
      ]
    }
  }
}
```

**Example WSL Configuration:**
```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "wsl.exe",
      "args": [
        "-d", "kali-linux",
        "--",
        "python3",
        "/home/username/deep-eye/mcp_server/server.py"
      ]
    }
  }
}
```

**3. Restart Claude Desktop**

1. Completely quit Claude Desktop (not just close the window)
2. Start it again
3. Look for the 🔌 (plug) icon - this means MCP servers are connected

**4. Verify Connection**

In Claude Desktop, ask:
```
List available Deep Eye security tools
```

You should see 7 tools available!

### Available MCP Tools

1. **scan_url** - Comprehensive vulnerability scanning (SQL injection, XSS, SSRF, XXE, 40+ vulnerabilities)
2. **generate_payload** - AI-powered payload generation with context awareness
3. **analyze_response** - HTTP response security analysis
4. **check_cve** - CVE vulnerability checking for technologies
5. **test_specific_vulnerability** - Targeted vulnerability testing
6. **get_scan_report** - Retrieve detailed scan reports
7. **reconnaissance** - OSINT and information gathering

### Usage Examples

#### Basic Vulnerability Scan
```
User: Scan https://testphp.vulnweb.com for vulnerabilities
Claude: [Executes scan_url tool and presents results]
```

#### Generate Custom Payloads
```
User: Generate SQL injection payloads for https://example.com/login?user=admin
Claude: [Uses generate_payload tool to create context-aware payloads]
```

#### Reconnaissance
```
User: Run reconnaissance on example.com
Claude: [Performs OSINT, DNS enumeration, subdomain discovery]
```

#### Check for CVEs
```
User: Check if WordPress 5.8 has any known vulnerabilities
Claude: [Looks up relevant CVEs with severity ratings]
```

#### Complete Workflow Example

```
User: I need to test example.com for security issues

Claude: I'll help with a comprehensive security assessment. Let's start with reconnaissance.
[Runs reconnaissance tool]
Found:
- 12 subdomains
- Technologies: Apache 2.4.41, PHP 7.4
- 3 email addresses

User: Great, now scan the main site

Claude: [Runs scan_url tool]
Found 8 vulnerabilities:
- SQL Injection (Critical) at /login
- XSS (High) at /search
...

User: Generate custom SQL injection payloads for the login page

Claude: [Generates optimized payloads]
Here are 10 SQL injection payloads tailored for PHP/MySQL...
```

### MCP Troubleshooting

#### MCP Server Not Starting

1. **Check Claude Desktop logs:**
   - Windows: `%APPDATA%\Claude\logs`
   - macOS: `~/Library/Logs/Claude`
   - Linux: `~/.config/Claude/logs`

2. **Verify Python path** in config matches your installation:
   ```bash
   which python3
   # Use the output path in your config
   ```

3. **Ensure dependencies are installed:**
   ```bash
   cd /path/to/deep-eye
   pip install -r requirements.txt
   pip install mcp
   ```

#### Tools Not Appearing

1. Restart Claude Desktop completely
2. Check configuration file syntax (must be valid JSON)
3. Verify file paths are absolute, not relative
4. Check for errors in Claude Desktop logs

#### Permission Errors

Ensure Deep Eye directory is readable:
```bash
chmod -R 755 /path/to/deep-eye
```

### MCP vs API Mode Comparison

| Feature | MCP Mode | API Mode |
|---------|----------|----------|
| **Cost** | Claude subscription only | Per-API-call pricing |
| **Usage** | Interactive, conversational | Automated, scripted |
| **Learning** | Great for learning/manual testing | Great for automation |
| **Flexibility** | Iterate and adapt in real-time | Fixed scan parameters |
| **Setup** | Configure once in Claude Desktop | API keys in config file |

## ⚙️ Configuration

Edit `config/config.yaml` to configure:

### AI Providers
```yaml
ai_providers:
  openai:
    enabled: true
    api_key: "your-api-key"
    model: "gpt-4"
  
  claude:
    enabled: true
    api_key: "your-api-key"
    model: "claude-3-5-sonnet-20241022"
  
  ollama:
    enabled: true
    base_url: "http://localhost:11434"
    model: "llama2"
```

### Scanner Settings
```yaml
scanner:
  target_url: ""
  default_threads: 5
  default_depth: 2
  max_urls: 1000
  timeout: 10
  enable_recon: false
  full_scan: false
  quick_scan: false
  ai_provider: "openai"  # or claude, grok, ollama
```

### Vulnerability Checks
```yaml
vulnerability_scanner:
  enabled_checks:
    - sql_injection
    - xss
    - command_injection
    - ssrf
    - xxe
    - path_traversal
    - csrf
    # ... and 40+ more
```

## 🎯 Usage Examples

### Basic Scanning

```bash
# Simple scan
python deep_eye.py -u https://example.com

# Quick scan (faster, less comprehensive)
python deep_eye.py -u https://example.com --quick

# Full scan with reconnaissance
python deep_eye.py -u https://example.com --full --recon

# Custom depth and threads
python deep_eye.py -u https://example.com --depth 3 --threads 10
```

### Advanced Features

```bash
# Use specific AI provider
python deep_eye.py -u https://example.com --ai-provider claude

# Generate report
python deep_eye.py -u https://example.com --report-format pdf

# Test specific vulnerability
python deep_eye.py -u https://example.com --test sql_injection

# Use proxy
python deep_eye.py -u https://example.com --proxy http://127.0.0.1:8080
```

## 📊 Reports

Deep Eye generates comprehensive reports in multiple formats:

- **PDF**: Professional reports with executive summary
- **HTML**: Interactive web-based reports
- **JSON**: Machine-readable format for automation

Reports include:
- Vulnerability details and severity ratings
- Proof of concepts and exploitation steps
- Remediation recommendations
- CVSS scores
- Executive summary for management

## 🔐 Security & Legal

### Important Notice

⚠️ **This tool is for authorized security testing only**

- Only test systems you own or have explicit written permission to test
- Unauthorized security testing is illegal in most jurisdictions
- The developers assume no liability for misuse of this tool

### Responsible Use

Deep Eye is designed for:
- Penetration testing with proper authorization
- Security research and education
- Bug bounty programs
- Your own applications and infrastructure

## 🛠️ Development

### Project Structure

```
deep-eye/
├── core/              # Core scanning engine
├── modules/           # Vulnerability detection modules
├── ai_providers/      # AI provider integrations
├── utils/             # Utility functions
├── config/            # Configuration files
├── mcp_server/        # MCP server for Claude Desktop
├── docs/              # Documentation
└── examples/          # Usage examples
```

### Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📚 Documentation

- [Installation Guide](INSTALLATION.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [AI Integration Guide](AI_INTEGRATION_SUMMARY.md)
- [MCP Quick Start](MCP_QUICKSTART.md)
- [Testing Methodology](docs/TESTING_GUIDE.md)
- [API Documentation](docs/API.md)
- [Plugin Development](docs/PLUGIN_DEVELOPMENT.md)

## 🐛 Troubleshooting

### Common Issues

**Import Errors**
```bash
pip install -r requirements.txt --upgrade
```

**Permission Denied**
```bash
chmod +x deep_eye.py
```

**SSL Certificate Errors**
```bash
# Use --no-verify flag (not recommended for production)
python deep_eye.py -u https://example.com --no-verify
```

## 🗺️ Roadmap

- [ ] GraphQL security testing enhancements
- [ ] Machine learning-based vulnerability detection
- [ ] Mobile application testing support
- [ ] Cloud security scanning (AWS, Azure, GCP)
- [ ] Kubernetes security assessment
- [ ] CI/CD pipeline integration
- [ ] Web UI for management
- [ ] Multi-user collaboration features

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Security research community
- Open source security tools
- AI model providers (OpenAI, Anthropic, xAI)
- Bug bounty hunters and ethical hackers

## 📧 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/zakirkun/deep-eye/issues)
- **Discussions**: [GitHub Discussions](https://github.com/zakirkun/deep-eye/discussions)
- **Documentation**: [Wiki](https://github.com/zakirkun/deep-eye/wiki)

## ⭐ Star History

If you find Deep Eye useful, please consider giving it a star on GitHub!

---

**Made with ❤️ by the security community**

**Remember: Use responsibly and ethically! 🔒**