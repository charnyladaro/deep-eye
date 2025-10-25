# Deep Eye MCP Quick Start Guide

Get up and running with Deep Eye + Claude Desktop in 5 minutes!

## Table of Contents

- [What is MCP Mode?](#what-is-mcp-mode)
- [Why Use MCP?](#why-use-mcp)
- [Quick Installation](#quick-installation)
- [Configuration](#configuration)
- [Your First Scan](#your-first-scan)
- [Available Tools](#available-tools)
- [Usage Examples](#usage-examples)
- [Workflow Patterns](#workflow-patterns)
- [Tips & Best Practices](#tips--best-practices)
- [Troubleshooting](#troubleshooting)

## What is MCP Mode?

MCP (Model Context Protocol) lets you use Deep Eye's security testing tools directly from Claude Desktop through natural conversation. Instead of paying for API calls, you use your Claude Desktop subscription (free or Pro).

**How it works:**
1. Deep Eye runs as an MCP server in the background
2. Claude Desktop connects to it automatically
3. You ask Claude to run security tests in plain English
4. Claude executes Deep Eye tools and explains the results

## Why Use MCP?

### Advantages

✅ **Free** - Uses Claude Desktop subscription, not API credits
✅ **Interactive** - Conversational workflow, iterate in real-time
✅ **Educational** - Claude explains vulnerabilities as it finds them
✅ **Flexible** - Combine automated scans with manual analysis
✅ **Context-Aware** - Claude remembers previous scan context
✅ **Beginner-Friendly** - No need to memorize command syntax

### Comparison

| Feature | MCP Mode | API Mode | CLI Mode |
|---------|----------|----------|----------|
| **Cost** | Free (subscription) | Per-call pricing | Free |
| **Interface** | Natural conversation | Programmatic | Command line |
| **Learning Curve** | Low | Medium | High |
| **Automation** | Limited | Excellent | Good |
| **Flexibility** | High | Medium | Medium |
| **Explanation** | Built-in | Manual | None |

## Quick Installation

### Step 1: Prerequisites

Ensure you have:
- [ ] Python 3.8+ installed
- [ ] Claude Desktop installed ([Download](https://claude.ai/download))
- [ ] Deep Eye cloned/downloaded
- [ ] Basic dependencies installed

```bash
# Verify Python
python --version
# or
python3 --version
```

### Step 2: Install MCP Package

```bash
cd /path/to/deep-eye
pip install mcp
```

**For system-wide installation issues:**
```bash
# Use --user flag
pip install mcp --user

# Or use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install mcp
```

### Step 3: Install Deep Eye Dependencies

```bash
cd /path/to/deep-eye
pip install -r requirements.txt
```

### Step 4: Configure Deep Eye

```bash
# Copy example config
cp config/config.example.yaml config/config.yaml

# Edit if needed (optional for MCP mode)
nano config/config.yaml
```

## Configuration

### Find Your Claude Config File

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```
Full path example: `C:\Users\YourUsername\AppData\Roaming\Claude\claude_desktop_config.json`

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

### Platform-Specific Setup

#### Windows (Standard Python)

```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "python",
      "args": ["C:\\path\\to\\deep-eye\\mcp_server\\server.py"]
    }
  }
}
```

**Finding your path:**
```powershell
# In PowerShell, navigate to deep-eye folder
cd path\to\deep-eye
pwd
# Copy the output and use it in config
```

#### macOS / Linux

```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "python3",
      "args": ["/absolute/path/to/deep-eye/mcp_server/server.py"]
    }
  }
}
```

**Finding your path:**
```bash
# Navigate to deep-eye folder
cd ~/path/to/deep-eye
pwd
# Copy the output and use it in config
```

#### WSL (Windows Subsystem for Linux)

```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "wsl.exe",
      "args": [
        "-d", "your-distro-name",
        "--",
        "python3",
        "/path/in/wsl/to/deep-eye/mcp_server/server.py"
      ]
    }
  }
}
```

**Common WSL distros:**
- Ubuntu: `"Ubuntu"`
- Kali Linux: `"kali-linux"`
- Debian: `"Debian"`

**Finding WSL path:**
```bash
# In WSL terminal
cd ~/deep-eye
pwd
# Example output: /home/username/deep-eye
```

#### Using Virtual Environment

If you installed in a venv:

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

**Windows venv:**
```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "C:\\path\\to\\deep-eye\\venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\deep-eye\\mcp_server\\server.py"]
    }
  }
}
```

### Complete Configuration Example

```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "python3",
      "args": ["/home/user/projects/deep-eye/mcp_server/server.py"]
    }
  }
}
```

**Important Notes:**
- Use **absolute paths**, not relative
- Use **forward slashes** (/) or **escaped backslashes** (\\\\) on Windows
- Ensure proper JSON syntax (commas, quotes)

## Your First Scan

### 1. Restart Claude Desktop

**Important:** Completely quit and restart Claude Desktop
- Don't just close the window
- Quit the application entirely
- Restart it

### 2. Verify Connection

Look for the **🔌 plug icon** in Claude Desktop - this means MCP servers are connected!

### 3. Test the Connection

In Claude Desktop, ask:
```
What Deep Eye security tools are available?
```

You should see a list of 7 tools!

### 4. Run Your First Scan

Try this:
```
Scan https://testphp.vulnweb.com for vulnerabilities
```

Claude will:
1. Use the `scan_url` tool
2. Crawl the target
3. Test for 40+ vulnerabilities
4. Present findings in an easy-to-read format

## Available Tools

### 1. scan_url 🔍

**Purpose:** Comprehensive security scanning

**What it does:**
- Crawls target site
- Tests for 45+ vulnerability types
- Analyzes security headers
- Checks for misconfigurations

**Parameters:**
- `url` (required) - Target URL
- `depth` (1-10) - Crawl depth
- `quick_scan` (true/false) - Fast scan mode
- `enable_recon` (true/false) - OSINT gathering

**Example usage:**
```
Scan https://example.com for all vulnerabilities
Scan https://example.com with depth 3
Quick scan of https://example.com
```

### 2. generate_payload 💉

**Purpose:** AI-powered payload generation

**What it does:**
- Creates context-aware attack payloads
- Includes WAF bypass techniques
- Tailored to target technology
- Explains how each payload works

**Supported types:**
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- SSRF
- XXE
- Path Traversal
- SSTI (Server-Side Template Injection)
- LDAP Injection
- CRLF Injection

**Example usage:**
```
Generate SQL injection payloads for https://example.com/login?user=admin
Create XSS payloads for a PHP application
Generate 20 SSRF payloads for this API endpoint
```

### 3. analyze_response 📊

**Purpose:** HTTP response security analysis

**What it does:**
- Checks security headers
- Identifies error message disclosure
- Detects information leakage
- Finds potential vulnerabilities

**Example usage:**
```
Analyze this HTTP response for security issues:
[paste response headers and body]
```

### 4. check_cve 🔒

**Purpose:** CVE vulnerability checking

**What it does:**
- Looks up known CVEs
- Identifies affected versions
- Provides severity ratings
- Suggests patches/mitigations

**Example usage:**
```
Check if WordPress 5.8 has any CVEs
Are there vulnerabilities in Apache 2.4.49?
Check nginx 1.18 for security issues
```

### 5. test_specific_vulnerability 🎯

**Purpose:** Targeted vulnerability testing

**What it does:**
- Tests for specific vulnerability type
- Uses custom or auto-generated payloads
- Provides detailed evidence
- Explains exploitation

**Supported tests:**
- SQL Injection
- XSS
- Command Injection
- SSRF
- XXE
- Path Traversal
- CSRF
- Open Redirect
- CORS Misconfiguration
- Security Headers

**Example usage:**
```
Test https://example.com for SQL injection
Check this API for SSRF vulnerabilities
Test for XSS in the search parameter
```

### 6. get_scan_report 📄

**Purpose:** Retrieve scan results

**What it does:**
- Shows previous scan findings
- Formats as summary or detailed
- Exports as JSON if needed
- Categorizes by severity

**Formats:**
- `summary` - Quick overview
- `detailed` - Full findings
- `json` - Machine-readable

**Example usage:**
```
Show me the last scan report
Give me a detailed report of findings
Export scan results as JSON
```

### 7. reconnaissance 🔭

**Purpose:** OSINT and information gathering

**What it does:**
- DNS enumeration
- Subdomain discovery
- Technology detection
- Email harvesting
- Public data gathering

**Modes:**
- Standard - Quick reconnaissance
- Deep - Thorough investigation (slower)

**Example usage:**
```
Run reconnaissance on example.com
Do a deep recon on target.com
Find subdomains of example.com
```

## Usage Examples

### Example 1: Complete Security Assessment

```
User: I need to assess example.com for security issues

Claude: I'll help with a comprehensive security assessment. Let's start with reconnaissance.

[Runs reconnaissance tool]

I found:
- 12 subdomains
- Technologies: Apache 2.4.41, PHP 7.4, MySQL
- 3 email addresses
- Open ports: 80, 443, 22

Would you like me to scan the main site now?

User: Yes, do a full scan

Claude: [Runs scan_url tool with depth 3]

I found 8 vulnerabilities:

**Critical (2):**
- SQL Injection at /login (POST parameter 'username')
- Command Injection at /admin/tools.php

**High (3):**
- XSS at /search (GET parameter 'q')
- Path Traversal at /download.php
- Insecure Deserialization at /api/import

**Medium (3):**
- CSRF on password change
- Missing security headers
- Information disclosure in error messages

User: Generate SQL injection payloads for the login page

Claude: [Uses generate_payload tool]

Here are 10 SQL injection payloads optimized for the MySQL database:

1. `admin' OR '1'='1' --` - Classic bypass
2. `admin' UNION SELECT NULL,NULL,NULL--` - Union-based
...

Each includes explanation and bypass techniques.
```

### Example 2: Quick Vulnerability Check

```
User: Quick scan of https://testsite.com

Claude: [Runs scan_url with quick_scan=true]

Quick scan complete! Found 3 issues:

1. Missing X-Frame-Options header (Clickjacking risk)
2. Weak SSL/TLS configuration
3. Information disclosure in Server header

No critical vulnerabilities detected in quick scan. 
Run a full scan for comprehensive testing?
```

### Example 3: Learning Mode

```
User: What's SSRF and how do I test for it?

Claude: SSRF (Server-Side Request Forgery) is when an attacker can make the server send requests to unintended locations. This can access internal services, cloud metadata, or perform port scanning.

User: Test https://example.com for SSRF

Claude: [Uses test_specific_vulnerability tool]

I tested for SSRF vulnerabilities at https://example.com

Found potential SSRF at /proxy endpoint:
- Parameter: 'url'
- Can access internal services
- Successfully accessed http://localhost/admin

Exploitation: An attacker could access internal resources not meant to be public.

User: Show me exploitation examples

Claude: [Provides detailed examples with payloads and explanations]
```

### Example 4: CVE Research

```
User: Is WordPress 6.0 vulnerable to anything?

Claude: [Uses check_cve tool]

WordPress 6.0 has several known vulnerabilities:

**Critical:**
- CVE-2022-xxxxx - SQL Injection (CVSS 9.8)
  Affects: 6.0 - 6.0.2
  Fixed in: 6.0.3

**High:**
- CVE-2022-yyyyy - XSS (CVSS 7.5)
  Affects: 6.0 - 6.0.1
  Fixed in: 6.0.2

Recommendation: Update to WordPress 6.1 or later
```

### Example 5: Custom Payload Testing

```
User: Test this endpoint for SQL injection using these payloads:
- ' OR 1=1--
- admin'--
- ' UNION SELECT null--

URL: https://example.com/api/users?id=1

Claude: [Uses test_specific_vulnerability with custom payloads]

Testing SQL injection with your custom payloads:

Payload 1: `' OR 1=1--`
- Response: 500 Internal Server Error
- Database error detected: "mysql_fetch_array() expects parameter 1"
- **VULNERABLE** ✓

Payload 2: `admin'--`
- Response: 200 OK but empty result
- Likely filtered or escaped

Payload 3: `' UNION SELECT null--`
- Response: Error "The used SELECT statements have a different number of columns"
- **VULNERABLE** - suggests union-based injection possible

Recommendation: Parameter 'id' is vulnerable to SQL injection.
```

## Workflow Patterns

### Pattern 1: External Assessment

```
1. Reconnaissance → 2. Full Scan → 3. Targeted Testing → 4. Report

User: "Run recon on example.com"
User: "Now scan it completely"
User: "Test the login for SQL injection"
User: "Generate a detailed report"
```

### Pattern 2: API Security Testing

```
1. Scan API endpoints → 2. Check for common issues → 3. Generate payloads

User: "Scan https://api.example.com"
User: "Test for SSRF and XXE"
User: "Generate XXE payloads for XML input"
```

### Pattern 3: Learning & Training

```
1. Explain vulnerability → 2. Demonstrate detection → 3. Show exploitation

User: "Explain path traversal vulnerabilities"
User: "Test https://example.com for path traversal"
User: "Show me how to exploit it"
```

### Pattern 4: Quick Health Check

```
1. Quick scan → 2. Check critical issues only

User: "Quick security check on https://example.com"
User: "Are there any critical vulnerabilities?"
```

## Tips & Best Practices

### Do's ✅

1. **Be Specific**
   - Good: "Scan example.com for SQL injection"
   - Bad: "Test this site"

2. **Provide Context**
   - Good: "This is a PHP/MySQL application"
   - Better: Claude can generate better payloads

3. **Iterate**
   - Start with reconnaissance
   - Then comprehensive scan
   - Finally targeted testing

4. **Ask for Explanations**
   - "Explain this vulnerability"
   - "How would this be exploited?"
   - "What's the remediation?"

5. **Request Specific Formats**
   - "Give me a summary report"
   - "Export as JSON"
   - "Detailed findings please"

### Don'ts ❌

1. **Don't scan without permission**
   - Only test systems you own
   - Get written authorization for pen tests

2. **Don't trust blindly**
   - Always manually verify findings
   - Check for false positives

3. **Don't ignore context**
   - Provide target technology info
   - Mention frameworks if known

4. **Don't forget to verify**
   - "Can you verify this finding?"
   - "Is this a false positive?"

### Getting Best Results

**For Scanning:**
```
Good: "Scan https://example.com with depth 3 and enable reconnaissance"
Better: "Do a deep scan of https://example.com. It's a WordPress site on Apache."
```

**For Payloads:**
```
Good: "Generate SQL injection payloads"
Better: "Generate SQL injection payloads for a MySQL database with WAF bypass techniques"
```

**For Analysis:**
```
Good: "Analyze this response"
Better: "Analyze this response for security issues, it's from a REST API"
```

## Troubleshooting

### MCP Server Not Connecting

**Symptoms:**
- No 🔌 icon in Claude Desktop
- Tools not available
- "Server not found" errors

**Solutions:**

1. **Check configuration file syntax:**
   ```json
   // Valid JSON - no comments, proper commas
   {
     "mcpServers": {
       "deep-eye": {
         "command": "python3",
         "args": ["/path/to/server.py"]
       }
     }
   }
   ```

2. **Verify paths are absolute:**
   ```bash
   # Find absolute path
   cd /path/to/deep-eye
   pwd
   # Use the full output in config
   ```

3. **Check Python path:**
   ```bash
   which python3  # Linux/macOS
   where python   # Windows
   # Use this path as "command"
   ```

4. **Restart completely:**
   - Quit Claude Desktop (not just close)
   - Wait 5 seconds
   - Start again

5. **Check logs:**
   - Windows: `%APPDATA%\Claude\logs\mcp*.log`
   - macOS: `~/Library/Logs/Claude/`
   - Linux: `~/.config/Claude/logs/`

### Tools Not Working

**Problem:** Tools exist but fail when used

**Solutions:**

1. **Check Deep Eye config:**
   ```bash
   cd /path/to/deep-eye
   cat config/config.yaml
   # Ensure it exists
   ```

2. **Verify dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install mcp
   ```

3. **Test manually:**
   ```bash
   cd /path/to/deep-eye
   python3 mcp_server/server.py
   # Should start without errors (Ctrl+C to stop)
   ```

4. **Check permissions:**
   ```bash
   chmod -R 755 /path/to/deep-eye
   ```

### Scan Errors

**Problem:** Scans fail or timeout

**Solutions:**

1. **Check target is accessible:**
   ```bash
   curl https://target.com
   ```

2. **Reduce scan depth:**
   ```
   "Quick scan of https://example.com"
   ```

3. **Check network/proxy:**
   - Verify internet connection
   - Check firewall settings
   - Try without VPN

### Performance Issues

**Problem:** Scans are very slow

**Solutions:**

1. **Use quick scan mode:**
   ```
   "Quick scan https://example.com"
   ```

2. **Reduce depth:**
   ```
   "Scan with depth 1"
   ```

3. **Check system resources:**
   - Close other applications
   - Monitor CPU/RAM usage

### JSON Parse Errors

**Problem:** "Invalid JSON" in logs

**Solution:** This usually means stdout contamination

1. **Check for print statements:**
   - Deep Eye should only output to stderr
   - Check recent changes to code

2. **Verify logger configuration:**
   - Logs should go to stderr, not stdout

## Advanced Tips

### Multiple Targets

```
Test these URLs for XSS:
- https://example.com/search
- https://example.com/comment
- https://example.com/profile
```

### Custom Workflows

```
1. Run recon on example.com
2. For each subdomain found, do a quick scan
3. For critical findings, generate exploitation payloads
4. Give me a summary report
```

### Integration with Bug Bounties

```
I'm testing example.com for a bug bounty:
1. Do reconnaissance
2. Focus on authentication and API endpoints
3. Test for high-impact vulnerabilities only
4. Generate PoC payloads for any findings
```

## Next Steps

Now that you're set up:

1. **Try the examples above** - Get familiar with the tools
2. **Read full documentation** - [README.md](README.md)
3. **Explore AI integration** - [AI_INTEGRATION_SUMMARY.md](AI_INTEGRATION_SUMMARY.md)
4. **Learn methodology** - [TESTING_GUIDE.md](docs/TESTING_GUIDE.md)
5. **Join community** - GitHub Discussions

## Legal & Ethical Reminder

🚨 **IMPORTANT** 🚨

**Only test systems you own or have explicit written permission to test.**

Unauthorized security testing is:
- ❌ Illegal in most jurisdictions
- ❌ Unethical
- ❌ Can result in criminal charges

Deep Eye is for:
- ✅ Your own systems
- ✅ Authorized penetration tests
- ✅ Bug bounty programs (within scope)
- ✅ Security research (with permission)
- ✅ Educational purposes (on test targets)

## Support & Resources

- **Documentation**: [README.md](README.md)
- **Full Installation Guide**: [INSTALLATION.md](INSTALLATION.md)
- **GitHub Issues**: [Report bugs](https://github.com/zakirkun/deep-eye/issues)
- **Discussions**: [Ask questions](https://github.com/zakirkun/deep-eye/discussions)

---

**Happy (ethical) security testing with Claude Desktop! 🔒🤖**

Remember: With great power comes great responsibility. Use Deep Eye wisely and ethically!