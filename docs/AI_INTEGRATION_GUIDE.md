# Deep Eye AI Integration Guide

Deep Eye supports **two AI integration modes** for intelligent security testing:

1. **API Mode** - Direct API integration (OpenAI, Claude API, Grok, Ollama)
2. **MCP Mode** - Claude Desktop integration via Model Context Protocol

## Table of Contents

- [Overview](#overview)
- [API Mode Setup](#api-mode-setup)
- [MCP Mode Setup](#mcp-mode-setup)
- [Comparison](#comparison)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)

---

## Overview

### API Mode
- **How it works**: Deep Eye calls AI APIs directly during scans
- **Best for**: Automated, unattended security scans
- **Cost**: Pay per API call (varies by provider)
- **Providers**: OpenAI, Claude API, Grok, Ollama (local)

### MCP Mode
- **How it works**: Claude Desktop provides AI intelligence interactively
- **Best for**: Interactive security testing with conversational workflow
- **Cost**: Claude Desktop subscription (free tier or Pro)
- **Provider**: Claude (via Desktop app)

---

## API Mode Setup

### 1. Choose Your Provider

Deep Eye supports multiple AI providers:

| Provider | Model | Cost | Setup Difficulty |
|----------|-------|------|------------------|
| **OpenAI** | GPT-4, GPT-3.5 | $$ | Easy |
| **Claude** | Claude 3.5 Sonnet | $$ | Easy |
| **Grok** | Grok-1 | $$ | Easy |
| **Ollama** | Local models | Free | Medium |

### 2. Get API Keys

**OpenAI:**
1. Visit https://platform.openai.com/api-keys
2. Create new API key
3. Copy the key

**Claude (Anthropic):**
1. Visit https://console.anthropic.com/
2. Go to API Keys section
3. Create new key
4. Copy the key

**Grok:**
1. Visit https://grok.x.ai/
2. Access API section
3. Generate API key

**Ollama (Local):**
1. Install Ollama: https://ollama.ai/download
2. Run: `ollama pull llama2` (or your preferred model)
3. Start Ollama server: `ollama serve`

### 3. Configure Deep Eye

Edit `config/config.yaml`:

```yaml
ai_providers:
  # OpenAI Configuration
  openai:
    enabled: true
    api_key: "sk-your-openai-api-key-here"
    model: "gpt-4"
    temperature: 0.7
    max_tokens: 2000

  # Claude Configuration
  claude:
    enabled: true
    api_key: "sk-ant-your-claude-api-key-here"
    model: "claude-3-5-sonnet-20241022"
    temperature: 0.7
    max_tokens: 2000

  # Grok Configuration
  grok:
    enabled: false
    api_key: "your-grok-api-key"
    model: "grok-1"
    temperature: 0.7
    max_tokens: 2000

  # Ollama Configuration (Local)
  ollama:
    enabled: false
    base_url: "http://localhost:11434"
    model: "llama2"
    temperature: 0.7

scanner:
  ai_provider: "claude"  # Choose: openai, claude, grok, ollama

vulnerability_scanner:
  payload_generation:
    use_ai: true  # Enable AI-powered payload generation
```

### 4. Run with API Mode

```bash
python deep_eye.py -u https://example.com
```

Deep Eye will automatically use the configured AI provider for:
- Intelligent payload generation
- Context-aware vulnerability testing
- CVE analysis
- Adaptive WAF bypass

---

## MCP Mode Setup

### 1. Prerequisites

- Python 3.8+
- Claude Desktop installed
- Deep Eye installed and working

### 2. Install MCP Dependencies

```bash
cd "F:\HACKING TOOLS\deep-eye"
pip install mcp
```

### 3. Configure Claude Desktop

Locate your Claude Desktop config file:

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Add the Deep Eye MCP server:

```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "python",
      "args": [
        "F:\\HACKING TOOLS\\deep-eye\\mcp_server\\server.py"
      ],
      "cwd": "F:\\HACKING TOOLS\\deep-eye",
      "env": {}
    }
  }
}
```

**Important**: Use your actual Deep Eye installation path!

### 4. Restart Claude Desktop

1. Completely quit Claude Desktop
2. Restart the application
3. Look for the 🔌 icon indicating MCP servers are connected

### 5. Verify Installation

In Claude Desktop, try:

```
List available Deep Eye tools
```

You should see 7 security testing tools available.

### 6. Start Testing

Example conversation:

```
You: Scan https://testsite.com for vulnerabilities

Claude: I'll perform a comprehensive security scan on that site.
[Uses scan_url tool]

Results show 5 vulnerabilities found:
- SQL Injection (High) at /login
- XSS (Medium) at /search
...

You: Generate custom SQL injection payloads for the login page

Claude: I'll generate context-aware SQL injection payloads...
[Generates intelligent payloads based on site context]
```

---

## Comparison

| Feature | API Mode | MCP Mode |
|---------|----------|----------|
| **Cost** | Pay per API call | Claude subscription |
| **Automation** | Fully automated | Interactive |
| **Flexibility** | Multi-provider support | Claude only |
| **Use Case** | CI/CD, scheduled scans | Manual testing |
| **Context Retention** | Per-scan only | Across conversation |
| **Learning Curve** | Low | Medium |
| **Setup Complexity** | Simple (API key) | Moderate (config file) |

### When to Use API Mode

✅ Automated security scans in CI/CD pipelines
✅ Scheduled vulnerability assessments
✅ Large-scale testing across multiple targets
✅ Unattended operation
✅ Need for provider flexibility

### When to Use MCP Mode

✅ Interactive penetration testing
✅ Learning security testing techniques
✅ Complex, multi-step security assessments
✅ Cost-sensitive environments (use free Claude tier)
✅ Want conversational workflow with AI guidance

---

## Usage Examples

### API Mode Example

```bash
# Basic scan with API-powered intelligence
python deep_eye.py -u https://example.com

# Full scan with reconnaissance
python deep_eye.py -u https://example.com

# Configuration file (config/config.yaml):
scanner:
  target_url: "https://example.com"
  ai_provider: "claude"
  enable_recon: true
  full_scan: true

vulnerability_scanner:
  payload_generation:
    use_ai: true  # Enable AI payload generation
```

The AI will:
1. Analyze the target context
2. Generate custom payloads
3. Adapt to detected technologies
4. Bypass WAFs intelligently
5. Provide CVE-aware testing

### MCP Mode Examples

#### Example 1: Basic Scan

```
User: Scan https://example.com for security issues

Claude: [Calls scan_url tool]
Found 8 vulnerabilities:
- SQL Injection (Critical) at /api/users
- XSS (High) at /search
...

User: Tell me more about the SQL injection

Claude: The SQL injection at /api/users is critical because...
[Provides detailed analysis]

User: Generate payloads to test it

Claude: [Calls generate_payload tool]
Here are 10 SQL injection payloads optimized for this endpoint...
```

#### Example 2: CVE Research

```
User: Check if Apache 2.4.49 has vulnerabilities

Claude: [Calls check_cve tool]
Apache 2.4.49 has several critical CVEs:

1. CVE-2021-41773 (CVSS 7.5) - Path Traversal
   - Allows reading files outside document root
   - Actively exploited in the wild
   - Patch: Upgrade to 2.4.51+
...
```

#### Example 3: Custom Payload Generation

```
User: I need XSS payloads that bypass Chrome's XSS auditor

Claude: [Calls generate_payload with context]
Here are 10 Chrome XSS Auditor bypass payloads:

1. <svg/onload=alert(1)>
2. <iframe src="javascript:alert(1)">
3. <img src=x onerror=eval(atob('YWxlcnQoMSk='))>
...

These use techniques like:
- SVG-based injection
- Base64 encoding
- Event handlers
- JavaScript protocol handlers
```

#### Example 4: Reconnaissance

```
User: Run recon on acme-corp.com

Claude: [Calls reconnaissance tool]

Found:
- 15 subdomains
- Technologies: Nginx 1.18, PHP 7.4, WordPress 5.8
- 3 email addresses
- 2 social media accounts
- DNS records: A, MX, TXT, CNAME

Potential attack surface:
- dev.acme-corp.com (exposed development site)
- old.acme-corp.com (outdated WordPress)
```

---

## Troubleshooting

### API Mode Issues

**Problem**: `Error: API key not provided`
**Solution**: Check `config/config.yaml` and ensure API key is set and `enabled: true`

**Problem**: `Error: Rate limit exceeded`
**Solution**: You've hit API rate limits. Wait or upgrade your API plan.

**Problem**: `Error: AI generation error`
**Solution**:
- Check internet connection
- Verify API key is valid
- Check provider status page
- Try switching providers

**Problem**: Ollama connection refused
**Solution**:
```bash
# Start Ollama server
ollama serve

# Pull a model if not already done
ollama pull llama2
```

### MCP Mode Issues

**Problem**: MCP server not appearing in Claude Desktop
**Solution**:
1. Check config file syntax (valid JSON)
2. Verify paths are absolute
3. Restart Claude Desktop completely
4. Check Claude Desktop logs

**Problem**: Tools not working
**Solution**:
1. Ensure Deep Eye dependencies are installed:
   ```bash
   pip install -r requirements.txt
   pip install mcp
   ```
2. Check Python path in config matches your installation
3. Verify Deep Eye config file exists: `config/config.yaml`

**Problem**: Permission errors
**Solution**:
- Ensure Deep Eye directory is readable
- Grant Python execution permissions
- On Windows, run as administrator if needed

**Problem**: `ImportError: No module named 'mcp'`
**Solution**:
```bash
pip install mcp
```

### Both Modes

**Problem**: No vulnerabilities found (false negatives)
**Solution**:
- Increase scan depth
- Enable full scan mode
- Check target is accessible
- Verify target has test vulnerabilities

**Problem**: Too many false positives
**Solution**:
- AI helps reduce false positives
- Review payload context
- Adjust detection sensitivity
- Use quick_scan for initial assessment

---

## Best Practices

### API Mode

1. **Start with Claude or GPT-4** - Best quality results
2. **Use Ollama for high-volume** - Free local processing
3. **Set reasonable rate limits** - Avoid API throttling
4. **Monitor API costs** - Track usage in provider dashboard
5. **Combine with default payloads** - AI + built-in = comprehensive

### MCP Mode

1. **Start conversations with context** - "I'm testing [site] for [purpose]"
2. **Iterative testing** - Use scan results to guide next steps
3. **Ask for explanations** - Claude can explain vulnerabilities
4. **Save important findings** - Copy results to external notes
5. **Combine tools** - Use recon → scan → generate_payload workflow

### Both Modes

1. **Always get authorization** - Only test systems you own/have permission
2. **Start with quick scans** - Gauge target before full scan
3. **Review results manually** - AI assists but human validates
4. **Keep software updated** - Update Deep Eye and AI providers regularly
5. **Document findings** - Use report generation features

---

## Advanced Configuration

### Hybrid Setup (Use Both!)

You can use both modes for maximum effectiveness:

1. **Use API Mode** for automated daily/weekly scans
2. **Use MCP Mode** for deep-dive manual testing
3. **Share findings** between modes via report files

### Custom AI Provider

Want to add your own AI provider? Edit:
- `ai_providers/your_provider.py`
- `ai_providers/provider_manager.py`

See existing providers as templates.

### Performance Tuning

**For faster scans:**
```yaml
scanner:
  default_threads: 10  # Increase parallelism
  default_depth: 1     # Reduce crawl depth

vulnerability_scanner:
  payload_generation:
    use_ai: false      # Skip AI for speed (use defaults)
```

**For thorough scans:**
```yaml
scanner:
  default_threads: 5   # More controlled
  default_depth: 3     # Deeper crawling
  full_scan: true      # All vulnerability tests

vulnerability_scanner:
  payload_generation:
    use_ai: true       # AI-powered payloads
```

---

## Support

- **Deep Eye Issues**: Open issue on GitHub repository
- **MCP Integration**: Check [Claude Desktop MCP docs](https://modelcontextprotocol.io/)
- **API Provider Issues**: Contact provider support
- **Security Questions**: See main documentation

---

## Legal Notice

**Always obtain proper authorization before security testing.**

Unauthorized access to computer systems is illegal. Deep Eye is for:
- Testing your own systems
- Authorized penetration testing engagements
- Security research in controlled environments
- Educational purposes with permission

The developers assume no liability for misuse.

---

## What's Next?

- Read the [Quick Start Guide](QUICKSTART.md)
- Check [Testing Guide](TESTING_GUIDE.md) for methodology
- Review [Architecture](ARCHITECTURE.md) for technical details
- Explore [Examples](../examples/) for sample scans

Happy (ethical) hacking! 🔒🔍
