# Deep Eye AI Integration - Complete Summary

## What Was Implemented

Deep Eye now supports **dual AI integration modes**:

### 1. API Mode (Existing + Enhanced)
- Direct integration with AI providers via APIs
- Supports: OpenAI, Claude API, Grok, Ollama
- Automated, unattended security scanning
- Pay-per-use pricing model

### 2. MCP Mode (NEW)
- Integration with Claude Desktop via Model Context Protocol
- Interactive, conversational security testing
- Use Claude Desktop subscription (no per-call API fees)
- 7 specialized security testing tools

## Files Created

### MCP Server
```
mcp_server/
├── __init__.py                 # Package initialization
├── server.py                   # Main MCP server with 7 security tools
├── pyproject.toml             # MCP package configuration
└── README.md                  # MCP server documentation
```

### Enhanced AI Management
```
core/
└── hybrid_ai_manager.py       # Unified AI manager for both modes
```

### Documentation
```
docs/
└── AI_INTEGRATION_GUIDE.md    # Complete AI integration guide (both modes)

INSTALLATION.md                 # Installation instructions
MCP_QUICKSTART.md              # Quick start for Claude Desktop integration
AI_INTEGRATION_SUMMARY.md      # This file
```

### Setup Scripts
```
scripts/
├── setup_mcp.py               # Python setup script (cross-platform)
└── setup_mcp.ps1              # PowerShell setup script (Windows)
```

### Dependencies
```
requirements.txt               # Updated with mcp>=0.1.0
```

## Available MCP Tools

When integrated with Claude Desktop, you get 7 powerful tools:

| Tool | Description | Use Case |
|------|-------------|----------|
| **scan_url** | Comprehensive vulnerability scan | Full security assessment |
| **generate_payload** | AI-powered payload generation | Custom exploit creation |
| **analyze_response** | HTTP response security analysis | Quick security checks |
| **check_cve** | CVE vulnerability lookup | Technology risk assessment |
| **test_specific_vulnerability** | Targeted vulnerability testing | Focus on specific issues |
| **get_scan_report** | Retrieve scan results | Report generation |
| **reconnaissance** | OSINT and info gathering | Target enumeration |

## Quick Setup

### For API Mode (Existing)

1. Get API key from provider (OpenAI, Claude, etc.)
2. Edit `config/config.yaml`:
   ```yaml
   ai_providers:
     claude:
       enabled: true
       api_key: "your-key-here"
   ```
3. Run: `python deep_eye.py -u https://target.com`

### For MCP Mode (New)

1. Install MCP: `pip install mcp`
2. Run setup: `python scripts/setup_mcp.py`
3. Restart Claude Desktop
4. Test: Ask Claude "List available Deep Eye tools"

## Integration Benefits

### API Mode Benefits
✅ Fully automated scanning
✅ CI/CD integration
✅ Scheduled assessments
✅ Multiple provider options
✅ No manual intervention

### MCP Mode Benefits
✅ Cost-effective (no per-call fees)
✅ Interactive workflow
✅ Conversational interface
✅ Claude explains findings
✅ Iterative testing approach
✅ Great for learning

### Use Both!
- **API Mode**: Automated daily/weekly scans
- **MCP Mode**: Manual deep-dive testing and investigation

## Key Features Enabled

### 1. Intelligent Payload Generation
- **API Mode**: Automated during scans
- **MCP Mode**: On-demand via conversation
- Context-aware payloads
- WAF bypass techniques
- Framework-specific attacks

### 2. CVE-Aware Testing
- **API Mode**: Automatic CVE analysis
- **MCP Mode**: Ask Claude about specific CVEs
- Version-based vulnerability detection
- Severity ratings
- Patch recommendations

### 3. Smart Payload Obfuscation
- **API Mode**: Built into scan process
- **MCP Mode**: Generate custom obfuscated payloads
- Encoding techniques
- Filter bypass methods
- Advanced evasion

## Example Workflows

### Workflow 1: Automated API Scan
```bash
# Run automated scan with AI
python deep_eye.py -u https://target.com

# AI automatically:
# - Generates context-aware payloads
# - Tests 40+ vulnerability types
# - Analyzes technologies
# - Creates comprehensive report
```

### Workflow 2: Interactive MCP Session
```
User → Claude Desktop:
"Scan example.com for vulnerabilities"

Claude: [Uses scan_url tool]
Found 5 issues. The SQL injection at /login is critical...

User: "Generate custom SQL injection payloads for that endpoint"

Claude: [Uses generate_payload]
Here are 10 context-aware payloads optimized for this target...

User: "Explain how the first payload works"

Claude: This payload uses a time-based blind SQL injection...
```

### Workflow 3: Hybrid Approach
```bash
# 1. Automated daily scan (API Mode)
python deep_eye.py -u https://target.com

# 2. Review findings in report
# 3. Deep-dive using Claude Desktop (MCP Mode)
#    "Analyze the SQL injection found at /api/users"
#    "Generate advanced exploitation payloads"
#    "Check if this version of Apache has known CVEs"
```

## Technical Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Deep Eye Core                        │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │         Hybrid AI Manager                       │    │
│  │  ┌──────────────┐     ┌──────────────┐        │    │
│  │  │  API Mode    │     │  MCP Mode    │        │    │
│  │  │              │     │              │        │    │
│  │  │ • OpenAI     │     │ • Claude     │        │    │
│  │  │ • Claude API │     │   Desktop    │        │    │
│  │  │ • Grok       │     │ • Interactive│        │    │
│  │  │ • Ollama     │     │ • Tools      │        │    │
│  │  └──────────────┘     └──────────────┘        │    │
│  └────────────────────────────────────────────────┘    │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │         Security Testing Engine                 │    │
│  │  • Vulnerability Scanner                        │    │
│  │  • Payload Generator                            │    │
│  │  • Web Crawler                                  │    │
│  │  • OSINT Engine                                 │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘

         ↓ API Calls                   ↓ MCP Protocol

┌──────────────────┐          ┌──────────────────┐
│  AI Providers    │          │  Claude Desktop  │
│  • OpenAI        │          │                  │
│  • Claude API    │          │  [User ↔ Claude] │
│  • Grok          │          │       ↕          │
│  • Ollama (local)│          │  MCP Server      │
└──────────────────┘          └──────────────────┘
```

## Configuration Examples

### API Mode Configuration
```yaml
# config/config.yaml

ai_providers:
  claude:
    enabled: true
    api_key: "sk-ant-your-key"
    model: "claude-3-5-sonnet-20241022"
    temperature: 0.7
    max_tokens: 2000

scanner:
  ai_provider: "claude"
  target_url: "https://example.com"
  default_depth: 2
  default_threads: 5

vulnerability_scanner:
  payload_generation:
    use_ai: true  # Enable AI payloads
```

### MCP Mode Configuration
```json
// %APPDATA%\Claude\claude_desktop_config.json

{
  "mcpServers": {
    "deep-eye": {
      "command": "python",
      "args": ["F:\\HACKING TOOLS\\deep-eye\\mcp_server\\server.py"],
      "cwd": "F:\\HACKING TOOLS\\deep-eye"
    }
  }
}
```

## Performance Comparison

| Metric | API Mode | MCP Mode |
|--------|----------|----------|
| **Speed** | Fast (automated) | Interactive (slower) |
| **Cost** | $$-$$$ per 1000 calls | $ (subscription only) |
| **Setup Time** | 5 minutes | 10 minutes |
| **Learning Curve** | Easy | Medium |
| **Automation** | Full | Manual/semi-automated |
| **Customization** | Config-based | Conversational |
| **Best For** | CI/CD, scheduled scans | Manual testing, learning |

## Cost Analysis

### API Mode
- OpenAI GPT-4: ~$0.03-0.06 per scan
- Claude API: ~$0.02-0.04 per scan
- Grok: Varies
- Ollama: Free (local)

**For 100 scans/month:**
- ~$2-6/month (API costs)

### MCP Mode
- Claude Free: $0 (with limits)
- Claude Pro: $20/month (unlimited Deep Eye usage)

**For unlimited scans/month:**
- $0-20/month (fixed cost)

## Testing Checklist

Before considering the integration complete, test:

### API Mode Tests
- [ ] API key configuration works
- [ ] Scan with AI payloads enabled
- [ ] Try different providers (OpenAI, Claude, Ollama)
- [ ] Verify AI-generated payloads in results
- [ ] Check report generation

### MCP Mode Tests
- [ ] MCP setup script runs successfully
- [ ] Claude Desktop shows Deep Eye tools
- [ ] Run scan_url tool
- [ ] Test generate_payload tool
- [ ] Test analyze_response tool
- [ ] Test check_cve tool
- [ ] Test reconnaissance tool
- [ ] Verify get_scan_report tool

### Integration Tests
- [ ] Switch between API and MCP modes
- [ ] Use both modes on same target
- [ ] Compare results between modes
- [ ] Verify reports are consistent

## Troubleshooting Quick Reference

| Issue | Solution |
|-------|----------|
| API key errors | Check `config/config.yaml` syntax and key validity |
| MCP not appearing | Verify JSON config, restart Claude Desktop |
| Import errors | Run `pip install -r requirements.txt` |
| Permission issues | Check file permissions, run as admin if needed |
| Tool not found | Verify MCP server path in Claude Desktop config |
| Scan failures | Check target accessibility, review logs |

## Documentation Index

1. **INSTALLATION.md** - Complete installation guide
2. **MCP_QUICKSTART.md** - Quick MCP setup (5 minutes)
3. **docs/AI_INTEGRATION_GUIDE.md** - Comprehensive guide (both modes)
4. **mcp_server/README.md** - MCP server technical details
5. **README.md** - Main Deep Eye documentation

## Next Steps

### For Users
1. Choose your mode (or use both!)
2. Follow installation guide
3. Run test scan
4. Read methodology guide
5. Start ethical security testing

### For Developers
1. Review `core/hybrid_ai_manager.py`
2. Check `mcp_server/server.py` for tool implementations
3. Extend with custom tools if needed
4. Submit pull requests for improvements

## Support & Community

- **Issues**: GitHub repository
- **Documentation**: `docs/` directory
- **Examples**: `examples/` directory
- **Updates**: Check CHANGELOG.md

## Legal & Ethical Use

⚠️ **CRITICAL REMINDER** ⚠️

This tool is for **authorized security testing only**:

✅ **Allowed:**
- Your own systems
- Client systems with written authorization
- Bug bounty programs
- Security research with permission
- Educational use in controlled environments

❌ **Not Allowed:**
- Unauthorized scanning
- Public websites without permission
- Systems you don't own
- Malicious use

**The developers assume no liability for misuse.**

## Credits

- **Deep Eye Core**: Original development team
- **MCP Integration**: Enhanced with Model Context Protocol
- **AI Providers**: OpenAI, Anthropic, Grok, Ollama
- **Community**: Contributors and security researchers

---

## Summary

Deep Eye now offers **the best of both worlds**:

1. **Automated API Mode** for efficient, scalable security testing
2. **Interactive MCP Mode** for cost-effective, conversational analysis

Choose the mode that fits your workflow, or use both for comprehensive security assessments!

**Happy (ethical) hacking! 🔒🤖**
