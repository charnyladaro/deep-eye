# Deep Eye MCP Server

Model Context Protocol integration for Claude Desktop, enabling AI-powered security testing through conversational interaction.

## Features

The MCP server exposes Deep Eye's security testing capabilities to Claude Desktop:

### Available Tools

1. **scan_url** - Comprehensive security scanning
   - SQL injection, XSS, SSRF, XXE, and 40+ vulnerabilities
   - Configurable depth and scan modes
   - Optional reconnaissance

2. **generate_payload** - AI-powered payload generation
   - Context-aware payloads for specific vulnerability types
   - WAF bypass techniques
   - Custom payload count

3. **analyze_response** - HTTP response security analysis
   - Security headers check
   - Error message detection
   - Vulnerability indicators

4. **check_cve** - CVE vulnerability checking
   - Technology-specific CVE lookup
   - Version-based vulnerability assessment
   - Mitigation recommendations

5. **test_specific_vulnerability** - Targeted testing
   - Test for specific vulnerability types
   - Support for custom payloads
   - Detailed results with evidence

6. **get_scan_report** - Scan results retrieval
   - Summary, detailed, or JSON format
   - Severity breakdowns
   - Vulnerability categorization

7. **reconnaissance** - OSINT and information gathering
   - DNS enumeration
   - Subdomain discovery
   - Technology detection
   - Public data collection

## Installation

### Prerequisites

- Python 3.8+
- Claude Desktop installed
- Deep Eye dependencies installed

### Setup

1. Install MCP dependencies:
```bash
cd "F:\HACKING TOOLS\deep-eye"
pip install mcp
```

2. Configure Claude Desktop (see Configuration section below)

3. Restart Claude Desktop

## Configuration

Add this to your Claude Desktop configuration file:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "deep-eye": {
      "command": "python",
      "args": [
        "F:\\HACKING TOOLS\\deep-eye\\mcp_server\\server.py"
      ],
      "cwd": "F:\\HACKING TOOLS\\deep-eye"
    }
  }
}
```

## Usage Examples

Once configured, you can interact with Deep Eye through Claude Desktop:

### Example 1: Basic Security Scan
```
User: Scan https://example.com for vulnerabilities
Claude: [Uses scan_url tool to perform comprehensive scan]
```

### Example 2: Generate Custom Payloads
```
User: Generate SQL injection payloads for https://example.com/login?user=admin
Claude: [Uses generate_payload tool and creates context-aware payloads]
```

### Example 3: Analyze Response
```
User: Analyze this HTTP response for security issues: [paste response]
Claude: [Uses analyze_response tool to check headers and content]
```

### Example 4: CVE Check
```
User: Check if Apache 2.4.49 has any known vulnerabilities
Claude: [Uses check_cve tool to lookup relevant CVEs]
```

### Example 5: Reconnaissance
```
User: Run reconnaissance on example.com
Claude: [Uses reconnaissance tool for OSINT gathering]
```

## How It Works

1. **MCP Server**: Runs in the background when Claude Desktop starts
2. **Tool Calls**: Claude Desktop calls Deep Eye tools based on your requests
3. **AI Enhancement**: Claude provides intelligent analysis and payload generation
4. **Results**: Security findings are presented conversationally

## Advantages Over Direct API Usage

- **Cost-Effective**: Use Claude Desktop (free/Pro) instead of API credits
- **Interactive**: Conversational security testing workflow
- **Context-Aware**: Claude remembers scan context across conversation
- **Flexible**: Combine automated scanning with manual analysis
- **Learning**: Claude can explain vulnerabilities and suggest fixes

## Troubleshooting

### MCP Server Not Starting

1. Check Claude Desktop logs:
   - Windows: `%APPDATA%\Claude\logs`
   - macOS: `~/Library/Logs/Claude`

2. Verify Python path in config matches your installation

3. Ensure all Deep Eye dependencies are installed:
```bash
pip install -r requirements.txt
```

### Tools Not Appearing

1. Restart Claude Desktop completely
2. Check configuration file syntax (valid JSON)
3. Verify file paths are absolute, not relative

### Permission Errors

Ensure Deep Eye directory is readable and Python has execution permissions.

## Legal Notice

This tool is for authorized security testing only. Always obtain proper authorization before testing any systems you don't own.

## Support

For issues specific to:
- MCP Integration: Check Claude Desktop documentation
- Deep Eye functionality: Refer to main Deep Eye documentation
- Security questions: Open an issue on the Deep Eye repository
