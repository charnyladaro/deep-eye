#!/usr/bin/env python3
"""
Deep Eye MCP Server
Provides security testing capabilities to Claude Desktop via MCP
"""

import json
import sys
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)

from core.scanner_engine import ScannerEngine
from core.vulnerability_scanner import VulnerabilityScanner
from utils.config_loader import ConfigLoader
from utils.logger import setup_logger
from utils.http_client import HTTPClient

# Setup logging
logger = setup_logger()
app = Server("deep-eye-security-scanner")

# Global state
config = None
scanner_instance = None


def load_config():
    """Load Deep Eye configuration."""
    global config
    try:
        config = ConfigLoader.load("config/config.yaml")
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        config = {}


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available Deep Eye security testing tools."""
    return [
        Tool(
            name="scan_url",
            description="Perform a comprehensive security scan on a target URL. This includes vulnerability detection for SQL injection, XSS, SSRF, XXE, path traversal, and 40+ other attack vectors.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to scan (must include http:// or https://)",
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Crawl depth (1-10, default: 2)",
                        "default": 2,
                    },
                    "quick_scan": {
                        "type": "boolean",
                        "description": "Enable quick scan mode (scans only main URL)",
                        "default": False,
                    },
                    "enable_recon": {
                        "type": "boolean",
                        "description": "Enable reconnaissance (OSINT, DNS enum, subdomain discovery)",
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="generate_payload",
            description="Generate intelligent, context-aware security testing payloads for specific vulnerability types. Returns customized payloads based on target context.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL for context analysis",
                    },
                    "vulnerability_type": {
                        "type": "string",
                        "description": "Type of vulnerability to generate payloads for",
                        "enum": [
                            "sql_injection",
                            "xss",
                            "command_injection",
                            "ssrf",
                            "xxe",
                            "path_traversal",
                            "ssti",
                            "ldap_injection",
                            "crlf_injection",
                        ],
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context about the target (frameworks, technologies detected, etc.)",
                        "default": "",
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of payloads to generate (1-20)",
                        "default": 10,
                    },
                },
                "required": ["url", "vulnerability_type"],
            },
        ),
        Tool(
            name="analyze_response",
            description="Analyze HTTP response for potential security issues. Checks for vulnerabilities, misconfigurations, and security headers.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL that was requested",
                    },
                    "response_body": {
                        "type": "string",
                        "description": "HTTP response body to analyze",
                    },
                    "response_headers": {
                        "type": "object",
                        "description": "HTTP response headers as key-value pairs",
                    },
                    "status_code": {
                        "type": "integer",
                        "description": "HTTP status code",
                    },
                },
                "required": ["url", "response_body"],
            },
        ),
        Tool(
            name="check_cve",
            description="Check if a target might be vulnerable to specific CVEs based on detected technologies and versions.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to analyze",
                    },
                    "technology": {
                        "type": "string",
                        "description": "Technology/framework name (e.g., WordPress, Apache, nginx)",
                    },
                    "version": {
                        "type": "string",
                        "description": "Version number if known",
                        "default": "",
                    },
                },
                "required": ["url", "technology"],
            },
        ),
        Tool(
            name="test_specific_vulnerability",
            description="Test for a specific vulnerability type on a target URL with custom or generated payloads.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to test",
                    },
                    "vulnerability_type": {
                        "type": "string",
                        "description": "Specific vulnerability to test for",
                        "enum": [
                            "sql_injection",
                            "xss",
                            "command_injection",
                            "ssrf",
                            "xxe",
                            "path_traversal",
                            "csrf",
                            "open_redirect",
                            "cors_misconfiguration",
                            "security_headers",
                        ],
                    },
                    "custom_payloads": {
                        "type": "array",
                        "description": "Optional custom payloads to test (uses generated payloads if not provided)",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                "required": ["url", "vulnerability_type"],
            },
        ),
        Tool(
            name="get_scan_report",
            description="Get detailed report of the last scan performed, including all vulnerabilities found with severity ratings and remediation advice.",
            inputSchema={
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "description": "Report format",
                        "enum": ["json", "summary", "detailed"],
                        "default": "summary",
                    },
                },
            },
        ),
        Tool(
            name="reconnaissance",
            description="Perform OSINT and reconnaissance on a target domain. Includes DNS enumeration, subdomain discovery, technology detection, and public data gathering.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target domain or URL for reconnaissance",
                    },
                    "deep": {
                        "type": "boolean",
                        "description": "Enable deep reconnaissance (slower but more thorough)",
                        "default": False,
                    },
                },
                "required": ["target"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool execution requests."""
    global config, scanner_instance

    if config is None:
        load_config()

    try:
        if name == "scan_url":
            return await handle_scan_url(arguments)
        elif name == "generate_payload":
            return await handle_generate_payload(arguments)
        elif name == "analyze_response":
            return await handle_analyze_response(arguments)
        elif name == "check_cve":
            return await handle_check_cve(arguments)
        elif name == "test_specific_vulnerability":
            return await handle_test_vulnerability(arguments)
        elif name == "get_scan_report":
            return await handle_get_report(arguments)
        elif name == "reconnaissance":
            return await handle_reconnaissance(arguments)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def handle_scan_url(args: Dict) -> list[TextContent]:
    """Handle URL scanning requests."""
    url = args.get("url")
    depth = args.get("depth", 2)
    quick_scan = args.get("quick_scan", False)
    enable_recon = args.get("enable_recon", False)

    # Validate URL
    if not url.startswith(("http://", "https://")):
        return [TextContent(type="text", text="Error: URL must start with http:// or https://")]

    # Note: MCP integration means Claude Desktop is providing the AI
    # So we disable API-based AI payload generation
    scan_config = config.copy()
    scan_config.setdefault('vulnerability_scanner', {})
    scan_config['vulnerability_scanner']['payload_generation'] = {'use_ai': False}

    # Create scanner (without AI manager since Claude Desktop provides intelligence)
    from ai_providers.provider_manager import AIProviderManager
    ai_manager = AIProviderManager(scan_config)

    scanner = ScannerEngine(
        target_url=url,
        config=scan_config,
        ai_manager=ai_manager,
        depth=depth,
        threads=config.get('scanner', {}).get('default_threads', 5),
        verbose=False
    )

    # Run scan
    results = scanner.scan(
        enable_recon=enable_recon,
        quick_scan=quick_scan
    )

    # Store results globally for later retrieval
    global scanner_instance
    scanner_instance = scanner

    # Format response
    vuln_count = len(results.get('vulnerabilities', []))
    severity = results.get('severity_summary', {})

    response = f"""Security Scan Complete for {url}

**Summary:**
- Total Vulnerabilities: {vuln_count}
- Critical: {severity.get('critical', 0)}
- High: {severity.get('high', 0)}
- Medium: {severity.get('medium', 0)}
- Low: {severity.get('low', 0)}
- URLs Crawled: {results.get('urls_crawled', 0)}
- Duration: {results.get('duration', 'N/A')}

**Vulnerabilities Found:**
"""

    # Add vulnerability details
    for vuln in results.get('vulnerabilities', [])[:10]:  # Show first 10
        response += f"\n- **{vuln.get('type', 'Unknown')}** ({vuln.get('severity', 'unknown').upper()})"
        response += f"\n  URL: {vuln.get('url', 'N/A')}"
        if vuln.get('description'):
            response += f"\n  {vuln.get('description')}"
        response += "\n"

    if vuln_count > 10:
        response += f"\n... and {vuln_count - 10} more vulnerabilities. Use 'get_scan_report' for full details."

    return [TextContent(type="text", text=response)]


async def handle_generate_payload(args: Dict) -> list[TextContent]:
    """Handle payload generation requests - Claude Desktop will provide intelligence."""
    url = args.get("url")
    vuln_type = args.get("vulnerability_type")
    context = args.get("context", "")
    count = args.get("count", 10)

    # Fetch target for context
    http_client = HTTPClient(config=config)
    response = http_client.get(url)

    response_text = f"""Please generate {count} intelligent, context-aware {vuln_type} payloads for:

**Target URL:** {url}
**Additional Context:** {context}

**Response Headers Detected:**
{dict(response.headers) if response else "Unable to fetch"}

**Technology Hints:**
- Analyze the URL structure and parameters
- Consider common frameworks and their vulnerabilities
- Include WAF bypass techniques
- Generate both basic and advanced payloads

Please provide the payloads in a numbered list format."""

    return [TextContent(type="text", text=response_text)]


async def handle_analyze_response(args: Dict) -> list[TextContent]:
    """Handle response analysis requests."""
    url = args.get("url")
    body = args.get("response_body", "")
    headers = args.get("response_headers", {})
    status_code = args.get("status_code", 200)

    analysis = f"""HTTP Response Analysis for: {url}

**Status Code:** {status_code}

**Security Headers Check:**
"""

    # Check security headers
    security_headers = {
        'X-Frame-Options': 'Clickjacking protection',
        'X-Content-Type-Options': 'MIME type sniffing protection',
        'Strict-Transport-Security': 'HTTPS enforcement',
        'Content-Security-Policy': 'XSS and injection protection',
        'X-XSS-Protection': 'XSS filter',
        'Referrer-Policy': 'Referrer information control',
    }

    for header, description in security_headers.items():
        if header.lower() in [h.lower() for h in headers.keys()]:
            analysis += f"✓ {header}: Present ({description})\n"
        else:
            analysis += f"✗ {header}: MISSING - {description}\n"

    # Check for common issues in response
    issues = []

    if 'error' in body.lower() or 'warning' in body.lower():
        issues.append("Error messages detected - potential information disclosure")

    if 'sql' in body.lower() and 'syntax' in body.lower():
        issues.append("Possible SQL error - SQL injection vulnerability")

    if '<script' in body.lower():
        issues.append("Script tags detected - verify XSS protection")

    if status_code >= 500:
        issues.append("Server error - potential for information disclosure")

    if issues:
        analysis += f"\n**Potential Issues:**\n"
        for issue in issues:
            analysis += f"- {issue}\n"
    else:
        analysis += f"\n**No obvious issues detected in response.**"

    return [TextContent(type="text", text=analysis)]


async def handle_check_cve(args: Dict) -> list[TextContent]:
    """Handle CVE checking - Claude will provide CVE intelligence."""
    url = args.get("url")
    technology = args.get("technology")
    version = args.get("version", "")

    prompt = f"""Please check for known CVEs affecting:

**Technology:** {technology}
**Version:** {version if version else "Unknown"}
**Target:** {url}

Please provide:
1. Relevant CVEs for this technology/version
2. Severity ratings
3. Brief description of vulnerabilities
4. Exploitation difficulty
5. Recommended patches or mitigations"""

    return [TextContent(type="text", text=prompt)]


async def handle_test_vulnerability(args: Dict) -> list[TextContent]:
    """Handle specific vulnerability testing."""
    url = args.get("url")
    vuln_type = args.get("vulnerability_type")
    custom_payloads = args.get("custom_payloads", [])

    http_client = HTTPClient(config=config)
    vuln_scanner = VulnerabilityScanner(config=config, http_client=http_client)

    # Prepare context
    context = {
        'url': url,
        'response': http_client.get(url)
    }

    # Use custom payloads or default
    payloads = {}
    if custom_payloads:
        payloads[vuln_type] = custom_payloads

    # Run specific vulnerability test
    results = vuln_scanner.scan(url=url, payloads=payloads, context=context)

    # Filter results for this specific vulnerability type
    filtered_results = [r for r in results if r.get('type', '').lower() == vuln_type.lower()]

    if filtered_results:
        response = f"**{vuln_type.upper()} Testing Results for {url}**\n\n"
        response += f"Found {len(filtered_results)} potential vulnerability instance(s):\n\n"

        for result in filtered_results:
            response += f"- **Severity:** {result.get('severity', 'unknown').upper()}\n"
            response += f"  **Description:** {result.get('description', 'N/A')}\n"
            response += f"  **Payload:** {result.get('payload', 'N/A')}\n"
            if result.get('evidence'):
                response += f"  **Evidence:** {result.get('evidence')}\n"
            response += "\n"
    else:
        response = f"No {vuln_type} vulnerabilities detected at {url}"
        if custom_payloads:
            response += f" using the provided {len(custom_payloads)} custom payload(s)."
        else:
            response += " using default payloads."

    return [TextContent(type="text", text=response)]


async def handle_get_report(args: Dict) -> list[TextContent]:
    """Handle scan report requests."""
    format_type = args.get("format", "summary")

    global scanner_instance
    if not scanner_instance:
        return [TextContent(type="text", text="No scan has been performed yet. Run 'scan_url' first.")]

    results = scanner_instance.scan_results if hasattr(scanner_instance, 'scan_results') else {}
    vulnerabilities = scanner_instance.vulnerabilities

    if format_type == "json":
        report = json.dumps({
            'vulnerabilities': vulnerabilities,
            'total_count': len(vulnerabilities)
        }, indent=2)

    elif format_type == "detailed":
        report = "**Detailed Security Scan Report**\n\n"

        for i, vuln in enumerate(vulnerabilities, 1):
            report += f"## Vulnerability {i}: {vuln.get('type', 'Unknown')}\n\n"
            report += f"- **Severity:** {vuln.get('severity', 'unknown').upper()}\n"
            report += f"- **URL:** {vuln.get('url', 'N/A')}\n"
            report += f"- **Description:** {vuln.get('description', 'N/A')}\n"
            report += f"- **Payload:** {vuln.get('payload', 'N/A')}\n"
            if vuln.get('evidence'):
                report += f"- **Evidence:** {vuln.get('evidence')}\n"
            if vuln.get('remediation'):
                report += f"- **Remediation:** {vuln.get('remediation')}\n"
            report += "\n---\n\n"

    else:  # summary
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        report = f"""**Security Scan Summary Report**

Total Vulnerabilities: {len(vulnerabilities)}

**By Severity:**
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Info: {severity_counts['info']}

**By Type:**
"""
        type_counts = {}
        for vuln in vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        for vtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            report += f"- {vtype}: {count}\n"

    return [TextContent(type="text", text=report)]


async def handle_reconnaissance(args: Dict) -> list[TextContent]:
    """Handle reconnaissance requests."""
    target = args.get("target")
    deep = args.get("deep", False)

    from modules.reconnaissance.recon_engine import ReconEngine

    recon_engine = ReconEngine(config=config, http_client=HTTPClient(config=config))
    results = recon_engine.run(target)

    response = f"**Reconnaissance Results for {target}**\n\n"

    if results.get('dns'):
        response += "**DNS Information:**\n"
        dns_data = results['dns']
        for record_type, records in dns_data.items():
            if records:
                response += f"- {record_type}: {', '.join(str(r) for r in records)}\n"
        response += "\n"

    if results.get('subdomains'):
        subs = results['subdomains']
        response += f"**Subdomains Found:** {len(subs)}\n"
        for sub in subs[:20]:  # Show first 20
            response += f"- {sub}\n"
        if len(subs) > 20:
            response += f"... and {len(subs) - 20} more\n"
        response += "\n"

    if results.get('technologies'):
        response += "**Technologies Detected:**\n"
        for tech in results['technologies']:
            response += f"- {tech}\n"
        response += "\n"

    if results.get('osint'):
        response += "**OSINT Data:**\n"
        osint = results['osint']
        if osint.get('emails'):
            response += f"Emails found: {len(osint['emails'])}\n"
        if osint.get('social_media'):
            response += f"Social media accounts: {len(osint['social_media'])}\n"
        response += "\n"

    return [TextContent(type="text", text=response)]


async def main():
    """Run the MCP server."""
    logger.info("Starting Deep Eye MCP Server...")
    load_config()

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
