"""
Hybrid AI Manager
Supports both API-based AI providers and MCP-based Claude Desktop integration
"""

from typing import Dict, List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class HybridAIManager:
    """
    Manages AI providers with support for both API and MCP modes.

    - API Mode: Uses OpenAI, Claude API, Grok, or Ollama directly
    - MCP Mode: Delegates intelligence to Claude Desktop via prompts
    """

    def __init__(self, config: Dict, mode: str = "api"):
        """
        Initialize hybrid AI manager.

        Args:
            config: Configuration dictionary
            mode: "api" for direct API calls, "mcp" for Claude Desktop integration
        """
        self.config = config
        self.mode = mode.lower()
        self.api_manager = None

        if self.mode == "api":
            from ai_providers.provider_manager import AIProviderManager
            self.api_manager = AIProviderManager(config)
            logger.info("Hybrid AI Manager initialized in API mode")
        else:
            logger.info("Hybrid AI Manager initialized in MCP mode")

    def set_provider(self, provider_name: str) -> bool:
        """Set active AI provider (only for API mode)."""
        if self.mode == "api" and self.api_manager:
            return self.api_manager.set_provider(provider_name)
        return True  # MCP mode doesn't need provider selection

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate AI response.

        Args:
            prompt: Input prompt
            **kwargs: Additional arguments

        Returns:
            Generated response or prompt for MCP mode
        """
        if self.mode == "api" and self.api_manager:
            return self.api_manager.generate(prompt, **kwargs)
        else:
            # MCP mode: Return a structured prompt that Claude Desktop will process
            # The MCP server will handle this by asking Claude to process it
            return self._create_mcp_prompt(prompt, **kwargs)

    def _create_mcp_prompt(self, prompt: str, **kwargs) -> str:
        """
        Create a structured prompt for MCP mode.
        Claude Desktop will process this through the conversational interface.
        """
        # For MCP mode, we return a placeholder that indicates
        # Claude Desktop should provide the intelligence
        return f"[MCP_MODE_PROMPT]\n{prompt}"

    def is_mcp_mode(self) -> bool:
        """Check if running in MCP mode."""
        return self.mode == "mcp"

    def is_api_mode(self) -> bool:
        """Check if running in API mode."""
        return self.mode == "api"

    def get_mode(self) -> str:
        """Get current mode."""
        return self.mode


class MCPPayloadGenerator:
    """
    Specialized payload generator for MCP mode.
    Returns prompts that Claude Desktop will process to generate payloads.
    """

    @staticmethod
    def generate_sql_injection_prompt(context: Dict) -> str:
        """Generate prompt for SQL injection payloads."""
        return f"""Generate 10 advanced SQL injection payloads for:

**Target URL:** {context.get('url')}
**Parameters:** {context.get('parameters', 'None detected')}
**Database hints:** {context.get('database_type', 'Unknown')}

Requirements:
1. Error-based SQL injection
2. Boolean-based blind SQL injection
3. Time-based blind SQL injection
4. Union-based SQL injection
5. Stacked queries

Include WAF bypass techniques. Return only payloads, one per line."""

    @staticmethod
    def generate_xss_prompt(context: Dict) -> str:
        """Generate prompt for XSS payloads."""
        return f"""Generate 10 advanced XSS payloads for:

**Target URL:** {context.get('url')}
**Input fields:** {context.get('input_fields', 'Unknown')}
**Content-Type:** {context.get('content_type', 'text/html')}

Requirements:
1. Reflected XSS
2. Stored XSS
3. DOM-based XSS
4. Filter bypass techniques
5. Event handler-based XSS

Include obfuscation and encoding. Return only payloads, one per line."""

    @staticmethod
    def generate_command_injection_prompt(context: Dict) -> str:
        """Generate prompt for command injection payloads."""
        return f"""Generate 10 advanced command injection payloads for:

**Target URL:** {context.get('url')}
**OS hints:** {context.get('os_type', 'Unknown')}
**Shell type:** {context.get('shell_type', 'Unknown')}

Requirements:
1. Command chaining (;, &&, ||, |)
2. Command substitution
3. Blind command injection
4. Time-based detection
5. Filter bypass

Include both Unix and Windows variants. Return only payloads, one per line."""

    @staticmethod
    def generate_ssrf_prompt(context: Dict) -> str:
        """Generate prompt for SSRF payloads."""
        return f"""Generate 10 advanced SSRF payloads for:

**Target URL:** {context.get('url')}
**Cloud environment:** {context.get('cloud_hints', 'Unknown')}

Requirements:
1. Internal network access (localhost, 127.0.0.1, 0.0.0.0)
2. Cloud metadata endpoints (AWS, GCP, Azure)
3. File protocol handlers
4. Protocol bypass techniques
5. IP obfuscation

Return only payloads, one per line."""

    @staticmethod
    def generate_path_traversal_prompt(context: Dict) -> str:
        """Generate prompt for path traversal payloads."""
        return f"""Generate 10 advanced path traversal payloads for:

**Target URL:** {context.get('url')}
**OS hints:** {context.get('os_type', 'Unknown')}

Requirements:
1. Standard traversal (../)
2. Encoded traversal (%2e%2e%2f)
3. Double encoding
4. Null byte injection
5. Filter bypass techniques

Include both Unix and Windows paths. Return only payloads, one per line."""

    @staticmethod
    def generate_cve_prompt(technology: str, version: str = "") -> str:
        """Generate prompt for CVE analysis."""
        return f"""Analyze CVE vulnerabilities for:

**Technology:** {technology}
**Version:** {version if version else "Latest/Unknown"}

Please provide:
1. Relevant CVE identifiers
2. Severity ratings (CVSS scores)
3. Brief vulnerability descriptions
4. Exploitation difficulty
5. Available patches/mitigations
6. Proof-of-concept availability

Focus on actively exploited vulnerabilities first."""

    @staticmethod
    def generate_response_analysis_prompt(url: str, response_data: Dict) -> str:
        """Generate prompt for response analysis."""
        return f"""Analyze this HTTP response for security vulnerabilities:

**URL:** {url}
**Status Code:** {response_data.get('status_code', 'Unknown')}
**Headers:**
{response_data.get('headers', {})}

**Response Body (first 1000 chars):**
{response_data.get('body', '')[:1000]}

Please identify:
1. Missing security headers
2. Information disclosure
3. Error messages revealing system details
4. Potential injection points
5. Authentication/session issues
6. CORS misconfigurations
7. Outdated software indicators

Provide severity ratings and remediation advice."""
