"""
Vulnerability Analysis Module

Analyzes MCP server responses to detect vulnerability indicators.
"""

from typing import Any, Dict, List, Optional


class VulnerabilityAnalyzer:
    """Analyzes tool responses to detect security vulnerabilities"""

    # Vulnerability indicators by category
    INDICATORS = {
        "command_injection": [
            "root:",
            "uid=",
            "/home/",
            "/bin/",
            "drwx",
            "total ",
            "cannot access",
            "permission denied",
            "/usr/bin",
            "/sbin",
            "nobody:",
        ],
        "path_traversal": [
            "root:",
            "/etc/",
            "x:0:",
            "daemon:",
            "/usr/bin",
            "windows\\system32",
            "c:\\windows",
            "[boot loader]",
            "localhost",
        ],
        "sql_injection": [
            "sql syntax",
            "mysql_",
            "ora-",
            "sqlite_error",
            "pg_query",
            "you have an error in your sql",
            "warning: mysql",
            "sqlstate",
            "syntax error at or near",
            "unclosed quotation mark",
        ],
        "ssrf": [
            "ami-id",
            "instance-id",
            "metadata",
            "computemetadata",
            "iam/security-credentials",
            "iam-info",
            "placement/availability",
            "instance-identity",
        ],
        "prompt_injection": [
            "developer mode",
            "system:",
            "ignoring previous",
            "new instructions",
            "override",
            "admin mode",
            "unrestricted",
            "safety protocols",
        ],
        "xss": [
            "<script",
            "onerror=",
            "javascript:",
            "alert(",
            "eval(",
            "onload=",
            "<iframe",
        ],
        "ldap_injection": [
            "ldap_search",
            "invalid dn syntax",
            "ldap error",
        ],
        "xml_injection": [
            "<?xml",
            "<!doctype",
            "<!entity",
            "parser error",
            "xml declaration",
        ],
        "nosql_injection": [
            "mongodb",
            "parseerror",
            "$where",
            "bson",
        ],
        "template_injection": [
            "jinja2",
            "templateerror",
            "render error",
            "__mro__",
            "subclasses",
        ],
    }

    # Generic error indicators
    ERROR_INDICATORS = [
        "error",
        "exception",
        "stack trace",
        "traceback",
        "warning",
        "failed",
        "denied",
        "fatal",
        "critical",
        "unexpected",
    ]

    # Severity scoring
    SEVERITY_SCORES = {
        "command_injection": "CRITICAL",
        "sql_injection": "CRITICAL",
        "ssrf": "CRITICAL",
        "path_traversal": "HIGH",
        "prompt_injection": "HIGH",
        "xml_injection": "HIGH",
        "nosql_injection": "HIGH",
        "xss": "MEDIUM",
        "ldap_injection": "MEDIUM",
        "template_injection": "HIGH",
        "crlf_injection": "MEDIUM",
        "null_bytes": "MEDIUM",
        "integer_overflow": "MEDIUM",
        "format_string": "MEDIUM",
    }

    @classmethod
    def analyze_response(
        cls, result: Any, payload: str, category: str
    ) -> tuple[bool, Optional[str]]:
        """
        Analyze tool response to detect vulnerabilities

        Args:
            result: MCP tool response object
            payload: The payload that was sent
            category: Payload category (e.g., "command_injection")

        Returns:
            Tuple of (is_vulnerable, reason)
        """
        if not hasattr(result, "content"):
            return False, None

        content_str = str(result.content).lower()

        # Check for category-specific indicators
        category_indicators = cls.INDICATORS.get(category, [])

        for indicator in category_indicators:
            if indicator.lower() in content_str:
                return True, f"Response contains '{indicator}' - indicator of {category}"

        # Check for generic error indicators combined with payload
        payload_lower = payload[:20].lower()
        has_error = any(
            indicator in content_str for indicator in cls.ERROR_INDICATORS
        )

        if has_error and payload_lower in content_str:
            return (
                True,
                f"Error response contains payload fragment - possible {category}",
            )

        return False, None

    @classmethod
    def get_severity(cls, category: str) -> str:
        """Get severity level for vulnerability category"""
        return cls.SEVERITY_SCORES.get(category, "LOW")

    @classmethod
    def analyze_error(cls, error: Exception, payload: str, category: str) -> bool:
        """
        Analyze exception to determine if it indicates a vulnerability

        Args:
            error: Exception that was raised
            payload: The payload that caused the error
            category: Payload category

        Returns:
            True if error indicates vulnerability
        """
        error_str = str(error).lower()

        # Security-relevant error patterns
        security_patterns = [
            "syntax error",
            "sql",
            "command",
            "permission denied",
            "access denied",
            "unauthorized",
            "forbidden",
            "invalid",
            "injection",
            "parse error",
            "malformed",
        ]

        return any(pattern in error_str for pattern in security_patterns)

    @classmethod
    def get_remediation(cls, category: str) -> str:
        """Get remediation advice for vulnerability type"""
        remediations = {
            "command_injection": "Use parameterized commands. Never use shell=True. Implement strict input validation and sanitization.",
            "path_traversal": "Implement path canonicalization and allowlisting. Reject paths containing '..' or absolute paths. Use chroot/jail environments.",
            "sql_injection": "Use prepared statements with parameterized queries. Never concatenate user input into SQL. Use ORM frameworks.",
            "prompt_injection": "Implement input sanitization and output filtering. Use structured prompts. Separate user content from system instructions.",
            "ssrf": "Implement strict allowlist for external requests. Validate and sanitize URLs. Block access to internal IP ranges.",
            "xss": "Sanitize user input and escape output. Use Content Security Policy headers. Validate against allowlist of safe characters.",
            "ldap_injection": "Use parameterized queries. Escape special LDAP characters. Implement strict input validation.",
            "xml_injection": "Disable external entity processing. Use safe XML parsers. Validate XML against schema.",
            "nosql_injection": "Use parameterized queries. Validate input types. Implement strict schema validation.",
            "template_injection": "Use sandboxed template engines. Avoid eval() and exec(). Validate template syntax.",
            "crlf_injection": "Sanitize newline characters from user input. Use HTTP libraries that auto-encode headers.",
            "null_bytes": "Reject inputs containing null bytes. Validate file extensions separately from names.",
            "integer_overflow": "Implement bounds checking. Use appropriate integer types. Validate numeric inputs.",
            "format_string": "Never use user input directly in format strings. Use safe formatting methods.",
        }

        return remediations.get(
            category, "Review input validation and implement appropriate security controls."
        )

    @classmethod
    def get_cwe_id(cls, category: str) -> Optional[str]:
        """Get CWE ID for vulnerability category"""
        cwe_mapping = {
            "command_injection": "CWE-78",
            "path_traversal": "CWE-22",
            "sql_injection": "CWE-89",
            "prompt_injection": "CWE-77",  # Command injection variant
            "ssrf": "CWE-918",
            "xss": "CWE-79",
            "ldap_injection": "CWE-90",
            "xml_injection": "CWE-611",
            "nosql_injection": "CWE-943",
            "crlf_injection": "CWE-93",
            "integer_overflow": "CWE-190",
            "format_string": "CWE-134",
        }

        return cwe_mapping.get(category)
