"""Vulnerability detection patterns using Tree-sitter queries."""

from typing import Dict, List
from dataclasses import dataclass


@dataclass
class VulnerabilityPattern:
    """Represents a vulnerability detection pattern."""

    name: str
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    cwe: str  # CWE identifier
    query: str  # Tree-sitter query pattern
    language: str


class VulnerabilityPatterns:
    """Collection of Tree-sitter patterns for detecting common vulnerabilities."""

    @staticmethod
    def get_sql_injection_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting SQL injection vulnerabilities."""
        return [
            VulnerabilityPattern(
                name="SQL Injection - String Concatenation",
                description="SQL query constructed using string concatenation with user input",
                severity="critical",
                cwe="CWE-89",
                query="""
                (call
                  function: (attribute
                    object: (_)
                    attribute: (identifier) @method)
                  arguments: (argument_list
                    (binary_operator) @concat))
                (#match? @method "^(execute|executemany|cursor)$")
                """,
                language="python"
            ),
            VulnerabilityPattern(
                name="SQL Injection - Format String",
                description="SQL query using string formatting with potential user input",
                severity="critical",
                cwe="CWE-89",
                query="""
                (call
                  function: (attribute
                    attribute: (identifier) @method)
                  arguments: (argument_list
                    (call
                      function: (attribute
                        attribute: (identifier) @format_method))))
                (#match? @method "^(execute|executemany)$")
                (#match? @format_method "^format$")
                """,
                language="python"
            ),
        ]

    @staticmethod
    def get_xss_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting Cross-Site Scripting (XSS) vulnerabilities."""
        return [
            VulnerabilityPattern(
                name="XSS - innerHTML assignment",
                description="Direct assignment to innerHTML with potential user input",
                severity="high",
                cwe="CWE-79",
                query="""
                (assignment_expression
                  left: (member_expression
                    property: (property_identifier) @prop)
                  right: (_))
                (#eq? @prop "innerHTML")
                """,
                language="javascript"
            ),
            VulnerabilityPattern(
                name="XSS - dangerouslySetInnerHTML in React",
                description="Using dangerouslySetInnerHTML without sanitization",
                severity="high",
                cwe="CWE-79",
                query="""
                (jsx_attribute
                  (property_identifier) @attr_name
                  (jsx_expression))
                (#eq? @attr_name "dangerouslySetInnerHTML")
                """,
                language="javascript"
            ),
        ]

    @staticmethod
    def get_command_injection_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting command injection vulnerabilities."""
        return [
            VulnerabilityPattern(
                name="Command Injection - subprocess with shell=True",
                description="Using subprocess with shell=True and potential user input",
                severity="critical",
                cwe="CWE-78",
                query="""
                (call
                  function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @func)
                  arguments: (argument_list
                    (keyword_argument
                      name: (identifier) @param
                      value: (true))))
                (#eq? @module "subprocess")
                (#match? @func "^(run|call|Popen)$")
                (#eq? @param "shell")
                """,
                language="python"
            ),
            VulnerabilityPattern(
                name="Command Injection - os.system",
                description="Using os.system with potential user input",
                severity="critical",
                cwe="CWE-78",
                query="""
                (call
                  function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @func))
                (#eq? @module "os")
                (#eq? @func "system")
                """,
                language="python"
            ),
        ]

    @staticmethod
    def get_path_traversal_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting path traversal vulnerabilities."""
        return [
            VulnerabilityPattern(
                name="Path Traversal - os.path.join without validation",
                description="Using os.path.join with user input without validation",
                severity="high",
                cwe="CWE-22",
                query="""
                (call
                  function: (attribute
                    object: (attribute
                      object: (identifier) @os_module
                      attribute: (identifier) @path_module)
                    attribute: (identifier) @func))
                (#eq? @os_module "os")
                (#eq? @path_module "path")
                (#eq? @func "join")
                """,
                language="python"
            ),
        ]

    @staticmethod
    def get_insecure_deserialization_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting insecure deserialization vulnerabilities."""
        return [
            VulnerabilityPattern(
                name="Insecure Deserialization - pickle.loads",
                description="Using pickle.loads with untrusted data",
                severity="critical",
                cwe="CWE-502",
                query="""
                (call
                  function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @func))
                (#eq? @module "pickle")
                (#match? @func "^(loads|load)$")
                """,
                language="python"
            ),
            VulnerabilityPattern(
                name="Insecure Deserialization - eval",
                description="Using eval() with user input",
                severity="critical",
                cwe="CWE-502",
                query="""
                (call
                  function: (identifier) @func)
                (#eq? @func "eval")
                """,
                language="python"
            ),
        ]

    @staticmethod
    def get_hardcoded_secrets_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting hardcoded secrets."""
        return [
            VulnerabilityPattern(
                name="Hardcoded Secrets - API Key",
                description="Potential hardcoded API key or secret",
                severity="high",
                cwe="CWE-798",
                query="""
                (assignment
                  left: (identifier) @var_name
                  right: (string) @secret)
                (#match? @var_name "(?i)(api_key|secret|password|token|auth)")
                """,
                language="python"
            ),
        ]

    @staticmethod
    def get_weak_crypto_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting weak cryptography."""
        return [
            VulnerabilityPattern(
                name="Weak Cryptography - MD5/SHA1",
                description="Using weak hashing algorithms (MD5, SHA1)",
                severity="medium",
                cwe="CWE-327",
                query="""
                (call
                  function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @func))
                (#eq? @module "hashlib")
                (#match? @func "^(md5|sha1)$")
                """,
                language="python"
            ),
        ]

    @staticmethod
    def get_xxe_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting XML External Entity (XXE) vulnerabilities."""
        return [
            VulnerabilityPattern(
                name="XXE - Unsafe XML parsing",
                description="XML parsing without disabling external entities",
                severity="high",
                cwe="CWE-611",
                query="""
                (call
                  function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @func))
                (#match? @module "^(xml|lxml|ElementTree)$")
                (#match? @func "^(parse|fromstring|XMLParser)$")
                """,
                language="python"
            ),
        ]

    @staticmethod
    def get_csrf_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting CSRF vulnerabilities."""
        return [
            VulnerabilityPattern(
                name="CSRF - Missing CSRF Protection",
                description="Django view without CSRF protection",
                severity="high",
                cwe="CWE-352",
                query="""
                (decorator
                  (identifier) @decorator)
                (#eq? @decorator "csrf_exempt")
                """,
                language="python"
            ),
        ]

    @staticmethod
    def get_open_redirect_patterns() -> List[VulnerabilityPattern]:
        """Get patterns for detecting open redirect vulnerabilities."""
        return [
            VulnerabilityPattern(
                name="Open Redirect - Unvalidated redirect",
                description="HTTP redirect with user-controlled URL",
                severity="medium",
                cwe="CWE-601",
                query="""
                (call
                  function: (identifier) @func
                  arguments: (argument_list))
                (#match? @func "^(redirect|HttpResponseRedirect)$")
                """,
                language="python"
            ),
        ]

    @staticmethod
    def get_all_patterns() -> Dict[str, List[VulnerabilityPattern]]:
        """Get all vulnerability patterns organized by category."""
        return {
            "sql_injection": VulnerabilityPatterns.get_sql_injection_patterns(),
            "xss": VulnerabilityPatterns.get_xss_patterns(),
            "command_injection": VulnerabilityPatterns.get_command_injection_patterns(),
            "path_traversal": VulnerabilityPatterns.get_path_traversal_patterns(),
            "insecure_deserialization": VulnerabilityPatterns.get_insecure_deserialization_patterns(),
            "hardcoded_secrets": VulnerabilityPatterns.get_hardcoded_secrets_patterns(),
            "weak_crypto": VulnerabilityPatterns.get_weak_crypto_patterns(),
            "xxe": VulnerabilityPatterns.get_xxe_patterns(),
            "csrf": VulnerabilityPatterns.get_csrf_patterns(),
            "open_redirect": VulnerabilityPatterns.get_open_redirect_patterns(),
        }

    @staticmethod
    def get_patterns_for_language(language: str) -> List[VulnerabilityPattern]:
        """Get all patterns applicable to a specific language."""
        all_patterns = VulnerabilityPatterns.get_all_patterns()
        result = []
        for patterns in all_patterns.values():
            result.extend([p for p in patterns if p.language == language])
        return result
