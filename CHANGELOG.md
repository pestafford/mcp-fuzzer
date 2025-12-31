# Changelog

All notable changes to MCP Fuzzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-30

### Added
- Initial release of MCP Fuzzer
- Comprehensive payload library with 150+ attack payloads
- Support for 14 vulnerability categories:
  - Command injection
  - Path traversal
  - SQL injection
  - Prompt injection
  - XSS
  - SSRF
  - LDAP injection
  - XML injection (XXE)
  - NoSQL injection
  - Template injection
  - CRLF injection
  - Null byte injection
  - Integer overflow
  - Format string vulnerabilities
- MCP SDK native integration
- Smart vulnerability detection and analysis
- CWE mapping for all vulnerability types
- Multiple output formats (Text, JSON, HTML)
- Command-line interface with rich options
- Python API for programmatic usage
- Severity scoring (CRITICAL, HIGH, MEDIUM, LOW)
- Remediation guidance for all vulnerability types
- CI/CD integration examples
- Comprehensive documentation
- Unit tests for core functionality
- Example scripts for common use cases

### Features
- Zero telemetry - all processing local
- Configurable timeout and payload limits
- Category-specific testing
- Verbose mode for debugging
- Exit codes based on severity for CI/CD
- Beautiful HTML reports
- Detailed finding analysis

## [Unreleased]

### Planned
- Passive scanning mode (read-only)
- Custom payload file support
- Mutation-based fuzzing
- Web UI dashboard
- Historical trend analysis
- Machine learning for response analysis
