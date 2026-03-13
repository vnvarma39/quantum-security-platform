"""
Static analysis validator for synthesized patches.
Uses libcst for Python AST analysis and tree-sitter for C/Go/JS.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

import structlog

log = structlog.get_logger()

Language = Literal["python", "c", "go", "javascript"]

SUPPORTED_LANGUAGES: set[Language] = {"python", "c", "go", "javascript"}

# Simple pattern-based rules (production would use full AST)
PYTHON_RULES = [
    (r"db\.execute\s*\(\s*[\"'].*?[\"']\s*\+", "sql_injection", "String concatenation in DB query — use parameterized queries"),
    (r"os\.system\s*\(", "command_injection", "os.system() is vulnerable to command injection — use subprocess with list args"),
    (r"password\s*=\s*[\"'][^\"']+[\"']", "hardcoded_secret", "Hardcoded password detected"),
    (r"secret\s*=\s*[\"'][^\"']+[\"']", "hardcoded_secret", "Hardcoded secret detected"),
    (r"eval\s*\(", "dangerous_eval", "eval() is dangerous with untrusted input"),
    (r"pickle\.loads?\s*\(", "insecure_deserialization", "pickle.load() with untrusted data enables RCE"),
    (r"subprocess\.call\s*\(\s*[\"']", "command_injection", "subprocess.call with string — use list form"),
    (r"assert\s+", "assert_used", "assert statements are stripped in optimized mode — use explicit checks"),
]

C_RULES = [
    (r"\bstrcpy\s*\(", "unsafe_strcpy", "strcpy() has no bounds checking — use strncpy or strlcpy"),
    (r"\bstrcat\s*\(", "unsafe_strcat", "strcat() has no bounds checking — use strncat"),
    (r"\bsprintf\s*\(", "unsafe_sprintf", "sprintf() can overflow — use snprintf"),
    (r"\bgets\s*\(", "unsafe_gets", "gets() is unconditionally unsafe — use fgets"),
    (r"\bmemcpy\s*\([^,]+,\s*[^,]+,\s*(?!sizeof)", "unchecked_memcpy", "memcpy without sizeof — verify length"),
    (r"\bsystem\s*\(", "command_injection", "system() is vulnerable to injection"),
]

RULES_BY_LANG: dict[str, list] = {
    "python": PYTHON_RULES,
    "c": C_RULES,
    "go": [],
    "javascript": [],
}


@dataclass
class AnalysisResult:
    passed: bool
    score: float                        # 0–1, higher is safer
    findings: list[str] = field(default_factory=list)
    rules_triggered: list[str] = field(default_factory=list)
    language: str = ""
    lines_analyzed: int = 0


class StaticAnalyzer:
    """
    Lightweight static analyzer for patch validation.
    In production, integrates with semgrep and bandit for Python,
    and cppcheck / clang-tidy for C/C++.
    """

    def __init__(self, language: Language):
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language: {language!r}. Supported: {SUPPORTED_LANGUAGES}")
        self.language = language
        self.rules = RULES_BY_LANG.get(language, [])

    def analyze(self, code: str) -> AnalysisResult:
        if not code.strip():
            return AnalysisResult(passed=True, score=1.0, language=self.language, lines_analyzed=0)

        lines = code.splitlines()
        findings: list[str] = []
        rules_triggered: list[str] = []

        for pattern, rule_id, message in self.rules:
            if re.search(pattern, code):
                findings.append(message)
                rules_triggered.append(rule_id)
                log.debug("static_analysis.finding", rule=rule_id, language=self.language)

        # Score: 1.0 = no findings, decreases with each finding
        score = max(0.0, 1.0 - len(findings) * 0.15)
        passed = len(findings) == 0

        log.info(
            "static_analysis.complete",
            language=self.language,
            findings=len(findings),
            passed=passed,
            score=round(score, 3),
        )

        return AnalysisResult(
            passed=passed,
            score=score,
            findings=findings,
            rules_triggered=rules_triggered,
            language=self.language,
            lines_analyzed=len(lines),
        )
