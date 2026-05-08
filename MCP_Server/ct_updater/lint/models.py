from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LintIssue:
    severity: str
    code: str
    message: str
    target: str = ""


@dataclass
class LintReport:
    ct_path: str
    issues: list[LintIssue] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(issue.severity == "error" for issue in self.issues)
