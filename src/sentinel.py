import argparse
import os
import re
import sys
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import urllib.request

@dataclass
class Finding:
    file_path: str
    line_number: int
    severity: str
    rule_id: str
    message: str

SECURITY_PATTERNS = [
    (r"(?i)(api_key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_\-]{12,}['"]", "SEC-001", "HIGH", "Potential hardcoded credential or API token detected."),
    (r"\beval\s*\(", "SEC-002", "HIGH", "Unsafe use of eval() detected; susceptible to code injection."),
    (r"subprocess\.(Popen|call|run)\(.*shell\s*=\s*True", "SEC-003", "MEDIUM", "Subprocess invoked with shell=True; verify input sanitization."),
    (r"(?i)SELECT\s+.*\s+FROM\s+.*\+%s", "SEC-004", "HIGH", "Potential SQL injection pattern via string formatting."),
]

class DiffScanner:
    def __init__(self, diff_text: str):
        self.diff_text = diff_text

    def scan_static(self) -> List[Finding]:
        findings: List[Finding] = []
        current_file = "unknown"
        current_line = 0

        for line in self.diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
            elif line.startswith("@@ "):
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line = int(match.group(1)) - 1
            elif line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                added_code = line[1:]
                for pattern, rule_id, severity, message in SECURITY_PATTERNS:
                    if re.search(pattern, added_code):
                        findings.append(
                            Finding(
                                file_path=current_file,
                                line_number=current_line,
                                severity=severity,
                                rule_id=rule_id,
                                message=message,
                            )
                        )
            elif not line.startswith("-"):
                current_line += 1

        return findings

    def request_ai_review(self, api_key: str, model: str = "gpt-4o-mini") -> Dict[str, str]:
        prompt = (
            "You are an expert open-source maintainer and security auditor. "
            "Review the following Git diff for bugs, security risks, and performance issues. "
            "Provide a concise markdown summary:\n\n" + self.diff_text[:6000]
        )
        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode("utf-8"))
                review_text = result["choices"][0]["message"]["content"]
                return {"status": "success", "review": review_text}
        except Exception as exc:
            return {"status": "error", "review": f"AI review request failed: {exc}"}

def format_markdown_report(findings: List[Finding], ai_summary: Optional[str] = None) -> str:
    lines = ["## 🛡️ Codex PR Sentinel Report\n"]
    if not findings:
        lines.append("✅ **Static Analysis:** No deterministic security issues detected.\n")
    else:
        lines.append(f"⚠️ **Static Analysis:** Found **{len(findings)}** potential issue(s):\n")
        lines.append("| Severity | Rule | Location | Description |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for f in findings:
            lines.append(f"| **{f.severity}** | `{f.rule_id}` | `{f.file_path}:{f.line_number}` | {f.message} |")
        lines.append("")

    if ai_summary:
        lines.append("### 🤖 AI Maintainer Review\n")
        lines.append(ai_summary)

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Codex PR Sentinel - Automated PR Triage & Security Scanner")
    parser.add_argument("--diff-file", type=str, required=True, help="Path to the git diff file to analyze")
    parser.add_argument("--ai-review", action="store_true", help="Enable OpenAI-powered deep code review")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    args = parser.parse_args()

    if not os.path.exists(args.diff_file):
        print(f"Error: Diff file '{args.diff_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(args.diff_file, "r", encoding="utf-8") as f:
        diff_content = f.read()

    scanner = DiffScanner(diff_content)
    findings = scanner.scan_static()

    ai_summary = None
    if args.ai_review:
        api_key = os.environ.get("OPENAI_API_KEY")
        if api_key:
            res = scanner.request_ai_review(api_key)
            ai_summary = res.get("review")
        else:
            ai_summary = "_Skipped AI review: `OPENAI_API_KEY` environment variable not set._"

    if args.format == "json":
        print(json.dumps({
            "findings": [asdict(f) for f in findings],
            "ai_review": ai_summary
        }, indent=2))
    else:
        print(format_markdown_report(findings, ai_summary))

    if any(f.severity == "HIGH" for f in findings):
        sys.exit(2)

if __name__ == "__main__":
    main()
