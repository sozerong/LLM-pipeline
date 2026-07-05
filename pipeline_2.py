import asyncio
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from llamafirewall_code_scanner import (
    extract_code_blocks,
    CodeShieldScanner,
    ReportFormatter,
)


class Pipeline:
    class Valves(BaseModel):
        pipelines: list = Field(default_factory=lambda: ["*"])
        enabled: bool = Field(default=True)
        priority: int = 5
        block_on_findings: bool = Field(default=True)
        min_severity_to_block: float = Field(default=0.5)
        annotate_on_safe: bool = Field(default=True)

    def __init__(self, client=None, valves: Optional[object] = None):
        self.type = "filter"
        self.id = "load_codeshield"
        self.name = "Load CodeShield Code Check"
        self.client = client
        self.valves = valves or self.Valves()

        if not isinstance(self.valves, self.Valves):
            try:
                self.valves = self.Valves(**(self.valves.__dict__ if hasattr(self.valves, '__dict__') else {}))
            except Exception:
                self.valves = self.Valves()

        self.scanner = CodeShieldScanner(client)
        self.formatter = ReportFormatter()

        self.block_on_findings = bool(getattr(self.valves, "block_on_findings", True))
        self.min_severity_to_block = float(getattr(self.valves, "min_severity_to_block", 0.5))
        self.annotate_on_safe = bool(getattr(self.valves, "annotate_on_safe", True))

    async def inlet(self, body: Dict[str, Any], user: Optional[dict] = None) -> Dict[str, Any]:
        if not getattr(self.valves, "enabled", True):
            return body

        messages = body.get("messages") or []
        if not messages:
            return body

        last = messages[-1]
        if last.get("role") != "user":
            return body

        content = last.get("content")
        if not isinstance(content, str) or not content.strip():
            return body

        if last.get("_codeshield_scanned", False):
            return body

        code_blocks = extract_code_blocks(content)
        if not code_blocks:
            code_blocks = [("plaintext", content)]
        results, _ = await self.scanner.scan_user_blocks(code_blocks)

        try:
            worst = max((float(r.get("severity", r.get("score", 0.0))) for r in results), default=0.0)
        except Exception:
            worst = 0.0

        has_issue = self.scanner.has_issue(results, threshold=self.min_severity_to_block)

        action = None
        should_block = False
        if has_issue and self.block_on_findings:
            action = "block"
            should_block = True
            final_action = "BLOCK"
        elif has_issue:
            action = "warn"
            should_block = False
            final_action = "WARN"
        else:
            action = "allow"
            should_block = False
            final_action = "ALLOW"

        body.setdefault("_filters", {})
        body["_filters"][self.id] = {
            "detected": bool(has_issue),
            "match_count": len(results),
            "worst_score": worst,
            "final_action": final_action,
            "findings": results,
        }

        if action:
            body["action"] = action
            body["should_block"] = should_block

        last["_codeshield_scanned"] = True
        return body

    async def outlet(self, body: Dict[str, Any], user: Optional[dict] = None) -> Dict[str, Any]:
        """모델 응답 검사"""
        if not getattr(self.valves, "enabled", True):
            return body

        messages = body.get("messages") or []
        if not messages:
            return body

        last_assistant = next((m for m in reversed(messages) if m.get("role") == "assistant"), None)
        if not last_assistant:
            return body

        text = last_assistant.get("content")
        if not isinstance(text, str) or not text.strip():
            return body

        if last_assistant.get("_codeshield_scanned", False):
            return body

        code_blocks = extract_code_blocks(text)
        if not code_blocks:
            code_blocks = [("plaintext", text)]
        results, _ = await self.scanner.scan_assistant_blocks(code_blocks)

        try:
            worst = max((float(r.get("severity", r.get("score", 0.0))) for r in results), default=0.0)
        except Exception:
            worst = 0.0

        has_issue = self.scanner.has_issue(results, threshold=self.min_severity_to_block)

        if has_issue and self.block_on_findings:
            final_action = "BLOCK"
            action = "block"
            should_block = True
        elif has_issue:
            final_action = "WARN"
            action = "warn"
            should_block = False
        else:
            final_action = "ALLOW"
            action = "allow"
            should_block = False

        body.setdefault("_filters", {})
        body["_filters"][self.id] = {
            "detected": bool(has_issue),
            "match_count": len(results),
            "worst_score": worst,
            "final_action": final_action,
            "findings": results,
        }


        return body