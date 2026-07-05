import asyncio
import logging
from typing import Any, Dict, List, Optional


class LFWRegexDetector:

    def __init__(self) -> None:
        self._available = False
        self._scanner = None
        self._UserMessage = None
        self._logger = logging.getLogger("commons.llamafirewall_regex_scanner")

        try:
            from llamafirewall.scanners.regex_scanner import RegexScanner
            from llamafirewall.llamafirewall_data_types import UserMessage

            self._UserMessage = UserMessage
            self._scanner = RegexScanner()
            self._available = True
            self._logger.info("RegexScanner initialized successfully.")
        except Exception as e:
            self._logger.error(f"Failed to initialize RegexScanner: {e}")
            self._available = False

    async def _scan(self, text: str) -> Any:
        if not self._available:
            self._logger.warning("RegexScanner not available. Skipping detection.")
            return None
        if not isinstance(text, str) or not text.strip():
            self._logger.warning("Invalid or empty text provided for scanning.")
            return None
        try:
            msg = self._UserMessage(content=text)
            raw = self._scanner.scan(msg)
            if asyncio.iscoroutine(raw):
                raw = await raw
            return raw
        except Exception as e:
            self._logger.exception(f"RegexScanner scan failed: {e}")
            return None

    @staticmethod
    def _extract_spans(result: Any, text: str) -> List[Dict[str, Any]]:  # 위치가 오면 추출
        spans: List[Dict[str, Any]] = []

        def _add(start, end, val_type="", val=""):
            if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(text):
                spans.append({"start": start, "end": end, "type": val_type, "value": val})

        if result is None:
            return spans

        try:
            if isinstance(result, dict):
                for section in ("spans", "matches", "findings", "entities", "detections", "results"):
                    for s in (result.get(section) or []):
                        if isinstance(s, dict):
                            start = s.get("start")
                            end = s.get("end")
                            typ = s.get("type") or s.get("kind") or s.get("label") or ""
                            val = s.get("value") or s.get("text") or s.get("match") or ""
                            span = s.get("span")
                            if (start is None or end is None) and isinstance(span, dict):
                                start = span.get("start")
                                end = span.get("end")
                            _add(start, end, typ, val)
                        else:
                            start = getattr(s, "start", None)
                            end = getattr(s, "end", None)
                            typ = getattr(s, "type", None) or getattr(s, "kind", None) or getattr(s, "label", None) or ""
                            val = getattr(s, "value", None) or getattr(s, "text", None) or getattr(s, "match", None) or ""
                            span_obj = getattr(s, "span", None)
                            if (start is None or end is None) and span_obj is not None:
                                start = getattr(span_obj, "start", None)
                                end = getattr(span_obj, "end", None)
                            _add(start, end, typ, val)
            else:
                for section in ("spans", "matches", "findings", "entities", "detections", "results"):
                    objs = getattr(result, section, None)
                    if not objs:
                        continue
                    for s in objs:
                        start = getattr(s, "start", None)
                        end = getattr(s, "end", None)
                        typ = getattr(s, "type", None) or getattr(s, "kind", None) or getattr(s, "label", None) or ""
                        val = getattr(s, "value", None) or getattr(s, "text", None) or getattr(s, "match", None) or ""
                        span_obj = getattr(s, "span", None)
                        if (start is None or end is None) and span_obj is not None:
                            start = getattr(span_obj, "start", None)
                            end = getattr(span_obj, "end", None)
                        _add(start, end, typ, val)
        except Exception as e:
            logging.warning(f"Span extraction failed: {e}")

        return spans

    @staticmethod
    def _truthy_decision(decision: Any, score: Optional[float]) -> bool:
        name = str(getattr(decision, "name", decision) or "").upper()
        if name in {"BLOCK", "FLAG", "DETECT", "FOUND"}:
            return True
        try:
            return (float(score) if score is not None else 0.0) > 0.0
        except Exception:
            return False

    async def detect(self, text: str, role: Optional[str] = None) -> Dict[str, Any]:
        result = await self._scan(text)
        spans = self._extract_spans(result, text)

        # ↓↓↓ 여기서 decision/score 기반으로도 detected 판단
        if isinstance(result, dict):
            decision = result.get("decision")
            score = result.get("score", 0.0)
            reason = result.get("reason")
        else:
            decision = getattr(result, "decision", None)
            score = getattr(result, "score", 0.0)
            reason = getattr(result, "reason", None)

        detected = bool(spans) or self._truthy_decision(decision, score)

        return {
            "detected": detected,
            "matches": spans,          # 위치가 없으면 빈 리스트(정상)
            "risk_score": float(score or 0.0),
            "decision": (getattr(decision, "name", decision) if decision is not None else None),
            "reason": reason,
        }