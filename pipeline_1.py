from typing import Dict, Any, Optional, List, Literal
import logging
from commons.llamafirewall_regex_scanner import LFWRegexDetector
from pydantic import BaseModel, Field
class Pipeline:
    class Valves(BaseModel):
        pipelines: List[str] = Field(default_factory=lambda: ['*'])
        enabled: bool = True
        priority: int = 2
        on_detect_policy: Literal['masking', 'block', 'allow'] = 'allow'  # 탐지만
        mask_placeholder: str = '[개인정보]'
        block_message: str = '정책에 의해 차단되었습니다. 다시 시도해주세요'
    def __init__(self, valves: Optional[object] = None):
        self.type = "filter"
        self.id = "load_llamafirewall_regex"
        self.name = "Load Llamafirewall Regex"
        if isinstance(valves, self.Valves):
            self.valves = valves
        elif isinstance(valves, dict):
            self.valves = self.Valves(**valves)
        elif hasattr(valves, "__dict__"):
            self.valves = self.Valves(**valves.__dict__)
        else:
            self.valves = self.Valves()
        self.logger = logging.getLogger(self.id)
        self.detector = None
    async def _get_detector_result(self, content: str) -> Dict[str, Any]:
        if self.detector is None:
            try:
                self.detector = LFWRegexDetector()
                self.logger.info("LFWRegexDetector initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize detector: {e}")
                return {"detected": False, "matches": [], "risk_score": 0.0}
        try:
            result = await self.detector.detect(content, role='user')
            self.logger.debug(f"Detection result: {result}")
            return result
        except Exception as e:
            self.logger.error(f"Detector error: {e}")
            return {"detected": False, "matches": [], "risk_score": 0.0}
    async def inlet(self, body: Dict[str, Any], user: Optional[dict] = None) -> Dict[str, Any]:
        if not getattr(self.valves, 'enabled', True):
            return body
        messages = body.get('messages') or []
        if not messages:
            return body
        last = messages[-1]
        if last.get('role') != 'user':
            return body
        content = last.get('content')
        if not isinstance(content, str) or not content.strip():
            return body
        self.logger.debug(f"Content passed to detector: {content}")
        result = await self._get_detector_result(content)
        detected = bool(result.get('detected', False))
        matches = result.get('matches', []) or []
        risk = float(result.get('risk_score', 0.0) or 0.0)
        decision = result.get('decision')
        reason = result.get('reason')
        filters = body.get('_filters', {})
        filters[self.id] = {
            'detected': detected,
            'match_count': len(matches),
            'risk_score': risk,
            'decision': decision,
            'reason': reason,
        }
        body['_filters'] = filters
        return body
    async def outlet(self, body: Dict[str, Any], user: Optional[dict] = None) -> Dict[str, Any]:
        return body