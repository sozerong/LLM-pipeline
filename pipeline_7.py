from typing import Any, Dict, List, Optional, Tuple, Literal
from pydantic import BaseModel, Field
import logging

from commons.detect_secrets import SecretDetector


class Pipeline:
    class Valves(BaseModel):
        pipelines: List[str] = Field(default_factory=lambda: ["*"])
        enabled: bool = Field(default=True)
        priority: int = Field(default=4)

        base64_limit: float = Field(default=4.5)
        hex_limit: float = Field(default=3.0)
        enable_high_entropy: bool = Field(default=True)
        on_detect_policy: str = Field(
            "masking",
            description='처리 정책: "masking" | "block" | "allow"',
            json_schema_extra={"enum": ["block", "masking", "allow"]},
        )

        mask_placeholder: str = Field(default="[MASK]")
        block_message: str = Field(default="시크릿 정보가 감지되어 차단되었습니다.")

    def __init__(self, valves: Optional[object] = None):
        self.type = "filter"
        self.id = "load_detect_secrets"
        self.name = "Detect Secrets"
        self.valves = valves or self.Valves()
        if not isinstance(self.valves, self.Valves):
            try:
                self.valves = self.Valves(**(self.valves.__dict__ if hasattr(self.valves, '__dict__') else {}))
            except Exception:
                self.valves = self.Valves()

        self.logger = logging.getLogger(self.id)
        self.detector = SecretDetector(logger=self.logger)

    def _mask_text(self, text: str, spans: List[Tuple[int, int]]) -> str:
        if not spans:
            return text

        spans = sorted(spans, key=lambda x: x[0])
        merged: List[Tuple[int, int]] = []

        for s, e in spans:
            if not merged or s > merged[-1][1]:
                merged.append((s, e))
            else:
                ps, pe = merged[-1]
                merged[-1] = (ps, max(pe, e))

        out = []
        last = 0
        for s, e in merged:
            out.append(text[last:s])
            out.append(self.valves.mask_placeholder)
            last = e
        out.append(text[last:])

        return "".join(out)

    async def inlet(
        self,
        body: Dict[str, Any],
        user: Optional[dict] = None
    ) -> Dict[str, Any]:

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

        cfg = {"base64_limit": float(self.valves.base64_limit), "hex_limit": float(self.valves.hex_limit)}
        spans, count = self.detector.detect(content, cfg)

        # _filters 메타 객체 준비
        filters = body.setdefault('_filters', {})

        if count <= 0:
            # === ALLOW (탐지 없음) ===
            body['action'] = 'allow'
            body['should_block'] = False
            body['mode'] = 'allow'
            # Load_regex_filter와 동일한 메타 구조
            filters[self.id] = {
                'decision': 'ALLOW',
                'score': 0.0,
                'types': [],
                'match_counts': {},
            }
            return body

        # 탐지된 경우, 공통 메타(FLAG + 카운트 정보)
        decision_meta = {
            'decision': 'FLAG',
            'score': 1.0,
            'types': ['secret'],
            'match_counts': {'secret': count},
        }

        policy = (self.valves.on_detect_policy or "masking")

        if policy == 'block':
            last['content'] = "정책에 의해 차단되었습니다. 다시 시도해주세요"
            body['action'] = 'block'
            body['should_block'] = True
            filters[self.id] = {**decision_meta, 'final_action': 'BLOCK'}
            return body

        if policy == 'masking':
            masked = self._mask_text(content, spans)
            last['content'] = masked
            body['action'] = 'masking'
            body['should_block'] = False
            filters[self.id] = {**decision_meta, 'final_action': 'MASKING'}
            return body

        # policy == 'allow' 인 경우: 탐지되었지만 허용
        body['action'] = 'allow'
        body['should_block'] = False
        filters[self.id] = {**decision_meta, 'final_action': 'ALLOW'}
        return body

    async def outlet(
        self,
        body: Dict[str, Any],
        __event_emitter__=None,
        __user__: Optional[dict] = None
    ) -> Dict[str, Any]:
        """메시지 후처리"""
        return body
