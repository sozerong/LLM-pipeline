from typing import Dict, Any, Optional, Literal
from pydantic import BaseModel, Field
import logging

from commons.llamafirewall_guard_scanner import PromptGuardScanner


class Pipeline:
    class Valves(BaseModel):
        pipelines: list = Field(default_factory=lambda: ["*"])
        enabled: bool = Field(default=True)
        priority: int = 4

        # ↓ 로컬에 받은 모델 경로로 기본값 변경
        guard_model_path: str = Field(default="/app/commons/models")
        guard_device: str = Field(default="auto")
        translation_enabled: bool = Field(default=False)
        translation_model: Optional[str] = Field(default=None)

        action_policy: Literal["block", "warn"] = Field(default="block")
        mask_placeholder: str = Field(default="[REDACTED]")
        block_message: str = Field(default="요청이 정책 위반으로 차단되었습니다.")

    def __init__(self, valves: Optional[object] = None):
        self.type = "filter"
        self.id = "load_prompt_guard_filter"
        self.name = "Load Prompt Guard"
        self.Valves = self.Valves
        self.valves = valves or self.Valves()
        if not isinstance(self.valves, self.Valves):
            try:
                self.valves = self.Valves(**valves)
            except Exception:
                self.valves = self.Valves()

        self.logger = logging.getLogger(self.id)
        self.scanner: Optional[PromptGuardScanner] = None

    async def on_startup(self):
        device = self.valves.guard_device
        model_path = getattr(self.valves, 'guard_model_path', None) or "/app/commons/models"
        self.scanner = PromptGuardScanner(model_path=model_path, device=device)
        loaded = self.scanner.load_model()
        if not loaded:
            self.logger.warning("PromptGuardScanner failed to load model")


    async def on_shutdown(self):
        if self.scanner:
            self.scanner.unload_model()

    def _apply_block_policy(self, reason: str, confidence: float, original: str) -> str:
        return "정책에 의해 차단되었습니다. 다시 시도해주세요"



    def _apply_warning_policy(self, reason: str, confidence: float, original: str) -> str:
        return f"[경고] {reason} (confidence={confidence:.2f})\n\n" + original

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

        # --- 2) Scan using PromptGuardScanner ---
        if not self.scanner:
            self.logger.debug("No scanner available; skipping guard.")
            return body

        try:
            res = self.scanner.scan(content)
        except Exception as e:
            self.logger.error("PromptGuardScanner.scan error: %s", e)
            return body

        # scan result shape: { 'safe': bool, 'label': str, 'reason': str|None, 'confidence': float }
        safe = bool(res.get('safe', False))
        reason = res.get('reason') or ''
        score = float(res.get('confidence') or 0.0)
        label = (res.get('label') or '').lower()

        # Always block on unsafe
        if not safe:
            # Replace final user content with configured block message
            last['content'] = getattr(self.valves, 'block_message', 'Request blocked by policy')
            body['action'] = 'block'
            body['should_block'] = True
            body['_filters'] = body.get('_filters', {})
            body['_filters'][self.id] = {
                'detected': True,
                'label': label,
                'reason': reason,
                'confidence': score,
                'final_action': 'BLOCK'
            }
            # index to OpenSearch

            return body

        # Safe -> allow 
        body['_filters'] = body.get('_filters', {})
        body['_filters'][self.id] = {
            'detected': False,
            'final_action': 'ALLOW'
        }
        # index allow event
    
        return body

    async def outlet(self, body: Dict[str, Any], user: Optional[dict] = None) -> Dict[str, Any]:
        return body