from typing import Any, Dict, List, Optional, Tuple
import logging
import re
import math

_DETECT_SECRETS_AVAILABLE = False
_scan_text_fn = None
try:
    import detect_secrets
    try:
        from detect_secrets.core.scan import scan_text as _scan_text_fn
    except Exception:
        try:
            from detect_secrets.core.scan import scan_string as _scan_text_fn
        except Exception:
            _scan_text_fn = None
    if _scan_text_fn is not None:
        _DETECT_SECRETS_AVAILABLE = True
except Exception:
    _DETECT_SECRETS_AVAILABLE = False


class SecretDetector:    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def get_plugins(self, config: Dict[str, Any]) -> List[Any]:
        if not _DETECT_SECRETS_AVAILABLE:
            return []
        # best-effort: try to introspect plugins from detect_secrets
        try:
            plugins = []
            # detect_secrets may expose plugin manager internals; be defensive
            manager = getattr(detect_secrets, 'plugins', None) or getattr(detect_secrets, 'core', None)
            if manager:
                # not guaranteed; just return empty or a simple marker
                return plugins
        except Exception:
            return []
        return []
    
    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        # Shannon entropy
        probs = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in probs)

    def detect(self, text: str, config: Dict[str, Any]) -> Tuple[List[Tuple[int, int]], int]:
        spans: List[Tuple[int, int]] = []

        if _DETECT_SECRETS_AVAILABLE and _scan_text_fn is not None:
            try:
                collection = _scan_text_fn(text)

                secret_values: List[str] = []
                try:
                    if hasattr(collection, 'secrets'):
                        for item in collection.secrets:
                            val = getattr(item, 'secret_value', None) or getattr(item, 'value', None)
                            if val:
                                secret_values.append(val)
                    elif hasattr(collection, 'data'):
                        for v in getattr(collection, 'data') or []:
                            val = getattr(v, 'secret_value', None) or getattr(v, 'value', None)
                            if val:
                                secret_values.append(val)
                    elif isinstance(collection, dict):
                        for k, v in collection.items():
                            try:
                                if isinstance(v, list):
                                    for it in v:
                                        cand = getattr(it, 'secret_value', None) or getattr(it, 'value', None) or (it.get('secret') if isinstance(it, dict) else None)
                                        if cand:
                                            secret_values.append(cand)
                            except Exception:
                                continue
                except Exception:
                    secret_values = []

                for sv in secret_values:
                    if not sv:
                        continue
                    start = 0
                    while True:
                        idx = text.find(sv, start)
                        if idx == -1:
                            break
                        spans.append((idx, idx + len(sv)))
                        start = idx + len(sv)

                if spans:
                    spans = sorted(spans, key=lambda x: x[0])
                    merged = [spans[0]]
                    for s, e in spans[1:]:
                        ps, pe = merged[-1]
                        if s <= pe:
                            merged[-1] = (ps, max(pe, e))
                        else:
                            merged.append((s, e))
                    spans = merged

                return spans, len(spans)
            except Exception as e:
                self.logger.exception('detect-secrets scan failed, falling back: %s', e)

        try:
            patterns = [ # 정책 로딩으로 변경 예정
                r"[A-Za-z0-9_\-]{20,}",  
                r"AKIA[0-9A-Z]{16}",      
                r"(?i)api[_-]?key\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})",
                r"-----BEGIN PRIVATE KEY-----",
                r"sk-[A-Za-z0-9]{24,}",    
            ]

            base64_limit = float(config.get("base64_limit", 4.5)) if config else 4.5
            hex_limit = float(config.get("hex_limit", 3.0)) if config else 3.0

            lines = text.split("\n")
            offset = 0
            for line in lines:
                for p in patterns:
                    for m in re.finditer(p, line):
                        s = offset + m.start()
                        e = offset + m.end()
                        spans.append((s, e))
                tokens = re.findall(r"[A-Za-z0-9+/=]{8,}", line)
                for t in tokens:
                    ent = self._entropy(t)
                    if ent >= base64_limit or (re.fullmatch(r"[0-9a-fA-F]+", t) and ent >= hex_limit):
                        idx = line.find(t)
                        if idx >= 0:
                            spans.append((offset + idx, offset + idx + len(t)))
                offset += len(line) + 1

            if spans:
                spans = sorted(spans, key=lambda x: x[0])
                merged = [spans[0]]
                for s, e in spans[1:]:
                    ps, pe = merged[-1]
                    if s <= pe:
                        merged[-1] = (ps, max(pe, e))
                    else:
                        merged.append((s, e))
                spans = merged

        except Exception as e:
            self.logger.exception("Secret detection failed: %s", e)

        return spans, len(spans)