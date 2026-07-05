from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Pattern, Iterable
import os
import re
import json

# =========================
# Datatypes
# =========================

@dataclass(frozen=True)
class Span:
    start: int
    end: int
    type: str
    value: str
    rule_name: str

@dataclass(frozen=True)
class Replacement:
    start: int
    end: int
    type: str
    value: str
    replacement: str
    rule_name: str

@dataclass
class DetectionPlan:
    decision: str
    score: float
    reason: str
    values_by_type: Dict[str, List[str]] = field(default_factory=dict)
    spans_all: List[Span] = field(default_factory=list)         
    replacements: List[Replacement] = field(default_factory=list) 

    def to_json(self) -> str:
        def _default(o):
            if isinstance(o, (Span, Replacement)):
                return o.__dict__
            return str(o)
        return json.dumps(self.__dict__, ensure_ascii=False, default=_default, indent=2)

# =========================
# Rule loader
# =========================

@dataclass(frozen=True)
class PatternRule:
    name: str
    typ: str
    regex: Pattern[str]
    mask_token: str

POLICY_RULES_PATH = os.getenv("POLICY_RULES_PATH", "/app/commons/policy_rules.json")

def load_rules() -> List[PatternRule]:
    rules: List[PatternRule] = []
    try:
        with open(POLICY_RULES_PATH, "r", encoding="utf-8") as f:
            payload = json.load(f)
        items = (payload or {}).get("data", [])
        for it in items:
            if (it.get("status") or "").lower() != "deployed":
                continue
            name = (it.get("name") or "").strip() or "UNNAMED"
            pattern_str = it.get("rule")
            if not pattern_str:
                continue
            try:
                regex = re.compile(pattern_str)
            except re.error:
                # 패턴 깨진 경우 스킵
                continue
            typ = name.lower()
            mask_token = f"[{name}]"
            rules.append(PatternRule(name=name, typ=typ, regex=regex, mask_token=mask_token))
    except FileNotFoundError:
        rules = []
    except Exception:
        rules = []
    return rules

# =========================
# Detection
# =========================

def _collect_raw_spans(text: str, rules: Iterable[PatternRule]) -> List[Span]:
    spans: List[Span] = []
    for rule in rules:
        for m in rule.regex.finditer(text):
            s, e = m.span()
            val = text[s:e]
            spans.append(Span(start=s, end=e, type=rule.typ, value=val, rule_name=rule.name))
    return spans

def _resolve_overlaps(spans: List[Span]) -> List[Span]:
    if not spans:
        return []
    # 길이(내림차순) -> 시작위치(오름차순)
    spans_sorted = sorted(spans, key=lambda s: (-(s.end - s.start), s.start))
    selected: List[Span] = []
    def overlaps(a: Span, b: Span) -> bool:
        return not (a.end <= b.start or a.start >= b.end)
    for sp in spans_sorted:
        if any(overlaps(sp, kept) for kept in selected):
            continue
        selected.append(sp)
    return sorted(selected, key=lambda s: s.start)

def _build_replacements(spans: List[Span]) -> List[Replacement]:
    repls: List[Replacement] = []
    for sp in spans:
        token = f"[{sp.rule_name}]"
        repls.append(Replacement(
            start=sp.start,
            end=sp.end,
            type=sp.type,
            value=sp.value,
            replacement=token,
            rule_name=sp.rule_name,
        ))
    return repls

def _values_by_type(spans: List[Span]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for sp in spans:
        arr = out.setdefault(sp.type, [])
        if sp.value not in arr:
            arr.append(sp.value)
    return out

def detect(text: Any) -> DetectionPlan:
    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            text = ""

    rules = load_rules() 
    print(rules)
    spans_raw = _collect_raw_spans(text, rules)
    spans_final = _resolve_overlaps(spans_raw)
    replacements = _build_replacements(spans_final)
    values_map = _values_by_type(spans_final)

    has_hit = len(spans_final) > 0
    plan = DetectionPlan(
        decision=("FLAG" if has_hit else "ALLOW"),
        score=(1.0 if has_hit else 0.0),
        reason=("pii detected" if has_hit else "no match"),
        values_by_type=values_map,
        spans_all=spans_raw,
        replacements=replacements,
    )
    return plan

def apply_plan(text: str, replacements: List[Replacement]) -> str:
    if not isinstance(text, str) or not text or not replacements:
        return text
    reps = sorted(replacements, key=lambda r: r.start, reverse=True)
    out = text
    for r in reps:
        out = out[:r.start] + r.replacement + out[r.end:]
    return out