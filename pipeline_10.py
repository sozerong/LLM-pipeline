import re
import asyncio
import logging
from typing import List, Tuple, Dict, Any

# llamafirewall 라이브러리 import
from llamafirewall import LlamaFirewall, Role, ScannerType, AssistantMessage, UserMessage

# Pygments import
try:
    from pygments.lexers import guess_lexer
    from pygments.util import ClassNotFound
    _PYGMENTS_AVAILABLE = True
except ImportError:
    _PYGMENTS_AVAILABLE = False


def extract_code_blocks(text: str) -> List[Tuple[str, str]]:
    """Pygments로 코드 블록 탐지"""
    code_blocks = []
    
    # Pygments로 전체 텍스트 분석
    if _PYGMENTS_AVAILABLE and text.strip():
        try:
            # 전체 텍스트에서 언어 추측
            lexer = guess_lexer(text)
            lang = lexer.name.lower()
            
            # 코드로 판단되면 추가
            if lang not in ['text', 'plaintext']:
                code_blocks.append((lang, text.strip()))
        except ClassNotFound:
            # 코드가 아닌 일반 텍스트
            pass
        except Exception:
            # Pygments 오류 시 무시
            pass
    
    return code_blocks


class CodeShieldScanner:
    def __init__(self, client=None):
        self.client = client
        self.logger = logging.getLogger("CodeShieldScanner")
       
        # llamafirewall 초기화
        try:
            self.firewall = LlamaFirewall(
                scanners={Role.ASSISTANT: [ScannerType.CODE_SHIELD]}
            )
            self.logger.info("LlamaFirewall CodeShield initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize LlamaFirewall: {e}")
            self.firewall = None
   
    async def scan_user_blocks(self, blocks: List[Tuple[str, str]]) -> Tuple[List[Dict[str, Any]], bool]:
        results = []
        for lang, code in blocks:
            severity = await self._evaluate_risk(code)
            results.append({
                "source": "user",
                "language": lang,
                "severity": severity,
            })
        return results, True
   
    async def scan_assistant_blocks(self, blocks: List[Tuple[str, str]]) -> Tuple[List[Dict[str, Any]], bool]:
        results = []
        for lang, code in blocks:
            severity = await self._evaluate_risk(code)
            results.append({
                "source": "assistant",
                "language": lang,
                "severity": severity,
            })
        return results, True
   
    def has_issue(self, results: List[Dict[str, Any]], threshold: float = 0.5) -> bool:
        return any(r["severity"] >= threshold for r in results)
   
    async def _evaluate_risk(self, code: str) -> float:
        """llamafirewall로 코드 위험도 평가"""
        if not self.firewall:
            self.logger.warning("Firewall not initialized, returning 0.0")
            return 0.0
       
        try:
            scan_result = await asyncio.to_thread(
                self.firewall.scan,
                AssistantMessage(content=code)
            )
           
            # score 추출
            score = float(getattr(scan_result, "score", 0.0))
            decision = str(getattr(scan_result, "decision", ""))
           
            # decision이 "block"이면 높은 점수
            if "block" in decision.lower():
                return max(score, 0.8)
           
            return score
           
        except Exception as e:
            self.logger.error(f"LlamaFirewall scan failed: {e}")
            return 0.0


class ReportFormatter:
    def render_report(self, results: List[Dict[str, Any]]) -> str:
        if not results:
            return "\nCodeShield 검사 통과 (분석된 코드 없음)"
        summary = "\n<details><summary>CodeShield 결과 보기</summary>\n\n"
        for r in results:
            summary += f"- 소스 : {r['source']} | 언어: {r['language']} | 점수: {r.get('severity', 0.0):.2f}\n"
        summary += "\n</details>"
        return summary
   
    def render_user_warning(self, results: List[Dict[str, Any]]) -> str:
        return (
            "\nCodeShield 경고: 위험한 코드가 감지되었습니다. 실행을 중단하세요.\n"
            + self.render_report(results)
        )
   
    def render_block_message(self, results: List[Dict[str, Any]]) -> str:
        return (
            "\nCodeShield 차단: 모델 응답에 보안상 위험 코드가 포함되어 있습니다.\n"
            + self.render_report(results)
        )