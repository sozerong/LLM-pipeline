from typing import Dict, Any, Optional
import os
import re
import requests
import torch


class PromptGuardScanner:
    def __init__(self, model_path: str, device: str = "auto"):
        self.model_path = os.path.abspath(model_path)
        self._device_pref = device  # "auto" | "cuda" | "cpu"
        self.device = self._resolve_device(device)
        self.model = None
        self.tokenizer = None

    def _resolve_device(self, device: str) -> str:
        if device == "auto":
            return "cuda" if torch.cuda.is_available() else "cpu"
        if device == "cuda":
            return "cuda" if torch.cuda.is_available() else "cpu"
        return "cpu"

    def load_model(self) -> bool:
        try:
            from transformers import AutoConfig, AutoTokenizer, AutoModelForSequenceClassification

            mp = os.path.abspath(self.model_path)
            print(f"[PromptGuard] model_path={mp}, device={self.device}")

            if not os.path.isdir(mp):
                print(f"[PromptGuard] 폴더 아님: {mp}")
                return False

            required = ["config.json", "model.safetensors"]
            missing = [f for f in required if not os.path.exists(os.path.join(mp, f))]
            if missing:
                print(f"[PromptGuard] 필수 파일 누락: {missing}")
                return False

            def _try_load(trust_remote_code: bool, use_fast_tokenizer: Optional[bool]):
                tok = AutoTokenizer.from_pretrained(
                    mp, local_files_only=True, trust_remote_code=trust_remote_code,
                    **({} if use_fast_tokenizer is None else {"use_fast": use_fast_tokenizer})
                )
                dtype = torch.float16 if self.device == "cuda" else torch.float32
                mdl = AutoModelForSequenceClassification.from_pretrained(
                    mp, local_files_only=True, trust_remote_code=trust_remote_code, torch_dtype=dtype
                )
                return tok, mdl

            try:
                self.tokenizer, self.model = _try_load(False, None)
            except Exception as e1:
                print(f"[PromptGuard] 1차 로드 실패: {e1}")
                try:
                    self.tokenizer, self.model = _try_load(False, False)
                except Exception as e2:
                    print(f"[PromptGuard] 2차 로드 실패: {e2}")
                    try:
                        self.tokenizer, self.model = _try_load(True, False)
                    except Exception as e3:
                        print(f"[PromptGuard] 3차 로드 실패: {e3}")
                        return False

            self.model.to(self.device)
            self.model.eval()
            print("[PromptGuard] 모델 로딩 완료")
            return True

        except ImportError:
            print("[PromptGuard] 설치 필요: pip install -U transformers torch safetensors sentencepiece protobuf")
            return False
        except Exception as e:
            print(f"[PromptGuard] 모델 로딩 실패(최상위): {e}")
            return False

    def unload_model(self):
        if self.model:
            del self.model
            del self.tokenizer
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            print("[PromptGuard] Model unloaded")

    def scan(self, text: str) -> Dict[str, Any]:
        if not self.model or not self.tokenizer:
            return {"safe": False, "label": "ERROR", "reason": "model_not_loaded", "confidence": 0.0}

        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True).to(self.device)
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.nn.functional.softmax(logits, dim=-1)
                predicted_class = probs.argmax(dim=-1).item()
                confidence = probs[0][predicted_class].item()

            is_safe = (predicted_class == 0)
            if is_safe:
                return {"safe": True, "label": "SAFE", "reason": None, "confidence": confidence, "predicted_class": predicted_class}

            reason = "unsafe"
            if predicted_class == 1:
                reason = "jailbreak"
            elif predicted_class == 2:
                reason = "injection"
            else:
                reason = f"unsafe_class_{predicted_class}"

            return {"safe": False, "label": "UNSAFE", "reason": reason, "confidence": confidence, "predicted_class": predicted_class}

        except Exception as e:
            print(f"[PromptGuard] 스캔 오류: {e}")
            return {"safe": False, "label": "ERROR", "reason": f"scan_error:{type(e).__name__}", "confidence": 0.0}
