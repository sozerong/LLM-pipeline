# llm-pipe

OpenWebUI용 보안 필터 파이프라인 모음입니다. 사용자 입력 및 모델 응답에 대해 PII, 시크릿, 악성 코드, 프롬프트 인젝션 등을 탐지합니다.

## 구조

```
llm-pipe/
├── pipeline_llamafirewall_regex.py   # LlamaFirewall 정규식 기반 PII 탐지
├── pipeline_codeshield.py            # CodeShield 코드 보안 검사
├── pipeline_prompt_guard.py          # PromptGuard 프롬프트 인젝션/탈옥 탐지
├── pipeline_detect_secrets.py        # 시크릿/자격증명 탐지
└── commons/
    ├── llamafirewall_regex_scanner.py       # LFWRegexDetector
    ├── llamafirewall_pii_regex_detector.py  # 정책 파일 기반 PII 탐지 유틸
    ├── llamafirewall_guard_scanner.py       # PromptGuardScanner (ML 모델)
    ├── llamafirewall_code_scanner.py        # CodeShieldScanner, ReportFormatter
    └── detect_secrets.py                   # SecretDetector
```

## 파이프라인

### `pipeline_llamafirewall_regex`
LlamaFirewall의 `RegexScanner`를 이용해 사용자 메시지에서 PII를 탐지합니다.  
`on_detect_policy` 설정으로 `masking` / `block` / `allow` 중 선택합니다.

### `pipeline_codeshield`
사용자 입력 및 모델 응답의 코드 블록을 LlamaFirewall `CodeShield`로 검사합니다.  
위험도 점수가 임계값(`min_severity_to_block`) 이상이면 차단 또는 경고합니다.

### `pipeline_prompt_guard`
로컬 ML 모델(`PromptGuard`)로 프롬프트 인젝션 및 탈옥 시도를 탐지합니다.  
모델 경로는 `guard_model_path` (기본: `/app/commons/models`)로 설정합니다.

### `pipeline_detect_secrets`
`detect-secrets` 라이브러리와 엔트로피 기반 휴리스틱으로 API 키, 비밀번호, 토큰 등을 탐지합니다.  
`on_detect_policy` 설정으로 `masking` / `block` / `allow` 중 선택합니다.

## 설정

각 파이프라인은 OpenWebUI의 Valves(설정 UI)를 통해 동작을 조정할 수 있습니다.

| 공통 Valve | 설명 |
|---|---|
| `enabled` | 파이프라인 활성화 여부 |
| `priority` | 파이프라인 실행 우선순위 |
| `pipelines` | 적용할 파이프라인 ID 목록 (`["*"]`이면 전체) |

## 의존성

```
llamafirewall
detect-secrets
transformers
torch
pygments
pydantic
```

## 정책 규칙 파일

`llamafirewall_pii_regex_detector`는 외부 JSON 파일에서 탐지 규칙을 로드합니다.

```
POLICY_RULES_PATH=/app/commons/policy_rules.json  # 기본값
```

파일 형식:
```json
{
  "data": [
    { "name": "PHONE_NUMBER", "rule": "01[0-9]-\\d{4}-\\d{4}", "status": "deployed" }
  ]
}
```
