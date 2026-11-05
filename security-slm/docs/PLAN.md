# 서버 보안 방어 + 포렌식 소형 LLM(SLM) 구축 계획

> 작성일: 2026-11-05 · 상태: 초안 v0.1 (Phase 0 착수 전)
> 목표: 허깅페이스(HF)에 공개된 모델·데이터셋을 최대한 재사용해 **온프레미스에서 돌아가는 4B~8B급 보안 특화 모델**과 그 주변 시스템을 만든다.

---

## 0. 한 줄 요약 (결론부터)

- **모델 하나로 다 하려 하지 않는다.** 작은 모델은 지식 암기량과 긴 추론에 한계가 있으므로
  `결정론적 보안 도구 + 경량 인코더 + RAG 지식베이스 + SLM 에이전트` 4계층으로 설계하고, SLM은 "해석·판단·보고서·룰 작성·도구 호출"에 집중시킨다.
- **즉시 쓸 기준선:** `fdtn-ai/Foundation-Sec-8B-Reasoning` (Cisco Foundation AI, Llama‑3.1‑8B에 보안 코퍼스 연속 사전학습 + 추론 학습). 공개 보안 모델 중 벤치마크 근거가 가장 탄탄하다.
- **직접 만들 본 모델의 베이스(1순위 가설):** `Qwen/Qwen3.5-4B` — Apache‑2.0, 262K 컨텍스트, 다국어(한국어), 경량 에이전트 지향. 대안은 `google/gemma-4-E4B`(Apache‑2.0).
- **만드는 방법:** 보안 SFT → 교사 모델 증류 → **검증 가능한 보상(RLVR, GRPO)** → 안전 정렬(DPO) → 4bit 양자화. 작은 모델의 성능을 가장 크게 끌어올리는 단계는 RLVR이다(ATT&CK ID 일치, Sigma 룰 실제 탐지 여부처럼 정답을 기계로 채점할 수 있는 과제가 보안 분야에 많다).
- **최종 선택은 Phase 1 평가로 확정한다.** 아래 후보 순위는 공개 자료 기반 가설이다.

---

## 1. 범위: 모델이 해야 할 일

| 영역 | 구체 업무 (유스케이스) | 입력 | 출력 |
|---|---|---|---|
| **탐지·분류** | 경보(Alert) 1차 분류, 오탐 판별, 심각도 산정 | Wazuh/Suricata/Zeek 경보, auth.log, journald, auditd | 판정(TP/FP/추가조사) + 근거 |
| **위협 매핑** | MITRE ATT&CK 기법 매핑, CVE→CWE 매핑, CVSS/EPSS 기반 우선순위 | 경보·로그·CVE 설명 | `T1110.001` 등 ID + 설명 |
| **방어 조치** | 하드닝 점검·권고(SSH, sudo, 커널 파라미터, 서비스 노출), 패치 우선순위 | 설정 파일, osquery 결과, 취약점 스캔 결과 | 조치 목록(명령어 초안 포함, **실행은 사람 승인**) |
| **탐지 룰 작성** | Sigma / YARA / Wazuh 룰 생성·개선 | 공격 설명, 로그 샘플 | 문법 검증을 통과하는 룰 |
| **포렌식** | 타임라인 재구성, 침입 경로 추정, IOC 추출, 지속성(persistence) 흔적 분석 | plaso 타임라인, Volatility3 출력, bash_history, cron/systemd, EVTX(Chainsaw/Hayabusa 결과) | 시간순 사건 서술, IOC 목록, 증거 위치 |
| **침해 대응 보고** | 사고 보고서 초안(한국어), 대응 플레이북 단계 안내 | 위 모든 결과 | KISA/사내 양식 보고서 초안 |

**하지 않을 일(명시적 비범위):** 익스플로잇·악성코드 제작, 공격 자동화, 사람 승인 없는 차단/격리/삭제 실행.

---

## 2. 시스템 아키텍처

```
          ┌─────────────────────────────────────────────────────────────┐
 분석가 ◀─▶│ L3  SLM 에이전트 (Qwen3.5-4B 파인튜닝 / Foundation-Sec-8B)      │
          │     - 해석·판단·보고서·룰 작성                                   │
          │     - MCP로 도구 호출 (기본 읽기 전용, 조치는 승인 게이트)          │
          └───────┬───────────────────────┬───────────────────────────────┘
                  │ 검색(RAG)              │ 도구 호출(MCP)
          ┌───────▼─────────┐     ┌───────▼──────────────────────────────┐
          │ L2  지식베이스     │     │ L0  결정론적 보안·포렌식 도구            │
          │ ATT&CK/D3FEND    │     │ Wazuh · Suricata · Zeek · osquery     │
          │ CVE/NVD·KEV·EPSS │     │ auditd · Sigma(Chainsaw/Hayabusa)     │
          │ CWE/CAPEC·Sigma  │     │ YARA · Volatility3 · plaso            │
          │ GTFOBins·런북    │     │ Velociraptor                          │
          │ 과거 사고 기록    │     └───────┬──────────────────────────────┘
          └───────▲─────────┘             │ 대량 이벤트
                  │ 임베딩                  ▼
          ┌───────┴──────────────────────────────────────────────────────┐
          │ L1  경량 인코더 (CPU 가능, 대량 처리)                              │
          │  SecureBERT 2.0: NER(IOC·엔티티), bi-encoder(검색), 분류기        │
          │  로그 이상탐지 소형 분류기 (LoRA)                                  │
          └──────────────────────────────────────────────────────────────┘
```

설계 원칙:

1. **파싱·탐지는 도구가, 해석은 LLM이.** 로그 수백만 줄을 LLM에 넣지 않는다. 도구·인코더가 걸러낸 수십~수백 건만 SLM이 본다.
2. **로그는 신뢰할 수 없는 입력이다.** 공격자가 User-Agent, 사용자명, 파일명에 "이전 지시를 무시하라" 같은 문장을 심을 수 있다(프롬프트 인젝션). 로그는 항상 데이터 구획으로 감싸고, 도구 권한은 allowlist로 제한하며, 출력은 스키마로 검증한다.
3. **증거 무결성.** 포렌식 도구는 사본에서만 실행하고, 입력·출력마다 SHA‑256 해시와 처리 이력(chain of custody)을 남긴다. 모델은 증거를 수정할 수 있는 도구를 갖지 않는다.
4. **조치는 사람이 승인.** IP 차단, 프로세스 종료, 호스트 격리 같은 쓰기 동작은 "제안 → 승인 → 실행 → 감사 로그" 2단계로만 수행한다.

---

## 3. 허깅페이스 후보 모델 (2026-11 기준 조사)

> 검증 상태: ✅ 공개 자료로 확인 · ⚠️ 모델 카드에서 직접 재확인 필요.
> 이번 조사 환경에서는 huggingface.co 직접 접속이 막혀 웹 검색 결과로 정리했다. Phase 0에서 `scripts/hf_scout.py`로 HF API를 직접 조회해 갱신한다.

### 3.1 보안 특화 생성 모델 (SLM 후보·기준선·교사)

| 모델 (HF repo) | 크기 / 베이스 | 강점 | 약점·주의 | 라이선스 | 역할 |
|---|---|---|---|---|---|
| `fdtn-ai/Foundation-Sec-8B-Reasoning` | 8B / Llama‑3.1‑8B (보안 연속사전학습 후 추론 학습, 2026‑01) | CTIBench‑RCM 75.3%로 Llama‑3.3‑70B(68.4%)·gpt‑oss‑120b(71.2%)보다 높다고 보고 ✅. 10개 보안 벤치 중 8개에서 Instruct 대비 향상 ✅ | 영어 중심, 한국어 약함 예상, Llama 3.1 세대 | ⚠️ 카드 확인 (베이스 모델은 Apache‑2.0 ✅, Llama 3.1 라이선스 승계 여부 확인) | **기준선 + 교사 모델** |
| `fdtn-ai/Foundation-Sec-8B-Instruct` | 8B / 위와 동일 (2025‑08) | 범용 지시 수행 유지 + 보안 성능 | Reasoning 버전보다 보안 벤치 낮음 | ⚠️ | 기준선 |
| `fdtn-ai/Foundation-Sec-8B` (+ 공식 `-Q4_K_M-GGUF`, `-Q8_0-GGUF`) | 8B base | 연속사전학습만 된 베이스 → 자체 SFT 출발점으로 사용 가능 | 대화형 아님 | Apache‑2.0 ✅ | 8B 트랙 SFT 베이스 |
| `trendmicro-ailab/Llama-Primus-Reasoning` (`-Merged`, `-Base`) | 8B / Llama‑3.1 | 공개 데이터셋(Primus) 기반 재현성, CISSP 0.778 보고 ✅ | 성능은 Foundation-Sec보다 근거 약함 | MIT + Llama 3.1 라이선스 준수 ✅ | 비교군, **데이터셋 출처** |
| `athena129/CyberSecQwen-4B` | 4B / Qwen3‑4B‑Instruct‑2507 | CTI‑MCQ 0.587로 Foundation‑Sec‑8B‑Instruct(0.500)보다 높다고 자체 보고 ✅ | CTI 특화(방어 전반·포렌식 아님), 자체 하네스 평가, 5‑shot 베이스 8B보다는 낮음 | Apache‑2.0 (보도 기준) ⚠️ | **4B 비교 기준선** |
| `BrainboxAI/cyber-analyst-4B` | 4B / Gemma‑4‑E4B, 116만 지시 데이터(카드 기재) | SOC·이중언어 지향, 최신 베이스 | 출처·평가 근거 불충분, 라이선스 불명확 | ⚠️ 불명확 | 참고만 |
| `Trendyol/Qwen3-14B-BaronLLM-v2-*`, `Trendyol/Trendyol-Cybersecurity-LLM-Qwen3-32B-Q8_0-GGUF` | 14B / 32B | 방어 중심 데이터 53K로 학습 | SLM 범위 초과. 독립 평가에서 "특화 효과는 홍보보다 작다"는 의견 존재 ✅ | ⚠️ | 데이터셋만 활용 |
| `WhiteRabbitNeo/*` (Qwen2.5‑Coder‑7B 기반 등) | 7B | 공방 겸용 | 공격 지향, 확장 라이선스에 사용 제한 ✅ | 제한적 | **운영 제외** |

### 3.2 범용 소형 베이스 모델 (자체 파인튜닝 출발점)

| 모델 | 크기 | 장점 | 주의 | 라이선스 | 판단 |
|---|---|---|---|---|---|
| **`Qwen/Qwen3.5-4B`** (2026‑03) | 4B | 262K 컨텍스트 ✅, 경량 에이전트 용도로 발표 ✅, Base·Instruct 모두 공개 ✅, 다국어 | 툴콜·thinking 템플릿 세부는 카드 확인 ⚠️ | Apache‑2.0 (복수 출처) ⚠️ | **1순위 베이스** |
| `Qwen/Qwen3.5-9B` | 9B | 4B보다 추론 강함 | 추론 비용 2배 | 동일 | 성능 부족 시 상향 |
| `Qwen/Qwen3.5-0.8B`, `-2B` | 0.8B / 2B | 엣지·서버 상주 에이전트용 | 복잡한 추론 불가 | 동일 | 1차 분류기·요약기 |
| `google/gemma-4-E4B` (2026‑04) | 유효 4.5B | Apache‑2.0 ✅, 128K, 에이전트·툴콜 지향 | 순수 텍스트 추론은 Qwen3.5‑4B가 낫다는 비교 다수 | Apache‑2.0 ✅ | **대안 베이스** |
| `google/gemma-4-E2B` | 유효 2.3B | 저사양 장비 | — | Apache‑2.0 ✅ | 엣지 대안 |
| `microsoft/Phi-4-mini-*` | 3.8B | 가벼움 | 한국어 약함 | MIT | 비교군 |
| `LGAI-EXAONE/EXAONE-4.0-1.2B` | 1.2B | 한국어 강점, 128K ✅ | 상업적 사용 제한 라이선스로 알려짐 | ⚠️ 비상업 여부 확인 | 연구용 비교만 |

**왜 Foundation-Sec-8B가 아니라 Qwen3.5-4B를 본 모델 베이스로 두는가?**
Foundation-Sec는 "보안 지식"에서 앞서지만, 우리 시스템은 지식을 RAG로 보충하고 SLM에는 **한국어 보고서, 긴 로그 컨텍스트, 도구 호출, 구조화 출력**을 요구한다. 이 네 가지는 더 최신 세대 베이스가 유리하고, 4B는 8B보다 추론 비용이 절반이라 서버 다수 배치에 맞다. 보안 지식 격차는 Foundation-Sec-8B-Reasoning을 **교사**로 써서 증류로 메운다. Phase 1 평가에서 4B가 기준선 대비 크게 뒤지면 8B 트랙(Foundation-Sec-8B base + 자체 SFT)으로 전환한다.

### 3.3 인코더·임베딩 (L1·L2)

| 모델 | 용도 | 라이선스 |
|---|---|---|
| `cisco-ai/SecureBERT2.0-base` | 보안 도메인 인코더 (ModernBERT 기반, 위협 보고서·코드로 사전학습) ✅ | Apache‑2.0 ✅ |
| `cisco-ai/SecureBERT2.0-biencoder` / `-cross-encoder` | 영문 보안 문서 검색·재순위 (768차원, 1024토큰) ✅ | Apache‑2.0 ✅ |
| `cisco-ai/SecureBERT2.0-NER` | IOC·엔티티 추출 (보고 F1 0.945) ✅ | Apache‑2.0 ✅ |
| `BAAI/bge-m3` 또는 `Qwen/Qwen3-Embedding-0.6B` + 리랭커 | 한국어·다국어 런북/사고기록 검색 | ⚠️ 각 카드 확인 |

---

## 4. 데이터 계획

### 4.1 HF 공개 데이터셋

| 데이터셋 | 규모 | 용도 | 비고 |
|---|---|---|---|
| `trendmicro-ailab/Primus-Seed`, `Primus-FineWeb` | 대용량 코퍼스 | (선택) 연속사전학습 | |
| `trendmicro-ailab/Primus-Instruct` | 약 1K | SFT | ODC‑By, GPT‑4o 생성 응답 ✅ |
| `trendmicro-ailab/Primus-Reasoning` | — | 추론 SFT | |
| `Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset` | 53,202건, 200+ 하위 분야 ✅ | SFT 주력 | 방어 중심, 익스플로잇 코드 미포함 표방 |
| SEvenLLM-Instruct / SEvenLLM-Bench | 약 85K / 1,200 ✅ | 사고 보고서 분석 SFT·평가 | 영·중 이중언어, 28개 과제 |
| CyberLLMInstruct | 54,928건 ✅ | **SFT에 직접 쓰지 않음** → 안전성 평가·거절 학습용 | 의사 악성 지시 포함 |
| CTIBench (`AI4Sec/cti-bench` ⚠️) | 다중 과제 ✅ | 평가 | MCQ·RCM·VSP·ATE·TAA |

### 4.2 HF 밖 공개 소스 (RAG·합성 데이터 원천)

- 위협 지식: MITRE ATT&CK·D3FEND·CAPEC·CWE (STIX), NVD CVE, CISA KEV, EPSS, SigmaHQ 룰, GTFOBins
- 로그·공격 데이터: Loghub(Linux, OpenSSH, BGL, Thunderbird), OTRF Security-Datasets, Splunk attack_data, EVTX-ATTACK-SAMPLES
- 포렌식: NIST CFReDS, Digital Corpora, DFIR-Metric 공개 데이터
- 국내: KISA 사이버보안 AI 데이터셋(일부 공개), KISA 침해사고 분석 보고서

### 4.3 자체 데이터 (가장 중요)

- 운영 서버 로그·경보·과거 사고 티켓 → **개인정보·자격증명 마스킹 후** 사용
- 랩 환경에서 공격 시뮬레이션(Atomic Red Team, Caldera)으로 **정답 라벨이 있는** 로그·포렌식 이미지 생성
- 한국어: 위 영문 데이터 일부를 교사 모델로 번역·현지화 + 사내 보고서 양식 예시

### 4.4 합성 데이터 생성 파이프라인

```
원천(ATT&CK 기법, CVE, Sigma 룰, 랩 로그)
  → 교사 모델이 과제·풀이 생성 (Foundation-Sec-8B-Reasoning + 대형 오픈 모델)
  → 자동 검증 (ID 일치, sigma check, YARA 컴파일, JSON 스키마, 도구 재실행)
  → 중복 제거 + 벤치마크 오염 제거(평가셋과 n-gram/임베딩 중복 검사)
  → 사람 샘플 검수 (5~10%)
  → SFT/RL 데이터셋
```

> 상용 API를 교사로 쓸 경우, 출력물을 모델 학습에 쓰는 것이 각 약관에서 허용되는지 먼저 확인한다. 공개 데이터셋도 라이선스(상업 이용, 2차 저작물)를 데이터 카드에서 확인해 `data/LICENSES.md`로 관리한다.

---

## 5. 평가 계획 (모델 선택 기준)

### 5.1 공개 벤치마크

| 벤치마크 | 측정 내용 |
|---|---|
| CTIBench (MCQ, RCM, VSP, ATE) | 위협 인텔리전스 지식, CVE→CWE, CVSS 예측, ATT&CK 기법 추출 |
| CyberMetric (80/500/2000/10000) | 보안 일반 지식 |
| SecBench, SecEval | 보안 지식·추론 |
| **DFIR-Metric** | 포렌식: 전문가 검수 MCQ 700, CTF형 과제 150, NIST CFTT 디스크·메모리 사례 500 ✅ |
| CyberSecEval (Meta PurpleLlama) | 프롬프트 인젝션 저항, 위험 응답 |

### 5.2 자체 평가셋 `KR-SecOps-Eval` (Phase 0에서 v0 300문항 → v1 1,000문항)

| 과제 | 채점 방식 | 목표(v1 출시 기준, 잠정) |
|---|---|---|
| 경보 분류 (TP/FP) | 정답 라벨 대비 F1 | ≥ 0.85 |
| ATT&CK 기법 매핑 | Top‑1 / Top‑3 정확도 | Top‑3 ≥ 0.80 |
| Sigma 룰 생성 | `sigma check` 통과 + 양성 로그 탐지 + 음성 로그 미탐지 | 유효율 ≥ 0.90 |
| 포렌식 타임라인 | 핵심 사건 재현율, 순서 정확도 | 재현율 ≥ 0.80 |
| IOC 추출 | 정밀도·재현율, **입력에 없는 IOC 생성(환각) 비율** | 환각 < 1% |
| 도구 호출 | 올바른 도구·인자 선택률, 스키마 유효율 | ≥ 0.95 |
| 프롬프트 인젝션 | 로그에 심은 지시를 따르는 비율 | < 2% |
| 한국어 보고서 | 루브릭 기반 LLM 심사 + 분석가 블라인드 평가 | 분석가 선호 ≥ 기준선 |
| 지연 시간 | 경보 1건 분석 p95 | ≤ 10초 (GPU), ≤ 60초 (CPU) |

### 5.3 Phase 1 비교 매트릭스

후보 3~4종 × 구성 3종(① 모델 단독 ② +RAG ③ +RAG+도구)을 같은 하네스에서 측정한다.
후보: Foundation-Sec-8B-Reasoning, Qwen3.5-4B(무학습), CyberSecQwen-4B, Gemma-4-E4B.

**Go/No-Go 규칙:** "Qwen3.5-4B + RAG + 도구" 구성이 "Foundation-Sec-8B-Reasoning + RAG + 도구"의 80% 이상 점수면 4B 트랙으로 학습 진행. 아니면 8B 트랙.

---

## 6. 학습 레시피

| 단계 | 방법 | 도구 | 비고 |
|---|---|---|---|
| S0 연속사전학습 | (선택) Primus‑FineWeb 등 보안 코퍼스 | — | Phase 1에서 지식 부족이 RAG로 해결 안 될 때만. 기본은 생략 |
| S1 SFT | LoRA/QLoRA → 효과 확인 후 전체 파인튜닝 검토 | TRL, Unsloth, LLaMA-Factory/Axolotl | 데이터 믹스: 보안 지시 40% · 합성 과제/도구 호출 궤적 30% · 한국어 10% · **범용 지시 리플레이 20%**(망각 방지) |
| S2 증류 | 교사 추론 궤적을 리젝션 샘플링(정답만 채택) | vLLM으로 대량 생성 | 교사: Foundation-Sec-8B-Reasoning + 대형 오픈 모델 |
| S3 RLVR | GRPO 계열, 검증 가능한 보상 | TRL `GRPOTrainer` 또는 verl | 보상: ATT&CK/CWE ID 일치, Sigma 컴파일·탐지 결과, JSON 스키마, 도구 호출 정답, IOC F1, 환각 페널티 |
| S4 안전 정렬 | DPO | TRL | 공격 무기화 요청 거절, 로그 속 인젝션 무시, 불확실하면 "모름/추가 조사" |
| S5 양자화 | GGUF Q4_K_M/Q5_K_M, AWQ | llama.cpp, llm-compressor | **양자화 후 재평가** 필수 (특히 툴콜·JSON) |

예상 자원(대략, Phase 1 이후 재산정):

- 4B QLoRA SFT: 24GB GPU 1장으로 가능
- 4B 전체 SFT / GRPO: 80GB급 GPU 1~2장
- 추론: 4B Q4 약 3GB 메모리(CPU 구동 가능, 느림), 8B Q4 약 5~6GB

---

## 7. 배포·운영

- **완전 온프레미스(폐쇄망 가능).** 로그·증거는 외부로 나가지 않는다.
- 서빙: GPU 서버는 vLLM(OpenAI 호환 API), 엣지·CPU는 llama.cpp / Ollama
- 도구 연결: MCP 서버 — Wazuh MCP, Velociraptor MCP, Volatility3 MCP(공개 구현 존재 ✅) + 자체 읽기 전용 도구(journalctl 조회, osquery `SELECT` 전용, 해시 계산, YARA 스캔)
  - 참고 설계: 셸 실행 도구를 아예 주지 않고 타입이 정해진 읽기 전용 포렌식 함수만 제공하는 방식 — "파괴적 명령은 거절하는 게 아니라 존재하지 않는다"
- 감사: 모든 프롬프트·도구 호출·응답을 변경 불가 저장소에 기록
- RAG 지식베이스: CVE/KEV/EPSS 일 1회, ATT&CK·Sigma 릴리스마다 갱신
- 운영 모드: ① 섀도우 모드(분석가와 병행, 결과 비교) 4주 → ② 보조 모드(초안 제공) → ③ 저위험 경보 자동 종결(정밀도 기준 충족 시에만)

---

## 8. 로드맵 (총 약 16주)

| Phase | 기간 | 산출물 | 완료 기준 |
|---|---|---|---|
| **0. 준비** | 1~2주 | 유스케이스 확정, `hf_scout.py`로 후보 갱신, 라이선스 표, `KR-SecOps-Eval` v0(300문항), 랩 환경 | 후보·평가셋 확정 |
| **1. 기준선 PoC** | 2~3주 | 평가 하네스, RAG v0, MCP 도구 3종, 후보 4종 × 구성 3종 결과표 | Go/No-Go 판정 (4B vs 8B 트랙) |
| **2. SFT + 증류** | 4~5주 | 합성 데이터 파이프라인, 데이터셋 v1, 모델 v0.1 | 기준선 대비 자체 평가 +10%p |
| **3. RLVR + 안전** | 3~4주 | 보상 함수, 모델 v0.2, 레드팀 리포트 | §5.2 목표 70% 이상 달성 |
| **4. 배포·섀도우** | 2~3주 | 양자화 모델, 서빙, 감사 로그, 대시보드 | 섀도우 4주 지표 수집 시작 |
| **5. 지속 개선** | 상시 | 월간 재학습, 오답 수집 → 데이터 반영 | 분석가 처리 시간·오탐률 개선 추이 |

---

## 9. 위험과 대응

| 위험 | 대응 |
|---|---|
| 환각(없는 IOC·CVE 생성) | 출력의 모든 IOC/ID를 입력·KB와 대조하는 후처리 검증기, RL 환각 페널티 |
| 프롬프트 인젝션(로그 경유) | 데이터 구획 분리, 도구 allowlist, 쓰기 도구 승인 게이트, CyberSecEval·자체 인젝션 셋 상시 평가 |
| 이중 용도(공격 악용) | 공격 지향 모델·데이터 배제, 거절 학습, 접근 통제·감사 |
| 라이선스 | 모델·데이터별 라이선스 표 유지, Llama 계열은 Llama 3.1 라이선스 조건 준수, 비상업 라이선스 모델은 운영 배제 |
| 개인정보·기밀 유출 | 학습 전 마스킹, 온프레미스 학습·서빙, 학습 데이터 접근 통제 |
| 최신 위협 반영 지연 | 지식은 RAG로 일 단위 갱신, 모델은 월 단위 재학습 |
| 작은 컨텍스트·긴 로그 | 도구로 사전 필터링, 단계적 요약(map-reduce), 262K 컨텍스트 활용은 최후 수단 |

---

## 10. (선택) 스마트팩토리/OT 확장

저장소 성격상 공장 네트워크 서버까지 보호 대상이 될 수 있다. 1차 범위는 IT 서버(리눅스/윈도우)로 두고, 이후 확장 시:

- ATT&CK for ICS 매트릭스를 KB에 추가
- Zeek ICS 파서(Modbus, DNP3, S7, OPC UA 등) 로그를 L0 입력으로 추가
- OT 환경은 **탐지·권고만** 하고 자동 조치는 금지(가용성 우선)

---

## 11. 바로 다음 할 일 (Phase 0 체크리스트)

- [ ] 환경에서 `huggingface.co` 접근 허용 후 `python security-slm/scripts/hf_scout.py` 실행 → `reports/` 결과로 §3 표 갱신
- [ ] 후보 모델 카드에서 라이선스·채팅 템플릿·툴콜 지원 확인 (⚠️ 항목 해소)
- [ ] 1차 유스케이스 3개 확정 (권장: 경보 분류, ATT&CK 매핑, 포렌식 타임라인 요약)
- [ ] `KR-SecOps-Eval` v0 300문항 작성 (랩 공격 시뮬레이션 로그 기반)
- [ ] GPU 자원 확보 (24GB 1장 이상, Phase 3에는 80GB급)

---

## 참고 자료

- Foundation-Sec-8B 기술 보고서: <https://arxiv.org/abs/2504.21039>
- Foundation-Sec-8B-Reasoning 기술 보고서: <https://arxiv.org/abs/2601.21051>
- Foundation-Sec-8B-Instruct 보고서: <https://arxiv.org/abs/2508.01059>
- Primus 데이터셋 논문: <https://arxiv.org/abs/2502.11191>
- SecureBERT 2.0: <https://arxiv.org/abs/2510.00240> · <https://github.com/cisco-ai-defense/securebert2>
- CyberSecQwen-4B 소개: <https://huggingface.co/blog/lablab-ai-amd-developer-hackathon/cybersecqwen-4b>
- DFIR-Metric: <https://arxiv.org/abs/2505.19973>
- CTIBench (NeurIPS 2024): <https://neurips.cc/virtual/2024/poster/97556>
- SEvenLLM: <https://arxiv.org/abs/2405.03446>
- CyberLLMInstruct: <https://arxiv.org/abs/2503.09334>
- LogTinyLLM (소형 LLM 로그 이상탐지): <https://arxiv.org/abs/2507.11071>
- Gemma 4 발표(Apache‑2.0): <https://the-decoder.com/googles-gemma-4-is-now-available-with-apache-2-0-licensing-for-the-first-time/>
- Qwen3.5 Small 발표: <https://gigazine.net/gsc_news/en/20260303-qwen-3-5-small>
- Trendyol 보안 지시 데이터셋: <https://huggingface.co/datasets/Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset>
- Wazuh MCP 서버: <https://mcpservers.org/tr/servers/gbrigandi/mcp-server-wazuh>
