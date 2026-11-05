# security-slm — 서버 보안 방어·포렌식용 소형 LLM

허깅페이스 공개 모델·데이터셋을 최대한 재사용해 온프레미스에서 돌아가는 4B~8B급 보안 특화 모델과 주변 시스템(RAG, 보안 도구 연동)을 만드는 프로젝트.

| 경로 | 내용 |
|---|---|
| [`docs/PLAN.md`](docs/PLAN.md) | 전체 계획: 아키텍처, HF 후보 모델·데이터셋, 평가, 학습 레시피, 배포, 로드맵 |
| [`scripts/hf_scout.py`](scripts/hf_scout.py) | HF Hub에서 보안 모델·데이터셋 후보를 검색해 순위표 생성 |
| [`configs/scout.yaml`](configs/scout.yaml) | 스카우트 검색어, 관심 목록(watchlist), 라이선스·크기 기준 |

## 후보 모델 스카우트 실행

```bash
pip install -r security-slm/requirements.txt
export HF_TOKEN=...   # 선택: 게이트 모델 조회, 호출 한도 완화
python security-slm/scripts/hf_scout.py          # → security-slm/reports/scout_report.md
```

huggingface.co 접속이 필요하다. 점수는 1차 선별용 휴리스틱이며, 최종 모델은 `docs/PLAN.md` §5 평가로 결정한다.
