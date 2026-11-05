#!/usr/bin/env python3
"""Hugging Face Hub에서 보안 특화 소형 모델·데이터셋 후보를 찾아 순위표를 만든다.

사용법:
    pip install -r security-slm/requirements.txt
    python security-slm/scripts/hf_scout.py
    python security-slm/scripts/hf_scout.py --config security-slm/configs/scout.yaml --out security-slm/reports

huggingface.co 접속이 필요하다. 게이트 모델 조회나 호출 한도 완화가 필요하면 HF_TOKEN 환경변수를 설정한다.
출력: <out>/models.json, <out>/datasets.json, <out>/scout_report.md
점수는 1차 선별용 휴리스틱일 뿐이며, 최종 선택은 docs/PLAN.md §5 평가로 한다.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml
from huggingface_hub import HfApi
from huggingface_hub.errors import HfHubHTTPError

ROOT = Path(__file__).resolve().parents[1]

MODEL_EXPAND = [
    "author", "downloads", "likes", "lastModified", "tags", "cardData",
    "safetensors", "baseModels", "pipeline_tag", "gated",
]
DATASET_EXPAND = ["author", "downloads", "likes", "lastModified", "tags", "cardData", "gated"]

_SIZE_IN_NAME = re.compile(r"(?<![\d.])(\d+(?:\.\d+)?)\s*[bB](?![a-zA-Z])")


def _card_get(card: Any, key: str) -> Any:
    if card is None:
        return None
    if isinstance(card, dict):
        return card.get(key)
    return getattr(card, key, None)


def license_of(info: Any) -> str | None:
    lic = _card_get(getattr(info, "card_data", None), "license")
    if isinstance(lic, list):
        lic = lic[0] if lic else None
    if lic:
        return str(lic).lower()
    for tag in getattr(info, "tags", None) or []:
        if tag.startswith("license:"):
            return tag.split(":", 1)[1].lower()
    return None


def params_b(info: Any) -> tuple[float | None, bool]:
    """(파라미터 수(십억), 추정 여부). safetensors 메타데이터가 없으면 repo 이름에서 추정한다."""
    st = getattr(info, "safetensors", None)
    total = getattr(st, "total", None) if st is not None else None
    if total:
        return round(total / 1e9, 2), False
    match = _SIZE_IN_NAME.search(info.id.split("/")[-1])
    if match:
        return float(match.group(1)), True
    return None, False


def base_model_of(info: Any) -> str | None:
    bm = getattr(info, "base_models", None)
    if isinstance(bm, dict) and bm.get("models"):
        return bm["models"][0].get("id")
    card_bm = _card_get(getattr(info, "card_data", None), "base_model")
    if isinstance(card_bm, list):
        card_bm = card_bm[0] if card_bm else None
    return card_bm


def derived_relation(info: Any) -> str | None:
    bm = getattr(info, "base_models", None)
    if isinstance(bm, dict):
        return bm.get("relation")
    return None


def _days_since(dt: datetime | None, now: datetime) -> int | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


def license_status(lic: str | None, cfg: dict) -> str:
    if not lic:
        return "unknown"
    if any(lic.startswith(p) for p in cfg.get("license_blocked_prefixes", [])):
        return "blocked"
    if lic in cfg.get("license_preferred", []):
        return "preferred"
    return "check"


def summarize_model(info: Any, cfg: dict, watch: set[str], now: datetime) -> dict:
    size, estimated = params_b(info)
    lic = license_of(info)
    tags = getattr(info, "tags", None) or []
    lo, hi = cfg.get("size_range_b", [0, math.inf])
    review_hits = [k for k in cfg.get("review_keywords", []) if k in info.id.lower()]
    return {
        "id": info.id,
        "params_b": size,
        "params_estimated": estimated,
        "in_size_range": None if size is None else lo <= size <= hi,
        "license": lic,
        "license_status": license_status(lic, cfg),
        "base_model": base_model_of(info),
        "relation": derived_relation(info),
        "pipeline_tag": getattr(info, "pipeline_tag", None),
        "downloads": getattr(info, "downloads", None) or 0,
        "likes": getattr(info, "likes", None) or 0,
        "days_since_update": _days_since(getattr(info, "last_modified", None), now),
        "gguf": "gguf" in tags,
        "gated": bool(getattr(info, "gated", False)),
        "watchlist": info.id in watch,
        "review_flags": review_hits,
    }


def score_model(row: dict, cfg: dict) -> float:
    s = 2.0 * math.log10(row["downloads"] + 1) + 1.5 * math.log10(row["likes"] + 1)
    days = row["days_since_update"]
    if days is not None:
        if days <= cfg.get("recent_days", 365) // 2:
            s += 2.0
        elif days <= cfg.get("recent_days", 365):
            s += 1.0
    s += {"preferred": 2.0, "check": 0.0, "unknown": -0.5, "blocked": -3.0}[row["license_status"]]
    if row["in_size_range"] is True:
        s += 1.0
    elif row["in_size_range"] is False:
        s -= 2.0
    if row["watchlist"]:
        s += 3.0
    if row["relation"] in ("quantized", "merge"):
        s -= 1.0  # 원본과 중복되는 파생 저장소는 아래로
    if row["review_flags"]:
        s -= 4.0
    return round(s, 2)


def summarize_dataset(info: Any, watch: set[str], now: datetime) -> dict:
    size_tags = [t.split(":", 1)[1] for t in (getattr(info, "tags", None) or []) if t.startswith("size_categories:")]
    return {
        "id": info.id,
        "license": license_of(info),
        "size_category": size_tags[0] if size_tags else None,
        "downloads": getattr(info, "downloads", None) or 0,
        "likes": getattr(info, "likes", None) or 0,
        "days_since_update": _days_since(getattr(info, "last_modified", None), now),
        "gated": bool(getattr(info, "gated", False)),
        "watchlist": info.id in watch,
    }


def score_dataset(row: dict) -> float:
    s = 2.0 * math.log10(row["downloads"] + 1) + 1.5 * math.log10(row["likes"] + 1)
    if row["days_since_update"] is not None and row["days_since_update"] <= 365:
        s += 1.0
    if row["watchlist"]:
        s += 3.0
    return round(s, 2)


def _collect(listing: Iterable[Any], bucket: dict[str, Any]) -> None:
    for info in listing:
        bucket.setdefault(info.id, info)


def scout_models(api: HfApi, cfg: dict, now: datetime) -> list[dict]:
    found: dict[str, Any] = {}
    limit = cfg.get("limit_per_query", 50)
    for q in cfg.get("model_queries", []):
        try:
            _collect(api.list_models(search=q.get("search"), filter=q.get("filter"),
                                     sort="downloads", limit=limit, expand=MODEL_EXPAND), found)
        except HfHubHTTPError as exc:
            print(f"[warn] model query {q} failed: {exc}", file=sys.stderr)
    watch = set(cfg.get("watchlist", []))
    for repo in sorted(watch - found.keys()):
        try:
            found[repo] = api.model_info(repo, expand=MODEL_EXPAND)
        except HfHubHTTPError as exc:
            print(f"[warn] watchlist model {repo} not found: {exc}", file=sys.stderr)
    rows = [summarize_model(info, cfg, watch, now) for info in found.values()]
    for row in rows:
        row["score"] = score_model(row, cfg)
    return sorted(rows, key=lambda r: r["score"], reverse=True)


def scout_datasets(api: HfApi, cfg: dict, now: datetime) -> list[dict]:
    found: dict[str, Any] = {}
    limit = cfg.get("limit_per_query", 50)
    for q in cfg.get("dataset_queries", []):
        try:
            _collect(api.list_datasets(search=q.get("search"), filter=q.get("filter"),
                                       sort="downloads", limit=limit, expand=DATASET_EXPAND), found)
        except HfHubHTTPError as exc:
            print(f"[warn] dataset query {q} failed: {exc}", file=sys.stderr)
    watch = set(cfg.get("dataset_watchlist", []))
    for repo in sorted(watch - found.keys()):
        try:
            found[repo] = api.dataset_info(repo, expand=DATASET_EXPAND)
        except HfHubHTTPError as exc:
            print(f"[warn] watchlist dataset {repo} not found: {exc}", file=sys.stderr)
    rows = [summarize_dataset(info, watch, now) for info in found.values()]
    for row in rows:
        row["score"] = score_dataset(row)
    return sorted(rows, key=lambda r: r["score"], reverse=True)


def _fmt(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "Y" if v else ""
    if isinstance(v, list):
        return ",".join(v)
    return str(v)


def render_report(models: list[dict], datasets: list[dict], top: int, now: datetime) -> str:
    lines = [
        f"# HF 스카우트 결과 ({now:%Y-%m-%d %H:%M} UTC)",
        "",
        "점수 = 다운로드·좋아요(log) + 최신성 + 라이선스 + 크기 적합성 + watchlist 가산 − 파생/검토필요 감점.",
        "1차 선별용이며 최종 선택은 docs/PLAN.md §5 평가로 한다.",
        "",
        f"## 모델 상위 {top} (전체 {len(models)}개, 크기 범위 내 {sum(1 for m in models if m['in_size_range'])}개)",
        "",
        "| # | 점수 | 모델 | 파라미터(B) | 라이선스 | 베이스 | 관계 | 다운로드 | 좋아요 | 수정(일 전) | GGUF | 검토 |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for i, m in enumerate(models[:top], 1):
        size = _fmt(m["params_b"]) + ("~" if m["params_estimated"] else "")
        lic = f"{_fmt(m['license'])} ({m['license_status']})"
        name = f"**{m['id']}**" if m["watchlist"] else m["id"]
        lines.append(
            f"| {i} | {m['score']} | {name} | {size} | {lic} | {_fmt(m['base_model'])} | {_fmt(m['relation'])} "
            f"| {m['downloads']} | {m['likes']} | {_fmt(m['days_since_update'])} | {_fmt(m['gguf'])} | {_fmt(m['review_flags'])} |"
        )
    lines += [
        "",
        f"## 데이터셋 상위 {top} (전체 {len(datasets)}개)",
        "",
        "| # | 점수 | 데이터셋 | 라이선스 | 규모 | 다운로드 | 좋아요 | 수정(일 전) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, d in enumerate(datasets[:top], 1):
        name = f"**{d['id']}**" if d["watchlist"] else d["id"]
        lines.append(
            f"| {i} | {d['score']} | {name} | {_fmt(d['license'])} | {_fmt(d['size_category'])} "
            f"| {d['downloads']} | {d['likes']} | {_fmt(d['days_since_update'])} |"
        )
    lines += ["", "굵은 글씨 = watchlist, `~` = 이름에서 추정한 파라미터 수.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", type=Path, default=ROOT / "configs" / "scout.yaml")
    parser.add_argument("--out", type=Path, default=ROOT / "reports")
    parser.add_argument("--top", type=int, default=40, help="보고서에 표시할 상위 개수")
    parser.add_argument("--skip-datasets", action="store_true")
    args = parser.parse_args(argv)

    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    api = HfApi()

    try:
        models = scout_models(api, cfg, now)
        datasets = [] if args.skip_datasets else scout_datasets(api, cfg, now)
    except Exception as exc:  # 네트워크 차단·DNS 실패 등 쿼리 단위로 처리되지 않은 오류
        print(f"[error] Hugging Face Hub 조회 실패: {exc}\n"
              "        huggingface.co 접속이 허용되어 있는지 확인하세요.", file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "models.json").write_text(json.dumps(models, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.out / "datasets.json").write_text(json.dumps(datasets, ensure_ascii=False, indent=2), encoding="utf-8")
    report = render_report(models, datasets, args.top, now)
    (args.out / "scout_report.md").write_text(report, encoding="utf-8")
    print(f"models={len(models)} datasets={len(datasets)} -> {args.out / 'scout_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
