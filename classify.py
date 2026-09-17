"""
IPS 로그 공격유형 자동 분류/집계

Dataiku DSS로 먼저 설계한 시각적 파이프라인(Stack → Prepare → Window → Join)을
동일한 로직의 순수 Python 함수로 재구현한 버전.

파이프라인 순서:
  1. 여러 대(1호기/2호기 등)의 IPS 로그 CSV를 하나로 병합
  2. 공격명/공격유형 기준으로 4개 카테고리로 분류
     (무작위대입공격 → 웹쉘공격 → 웹사이트위협공격 → 그 외 제외, 이 순서가 중요함)
  3. 로그 내용의 실제 타임스탬프에서 "가장 최근 날짜"를 자동 추출해 그 날짜만 필터링
     (운영자가 파일명을 신경 쓰지 않아도, 오래된 파일이 섞여 있어도 항상 최신 날짜만 집계됨)
  4. 카테고리별 건수 집계, 그날 발생하지 않은 카테고리도 0건으로 채워 항상 4행 고정 출력
     (DDoS는 별도 시스템에서 처리하므로 이 파이프라인에서는 항상 0건 고정)
"""

from __future__ import annotations
import pandas as pd

# 원본 CSV 컬럼 순서 (헤더 행은 스킵하고 위치 기준으로 읽음)
COLUMNS = [
    "기간", "공격유형", "공격코드", "공격명", "그룹ID", "그룹명", "객체ID", "객체명",
    "국가(공격자)", "공격자", "국가(대상자)", "대상자", "프로토콜", "위험도",
    "자산영향도", "차단", "시도횟수", "통신량", "TTL", "RAW", "상태", "NIC포트",
    "통신방향", "부가정보", "Application명", "프로토콜인지명",
]

FIXED_CATEGORIES = ["DDoS", "웹사이트위협공격", "무작위대입공격", "웹쉘공격"]


def _classify_row(attack_type: str, attack_name: str) -> str:
    """공격유형/공격명 → 4개 카테고리 중 하나, 또는 'EXCLUDE'.

    판정 순서가 결과를 좌우한다: Brute Force나 Webshell 키워드가 포함된 로그는
    공격유형상 '정보 수집'/'서비스 공격' 등으로도 동시에 잡히는 경우가 있어서,
    키워드 매칭을 DDoS 판정보다 먼저 확인해야 오분류가 안 생긴다.
    """
    name = "" if pd.isna(attack_name) else str(attack_name)
    if "brute" in name.lower():
        return "무작위대입공격"
    if "webshell" in name.lower():
        return "웹쉘공격"
    if attack_type == "Web CGI 공격":
        return "웹사이트위협공격"
    # 정보 수집 / 서비스 거부 / 서비스 공격 등은 DDoS 별도 시스템에서 처리하므로 제외
    return "EXCLUDE"


def load_logs(paths: list[str]) -> pd.DataFrame:
    """여러 장비의 IPS 로그 CSV를 하나로 병합."""
    frames = [
        pd.read_csv(
            p, header=None, names=COLUMNS, skiprows=1, encoding="utf-8",
            index_col=False,  # 원본 CSV의 마지막 잉여 컬럼이 첫 컬럼(기간)을
                               # 인덱스로 오인되는 걸 방지 — 없으면 전체가 한 칸씩 밀림
        )
        for p in paths
    ]
    return pd.concat(frames, ignore_index=True)


def classify_and_count(paths: list[str]) -> pd.DataFrame:
    """CSV 경로 목록 → 공격유형별 건수 DataFrame (항상 4행, DDoS=0 고정)."""
    df = load_logs(paths)

    # "기간" 컬럼은 "시작시각 - 종료시각" 형태이므로 앞 10글자(날짜)만 추출
    df["로그날짜"] = df["기간"].str.slice(0, 10)

    # 가장 최근 날짜만 남긴다 — 폴더에 예전 파일이 섞여 있어도 자동으로 걸러짐
    latest_date = df["로그날짜"].max()
    df = df[df["로그날짜"] == latest_date]

    df["IPS_분류"] = df.apply(
        lambda r: _classify_row(r["공격유형"], r["공격명"]), axis=1
    )
    df = df[df["IPS_분류"] != "EXCLUDE"]

    counts = df.groupby("IPS_분류").size()

    # 고정 카테고리 4개를 항상 포함시키고, 발생하지 않은 건 0으로 채움
    result = pd.Series(0, index=FIXED_CATEGORIES)
    result.update(counts)
    result["DDoS"] = 0  # 별도 시스템 처리 대상이므로 항상 고정

    return (
        result.reindex(FIXED_CATEGORIES)
        .rename_axis("IPS_분류")
        .reset_index(name="count")
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("사용법: python classify.py <로그1.csv> [로그2.csv ...]")
        sys.exit(1)

    report = classify_and_count(sys.argv[1:])
    print(report.to_string(index=False))
