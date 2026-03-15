#!/usr/bin/env python3
"""
Generate CVE-centric pass/fail artifacts from live benchmark NDJSON output.

Outputs:
- JSON report with per-CVE confusion metrics and per-scenario status
- Markdown report suitable for demos/paper bundle evidence
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class CveStats:
    cve_id: str
    runs: int = 0
    attack_runs: int = 0
    benign_runs: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    pass_runs: int = 0

    def add(self, expected_class: str, observed_divergence: bool, passed: bool) -> None:
        self.runs += 1
        if expected_class == "attack":
            self.attack_runs += 1
            if observed_divergence:
                self.tp += 1
            else:
                self.fn += 1
        else:
            self.benign_runs += 1
            if observed_divergence:
                self.fp += 1
            else:
                self.tn += 1
        if passed:
            self.pass_runs += 1

    def detection_rate(self) -> float | None:
        denom = self.tp + self.fn
        if denom == 0:
            return None
        return self.tp / denom

    def false_positive_rate(self) -> float | None:
        denom = self.fp + self.tn
        if denom == 0:
            return None
        return self.fp / denom

    def pass_rate(self) -> float | None:
        if self.runs == 0:
            return None
        return self.pass_runs / self.runs

    def to_json(self) -> dict[str, Any]:
        out = asdict(self)
        out["detection_rate"] = self.detection_rate()
        out["false_positive_rate"] = self.false_positive_rate()
        out["pass_rate"] = self.pass_rate()
        return out


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fmt_pct(v: float | None) -> str:
    if v is None:
        return "n/a"
    return f"{v * 100:.1f}%"


def _row_passed(expected_class: str, observed_divergence: bool) -> bool:
    if expected_class == "attack":
        return observed_divergence
    return not observed_divergence


def load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        rows.append(json.loads(raw))
    return rows


def build_report(rows: list[dict[str, Any]], source_path: Path) -> tuple[dict[str, Any], str]:
    by_cve: dict[str, CveStats] = {}
    scenario_rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for row in rows:
        scenario_id = str(row.get("scenario_id") or "")
        category = str(row.get("category") or "")
        expected_class = str(row.get("expected_class") or "")
        observed_divergence = bool(row.get("observed_divergence"))
        cve_ids = row.get("cve_ids") or []
        if not isinstance(cve_ids, list):
            cve_ids = []
        cve_ids = [str(c).strip() for c in cve_ids if str(c).strip()]
        passed = _row_passed(expected_class, observed_divergence)

        if cve_ids:
            scenario_rows.append(
                {
                    "scenario_id": scenario_id,
                    "category": category,
                    "cve_ids": cve_ids,
                    "expected_class": expected_class,
                    "observed_divergence": observed_divergence,
                    "status": "PASS" if passed else "FAIL",
                    "trace_dir": row.get("trace_dir"),
                }
            )
            if not passed:
                failures.append(
                    {
                        "scenario_id": scenario_id,
                        "cve_ids": cve_ids,
                        "expected_class": expected_class,
                        "observed_divergence": observed_divergence,
                        "trace_dir": row.get("trace_dir"),
                    }
                )

        for cve_id in cve_ids:
            stats = by_cve.setdefault(cve_id, CveStats(cve_id=cve_id))
            stats.add(expected_class, observed_divergence, passed)

    cve_stats = [by_cve[k].to_json() for k in sorted(by_cve.keys())]
    total_cve_runs = sum(item["runs"] for item in cve_stats)
    total_cve_failures = len(failures)

    report_json: dict[str, Any] = {
        "generated_at_utc": _now_utc_iso(),
        "source_results": str(source_path),
        "total_rows_in_results": len(rows),
        "total_rows_with_cve_ids": len(scenario_rows),
        "total_cve_runs": total_cve_runs,
        "total_cve_failures": total_cve_failures,
        "cves": cve_stats,
        "scenario_status": scenario_rows,
        "failures": failures,
    }

    md_lines: list[str] = []
    md_lines.append("# Live CVE Detection Report")
    md_lines.append("")
    md_lines.append(f"- Generated at: `{report_json['generated_at_utc']}`")
    md_lines.append(f"- Source NDJSON: `{source_path}`")
    md_lines.append(f"- Total benchmark rows: `{len(rows)}`")
    md_lines.append(f"- Rows tagged with CVEs: `{len(scenario_rows)}`")
    md_lines.append(f"- CVE-attributed failures: `{total_cve_failures}`")
    md_lines.append("")

    if not cve_stats:
        md_lines.append("No CVE-tagged scenario rows were found in the input results.")
    else:
        md_lines.append("## Per-CVE Summary")
        md_lines.append("")
        md_lines.append("| CVE | Runs | Attack | Benign | TP | FP | FN | TN | Detect Rate | FPR | Pass Rate |")
        md_lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for item in cve_stats:
            md_lines.append(
                "| {cve} | {runs} | {attack} | {benign} | {tp} | {fp} | {fn} | {tn} | {dr} | {fpr} | {pr} |".format(
                    cve=item["cve_id"],
                    runs=item["runs"],
                    attack=item["attack_runs"],
                    benign=item["benign_runs"],
                    tp=item["tp"],
                    fp=item["fp"],
                    fn=item["fn"],
                    tn=item["tn"],
                    dr=_fmt_pct(item.get("detection_rate")),
                    fpr=_fmt_pct(item.get("false_positive_rate")),
                    pr=_fmt_pct(item.get("pass_rate")),
                )
            )

    md_lines.append("")
    md_lines.append("## Failed CVE-Tagged Scenarios")
    md_lines.append("")
    if not failures:
        md_lines.append("None.")
    else:
        md_lines.append("| Scenario | CVE IDs | Expected | Observed Divergence | Trace |")
        md_lines.append("|---|---|---|---|---|")
        for f in failures:
            md_lines.append(
                "| {sid} | {cves} | {exp} | {obs} | `{trace}` |".format(
                    sid=f["scenario_id"],
                    cves=", ".join(f["cve_ids"]),
                    exp=f["expected_class"],
                    obs=str(f["observed_divergence"]).lower(),
                    trace=f.get("trace_dir") or "",
                )
            )

    md_text = "\n".join(md_lines).rstrip() + "\n"
    return report_json, md_text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, help="Path to benchmark NDJSON results.")
    ap.add_argument("--output-json", required=True, help="Output JSON report path.")
    ap.add_argument("--output-md", required=True, help="Output Markdown report path.")
    args = ap.parse_args()

    results_path = Path(args.results)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)

    rows = load_rows(results_path)
    report_json, report_md = build_report(rows, results_path)

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report_json, indent=2) + "\n", encoding="utf-8")
    output_md.write_text(report_md, encoding="utf-8")

    print(f"Wrote CVE JSON report: {output_json}")
    print(f"Wrote CVE Markdown report: {output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

