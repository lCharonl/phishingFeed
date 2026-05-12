#!/usr/bin/env python3
"""Regenerate the auto-managed KPI sections in README.md and docs/index.html.

Reads:
  - output/last_run.json
  - output/stats.csv
  - output/false_positives.csv
  - scripts/source_notes.json   (curated short descriptions per source)

Replaces content between:
  - README.md:        <!-- BEGIN AUTO-KPI --> ... <!-- END AUTO-KPI -->
  - docs/index.html:  <!-- BEGIN AUTO-DATA --> ... <!-- END AUTO-DATA -->

Exits 0 on success, 1 if sentinels are missing in any target file.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "output"
README = ROOT / "README.md"
SITE_HTML = ROOT / "docs" / "index.html"
SOURCE_NOTES = ROOT / "scripts" / "source_notes.json"

README_BEGIN = "<!-- BEGIN AUTO-KPI -->"
README_END = "<!-- END AUTO-KPI -->"
HTML_BEGIN = "<!-- BEGIN AUTO-DATA -->"
HTML_END = "<!-- END AUTO-DATA -->"

TOP_FP_EXAMPLES = 5


def fmt_int(n: int | str) -> str:
    if isinstance(n, str):
        n = int(n)
    return f"{n:,}"


def fmt_pct(numerator: int, denominator: int) -> str:
    if not denominator:
        return "0.0 %"
    return f"{numerator / denominator * 100:.1f} %"


def load_data() -> dict:
    summary = json.loads((OUTPUT_DIR / "last_run.json").read_text())
    notes = json.loads(SOURCE_NOTES.read_text()) if SOURCE_NOTES.exists() else {}

    sources_rows: list[dict] = []
    with (OUTPUT_DIR / "stats.csv").open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            sources_rows.append({
                "name": r["source"],
                "valid_iocs": int(r["valid_iocs"]),
                "unique": int(r["unique_to_source"]),
                "overlap_pct": float(r["overlap_pct"]),
                "note": notes.get(r["source"], ""),
            })
    sources_rows.sort(key=lambda x: -x["valid_iocs"])

    fp_examples: list[dict] = []
    with (OUTPUT_DIR / "false_positives.csv").open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r.get("excluded_from_consolidated") != "yes":
                continue
            fp_examples.append({
                "domain": r["domain"],
                "tranco_rank": r["tranco_rank"] or "",
                "sources": r["sources"],
            })
            if len(fp_examples) >= TOP_FP_EXAMPLES:
                break

    return {
        "summary": summary,
        "sources_rows": sources_rows,
        "fp_examples": fp_examples,
    }


def render_readme(data: dict) -> str:
    summary = data["summary"]
    sources_rows = data["sources_rows"]
    fp_examples = data["fp_examples"]

    run_at = summary["run_at"]
    run_date = run_at.split("T", 1)[0]
    total = summary["total_unique_iocs"]
    kept = summary["consolidated_kept"]
    fp_excluded = summary["false_positives_excluded"]
    fp_reported = summary["false_positives_reported"]
    params = summary["params"]
    consensus = {int(k): v for k, v in summary["consensus_distribution"].items()}
    n_sources = len(summary["sources"])

    # --- Volume table ---
    lines: list[str] = []
    lines.append("")
    lines.append(
        f"Numbers from the latest run committed in `output/` "
        f"(run on **{run_date}**, default parameters: "
        f"`--min-consensus {params['min_consensus']} "
        f"--fp-threshold {params['fp_tranco_threshold']}`)."
    )
    lines.append("")
    lines.append("### Volume")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Sources monitored | **{n_sources}** |")
    lines.append(f"| Unique IOCs aggregated | **{fmt_int(total)}** |")
    lines.append(f"| Entries in `consolidated.hosts` | **{fmt_int(kept)}** |")
    lines.append(
        f"| Strict false positives excluded "
        f"(Tranco top {fmt_int(params['fp_tranco_threshold'])} + whitelist) "
        f"| **{fmt_int(fp_excluded)}** |"
    )
    lines.append(
        f"| FP review candidates reported (any Tranco rank) | **{fmt_int(fp_reported)}** |"
    )
    lines.append("")

    # --- Consensus distribution ---
    lines.append("### Consensus distribution")
    lines.append("")
    lines.append(
        "How many sources independently report each IOC. Most threats are seen "
        "by a single feed because sources specialize in different threat categories."
    )
    lines.append("")
    lines.append("| Reported by | IOCs | Share | Cumulative if `--min-consensus = N` |")
    lines.append("|---|---:|---:|---:|")
    sorted_levels = sorted(consensus)
    cumulative = total
    for level in sorted_levels:
        count = consensus[level]
        share = fmt_pct(count, total)
        cum_label = f"**{fmt_int(cumulative)} (N={level})**"
        if level == 1:
            cum_label = f"{fmt_int(cumulative)} (N=1)"
        label = f"{level} source" if level == 1 else f"{level} sources"
        lines.append(f"| {label} | {fmt_int(count)} | {share} | {cum_label} |")
        cumulative -= count
    lines.append("")
    lines.append(
        "Raise `--min-consensus` to trade coverage for confidence depending on "
        "tolerance for false positives in downstream blocking."
    )
    lines.append("")

    # --- Per-source contribution ---
    lines.append("### Per-source contribution")
    lines.append("")
    lines.append(
        "Sorted by `valid_iocs`. `unique_to_source` counts IOCs no other feed reports — "
        "high values mean the source carries differentiated intel; high `overlap %` "
        "means the source is largely a re-aggregation of others."
    )
    lines.append("")
    lines.append("| Source | Valid IOCs | Unique | Overlap % | Notes |")
    lines.append("|---|---:|---:|---:|---|")
    for s in sources_rows:
        lines.append(
            f"| {s['name']} | {fmt_int(s['valid_iocs'])} | {fmt_int(s['unique'])} | "
            f"{s['overlap_pct']:.1f} % | {s['note']} |"
        )
    lines.append("")

    # --- Top FP examples ---
    lines.append("### False positives intercepted")
    lines.append("")
    lines.append(
        f"The {fmt_int(fp_excluded)} strict FPs excluded from `consolidated.hosts` are "
        "dominated by widely-used platforms incorrectly flagged in one feed. A sample "
        "of what gets caught:"
    )
    lines.append("")
    lines.append("| Domain | Tranco rank | Reported by |")
    lines.append("|---|---:|---|")
    for fp in fp_examples:
        rank = fp["tranco_rank"] or "—"
        lines.append(f"| {fp['domain']} | {rank} | {fp['sources']} |")
    lines.append("")
    lines.append(
        f"The full review list (`false_positives.csv`, {fmt_int(fp_reported)} entries) "
        "also includes lower-popularity domains that **are not** excluded automatically — "
        "review and extend `whitelist.txt` as needed."
    )
    lines.append("")
    lines.append(
        f"<sub>Auto-generated from `output/last_run.json` at "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC. "
        "Do not edit this section by hand.</sub>"
    )
    lines.append("")
    return "\n".join(lines)


def build_html_payload(data: dict) -> str:
    summary = data["summary"]
    payload = {
        "run_at": summary["run_at"],
        "num_sources": len(summary["sources"]),
        "total_unique_iocs": summary["total_unique_iocs"],
        "consolidated_kept": summary["consolidated_kept"],
        "false_positives_excluded": summary["false_positives_excluded"],
        "false_positives_reported": summary["false_positives_reported"],
        "consensus_distribution": summary["consensus_distribution"],
        "sources": data["sources_rows"],
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def replace_between(text: str, begin: str, end: str, replacement: str) -> str | None:
    """Return new text with content between sentinels replaced. None if sentinels missing."""
    if begin not in text or end not in text:
        return None
    before, _, rest = text.partition(begin)
    _, _, after = rest.partition(end)
    return f"{before}{begin}\n{replacement}{end}{after}"


def update_file(path: Path, begin: str, end: str, payload: str, label: str) -> int:
    """Update a file's sentinel section. Returns 0=ok, 1=missing sentinels."""
    if not path.exists():
        print(f"NOTE: {path.relative_to(ROOT)} not found, skipping {label}.")
        return 0
    text = path.read_text(encoding="utf-8")
    new_text = replace_between(text, begin, end, payload)
    if new_text is None:
        print(f"ERROR: sentinels {begin}/{end} not found in {path.name}", file=sys.stderr)
        return 1
    if new_text == text:
        print(f"{label}: already up to date.")
        return 0
    path.write_text(new_text, encoding="utf-8")
    print(f"{label}: updated.")
    return 0


def main() -> int:
    data = load_data()
    rc = 0
    rc |= update_file(README, README_BEGIN, README_END, render_readme(data), "README.md")
    rc |= update_file(SITE_HTML, HTML_BEGIN, HTML_END,
                      f'  <script id="kpi-data" type="application/json">\n  {build_html_payload(data)}\n  </script>\n  ',
                      "docs/index.html")
    return rc


if __name__ == "__main__":
    sys.exit(main())
