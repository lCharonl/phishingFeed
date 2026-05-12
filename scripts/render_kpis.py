#!/usr/bin/env python3
"""Regenerate the auto-managed KPI section in README.md from the latest run.

Reads:
  - output/last_run.json
  - output/stats.csv
  - output/false_positives.csv
  - scripts/source_notes.json   (curated short descriptions per source)

Replaces everything between the sentinels:
  <!-- BEGIN AUTO-KPI -->
  ...
  <!-- END AUTO-KPI -->

Exits with code 0 on success, 1 if sentinels are missing.
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
SOURCE_NOTES = ROOT / "scripts" / "source_notes.json"

BEGIN = "<!-- BEGIN AUTO-KPI -->"
END = "<!-- END AUTO-KPI -->"

TOP_FP_EXAMPLES = 5


def fmt_int(n: int | str) -> str:
    if isinstance(n, str):
        n = int(n)
    return f"{n:,}"


def fmt_pct(numerator: int, denominator: int) -> str:
    if not denominator:
        return "0.0 %"
    return f"{numerator / denominator * 100:.1f} %"


def render() -> str:
    summary = json.loads((OUTPUT_DIR / "last_run.json").read_text())
    notes = json.loads(SOURCE_NOTES.read_text()) if SOURCE_NOTES.exists() else {}

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
    rows: list[tuple[str, int, int, float, str]] = []
    with (OUTPUT_DIR / "stats.csv").open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append((
                r["source"],
                int(r["valid_iocs"]),
                int(r["unique_to_source"]),
                float(r["overlap_pct"]),
                notes.get(r["source"], ""),
            ))
    rows.sort(key=lambda x: -x[1])
    for name, valid, unique, overlap, note in rows:
        lines.append(
            f"| {name} | {fmt_int(valid)} | {fmt_int(unique)} | "
            f"{overlap:.1f} % | {note} |"
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
    with (OUTPUT_DIR / "false_positives.csv").open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        shown = 0
        for r in reader:
            if r.get("excluded_from_consolidated") != "yes":
                continue
            rank = r["tranco_rank"] or "—"
            lines.append(f"| {r['domain']} | {rank} | {r['sources']} |")
            shown += 1
            if shown >= TOP_FP_EXAMPLES:
                break
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


def main() -> int:
    text = README.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        print(f"ERROR: sentinels {BEGIN} / {END} not found in README.md", file=sys.stderr)
        return 1
    before, _, rest = text.partition(BEGIN)
    _, _, after = rest.partition(END)

    new_section = render()
    new_text = f"{before}{BEGIN}\n{new_section}{END}{after}"

    if new_text == text:
        print("README.md KPI section is already up to date.")
        return 0

    README.write_text(new_text, encoding="utf-8")
    print("README.md KPI section updated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
