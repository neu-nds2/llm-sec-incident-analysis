#!/usr/bin/env python3
"""
Extract cost-effectiveness statistics from LLM reports.

Reads duration and question count from each report's metadata section.
Outputs a summary table with per-provider timing statistics.

Usage:
    python cost_effectiveness.py
"""

import re
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "evaluation"
SCORING_DIR = Path(__file__).resolve().parent


def extract_metadata(report_path):
    """Extract provider, duration, and question count from a report."""
    text = report_path.read_text()
    m_prov = re.search(r"\*\*Provider:\*\*\s*(.+)", text)
    m_dur = re.search(r"\*\*Duration:\*\*\s*([\d.]+)s", text)
    m_qs = re.search(r"\*\*Questions:\*\*\s*(\d+)", text)
    if not (m_prov and m_dur):
        return None
    return {
        "provider": m_prov.group(1).strip(),
        "duration": float(m_dur.group(1)),
        "questions": int(m_qs.group(1)) if m_qs else 0,
    }


def provider_label(raw_provider, filename):
    """Map raw provider name + filename to display label."""
    if raw_provider == "OpenAI":
        if "gpt4o" in filename:
            return "GPT-4o"
        elif "gpt4" in filename:
            return "GPT-4"
        elif "gpt5mini" in filename:
            return "GPT-5-mini"
        elif "gpt52" in filename:
            return "GPT-5.2"
    labels = {
        "Anthropic": "Claude Sonnet 4",
        "DeepSeek": "DeepSeek V3",
        "Ollama": "Ollama 3.1:70b",
        "CiscoFoundationLocal": "Cisco 8B",
    }
    return labels.get(raw_provider, raw_provider)


def load_recall():
    """Load average recall per provider from per_answer.csv."""
    csv_path = SCORING_DIR / "per_answer.csv"
    if not csv_path.exists():
        return {}
    data = defaultdict(list)
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["recall"]:
                data[row["provider"]].append(float(row["recall"]))
    return {p: sum(v) / len(v) * 100 for p, v in data.items()}


def main():
    stats = defaultdict(lambda: {"durations": [], "questions": 0})

    for scenario_dir in sorted(ROOT.iterdir()):
        reports_dir = scenario_dir / "llm_reports"
        if not reports_dir.exists():
            continue
        for report in sorted(reports_dir.glob("*.md")):
            meta = extract_metadata(report)
            if not meta:
                continue
            label = provider_label(meta["provider"], report.stem)
            stats[label]["durations"].append(meta["duration"])
            stats[label]["questions"] += meta["questions"]

    recall = load_recall()

    order = [
        "Claude Sonnet 4", "DeepSeek V3", "GPT-4", "GPT-4o",
        "GPT-5-mini", "GPT-5.2", "Ollama 3.1:70b", "Cisco 8B",
    ]

    lines = []
    lines.append("# Cost-Effectiveness Summary")
    lines.append("")
    lines.append("| Provider | Type | Avg time/scenario | Avg time/question | "
                 "Recall | Total time (17 scenarios) |")
    lines.append("|---|---|---|---|---|---|")

    for p in order:
        if p not in stats:
            continue
        s = stats[p]
        n = len(s["durations"])
        total = sum(s["durations"])
        avg_scen = total / n
        avg_q = total / s["questions"] if s["questions"] else 0
        rec = recall.get(p, 0)
        ptype = "Local" if p in ("Ollama 3.1:70b", "Cisco 8B") else "Cloud"
        lines.append(
            f"| {p} | {ptype} | {avg_scen:.0f}s | {avg_q:.1f}s | "
            f"{rec:.0f}% | {total:.0f}s |"
        )

    lines.append("")
    lines.append("Durations extracted from report metadata "
                 "(evaluation/*/llm_reports/*.md).")

    output = "\n".join(lines) + "\n"
    out_path = SCORING_DIR / "cost_effectiveness.md"
    out_path.write_text(output)
    print(output)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
