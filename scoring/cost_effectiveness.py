#!/usr/bin/env python3
"""
Extract cost-effectiveness statistics from LLM reports.

Reads duration and question count from each report's metadata section.
Outputs a summary table with per-provider timing statistics and the USD
cost-per-analysis estimate (paper Table 5, Equation 1).

Cost is computed via Equation 1 (Section 6.5):
    C_analysis = N_calls * (T_in/1e6 * P_in + T_out/1e6 * P_out)
with N_calls = 8 (one per forensic question), T_in = 3000, T_out = 400.
Prices (P_in, P_out) are vendor-published USD per million tokens as of
early 2026; see PRICING below.

Usage:
    python cost_effectiveness.py
"""

import re
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "evaluation"
SCORING_DIR = Path(__file__).resolve().parent

# ----- Pricing (USD per million tokens) ------------------------------------
# Sourced from vendor documentation as of early 2026. Matches paper Table 5.
# GPT-4 row uses GPT-4.1 pricing (legacy GPT-4 is no longer published).
# Local-deployment providers have no per-token cost.
PRICING = {
    "Claude Sonnet 4": {"in": 3.00, "out": 15.00},
    "DeepSeek V3":     {"in": 0.28, "out":  0.42},
    "GPT-4":           {"in": 3.00, "out": 12.00},
    "GPT-4o":          {"in": 2.50, "out": 10.00},
    "GPT-5-mini":      {"in": 0.25, "out":  2.00},
    "GPT-5.2":         {"in": 1.75, "out": 14.00},
    "Ollama 3.1:70b":  None,  # local, no per-token cost
    "Cisco 8B":        None,  # local, no per-token cost
}

# Equation 1 parameters
N_CALLS = 8         # one LLM call per forensic question
T_IN    = 3000      # conservative avg input tokens per call
T_OUT   = 400       # conservative avg output tokens per call


def cost_per_analysis(provider: str) -> float | None:
    p = PRICING.get(provider)
    if p is None:
        return None
    return N_CALLS * (T_IN / 1e6 * p["in"] + T_OUT / 1e6 * p["out"])


def fmt_cost(c: float | None) -> str:
    if c is None:
        return "$0*"
    # Match paper Table 5: 4 decimals only for sub-cent values (DeepSeek
    # $0.0080); 2 decimals otherwise (Claude $0.12, GPT-5-mini $0.01).
    if c < 0.01:
        return f"${c:.4f}"
    return f"${c:.2f}"


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
    lines.append("# Cost-Effectiveness Summary (paper Table 5)")
    lines.append("")
    lines.append("| Provider | Type | Recall | Avg time/scenario | "
                 "Avg time/question | In ($/M) | Out ($/M) | Cost/Analysis | "
                 "Total time (17 scenarios) |")
    lines.append("|---|---|---|---|---|---|---|---|---|")

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
        price = PRICING.get(p)
        p_in  = f"{price['in']:.2f}"  if price else "–"
        p_out = f"{price['out']:.2f}" if price else "–"
        cost = fmt_cost(cost_per_analysis(p))
        lines.append(
            f"| {p} | {ptype} | {rec:.0f}% | {avg_scen:.0f}s | {avg_q:.1f}s | "
            f"{p_in} | {p_out} | {cost} | {total:.0f}s |"
        )

    lines.append("")
    lines.append("Durations extracted from report metadata "
                 "(evaluation/*/llm_reports/*.md).")
    lines.append("")
    lines.append(
        f"Cost/Analysis computed via Equation 1 with N_calls={N_CALLS}, "
        f"T_in={T_IN}, T_out={T_OUT}. \\* Local deployment; requires GPU "
        "infrastructure, cost not included."
    )

    output = "\n".join(lines) + "\n"
    out_path = SCORING_DIR / "cost_effectiveness.md"
    out_path.write_text(output)
    print(output)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
