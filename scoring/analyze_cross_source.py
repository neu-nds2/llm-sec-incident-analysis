#!/usr/bin/env python3
"""
Analyze LLM reports across all scenarios.

Reads reports from evaluation/<scenario>/llm_reports/*.md, scores
against reference answers in evaluation/<scenario>/config/answers.txt, and
produces per_answer.csv + summary.md.

Reports contain structured fields per question:
  FINAL ANSWER = [...]
  CITED CHUNKS = [filename1, filename2, ...]
  RETRIEVED CHUNKS = [filename1, filename2, ...]
"""

import re
import csv
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent / "evaluation"
OUT_DIR = Path(__file__).resolve().parent

# ----- Provider labels -------------------------------------------------------
PROVIDER_LABELS = {
    "anthropic": "Claude Sonnet 4",
    "deepseek": "DeepSeek V3",
    "ollama": "Ollama 3.1:70b",
    "cisco": "Cisco 8B",
    "openai_gpt4": "GPT-4",
    "openai_gpt4o": "GPT-4o",
    "openai_gpt5mini": "GPT-5-mini",
    "openai_gpt52": "GPT-5.2",
}


def provider_of(report: Path) -> str:
    stem = report.stem
    candidates = [k for k in PROVIDER_LABELS if stem.endswith(k)]
    if not candidates:
        return "UNKNOWN"
    return PROVIDER_LABELS[max(candidates, key=len)]


# ----- Report discovery ------------------------------------------------------
def report_sources(reports_subdir="llm_reports"):
    """Yield (scenario_name, report_path) for every report in the tree."""
    for d in sorted(ROOT.glob("*")):
        if not d.is_dir():
            continue
        scen = d.name
        v2 = d / reports_subdir
        if v2.exists():
            for r in sorted(v2.glob("*.md")):
                yield scen, r


# ----- Ground truth ----------------------------------------------------------
def parse_answers(path: Path) -> dict:
    """Parse answers file → {q_num: set_of_lowercase_tokens}.

    Strips parenthetical commentary before splitting on commas.
    """
    text = path.read_text()
    out = {}
    for m in re.finditer(r"^A(\d+):\s*(.+)$", text, re.MULTILINE):
        qnum = int(m.group(1))
        raw = m.group(2).strip()
        if raw.lower().startswith("n/a"):
            out[qnum] = set()
            continue
        cleaned = re.sub(r"\([^()]*\)", "", raw)
        while "(" in cleaned and ")" in cleaned:
            new = re.sub(r"\([^()]*\)", "", cleaned)
            if new == cleaned:
                break
            cleaned = new
        tokens = [t.strip().lower() for t in cleaned.split(",")]
        out[qnum] = {t for t in tokens if t}
    return out


def load_reference_answers(scenario: str) -> dict | None:
    p = ROOT / scenario / "config" / "answers.txt"
    return parse_answers(p) if p.exists() else None


# ----- Report parsing --------------------------------------------------------
# Require '?' in the header line so bolded subsection headers inside
# analysis blocks are not misparsed as question headers.
QUESTION_HEADER = re.compile(r"^\*\*(\d+)\.[^\n]*\?[^\n]*\*\*\s*$", re.MULTILINE)
LINE_FINAL = re.compile(r"^\**\s*FINAL ANSWER\s*=\s*(.*)$", re.MULTILINE | re.IGNORECASE)
LINE_CITED = re.compile(r"^\**\s*CITED CHUNKS\s*=\s*(.*)$", re.MULTILINE | re.IGNORECASE)
LINE_RETR = re.compile(r"^\**\s*RETRIEVED CHUNKS\s*=\s*(.*)$", re.MULTILINE | re.IGNORECASE)


def normalize_filename(name: str) -> str:
    name = name.strip().strip("[]`*\" ")
    return name.split("/")[-1].lower()


def parse_list(line: str) -> list:
    if line is None:
        return []
    s = line.strip().strip("[]")
    return [x for x in (p.strip() for p in s.split(",")) if x] if s else []


def parse_answer_tokens(raw: str) -> set:
    s = raw.strip().strip("[]").strip("*")
    if not s or s.lower() in {"n/a", "none", "not found in provided data"}:
        return set()
    return {p.strip().lower() for p in s.split(",") if p.strip()}


def split_question_blocks(text: str) -> dict:
    headers = list(QUESTION_HEADER.finditer(text))
    blocks = {}
    for i, m in enumerate(headers):
        qnum = int(m.group(1))
        # Keep only the first occurrence of each question number.
        # Some models (e.g., Cisco) echo question headers in post-analysis
        # summaries, which would otherwise overwrite the real Q block.
        if qnum in blocks:
            continue
        start = m.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        block = re.split(r"^##\s+(SUMMARY|METADATA)\b", text[start:end],
                         maxsplit=1, flags=re.MULTILINE)[0]
        blocks[qnum] = block
    return blocks


def _extract_bold_tokens(block: str) -> set:
    """Lenient fallback for models (e.g. Cisco) that embed answers in bold
    text or backtick-quoted text rather than a structured FINAL ANSWER line.
    Extracts IPs, hostnames, usernames, and domains from **bold** and
    `backtick` spans in the block."""
    bolds = re.findall(r"\*\*([^*]{2,60})\*\*", block)
    bolds += re.findall(r"`([^`]{2,60})`", block)
    tokens = set()
    for b in bolds:
        b = b.strip().lower()
        # IPs
        for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", b):
            tokens.add(ip)
        # Hostnames (desktop-xxx, laptop-xxx)
        for h in re.findall(r"(?:desktop|laptop)-[a-z0-9]+", b, re.IGNORECASE):
            tokens.add(h.lower())
        # Usernames (first.last pattern)
        for u in re.findall(r"\b[a-z]{2,20}\.[a-z]{2,20}\b", b):
            tokens.add(u)
        # Domains
        for d in re.findall(r"[a-z0-9][\w.-]+\.(?:com|net|org|top|xyz|su|biz|site|shop|cc)", b, re.IGNORECASE):
            tokens.add(d.lower())
    return tokens


def extract_fields(block: str, lenient: bool = False) -> tuple:
    """Return (predicted_set, cited_set, retrieved_set).

    If lenient=True AND no FINAL ANSWER is found, falls back to extracting
    bold-text tokens from the analysis block (for models like Cisco that
    produce analytical prose instead of structured output).
    """
    # Refang defanged indicators (e.g. 172.17.0[.]99 → 172.17.0.99)
    block = block.replace("[.]", ".").replace("[:]", ":")
    # Match many FINAL ANSWER variants:
    #   FINAL ANSWER = [...]
    #   **FINAL ANSWER** = ...
    #   **FINAL ANSWER**: ...
    #   **Final Answer:**  \n[...]
    #   ### FINAL ANSWER = [...]
    #   ### FINAL ANSWER  \n value
    #   - **Final Answer:** value
    # Try with separator first (=/:), then without (value on next line).
    # Use findall + take LAST match: Cisco often writes a heading like
    # "### Final Answer:" before the actual "FINAL ANSWER = value" line.
    _FA_SEP = re.compile(
        r"^[-#*\s]*FINAL ANSWER[* \t]*[=:]+[* \t]*\[?([^\]\n]+)",
        re.MULTILINE | re.IGNORECASE
    )
    _FA_NL = re.compile(
        r"^[-#*\s]*FINAL ANSWER[* \t]*[=:]?[* \t]*\n[* \t]*\[?([^\]\n]+)",
        re.MULTILINE | re.IGNORECASE
    )
    # Filter out matches that are only markup (asterisks, brackets, spaces)
    def _is_meaningful(s):
        return bool(s.strip().strip("*[]").strip())
    all_matches = [m.strip() for m in _FA_SEP.findall(block) if _is_meaningful(m)]
    fa_val = all_matches[-1] if all_matches else None
    if not fa_val:
        nl_matches = [m.strip() for m in _FA_NL.findall(block) if _is_meaningful(m)]
        fa_val = nl_matches[-1] if nl_matches else None
    # Handle Cisco's multi-line format:
    #   ### Final Answer:
    #   **SUB-HEADING ENDING IN COLON:**
    #   **actual answer**
    # If the captured value ends with ':' after stripping markup, look at the next
    # non-empty line in the block after "Final Answer".
    if fa_val and fa_val.rstrip(" *:").rstrip().endswith((":",)) or (
        fa_val and fa_val.strip(" *").endswith(":")
    ):
        # Find "Final Answer" heading and skip to the line after the sub-heading
        m = re.search(r"^[-#*\s]*FINAL ANSWER[^\n]*\n", block, re.MULTILINE | re.IGNORECASE)
        if m:
            rest = block[m.end():]
            lines = [l.strip(" *") for l in rest.split("\n") if l.strip()]
            # Skip sub-heading lines (ending with :), take first content line
            for line in lines[:5]:
                stripped = line.strip(" *`")
                if stripped and not stripped.endswith(":"):
                    fa_val = stripped
                    break
    cc = LINE_CITED.search(block)
    rc = LINE_RETR.search(block)

    if fa_val:
        raw = fa_val.strip().rstrip("]")
        tokens = parse_answer_tokens(raw)
        # Detect malformed answers: question echoes, meta-commentary, or
        # long text without any concrete indicator (IP, domain, hostname).
        has_indicator = any(
            re.search(r"\d+\.\d+\.\d+\.\d+|[a-z][\w.-]+\.\w{2,4}|desktop-|laptop-", t)
            for t in tokens
        )
        if not has_indicator and len(raw) > 40:
            pred = _extract_bold_tokens(block) if lenient else set()
        else:
            pred = tokens
    elif not fa_val and lenient:
        pred = _extract_bold_tokens(block)
    else:
        pred = set()

    cited = {normalize_filename(x) for x in parse_list(cc.group(1) if cc else "")}
    retrieved = {normalize_filename(x) for x in parse_list(rc.group(1) if rc else "")}
    cited.discard("")
    retrieved.discard("")
    return pred, cited, retrieved


# ----- Scoring ---------------------------------------------------------------
_FILLER = {"at", "approximately", "around", "about", "on", "the", "of", "in",
           "utc", "pm", "am"}


def _keyword_match(ref_token: str, predicted: set) -> bool:
    """Fallback for reformatted timestamps: check if all significant words
    in the reference appear somewhere in the combined predicted text."""
    words = [w for w in re.split(r"[\s\-T:Z.()]+", ref_token)
             if w and w not in _FILLER]
    if len(words) < 2:
        return False
    combined = " ".join(predicted)
    return all(w in combined for w in words)


def _normalize(token: str) -> str:
    """Normalize tokens for comparison: strip default ports, trailing slashes."""
    token = re.sub(r":80(/)", r"\1", token)   # http://x:80/path → http://x/path
    token = re.sub(r":443(/)", r"\1", token)  # https://x:443/path → https://x/path
    return token.rstrip("/")


def score(predicted: set, reference: set) -> tuple:
    if not reference:
        return (None, None)
    pred_norm = {_normalize(p) for p in predicted}
    matched = 0
    for r in reference:
        r_norm = _normalize(r)
        if any(r_norm in p or p in r_norm for p in pred_norm):
            matched += 1
        elif _keyword_match(r, predicted):
            matched += 1
    return (matched / len(reference), matched > 0)


# ----- Main ------------------------------------------------------------------
def avg(seq):
    seq = list(seq)
    return sum(seq) / len(seq) if seq else 0.0


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", default="llm_reports",
                        help="Subdirectory under each scenario to read reports from")
    parser.add_argument("--output-prefix", default="",
                        help="Prefix for output files (e.g. 'k14_' produces k14_per_answer.csv)")
    args = parser.parse_args()

    rows = []
    ref_cache: dict[str, dict | None] = {}

    for scenario, report in report_sources(args.reports_dir):
        if scenario not in ref_cache:
            ref_cache[scenario] = load_reference_answers(scenario)
        ref_answers = ref_cache[scenario]
        provider = provider_of(report)
        if provider == "UNKNOWN":
            continue

        text = report.read_text()
        blocks = split_question_blocks(text)
        lenient = provider == "Cisco 8B"

        for qnum, block in blocks.items():
            pred, cited, retrieved = extract_fields(block, lenient=lenient)
            ref = ref_answers.get(qnum, set()) if ref_answers else None
            if ref is None or len(ref) == 0:
                recall, correct = (None, None)
            else:
                recall, correct = score(pred, ref)

            n_c = len(cited)
            n_r = len(retrieved)
            cited_in_retrieved = len(cited & retrieved)

            rows.append({
                "scenario": scenario,
                "provider": provider,
                "question": qnum,
                "recall": "" if recall is None else round(recall, 2),
                "correct": "" if correct is None else int(correct),
                "n_cited": n_c,
                "n_retrieved": n_r,
                "single_chunk": int(n_c == 1),
                "multi_chunk": int(n_c >= 2),
                "citation_precision": "" if not n_c else round(cited_in_retrieved / n_c, 2),
                "citation_efficiency": "" if not n_r else round(n_c / n_r, 2),
                "cited": "+".join(sorted(cited)),
                "retrieved": "+".join(sorted(retrieved)),
                "predicted": ";".join(sorted(pred)) or "(none)",
                "reference": ";".join(sorted(ref)) if ref else "(no GT)",
            })

    if not rows:
        print(f"No reports found under evaluation/*/{args.reports_dir}/")
        return

    # ---- Write CSV -----------------------------------------------------------
    csv_path = OUT_DIR / f"{args.output_prefix}per_answer.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {csv_path} ({len(rows)} rows)")

    # ---- Summary -------------------------------------------------------------
    scored_rows = [r for r in rows if r["correct"] != ""]
    correct_rows = [r for r in rows if r["correct"] == 1]
    n_scored = len(scored_rows)
    n_correct = len(correct_rows)
    overall_recall = (
        sum(float(r["recall"]) for r in scored_rows if r["recall"] != "")
        / max(1, n_scored)
    )

    md = []
    md.append("# Analysis Summary\n")
    md.append(f"- Reports parsed: **{len(rows)}** rows")
    md.append(f"- Scored against reference answers: **{n_scored}**")
    md.append(f"- Mean recall: **{100*overall_recall:.1f}%**")
    md.append(f"- Correct (≥1 token matched): **{n_correct}** "
              f"({100*n_correct/max(1,n_scored):.1f}%)\n")

    # Per-provider
    md.append("## Per-provider\n")
    md.append("| Provider | Scored | Recall | Correct |")
    md.append("|----------|--------|--------|---------|")
    sc_by_p = defaultdict(list)
    for r in scored_rows:
        sc_by_p[r["provider"]].append(r)
    for p in sorted(sc_by_p):
        srs = sc_by_p[p]
        rec = avg(float(r["recall"]) for r in srs if r["recall"] != "")
        cor = sum(1 for r in srs if r["correct"] == 1)
        md.append(f"| {p} | {len(srs)} | {100*rec:.1f}% | {cor} |")
    md.append("")

    # Per-scenario
    md.append("## Per-scenario\n")
    md.append("| Scenario | Reports | Scored | Recall | Correct |")
    md.append("|----------|---------|--------|--------|---------|")
    by_s = defaultdict(list)
    for r in rows:
        by_s[r["scenario"]].append(r)
    for s in sorted(by_s):
        rs = by_s[s]
        scored = [r for r in rs if r["correct"] != ""]
        correct = [r for r in rs if r["correct"] == 1]
        rec = avg(float(r["recall"]) for r in scored if r["recall"] != "")
        md.append(f"| {s} | {len(rs)} | {len(scored)} | {100*rec:.1f}% | {len(correct)} |")
    md.append("")

    # Per-scenario x per-provider recall table
    provider_order = ["Claude Sonnet 4", "DeepSeek V3", "Ollama 3.1:70b",
                      "Cisco 8B", "GPT-4", "GPT-4o", "GPT-5-mini", "GPT-5.2"]
    short_names = {"Claude Sonnet 4": "Claude", "DeepSeek V3": "DeepSeek",
                   "Ollama 3.1:70b": "Ollama", "Cisco 8B": "Cisco",
                   "GPT-4": "GPT-4", "GPT-4o": "GPT-4o",
                   "GPT-5-mini": "GPT-5m", "GPT-5.2": "GPT-5.2"}
    # Build per-scenario per-provider data
    sp_data = defaultdict(lambda: defaultdict(list))
    for r in scored_rows:
        sp_data[r["scenario"]][r["provider"]].append(float(r["recall"]))
    # Only include providers that appear in the data
    active = [p for p in provider_order if any(p in sp_data[s] for s in sp_data)]
    if active:
        md.append("## Recall (%) by scenario and provider\n")
        header = "| Scenario | " + " | ".join(short_names.get(p, p) for p in active) + " |"
        sep = "|---|" + "---|" * len(active)
        md.append(header)
        md.append(sep)
        for s in sorted(sp_data):
            vals = []
            for p in active:
                if p in sp_data[s]:
                    v = sum(sp_data[s][p]) / len(sp_data[s][p]) * 100
                    vals.append(str(int(round(v))))
                else:
                    vals.append("-")
            md.append(f"| {s} | " + " | ".join(vals) + " |")
        # Averages row
        avgs = []
        for p in active:
            all_r = [v for s in sp_data for v in sp_data[s].get(p, [])]
            avgs.append(f"**{int(round(sum(all_r)/len(all_r)*100))}**" if all_r else "-")
        md.append(f"| **Average** | " + " | ".join(avgs) + " |")
        md.append("")

    md_path = OUT_DIR / f"{args.output_prefix}summary.md"
    md_path.write_text("\n".join(md) + "\n")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
