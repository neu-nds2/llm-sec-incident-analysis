#!/bin/bash
# Regenerate all No-RAG reports for the fake_auth scenario.
#
# Output filenames are aligned with analyze_cross_source.py's provider keys
# so the resulting no_rag_reports/ directory can be scored directly:
#   cd scoring && python analyze_cross_source.py \
#       --reports-dir no_rag_reports --output-prefix no_rag_
#
# Run from the llm_analyzer/ directory. Requires API keys at:
#   keys/anthropic.txt, keys/deepseek.txt, keys/openai.txt
set -euo pipefail

SCENARIO="fake_auth"
EVAL_DIR="../evaluation/${SCENARIO}"
RAW_LOGS="${EVAL_DIR}/raw_logs"
OUT_DIR="${EVAL_DIR}/no_rag_reports"
QUESTIONS="${EVAL_DIR}/config/questions.txt"
NETWORK="${EVAL_DIR}/config/network.txt"

mkdir -p "${OUT_DIR}"

run_one() {
  local provider="$1"
  local model="$2"
  local out_suffix="$3"

  local args=(--provider "${provider}" --questions-file "${QUESTIONS}" \
              --network-file "${NETWORK}" \
              --output "${OUT_DIR}/${SCENARIO}_no_rag_${out_suffix}.md" \
              --delay 30)

  if [[ "${provider}" == "anthropic" ]]; then
    args+=(--api-key-file keys/anthropic.txt)
  elif [[ "${provider}" == "deepseek" ]]; then
    args+=(--api-key-file keys/deepseek.txt)
  elif [[ "${provider}" == "openai" ]]; then
    args+=(--api-key-file keys/openai.txt --model "${model}")
  fi

  echo "=== No-RAG: ${provider} ${model} -> ${out_suffix} ==="
  python analyzer/no_rag_analyzer.py "${RAW_LOGS}" "${args[@]}"
}

run_one anthropic ""               anthropic
run_one deepseek  ""               deepseek
run_one openai    gpt-4.1          openai_gpt4
run_one openai    gpt-4o           openai_gpt4o
run_one openai    gpt-5-mini       openai_gpt5mini
run_one openai    gpt-5.2          openai_gpt52

echo
echo "All No-RAG reports written to ${OUT_DIR}"
echo "Now score them:"
echo "  cd ../scoring && python analyze_cross_source.py \\"
echo "      --reports-dir no_rag_reports --output-prefix no_rag_"
