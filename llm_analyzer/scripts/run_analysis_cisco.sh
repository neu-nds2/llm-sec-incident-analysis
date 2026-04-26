#!/bin/bash
# Analyze security incident using Cisco Foundation-Sec (local)
# Run from the llm_analyzer/ directory

# === CHANGE THESE ===
SCENARIO="fake_auth"
MODEL_PATH="/path/to/Foundation-Sec-8B-Reasoning/"

# Derived paths
EVAL_DIR="../evaluation/${SCENARIO}"

echo "Running Cisco Foundation-Sec analysis for: ${SCENARIO}"

python analyze.py "${EVAL_DIR}/es_results" \
    --provider cisco \
    --model "${MODEL_PATH}" \
    --questions-file "${EVAL_DIR}/config/questions.txt" \
    --network-file "${EVAL_DIR}/config/network.txt" \
    --cache "${EVAL_DIR}/cache_embeddings/${SCENARIO}_embeddings.pkl" \
    --output "${EVAL_DIR}/llm_reports/${SCENARIO}_cisco.md" \
    --debug

echo "Done! Check ${EVAL_DIR}/llm_reports/${SCENARIO}_cisco.md"
