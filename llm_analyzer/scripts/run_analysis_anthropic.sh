#!/bin/bash
# Analyze security incident using Anthropic Claude
# Run from the llm_analyzer/ directory

# === CHANGE THESE ===
SCENARIO="fake_auth"
API_KEY_FILE="keys/anthropic.txt"  # Create this file with your API key

# Derived paths
EVAL_DIR="../evaluation/${SCENARIO}"

echo "Running Anthropic analysis for: ${SCENARIO}"

python analyze.py "${EVAL_DIR}/es_results" \
    --provider anthropic \
    --api-key-file "${API_KEY_FILE}" \
    --questions-file "${EVAL_DIR}/config/questions.txt" \
    --network-file "${EVAL_DIR}/config/network.txt" \
    --cache "${EVAL_DIR}/cache_embeddings/${SCENARIO}_embeddings.pkl" \
    --output "${EVAL_DIR}/llm_reports/${SCENARIO}_anthropic.md" \
    --debug

echo "Done! Check ${EVAL_DIR}/llm_reports/${SCENARIO}_anthropic.md"
