#!/bin/bash
# Analyze security incident using OpenAI GPT
# Run from the llm_analyzer/ directory

# === CHANGE THESE ===
SCENARIO="fake_auth"
MODEL="gpt-4o"
API_KEY_FILE="keys/openai.txt"  # Create this file with your API key

# Derived paths
EVAL_DIR="../evaluation/${SCENARIO}"

echo "Running OpenAI (${MODEL}) analysis for: ${SCENARIO}"

python analyze.py "${EVAL_DIR}/es_results" \
    --provider openai \
    --model "${MODEL}" \
    --api-key-file "${API_KEY_FILE}" \
    --questions-file "${EVAL_DIR}/config/questions.txt" \
    --network-file "${EVAL_DIR}/config/network.txt" \
    --cache "${EVAL_DIR}/cache_embeddings/${SCENARIO}_embeddings.pkl" \
    --output "${EVAL_DIR}/llm_reports/${SCENARIO}_openai_${MODEL}.md" \
    --debug

echo "Done! Check ${EVAL_DIR}/llm_reports/${SCENARIO}_openai_${MODEL}.md"
