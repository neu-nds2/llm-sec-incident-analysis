#!/bin/bash
# Analyze security incident using Ollama (local)
# Run from the llm_analyzer/ directory
# Requires: ollama serve running with the model pulled

# === CHANGE THESE ===
SCENARIO="fake_auth"
MODEL="llama3.1:70b"

# Derived paths
EVAL_DIR="../evaluation/${SCENARIO}"

echo "Running Ollama (${MODEL}) analysis for: ${SCENARIO}"
echo "Make sure Ollama is running: ollama serve"

python analyze.py "${EVAL_DIR}/es_results" \
    --provider ollama \
    --model "${MODEL}" \
    --questions-file "${EVAL_DIR}/config/questions.txt" \
    --network-file "${EVAL_DIR}/config/network.txt" \
    --cache "${EVAL_DIR}/cache_embeddings/${SCENARIO}_embeddings.pkl" \
    --output "${EVAL_DIR}/llm_reports/${SCENARIO}_ollama.md" \
    --debug

echo "Done! Check ${EVAL_DIR}/llm_reports/${SCENARIO}_ollama.md"
