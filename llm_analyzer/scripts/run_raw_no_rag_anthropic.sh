#!/bin/bash
# No-RAG Analyzer - Alternative approach for comparison
# Run from the llm_analyzer/ directory
#
# This script runs analysis WITHOUT RAG (Retrieval-Augmented Generation).
# Instead of using embeddings to find relevant chunks, it sends raw logs
# directly to the LLM up to the context window limit.
#
# Raw logs for fake_auth are included in evaluation/fake_auth/raw_logs/.

# === CHANGE THESE ===
SCENARIO="fake_auth"
API_KEY_FILE="keys/anthropic.txt"  # Create this file with your API key

# Derived paths
EVAL_DIR="../evaluation/${SCENARIO}"

echo "Running No-RAG analysis for: ${SCENARIO}"

python analyzer/no_rag_analyzer.py "${EVAL_DIR}/raw_logs" \
    --provider anthropic \
    --api-key-file "${API_KEY_FILE}" \
    --questions-file "${EVAL_DIR}/config/questions.txt" \
    --network-file "${EVAL_DIR}/config/network.txt" \
    --output "${EVAL_DIR}/no_rag_reports/${SCENARIO}_no_rag_anthropic.md" \
    --delay 30

echo "Done! Check ${EVAL_DIR}/no_rag_reports/${SCENARIO}_no_rag_anthropic.md"
