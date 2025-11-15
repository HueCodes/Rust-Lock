#!/bin/bash
# Example: Check controller health

CONTROLLER_URL="${CONTROLLER_URL:-http://localhost:8080}"

echo "Checking controller health..."
curl -s "${CONTROLLER_URL}/health" | jq .

echo -e "\nGetting metrics..."
curl -s "${CONTROLLER_URL}/api/v1/metrics" | jq .

echo -e "\nGetting runners..."
curl -s "${CONTROLLER_URL}/api/v1/runners" | jq .

echo -e "\nGetting history..."
curl -s "${CONTROLLER_URL}/api/v1/history" | jq .
