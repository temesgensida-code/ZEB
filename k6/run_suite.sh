#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZEB Performance Testing Suite Runner (Powered by k6)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"

echo "====================================================================="
echo "   ZEB URL Security Scanner — k6 Performance Testing Suite           "
echo "====================================================================="
echo "Target Base URL: ${BASE_URL}"
echo ""

print_usage() {
  echo "Usage: $0 [smoke|load|stress|all] [extra-k6-args...]"
  echo ""
  echo "Commands:"
  echo "  smoke     Run smoke test (1-2 VUs, 15s) to verify sanity & contracts"
  echo "  load      Run load test (up to 25 VUs, 2m10s) simulating peak traffic"
  echo "  stress    Run stress test (up to 150 VUs) for saturation limits"
  echo "  all       Run smoke, load, and stress sequentially"
  echo ""
  echo "Examples:"
  echo "  $0 smoke"
  echo "  $0 load -e BASE_URL=http://production-host:8000"
  echo "  $0 stress --summary-export=stress-report.json"
  exit 1
}

if ! command -v k6 &> /dev/null; then
  echo "Error: k6 is not installed or not in PATH."
  echo "Please install k6 (https://grafana.com/docs/k6/latest/set-up/install-k6/)."
  exit 1
fi

TEST_TYPE="${1:-smoke}"
shift || true

run_smoke() {
  echo ">> Running Smoke Test on GET /api/check-progress/ ..."
  k6 run -e BASE_URL="${BASE_URL}" "${SCRIPT_DIR}/smoke_test.js" "$@"
}

run_load() {
  echo ">> Running Load Test on GET /api/check-progress/ under realistic user workflow ..."
  k6 run -e BASE_URL="${BASE_URL}" "${SCRIPT_DIR}/load_test.js" "$@"
}

run_stress() {
  echo ">> Running Stress Test on GET /api/check-progress/ with high concurrency ..."
  k6 run -e BASE_URL="${BASE_URL}" "${SCRIPT_DIR}/stress_test.js" "$@"
}

case "${TEST_TYPE}" in
  smoke)
    run_smoke "$@"
    ;;
  load)
    run_load "$@"
    ;;
  stress)
    run_stress "$@"
    ;;
  all)
    echo "Starting full test suite sequence..."
    run_smoke "$@"
    echo ""
    run_load "$@"
    echo ""
    run_stress "$@"
    ;;
  *)
    print_usage
    ;;
esac

echo ""
echo ">> Performance test suite execution finished successfully."
