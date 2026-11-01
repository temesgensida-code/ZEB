#!/usr/bin/env bash
# ==============================================================================
# run_benchmark.sh - Automated Locust Stress Testing & Profiling Runner
# ==============================================================================
set -euo pipefail

# Directory paths
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCHMARK_DIR="${PROJECT_ROOT}/benchmark"
REPORTS_DIR="${BENCHMARK_DIR}/reports"
mkdir -p "${REPORTS_DIR}"

# Python virtual environment resolution
if [ -x "${PROJECT_ROOT}/.venv/bin/python" ]; then
    PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
    LOCUST_BIN="${PROJECT_ROOT}/.venv/bin/locust"
    GUNICORN_BIN="${PROJECT_ROOT}/.venv/bin/gunicorn"
else
    PYTHON_BIN="python3"
    LOCUST_BIN="locust"
    GUNICORN_BIN="gunicorn"
fi

# Default configuration
SERVER_TYPE="gunicorn"      # "gunicorn" or "runserver"
MODE="headless"             # "headless" or "web"
USERS=25                    # Concurrent virtual users
SPAWN_RATE=5                # Users spawned per second
DURATION="30s"              # Test duration
PORT=8000                   # Target server port
HOST="http://127.0.0.1:${PORT}"
USER_CLASS="MixedWorkloadUser" # "MixedWorkloadUser", "CpuBoundUser", "NetworkIoUser"

function show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --server TYPE        Server to run: 'gunicorn' (default, 4w/4t) or 'runserver' (single process)
  --mode MODE          Benchmark mode: 'headless' (default) or 'web' (Locust dashboard on :8089)
  --users NUM          Number of concurrent virtual users (default: 25)
  --spawn-rate RATE    User spawn rate per second (default: 5)
  --duration TIME      Test duration, e.g. 30s, 1m, 2m (default: 30s, headless only)
  --scenario SCENARIO  User scenario: 'mixed' (default), 'cpu', or 'io'
  --port PORT          Local HTTP port for Django/Gunicorn (default: 8000)
  --help               Display this help message and exit

Examples:
  ./benchmark/run_benchmark.sh --mode web
  ./benchmark/run_benchmark.sh --server runserver --scenario cpu --users 20
  ./benchmark/run_benchmark.sh --server gunicorn --scenario io --users 50 --duration 1m
EOF
}

# Parse command line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)
            SERVER_TYPE="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        --users)
            USERS="$2"
            shift 2
            ;;
        --spawn-rate)
            SPAWN_RATE="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --scenario)
            case "$2" in
                cpu) USER_CLASS="CpuBoundUser" ;;
                io) USER_CLASS="NetworkIoUser" ;;
                mixed|all) USER_CLASS="MixedWorkloadUser" ;;
                *) echo "Unknown scenario '$2'. Use 'cpu', 'io', or 'mixed'." && exit 1 ;;
            esac
            shift 2
            ;;
        --port)
            PORT="$2"
            HOST="http://127.0.0.1:${PORT}"
            shift 2
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            show_help
            exit 1
            ;;
    esac
done

TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
REPORT_HTML="${REPORTS_DIR}/report_${SERVER_TYPE}_${TIMESTAMP}.html"
REPORT_CSV_PREFIX="${REPORTS_DIR}/locust_${SERVER_TYPE}_${TIMESTAMP}"
METRICS_CSV="${REPORTS_DIR}/system_metrics_${SERVER_TYPE}_${TIMESTAMP}.csv"

SERVER_PID=""
MONITOR_PID=""
SERVER_STARTED_BY_SCRIPT=0

# Cleanup handler on exit
cleanup() {
    echo ""
    echo "[benchmark] Shutting down background processes..."
    if [ -n "${MONITOR_PID}" ] && kill -0 "${MONITOR_PID}" 2>/dev/null; then
        kill -INT "${MONITOR_PID}" 2>/dev/null || true
        wait "${MONITOR_PID}" 2>/dev/null || true
    fi
    if [ "${SERVER_STARTED_BY_SCRIPT}" -eq 1 ] && [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill -TERM "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    echo "[benchmark] Clean exit complete."
}
trap cleanup EXIT INT TERM

# ── 1. Check if server is already running on PORT ─────────────────────────────
if curl -s -o /dev/null -w "%{http_code}" "${HOST}/api/check-url/" -X POST -H "Content-Type: application/json" -d '{"url":"https://example.com"}' > /dev/null 2>&1; then
    echo "[benchmark] Detected server already listening and responding on ${HOST}."
    SERVER_STARTED_BY_SCRIPT=0
    SERVER_PID="$(lsof -ti :${PORT} | head -n 1 2>/dev/null || echo "")"
else
    echo "[benchmark] Starting target server (${SERVER_TYPE}) on port ${PORT}..."
    SERVER_STARTED_BY_SCRIPT=1

    if [ "${SERVER_TYPE}" = "gunicorn" ]; then
        PYTHONPATH="${PROJECT_ROOT}/backend" "${GUNICORN_BIN}" backend.wsgi:application \
            --bind "127.0.0.1:${PORT}" \
            --workers 4 \
            --threads 4 \
            --access-logfile - \
            --error-logfile - &
        SERVER_PID=$!
    else
        "${PYTHON_BIN}" "${PROJECT_ROOT}/backend/manage.py" runserver "127.0.0.1:${PORT}" --noreload &
        SERVER_PID=$!
    fi

    # Wait for server to become responsive
    echo -n "[benchmark] Waiting for ${HOST} to become ready..."
    MAX_RETRIES=20
    COUNT=0
    until curl -s -o /dev/null -w "%{http_code}" "${HOST}/api/check-url/" -X POST -H "Content-Type: application/json" -d '{"url":"https://example.com"}' | grep -E "200|400" > /dev/null 2>&1; do
        sleep 0.5
        COUNT=$((COUNT + 1))
        echo -n "."
        if [ "$COUNT" -ge "$MAX_RETRIES" ]; then
            echo ""
            echo "[benchmark] Error: Server failed to start within timeout."
            exit 1
        fi
    done
    echo " Ready (PID ${SERVER_PID})!"
fi

# ── 2. Start psutil System Monitor ────────────────────────────────────────────
echo "[benchmark] Launching system resource profiler (logging to ${METRICS_CSV})..."
MONITOR_ARGS=("--output" "${METRICS_CSV}" "--interval" "1.0")
if [ -n "${SERVER_PID}" ]; then
    MONITOR_ARGS+=("--pid" "${SERVER_PID}")
else
    MONITOR_ARGS+=("--port" "${PORT}")
fi
"${PYTHON_BIN}" "${BENCHMARK_DIR}/system_monitor.py" "${MONITOR_ARGS[@]}" &
MONITOR_PID=$!

# ── 3. Execute Locust ─────────────────────────────────────────────────────────
echo "======================================================================"
echo " RUNNING LOCUST BENCHMARK"
echo " Server Profile:   ${SERVER_TYPE}"
echo " User Scenario:    ${USER_CLASS}"
echo " Mode:             ${MODE}"
echo " Host:             ${HOST}"
if [ "${MODE}" = "headless" ]; then
    echo " Concurrency:      ${USERS} users (ramp: ${SPAWN_RATE} users/s)"
    echo " Duration:         ${DURATION}"
fi
echo "======================================================================"

cd "${BENCHMARK_DIR}"

if [ "${MODE}" = "web" ]; then
    echo ""
    echo ">>> Locust Web UI available at: http://localhost:8089"
    echo ">>> Press Ctrl+C in this terminal when finished to stop benchmark."
    echo ""
    "${LOCUST_BIN}" -f locustfile.py --host "${HOST}" --web-port 8089 --class-picker
else
    "${LOCUST_BIN}" -f locustfile.py \
        --host "${HOST}" \
        --headless \
        -u "${USERS}" \
        -r "${SPAWN_RATE}" \
        -t "${DURATION}" \
        --html "${REPORT_HTML}" \
        --csv "${REPORT_CSV_PREFIX}" \
        "${USER_CLASS}"

    echo ""
    echo "======================================================================"
    echo " BENCHMARK COMPLETE - ARTIFACTS GENERATED"
    echo " HTML Report:      ${REPORT_HTML}"
    echo " Locust CSVs:      ${REPORT_CSV_PREFIX}_*.csv"
    echo " System CSV:       ${METRICS_CSV}"
    echo "======================================================================"

    # Print summary table if stats CSV exists
    if [ -f "${REPORT_CSV_PREFIX}_stats.csv" ]; then
        echo ""
        echo "PERFORMANCE & TELEMETRY BREAKDOWN:"
        column -s, -t < "${REPORT_CSV_PREFIX}_stats.csv" | head -n 12 || true
    fi
fi
