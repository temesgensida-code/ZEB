# ZEB Performance Testing Suite (k6)

Comprehensive performance, load, and concurrency stress testing suite for **ZEB URL Security Scanner**, built and validated using the **k6 MCP Server** tools and k6 OSS best practices.

The suite focuses on realistic user workflows interacting with the core polling telemetry endpoint:
`GET /api/check-progress/?sessionId=<id>`

---

## Architecture & Workflows

### Realistic User Polling Workflow Emulation
During normal operation, the frontend React application (`App.jsx`) generates a client UUID `sessionId` upon submission and triggers an asynchronous URL safety audit while actively polling:

```http
GET /api/check-progress/?sessionId=9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d
```

* **Polling Cadence:** Frontend polls every `300ms - 450ms` until the analysis completes or reaches max poll limit.
* **State Evolution:** The backend transitions through stages (`Validating URL format...`, `Querying multi-engine threat intelligence feeds...`, `Analyzing URL structure...`, `Following redirect chain...`, `Running sandbox page analysis...`) before setting `isComplete: true`.
* **Cold & Shared Inquiries:** The test suite generates both high-cardinality unique session IDs and high-contention shared "hot" sessions to test dictionary read contention and memory footprint.
* **Resilience Testing:** Evaluates proper HTTP 400 rejection and payload structure when `sessionId` is missing or invalid.

---

## Test Suites

| Suite | File | VUs / Concurrency Profile | Purpose |
| :--- | :--- | :--- | :--- |
| **Smoke Test** | `smoke_test.js` | 2 VUs constant, 15s | Verifies endpoint contracts, valid/invalid inputs, JSON schema sanity, and baseline latency. |
| **Load Test** | `load_test.js` | 1 &rarr; 10 &rarr; 25 VUs, 2m 10s | Simulates realistic peak concurrent user traffic with weighted active scanners (80%) and passive inquiries (20%). |
| **Stress Test** | `stress_test.js` | 1 &rarr; 20 &rarr; 60 &rarr; 120 &rarr; 150 VUs, 2m 20s | Pushes concurrency beyond normal operational bounds to find queue saturation points, latency degradation curves, and recovery behavior. |

---

## Performance Thresholds & Budgets

```javascript
// Smoke Test Thresholds
thresholds: {
  'http_req_duration{endpoint:check_progress}': ['p(95)<150'],
  'progress_success_rate': ['rate>0.99'],
  'http_req_failed{expected_error:false}': ['rate<0.01'],
  'checks': ['rate>0.99'],
}

// Load Test Thresholds
thresholds: {
  'http_req_duration{endpoint:check_progress}': ['p(95)<200', 'p(99)<400'],
  'http_req_failed{expected_error:false}': ['rate<0.01'],
  'progress_success_rate': ['rate>0.99'],
  'checks': ['rate>0.99'],
}

// Stress Test Thresholds (Up to 150 VUs)
thresholds: {
  'http_req_duration{endpoint:check_progress}': ['p(90)<300', 'p(95)<500', 'p(99)<1000'],
  'http_req_failed': ['rate<0.05'],
  'stress_success_rate': ['rate>0.95'],
  'checks': ['rate>0.95'],
}
```

---

## Running Tests

### Option A: Using the CLI Runner Script
```bash
# Make executable
chmod +x k6/run_suite.sh

# Run smoke test
./k6/run_suite.sh smoke

# Run load test
./k6/run_suite.sh load

# Run stress test
./k6/run_suite.sh stress

# Run all tests sequentially
./k6/run_suite.sh all

# Target a remote or staging URL
BASE_URL="https://api.yourdomain.com" ./k6/run_suite.sh load
```

### Option B: Using Native k6 CLI
```bash
# Smoke
k6 run -e BASE_URL=http://127.0.0.1:8000 k6/smoke_test.js

# Load
k6 run -e BASE_URL=http://127.0.0.1:8000 k6/load_test.js

# Stress
k6 run -e BASE_URL=http://127.0.0.1:8000 k6/stress_test.js
```

### Option C: Using k6 MCP Tools
Every test in this suite is self-contained and formatted to be executed directly through the **k6 MCP Server**:
* `call_mcp_tool("k6", "validate_script", { script: "..." })`
* `call_mcp_tool("k6", "run_script", { script: "...", vus: 10, duration: "30s" })`

---

## Observability & Custom Metrics

* `progress_req_duration`: Custom Trend tracking exact duration of `GET /api/check-progress/`.
* `progress_success_rate`: Percentage of successful progress responses (HTTP 200 with valid schema).
* `progress_poll_count`: Cumulative counter of individual polling iterations performed.
* `workflow_total_duration`: Time taken for a complete multi-poll frontend scan cycle.
* `stress_slow_requests_rate`: Proportion of requests exceeding 250ms during heavy concurrency.
