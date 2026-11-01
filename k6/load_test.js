import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

// ── Global Configuration ─────────────────────────────────────────────────────
const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8000';
const ENDPOINTS = {
  CHECK_PROGRESS: `${BASE_URL}/api/check-progress/`,
  CHECK_URL: `${BASE_URL}/api/check-url/`,
};

const DEFAULT_HEADERS = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
  'User-Agent': 'k6-load-suite/1.0 (ZEB Security Scanner)',
};

// ── Custom Performance & Business Metrics ────────────────────────────────────
const progressDuration = new Trend('progress_req_duration', true);
const progressSuccessRate = new Rate('progress_success_rate');
const progressPollCounter = new Counter('progress_poll_count');
const workflowDuration = new Trend('workflow_total_duration', true);

// ── Test Options: Load Testing (Ramping VUs simulating peak normal traffic) ──
export const options = {
  scenarios: {
    realistic_concurrent_load: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '20s', target: 10 }, // Ramp-up to initial load
        { duration: '30s', target: 25 }, // Ramp-up to peak expected concurrency
        { duration: '1m', target: 25 },  // Sustained steady-state traffic
        { duration: '20s', target: 0 },  // Graceful ramp-down
      ],
      gracefulRampDown: '10s',
    },
  },
  thresholds: {
    // 95% of progress polling requests must resolve under 200ms
    'http_req_duration{endpoint:check_progress}': ['p(95)<200', 'p(99)<400'],
    // Overall non-expected failure rate must remain below 1%
    'http_req_failed{expected_error:false}': ['rate<0.01'],
    'progress_success_rate': ['rate>0.99'],
    'checks': ['rate>0.99'],
  },
};

// ── Helper: UUID Generator ───────────────────────────────────────────────────
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function randomBetween(min, max) {
  return Math.random() * (max - min) + min;
}

// ── Realistic User Workflow Simulation ───────────────────────────────────────
export default function () {
  const workflowStart = Date.now();
  const sessionId = generateUUID();

  // 1. Initial State Poll (Simulates client immediately polling after submission)
  const initialUrl = `${ENDPOINTS.CHECK_PROGRESS}?sessionId=${encodeURIComponent(sessionId)}`;
  const initRes = http.get(initialUrl, {
    headers: DEFAULT_HEADERS,
    tags: {
      endpoint: 'check_progress',
      user_type: 'initial_poll',
      expected_error: 'false',
    },
  });

  progressPollCounter.add(1);
  progressDuration.add(initRes.timings.duration, { endpoint: 'check_progress' });
  progressSuccessRate.add(initRes.status === 200);

  check(initRes, {
    'load: initial status is 200': (r) => r.status === 200,
    'load: body contains currentStage': (r) => {
      try {
        return typeof JSON.parse(r.body).currentStage === 'string';
      } catch {
        return false;
      }
    },
  });

  sleep(0.35);

  // 2. Continuous Polling Stream
  // 80% Active Scanning Users: Rapid polling (300ms - 450ms) matching frontend behavior
  // 20% Follow-up/Re-checking Users: Slower polling interval
  const isRapidScanner = Math.random() < 0.80;

  if (isRapidScanner) {
    group('Active Scan Progress Polling', function () {
      const numPolls = Math.floor(randomBetween(5, 10));

      for (let i = 0; i < numPolls; i++) {
        const url = `${ENDPOINTS.CHECK_PROGRESS}?sessionId=${encodeURIComponent(sessionId)}`;
        const res = http.get(url, {
          headers: DEFAULT_HEADERS,
          tags: {
            endpoint: 'check_progress',
            user_type: 'active_scanner',
            expected_error: 'false',
          },
        });

        progressPollCounter.add(1);
        progressDuration.add(res.timings.duration, { endpoint: 'check_progress' });
        progressSuccessRate.add(res.status === 200);

        check(res, {
          'load: progress status is 200': (r) => r.status === 200,
          'load: response time < 250ms': (r) => r.timings.duration < 250,
          'load: valid JSON structure': (r) => {
            try {
              const body = JSON.parse(r.body);
              return typeof body.currentStage === 'string' && typeof body.isComplete === 'boolean';
            } catch {
              return false;
            }
          },
        });

        // Browser frontend think time between polls (300ms to 450ms)
        sleep(randomBetween(0.30, 0.45));
      }
    });
  } else {
    group('Passive Status Inquiry', function () {
      for (let i = 0; i < 3; i++) {
        const url = `${ENDPOINTS.CHECK_PROGRESS}?sessionId=${encodeURIComponent(sessionId)}`;
        const res = http.get(url, {
          headers: DEFAULT_HEADERS,
          tags: {
            endpoint: 'check_progress',
            user_type: 'passive_inquiry',
            expected_error: 'false',
          },
        });

        progressPollCounter.add(1);
        progressDuration.add(res.timings.duration, { endpoint: 'check_progress' });
        progressSuccessRate.add(res.status === 200);

        check(res, {
          'load: passive inquiry status is 200': (r) => r.status === 200,
        });

        sleep(randomBetween(0.8, 1.4));
      }
    });
  }

  workflowDuration.add(Date.now() - workflowStart);

  // Think time between complete user tasks (1 to 2 seconds)
  sleep(randomBetween(1.0, 2.0));
}
