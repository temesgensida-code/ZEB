import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

// ── Configuration ────────────────────────────────────────────────────────────
const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8000';
const ENDPOINTS = {
  CHECK_PROGRESS: `${BASE_URL}/api/check-progress/`,
  CHECK_URL: `${BASE_URL}/api/check-url/`,
};

const DEFAULT_HEADERS = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
  'User-Agent': 'k6-smoke-suite/1.0 (ZEB Security Scanner)',
};

// ── Custom Metrics ───────────────────────────────────────────────────────────
const progressDuration = new Trend('progress_req_duration', true);
const progressSuccessRate = new Rate('progress_success_rate');
const progressPollCounter = new Counter('progress_poll_count');

// ── Test Options: Smoke Test (1-2 VUs, Quick Sanity Check) ───────────────────
export const options = {
  scenarios: {
    smoke_check: {
      executor: 'constant-vus',
      vus: 2,
      duration: '15s',
    },
  },
  thresholds: {
    // 95% of progress requests should resolve under 150ms during smoke testing
    'http_req_duration{endpoint:check_progress}': ['p(95)<150'],
    'progress_success_rate': ['rate>0.99'],
    'http_req_failed{expected_error:false}': ['rate<0.01'],
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

// ── Default Scenario Execution ───────────────────────────────────────────────
export default function () {
  const sessionId = generateUUID();

  // 1. Sanity check: Valid session polling
  group('Valid Session Polling', function () {
    const url = `${ENDPOINTS.CHECK_PROGRESS}?sessionId=${encodeURIComponent(sessionId)}`;
    const res = http.get(url, {
      headers: DEFAULT_HEADERS,
      tags: { endpoint: 'check_progress', scenario: 'smoke_valid', expected_error: 'false' },
    });

    progressPollCounter.add(1);
    progressDuration.add(res.timings.duration, { endpoint: 'check_progress' });
    progressSuccessRate.add(res.status === 200);

    check(res, {
      'smoke: status is 200': (r) => r.status === 200,
      'smoke: response has JSON Content-Type': (r) =>
        r.headers['Content-Type'] && r.headers['Content-Type'].includes('application/json'),
      'smoke: body contains currentStage string': (r) => {
        try {
          const b = JSON.parse(r.body);
          return typeof b.currentStage === 'string';
        } catch {
          return false;
        }
      },
      'smoke: body contains isComplete boolean': (r) => {
        try {
          const b = JSON.parse(r.body);
          return typeof b.isComplete === 'boolean';
        } catch {
          return false;
        }
      },
    });
  });

  // Brief think time simulating frontend poll cycle (350ms)
  sleep(0.35);

  // 2. Error handling: Missing sessionId parameter (Negative Validation)
  group('Missing SessionId Validation', function () {
    const res = http.get(ENDPOINTS.CHECK_PROGRESS, {
      headers: DEFAULT_HEADERS,
      tags: { endpoint: 'check_progress_validation', scenario: 'smoke_invalid', expected_error: 'true' },
      responseCallback: http.expectedStatuses(400),
    });

    check(res, {
      'smoke: returns 400 when sessionId is missing': (r) => r.status === 400,
      'smoke: returns error message': (r) => {
        try {
          const b = JSON.parse(r.body);
          return b.error && b.error.includes('sessionId is required');
        } catch {
          return false;
        }
      },
    });
  });

  // 3. Simulated user workflow: multiple sequential progress polls on the same session
  group('Sequential Frontend Polling Cycle', function () {
    for (let i = 0; i < 3; i++) {
      const url = `${ENDPOINTS.CHECK_PROGRESS}?sessionId=${encodeURIComponent(sessionId)}`;
      const res = http.get(url, {
        headers: DEFAULT_HEADERS,
        tags: { endpoint: 'check_progress', scenario: 'smoke_workflow', expected_error: 'false' },
      });

      progressPollCounter.add(1);
      progressDuration.add(res.timings.duration, { endpoint: 'check_progress' });
      progressSuccessRate.add(res.status === 200);

      check(res, {
        'smoke: multi-poll status is 200': (r) => r.status === 200,
      });

      sleep(0.25);
    }
  });

  sleep(1.0);
}
