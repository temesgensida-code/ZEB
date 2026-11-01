import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

// ── Global Configuration ─────────────────────────────────────────────────────
const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8000';
const ENDPOINTS = {
  CHECK_PROGRESS: `${BASE_URL}/api/check-progress/`,
};

const DEFAULT_HEADERS = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
  'User-Agent': 'k6-stress-suite/1.0 (ZEB Concurrency Stress Test)',
};

// ── Observability & Saturation Metrics ───────────────────────────────────────
const stressReqDuration = new Trend('stress_req_duration', true);
const stressSuccessRate = new Rate('stress_success_rate');
const stressPollCounter = new Counter('stress_poll_count');
const slowRequestsRate = new Rate('stress_slow_requests_rate'); // Requests > 250ms

// ── Stress Testing Stages: Progressive Concurrency Ramp to Saturation ───────
export const options = {
  scenarios: {
    concurrency_stress_ramp: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '20s', target: 20 },  // Stage 1: Fast warm-up to moderate load
        { duration: '30s', target: 60 },  // Stage 2: Heavy concurrent load
        { duration: '40s', target: 120 }, // Stage 3: Extreme concurrency stress
        { duration: '30s', target: 150 }, // Stage 4: Peak saturation plateau (150 concurrent VUs)
        { duration: '20s', target: 0 },   // Stage 5: Recovery and graceful cool-down
      ],
      gracefulRampDown: '15s',
    },
  },
  thresholds: {
    // Under extreme concurrency (up to 150 VUs), 95% of progress requests should be under 500ms
    'http_req_duration{endpoint:check_progress}': ['p(90)<300', 'p(95)<500', 'p(99)<1000'],
    // Maximum allowable failure rate under extreme stress is 5%
    'http_req_failed': ['rate<0.05'],
    'stress_success_rate': ['rate>0.95'],
    'checks': ['rate>0.95'],
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

// Fixed pool of hot sessions to simulate multiple concurrent clients querying shared scans
const HOT_SESSION_POOL = [
  'hot-session-alpha-001',
  'hot-session-beta-002',
  'hot-session-gamma-003',
  'hot-session-delta-004',
  'hot-session-omega-005',
];

// ── Stress Scenario Execution ────────────────────────────────────────────────
export default function () {
  // 60% of requests query a unique new session ID (high cardinality state)
  // 40% of requests query a shared hot session ID (high contention on same key)
  const isHotSession = Math.random() < 0.40;
  const sessionId = isHotSession
    ? HOT_SESSION_POOL[Math.floor(Math.random() * HOT_SESSION_POOL.length)]
    : generateUUID();

  // Burst of 4 to 8 rapid polling requests per VU cycle (simulating aggressive frontend or multi-tab polling)
  const burstCount = Math.floor(randomBetween(4, 8));

  group('Concurrent Polling Burst', function () {
    for (let i = 0; i < burstCount; i++) {
      const url = `${ENDPOINTS.CHECK_PROGRESS}?sessionId=${encodeURIComponent(sessionId)}`;
      const res = http.get(url, {
        headers: DEFAULT_HEADERS,
        tags: {
          endpoint: 'check_progress',
          contention: isHotSession ? 'shared_session' : 'unique_session',
          stage: 'stress_burst',
        },
        timeout: '5s',
      });

      stressPollCounter.add(1);
      stressReqDuration.add(res.timings.duration, { endpoint: 'check_progress' });
      stressSuccessRate.add(res.status === 200);
      slowRequestsRate.add(res.timings.duration > 250);

      check(res, {
        'stress: status is 200': (r) => r.status === 200,
        'stress: valid JSON body': (r) => {
          try {
            const b = JSON.parse(r.body);
            return typeof b.currentStage === 'string';
          } catch {
            return false;
          }
        },
      });

      // Rapid polling pacing under concurrency (200ms to 350ms)
      sleep(randomBetween(0.20, 0.35));
    }
  });

  // Short pause before next VU iteration (0.5s to 1.2s)
  sleep(randomBetween(0.5, 1.2));
}
