import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { ENDPOINTS, DEFAULT_HEADERS, TIMINGS } from './config.js';

// Custom metrics for precision observability
export const progressReqDuration = new Trend('progress_req_duration', true);
export const progressSuccessRate = new Rate('progress_success_rate');
export const progressTotalPolls = new Counter('progress_total_polls');
export const workflowPollIterations = new Trend('workflow_poll_iterations');

/**
 * Generate RFC4122 v4 UUID for session correlation
 */
export function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Select random item from an array
 */
export function randomChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

/**
 * Random sleep interval between min and max seconds
 */
export function randomSleep(min = TIMINGS.POLL_INTERVAL_MIN, max = TIMINGS.POLL_INTERVAL_MAX) {
  const duration = Math.random() * (max - min) + min;
  sleep(duration);
}

/**
 * Poll the GET /api/check-progress/ endpoint once
 *
 * @param {string|null} sessionId - Session ID (or null/empty for negative validation)
 * @param {object} customTags - Extra tags for metrics grouping
 * @returns {object} { res, parsed, isComplete, currentStage }
 */
export function pollProgress(sessionId, customTags = {}) {
  const tags = Object.assign({ endpoint: 'check_progress' }, customTags);
  const url = sessionId
    ? `${ENDPOINTS.CHECK_PROGRESS}?sessionId=${encodeURIComponent(sessionId)}`
    : ENDPOINTS.CHECK_PROGRESS;

  const res = http.get(url, {
    headers: DEFAULT_HEADERS,
    tags: tags,
  });

  progressTotalPolls.add(1, tags);
  progressReqDuration.add(res.timings.duration, tags);

  if (sessionId) {
    const isOk = res.status === 200;
    progressSuccessRate.add(isOk, tags);

    const checksPassed = check(res, {
      'status is 200': (r) => r.status === 200,
      'response has valid content-type': (r) =>
        r.headers['Content-Type'] && r.headers['Content-Type'].includes('application/json'),
      'body contains currentStage': (r) => {
        try {
          const body = JSON.parse(r.body);
          return typeof body.currentStage === 'string';
        } catch {
          return false;
        }
      },
      'body contains isComplete': (r) => {
        try {
          const body = JSON.parse(r.body);
          return typeof body.isComplete === 'boolean';
        } catch {
          return false;
        }
      },
    }, tags);

    let parsed = null;
    try {
      parsed = JSON.parse(res.body);
    } catch {
      parsed = null;
    }

    return {
      res,
      checksPassed,
      parsed,
      isComplete: parsed ? Boolean(parsed.isComplete) : false,
      currentStage: parsed ? parsed.currentStage : null,
    };
  } else {
    // Missing sessionId negative test: expected 400 Bad Request
    const checksPassed = check(res, {
      'status is 400 for missing sessionId': (r) => r.status === 400,
      'error message specifies sessionId required': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.error && body.error.includes('sessionId is required');
        } catch {
          return false;
        }
      },
    }, tags);

    return {
      res,
      checksPassed,
      parsed: null,
      isComplete: false,
      currentStage: null,
    };
  }
}
