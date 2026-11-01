import http from 'k6/http';
import { check } from 'k6';
import { ENDPOINTS, DEFAULT_HEADERS, SAMPLE_URLS, TIMINGS } from './config.js';
import {
  generateUUID,
  randomChoice,
  randomSleep,
  pollProgress,
  workflowPollIterations,
} from './helpers.js';

/**
 * Execute realistic user workflow simulating the frontend polling behavior:
 *
 * 1. Generate unique session ID
 * 2. Rapid polling loop on GET /api/check-progress/?sessionId=<sessionId>
 *    matching the real browser frontend polling rate (250ms-400ms interval)
 * 3. Occasional trigger of background inspection or cold inquiry
 * 4. Pacing with think time between checks
 *
 * @param {object} options
 * @param {boolean} options.triggerCheckUrl - Whether to also dispatch POST /api/check-url/
 * @param {number} options.maxPolls - Maximum polls per iteration (default 10)
 * @param {string} options.scenarioTag - Tag name for scenario metrics
 */
export function executeRealisticUserWorkflow(options = {}) {
  const {
    triggerCheckUrl = false,
    maxPolls = 8,
    scenarioTag = 'user_workflow',
  } = options;

  const sessionId = generateUUID();
  const testUrl = randomChoice(SAMPLE_URLS);

  // If requested, start inspection to produce dynamic server-side state transitions
  if (triggerCheckUrl) {
    const payload = JSON.stringify({
      url: testUrl,
      sessionId: sessionId,
    });

    http.asyncRequest('POST', ENDPOINTS.CHECK_URL, payload, {
      headers: DEFAULT_HEADERS,
      tags: { scenario: scenarioTag, endpoint: 'check_url_async' },
      timeout: '15s',
    });
  }

  // Realistic polling loop matching frontend setInterval (350ms in App.jsx)
  let pollCount = 0;
  let complete = false;

  for (let i = 0; i < maxPolls; i++) {
    pollCount++;
    const pollResult = pollProgress(sessionId, {
      scenario: scenarioTag,
      poll_index: String(i + 1),
    });

    if (pollResult.isComplete) {
      complete = true;
      break;
    }

    // Realistic frontend interval think time (250ms - 450ms)
    randomSleep(TIMINGS.POLL_INTERVAL_MIN, TIMINGS.POLL_INTERVAL_MAX);
  }

  workflowPollIterations.add(pollCount, { scenario: scenarioTag });

  return {
    sessionId,
    pollCount,
    complete,
  };
}
