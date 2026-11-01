/**
 * Global Configuration for k6 Performance Testing Suite
 *
 * Configurable via environment variables (e.g., -e BASE_URL=http://localhost:8000)
 */

export const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8000';

export const ENDPOINTS = {
  CHECK_PROGRESS: `${BASE_URL}/api/check-progress/`,
  CHECK_URL: `${BASE_URL}/api/check-url/`,
};

export const DEFAULT_HEADERS = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
  'User-Agent': 'k6-performance-suite/1.0 (ZEB Security Scanner Benchmarking)',
};

export const SAMPLE_URLS = [
  'https://github.com',
  'https://www.google.com',
  'https://bit.ly/3xSecurityDemo',
  'http://192.168.1.1/admin',
  'https://example.com/test-path?param=safe',
];

export const TIMINGS = {
  POLL_INTERVAL_MIN: 0.25, // 250ms simulated frontend polling
  POLL_INTERVAL_MAX: 0.50, // 500ms simulated frontend polling
  USER_THINK_TIME_MIN: 1.0,
  USER_THINK_TIME_MAX: 3.0,
};
