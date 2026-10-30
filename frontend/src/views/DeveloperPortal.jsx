import React, { useState, useEffect, useRef, useCallback } from 'react'
import {
  Key,
  Plus,
  Trash,
  Copy,
  Check,
  Code,
  ShieldCheck,
  ArrowLeft,
  WarningCircle,
  TerminalWindow,
  GoogleLogo,
  SignOut,
  User,
  Lock,
  ChartLineUp,
  Lightning,
  Clock,
} from '@phosphor-icons/react'

export function DeveloperPortal({ onBackToInspector }) {
  const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')
  const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || ''

  const [authToken, setAuthToken] = useState(() => localStorage.getItem('zeb-auth-token') || null)
  const [user, setUser] = useState(null)
  const [loadingAuth, setLoadingAuth] = useState(true)
  const [keys, setKeys] = useState([])
  const [newKeyName, setNewKeyName] = useState('')
  const [justCreatedSecret, setJustCreatedSecret] = useState(null)
  const [copiedKey, setCopiedKey] = useState(null)
  const [error, setError] = useState('')
  const [usageStats, setUsageStats] = useState(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const googleBtnRef = useRef(null)

  // Fetch current user and active keys
  const loadUserData = useCallback(async (token) => {
    if (!token) {
      setUser(null)
      setKeys([])
      setUsageStats(null)
      setLoadingAuth(false)
      return
    }

    try {
      setLoadingAuth(true)
      const res = await fetch(`${apiBaseUrl}/api/v1/auth/me/`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (res.ok) {
        const data = await res.json()
        setUser(data.user)
        setKeys(data.activeKey ? [data.activeKey] : [])
        setUsageStats(data.analytics)
        setError('')
      } else if (res.status === 401) {
        localStorage.removeItem('zeb-auth-token')
        setAuthToken(null)
        setUser(null)
        setKeys([])
        setUsageStats(null)
      } else {
        setError('Failed to load developer profile.')
      }
    } catch {
      setError('Network communication failed while verifying session.')
    } finally {
      setLoadingAuth(false)
    }
  }, [apiBaseUrl])

  useEffect(() => {
    loadUserData(authToken)
  }, [authToken, loadUserData])

  // Handle Google OAuth Credential response
  const handleGoogleCredential = useCallback(async (response) => {
    if (!response || !response.credential) return
    setIsSubmitting(true)
    setError('')

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/auth/google/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken: response.credential }),
      })

      const data = await res.json()
      if (res.ok && data.accessToken) {
        localStorage.setItem('zeb-auth-token', data.accessToken)
        setAuthToken(data.accessToken)
        setUser(data.user)
        await loadUserData(data.accessToken)
      } else {
        setError(data.error || 'Google authentication failed.')
      }
    } catch {
      setError('Network error during Google sign-in.')
    } finally {
      setIsSubmitting(false)
    }
  }, [apiBaseUrl, loadUserData])

  // Dev mock login for local testing
  const handleMockLogin = async () => {
    setIsSubmitting(true)
    setError('')
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/auth/google/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken: 'mock_developer_user' }),
      })
      const data = await res.json()
      if (res.ok && data.accessToken) {
        localStorage.setItem('zeb-auth-token', data.accessToken)
        setAuthToken(data.accessToken)
        setUser(data.user)
        await loadUserData(data.accessToken)
      } else {
        setError(data.error || 'Mock login failed.')
      }
    } catch {
      setError('Network error during mock sign-in.')
    } finally {
      setIsSubmitting(false)
    }
  }

  // Initialize GIS button
  useEffect(() => {
    if (user || !googleClientId) return

    function renderGis() {
      if (window.google?.accounts?.id && googleBtnRef.current) {
        try {
          window.google.accounts.id.initialize({
            client_id: googleClientId,
            callback: handleGoogleCredential,
          })
          window.google.accounts.id.renderButton(googleBtnRef.current, {
            theme: 'outline',
            size: 'large',
            type: 'standard',
            shape: 'rectangular',
            text: 'signin_with',
            width: 260,
          })
        } catch (e) {
          console.error('GIS initialization error:', e)
        }
      }
    }

    const interval = setInterval(() => {
      if (window.google?.accounts?.id) {
        renderGis()
        clearInterval(interval)
      }
    }, 200)

    return () => clearInterval(interval)
  }, [user, googleClientId, handleGoogleCredential])

  const handleSignOut = () => {
    localStorage.removeItem('zeb-auth-token')
    setAuthToken(null)
    setUser(null)
    setKeys([])
    setUsageStats(null)
    setJustCreatedSecret(null)
    setError('')
  }

  // Create API Key (Enforces 1 key limit)
  const handleCreateKey = async (e) => {
    e.preventDefault()
    if (!authToken || keys.length >= 1) return
    setIsSubmitting(true)
    setError('')

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/keys/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({ name: newKeyName.trim() || 'Default API Key' }),
      })

      const data = await res.json()
      if (res.ok) {
        setJustCreatedSecret(data.rawSecret)
        setNewKeyName('')
        await loadUserData(authToken)
      } else {
        setError(data.error || 'Failed to create API key.')
      }
    } catch {
      setError('Network communication failed.')
    } finally {
      setIsSubmitting(false)
    }
  }

  // Revoke API Key
  const handleRevokeKey = async (keyId) => {
    if (!window.confirm('Are you sure you want to revoke your API key? This action is permanent and will immediately invalidate the key.')) {
      return
    }

    setError('')
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/keys/${keyId}/`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${authToken}`,
        },
      })

      if (res.ok) {
        setJustCreatedSecret(null)
        await loadUserData(authToken)
      } else {
        const data = await res.json()
        setError(data.error || 'Could not revoke key.')
      }
    } catch {
      setError('Could not revoke key.')
    }
  }

  const handleCopy = (text, key) => {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const activeKey = keys.length > 0 ? keys[0] : null
  const displaySecret = justCreatedSecret || (activeKey ? `${activeKey.key_prefix}...` : 'zeb_live_your_api_key_here')

  const curlSnippet = `curl -X POST https://zeb.security/api/v1/scan \\
  -H "X-API-Key: ${displaySecret}" \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://suspicious-target.xyz/login"}'`

  const pythonSnippet = `import requests

headers = {
    "X-API-Key": "${displaySecret}",
    "Content-Type": "application/json"
}

payload = {"url": "https://suspicious-target.xyz/login"}
response = requests.post("https://zeb.security/api/v1/scan", headers=headers, json=payload)
print(response.json())`

  const todayCount = usageStats?.todayCount ?? 0
  const dailyQuota = 1000
  const quotaPercent = Math.min(100, Math.round((todayCount / dailyQuota) * 100))

  return (
    <div className="dev-portal-shell">
      {/* Top Bar with Back Button, Platform Badge, and User Session */}
      <div className="dev-portal-top-bar">
        <button
          type="button"
          className="mech-btn dev-back-btn"
          onClick={onBackToInspector}
        >
          <ArrowLeft size={14} weight="bold" />
          <span>Return to URL Inspector</span>
        </button>

        <div className="dev-top-actions">
          <span className="dev-portal-badge">
            <TerminalWindow size={14} weight="bold" />
            <span>DEVELOPER API PLATFORM</span>
          </span>

          {user && (
            <div className="dev-user-chip">
              {user.picture ? (
                <img src={user.picture} alt={user.name || 'User'} className="dev-user-avatar" />
              ) : (
                <User size={14} weight="bold" />
              )}
              <span className="dev-user-name">{user.name || user.email}</span>
              <button
                type="button"
                className="mech-btn dev-signout-btn"
                onClick={handleSignOut}
                title="Sign out of developer account"
              >
                <SignOut size={12} weight="bold" />
                <span>Sign Out</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Hero */}
      <section className="cardless-hero-section">
        <h1 className="hero-headline">ZEB Developer API & Usage</h1>
        <p className="hero-lead-text">
          Integrate ZEB's proprietary zero-trust URL security heuristics directly into your SOC pipelines, SIEM ingest, Slack bots, and build processes.
        </p>
      </section>

      {/* Third-Party Service Isolation Banner */}
      <div className="threat-module" style={{ background: 'var(--bg-inset)', borderColor: 'var(--border-muted)', borderLeftColor: 'var(--border-primary)' }}>
        <div className="threat-module-title" style={{ color: 'var(--text-primary)' }}>
          <ShieldCheck size={16} weight="bold" />
          <span>Third-Party Isolation Guarantee</span>
        </div>
        <p className="threat-explanation" style={{ color: 'var(--text-secondary)' }}>
          The Developer API endpoint (<code>POST /api/v1/scan</code>) provides programmatic access exclusively to ZEB's proprietary analytical engines (Dword IP decoding, homograph TR39 skeletons, Web3 drainer sniffer, and Fast-Flux DNS). Commercial third-party threat feeds are strictly excluded.
        </p>
      </div>

      {/* Just Created Secret Notification */}
      {justCreatedSecret && (
        <div className="threat-module" style={{ background: 'var(--risk-warn-bg)', borderColor: 'var(--risk-warn-border)', borderLeftColor: 'var(--risk-warn-accent)' }}>
          <div className="threat-module-title" style={{ color: 'var(--risk-warn-text)' }}>
            <Key size={16} weight="bold" />
            <span>New Live API Key Generated</span>
          </div>
          <p className="threat-explanation" style={{ color: 'var(--risk-warn-text)', marginBottom: 10 }}>
            Make sure to copy your API key now. You will not be able to see it again!
          </p>
          <div className="target-url-console" style={{ background: 'var(--bg-page)' }}>
            <code className="target-url-code" style={{ color: 'var(--text-primary)' }}>{justCreatedSecret}</code>
            <button
              type="button"
              className={`copy-mini-btn ${copiedKey === 'new-secret' ? 'copied' : ''}`}
              onClick={() => handleCopy(justCreatedSecret, 'new-secret')}
            >
              {copiedKey === 'new-secret' ? <><Check size={12} weight="bold" /> Copied</> : <><Copy size={12} weight="bold" /> Copy Key</>}
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="threat-module" role="alert">
          <div className="threat-module-title">
            <WarningCircle size={16} weight="bold" />
            <span>Error</span>
          </div>
          <p className="threat-explanation">{error}</p>
        </div>
      )}

      {/* Unauthenticated View: Google Sign-In & Policy Gate */}
      {!user && !loadingAuth && (
        <div className="dev-auth-gate-card">
          <div className="dev-auth-gate-icon">
            <Lock size={32} weight="bold" />
          </div>
          <h2 className="dev-auth-gate-title">Google Developer Authentication Required</h2>
          <p className="dev-auth-gate-desc">
            To prevent automated abuse, protect infrastructure, and provide real-time usage metrics, API keys are provisioned exclusively to authenticated developers.
          </p>

          <div className="dev-policy-grid">
            <div className="dev-policy-item">
              <div className="dev-policy-item-title">
                <Key size={14} weight="bold" />
                <span>Single Key Policy</span>
              </div>
              <div className="dev-policy-item-desc">
                Maximum 1 active key per account. Revoke and rotate anytime with zero downtime.
              </div>
            </div>

            <div className="dev-policy-item">
              <div className="dev-policy-item-title">
                <Clock size={14} weight="bold" />
                <span>1,000 Reqs / Day</span>
              </div>
              <div className="dev-policy-item-desc">
                Generous daily automated scan quota. Resets every night at 00:00 UTC.
              </div>
            </div>

            <div className="dev-policy-item">
              <div className="dev-policy-item-title">
                <Lightning size={14} weight="bold" />
                <span>5 Reqs / Min Burst</span>
              </div>
              <div className="dev-policy-item-desc">
                Sustained burst rate limit for reliable analysis without queuing timeouts.
              </div>
            </div>

            <div className="dev-policy-item">
              <div className="dev-policy-item-title">
                <ShieldCheck size={14} weight="bold" />
                <span>Zero Feed Leakage</span>
              </div>
              <div className="dev-policy-item-desc">
                Proprietary heuristics only. Target URLs are never submitted to public feeds.
              </div>
            </div>
          </div>

          <div className="dev-signin-container">
            {googleClientId ? (
              <div ref={googleBtnRef} id="google-signin-btn" />
            ) : null}

            {/* Dev Mock Sign-In fallback for local development or when client ID is unset */}
            {(!googleClientId || import.meta.env.DEV) && (
              <div className="dev-mock-signin-box">
                <button
                  type="button"
                  className="mech-btn mech-btn-primary"
                  onClick={handleMockLogin}
                  disabled={isSubmitting}
                >
                  <GoogleLogo size={14} weight="bold" />
                  <span>{isSubmitting ? 'Authenticating...' : 'Sign In with Google (Dev Mock)'}</span>
                </button>
                <span className="dev-mock-signin-hint">
                  Local development mode: test mock account without credentials
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Authenticated Developer Dashboard */}
      {user && (
        <>
          {/* Quota & Usage Overview */}
          <div className="dev-metrics-grid">
            <div className="metric-tile">
              <span className="metric-tile-label">Daily Quota</span>
              <span className="metric-tile-value">
                {todayCount} / 1,000 reqs
              </span>
              <div className="dev-quota-progress-container">
                <div
                  className={`dev-quota-progress-fill ${quotaPercent > 90 ? 'danger' : quotaPercent > 70 ? 'warn' : ''}`}
                  style={{ width: `${quotaPercent}%` }}
                />
              </div>
              <span className="metric-tile-label" style={{ marginTop: 4 }}>
                {1000 - todayCount} remaining • Resets 00:00 UTC
              </span>
            </div>

            <div className="metric-tile">
              <span className="metric-tile-label">Burst Rate Limit</span>
              <span className="metric-tile-value">5 req / min</span>
              <span className="metric-tile-label" style={{ marginTop: 4 }}>Controlled Window</span>
            </div>

            <div className="metric-tile">
              <span className="metric-tile-label">Active API Key</span>
              <span className="metric-tile-value">{keys.length} / 1 Active</span>
              <span className="metric-tile-label" style={{ marginTop: 4 }}>Strict Single Key Limit</span>
            </div>

            <div className="metric-tile">
              <span className="metric-tile-label">Authenticated Account</span>
              <span className="metric-tile-value" style={{ fontSize: '0.875rem', wordBreak: 'break-all' }}>
                {user.email}
              </span>
              <span className="metric-tile-label" style={{ marginTop: 4 }}>Verified Google Identity</span>
            </div>
          </div>

          {/* Key Management Card */}
          <div className="dev-section-block">
            <div className="dev-section-header">
              <div className="dev-section-title">
                <Key size={16} weight="bold" />
                <h3>Your API Key</h3>
              </div>

              {keys.length === 0 && (
                <form className="create-key-form" onSubmit={handleCreateKey}>
                  <input
                    type="text"
                    className="url-input-field key-input-field"
                    placeholder="Key Name (e.g. Production Pipeline)"
                    value={newKeyName}
                    onChange={e => setNewKeyName(e.target.value)}
                    disabled={isSubmitting}
                  />
                  <button
                    type="submit"
                    className="mech-btn mech-btn-primary"
                    disabled={isSubmitting || !newKeyName.trim()}
                  >
                    <Plus size={14} weight="bold" />
                    <span>Generate Key</span>
                  </button>
                </form>
              )}
            </div>

            {activeKey ? (
              <div className="dev-key-card">
                <div className="dev-key-card-header">
                  <div>
                    <strong style={{ color: 'var(--text-primary)', marginRight: 8 }}>{activeKey.name}</strong>
                    <span className="dev-key-tag">ACTIVE</span>
                  </div>
                  <button
                    type="button"
                    className="mech-btn revoke-btn"
                    onClick={() => handleRevokeKey(activeKey._id)}
                    title="Revoke API Key"
                  >
                    <Trash size={12} weight="bold" />
                    <span>Revoke Key</span>
                  </button>
                </div>

                <div className="dev-key-meta-grid">
                  <div className="dev-key-meta-item">
                    <span className="dev-key-meta-label">Key Prefix</span>
                    <span className="dev-key-meta-val"><code>{activeKey.key_prefix}...</code></span>
                  </div>
                  <div className="dev-key-meta-item">
                    <span className="dev-key-meta-label">Daily Quota</span>
                    <span className="dev-key-meta-val">{activeKey.daily_quota || 1000} req/day</span>
                  </div>
                  <div className="dev-key-meta-item">
                    <span className="dev-key-meta-label">Rate Limit</span>
                    <span className="dev-key-meta-val">{activeKey.rate_limit_per_minute || 5} req/min</span>
                  </div>
                  <div className="dev-key-meta-item">
                    <span className="dev-key-meta-label">Created</span>
                    <span className="dev-key-meta-val">{new Date(activeKey.created_at).toLocaleDateString()}</span>
                  </div>
                </div>

                <div className="dev-key-warning-notice">
                  <strong>Policy Reminder:</strong> You have reached your limit of 1 active API key. To generate a new key or rotate credentials, revoke your current active key.
                </div>
              </div>
            ) : (
              <p className="no-keys-lead">
                No active API key found. Enter a name above and click <strong>Generate Key</strong> to provision your 1 active key.
              </p>
            )}
          </div>

          {/* Real-time Usage Telemetry */}
          <div className="dev-section-block">
            <div className="dev-section-title" style={{ marginBottom: 12 }}>
              <ChartLineUp size={16} weight="bold" />
              <h3>Recent Scan Activity & Telemetry</h3>
            </div>

            {usageStats?.recentLogs && usageStats.recentLogs.length > 0 ? (
              <div className="dev-keys-table-wrap">
                <table className="dev-keys-table">
                  <thead>
                    <tr>
                      <th>TARGET URL</th>
                      <th>STATUS</th>
                      <th>LATENCY</th>
                      <th>TIMESTAMP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {usageStats.recentLogs.map((log, idx) => (
                      <tr key={idx}>
                        <td><code>{log.target_url || '—'}</code></td>
                        <td>
                          <span style={{
                            color: log.response_status === 200 ? 'var(--risk-safe-text, #10b981)' : 'var(--risk-danger-text)',
                            fontWeight: 700,
                          }}>
                            {log.response_status}
                          </span>
                        </td>
                        <td>{log.latency_ms} ms</td>
                        <td>{new Date(log.timestamp).toLocaleTimeString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="no-keys-lead">
                No scan requests logged today yet. Use the code snippet below with your API key to perform automated scans.
              </p>
            )}
          </div>
        </>
      )}

      {/* Integration Quickstart */}
      <div className="dev-section-block">
        <div className="dev-section-title" style={{ marginBottom: 12 }}>
          <Code size={16} weight="bold" />
          <h3>Integration Quickstart</h3>
        </div>

        <div className="quickstart-tabs">
          <div className="quickstart-code-box">
            <div className="code-box-header">
              <span>cURL</span>
              <button
                type="button"
                className="copy-mini-btn"
                onClick={() => handleCopy(curlSnippet, 'curl')}
              >
                {copiedKey === 'curl' ? <><Check size={12} weight="bold" /> Copied</> : <><Copy size={12} weight="bold" /> Copy</>}
              </button>
            </div>
            <pre className="code-pre"><code>{curlSnippet}</code></pre>
          </div>

          <div className="quickstart-code-box" style={{ marginTop: 12 }}>
            <div className="code-box-header">
              <span>Python (requests)</span>
              <button
                type="button"
                className="copy-mini-btn"
                onClick={() => handleCopy(pythonSnippet, 'python')}
              >
                {copiedKey === 'python' ? <><Check size={12} weight="bold" /> Copied</> : <><Copy size={12} weight="bold" /> Copy</>}
              </button>
            </div>
            <pre className="code-pre"><code>{pythonSnippet}</code></pre>
          </div>
        </div>
      </div>
    </div>
  )
}
