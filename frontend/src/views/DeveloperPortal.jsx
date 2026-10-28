import React, { useState, useEffect } from 'react'
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
} from '@phosphor-icons/react'

export function DeveloperPortal({ onBackToInspector }) {
  const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')
  const [keys, setKeys] = useState([])
  const [newKeyName, setNewKeyName] = useState('')
  const [justCreatedSecret, setJustCreatedSecret] = useState(null)
  const [copiedKey, setCopiedKey] = useState(null)
  const [error, setError] = useState('')
  const [selectedKeyId, setSelectedKeyId] = useState(null)
  const [usageStats, setUsageStats] = useState(null)

  // Fetch keys on mount
  useEffect(() => {
    let ignore = false
    async function initKeys() {
      try {
        const res = await fetch(`${apiBaseUrl}/api/v1/keys/`)
        const data = await res.json()
        if (!ignore && res.ok && data.keys) {
          setKeys(data.keys)
          if (data.keys.length > 0) {
            setSelectedKeyId(data.keys[0]._id)
          }
        }
      } catch {
        if (!ignore) setError('Could not connect to API server.')
      }
    }
    initKeys()
    return () => { ignore = true }
  }, [apiBaseUrl])

  // Fetch usage stats when selected key changes
  useEffect(() => {
    if (!selectedKeyId) return
    let ignore = false
    async function loadUsage() {
      try {
        const res = await fetch(`${apiBaseUrl}/api/v1/usage/?keyId=${selectedKeyId}`)
        const data = await res.json()
        if (!ignore && res.ok) {
          setUsageStats(data)
        }
      } catch {
        // Graceful error ignore
      }
    }
    loadUsage()
    return () => { ignore = true }
  }, [apiBaseUrl, selectedKeyId])

  async function reloadKeys() {
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/keys/`)
      const data = await res.json()
      if (res.ok && data.keys) {
        setKeys(data.keys)
      }
    } catch {
      setError('Could not connect to API server.')
    }
  }

  async function handleCreateKey(e) {
    e.preventDefault()
    if (!newKeyName.trim()) return
    setError('')

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/keys/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName.trim() }),
      })
      const data = await res.json()
      if (res.ok) {
        setJustCreatedSecret(data.rawSecret)
        setNewKeyName('')
        reloadKeys()
        if (data.key && data.key._id) {
          setSelectedKeyId(data.key._id)
        }
      } else {
        setError(data.error || 'Failed to create API key.')
      }
    } catch {
      setError('Network communication failed.')
    }
  }

  async function handleRevokeKey(keyId) {
    if (!window.confirm('Are you sure you want to revoke this API key? This cannot be undone.')) {
      return
    }

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/keys/${keyId}/`, {
        method: 'DELETE',
      })
      if (res.ok) {
        reloadKeys()
        if (selectedKeyId === keyId) {
          setSelectedKeyId(null)
          setUsageStats(null)
        }
      }
    } catch {
      setError('Could not revoke key.')
    }
  }

  function handleCopy(text, key) {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const curlSnippet = `curl -X POST https://zeb.security/api/v1/scan \\
  -H "X-API-Key: ${justCreatedSecret || 'zeb_live_your_api_key_here'}" \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://suspicious-target.xyz/login"}'`

  const pythonSnippet = `import requests

headers = {
    "X-API-Key": "${justCreatedSecret || 'zeb_live_your_api_key_here'}",
    "Content-Type": "application/json"
}

payload = {"url": "https://suspicious-target.xyz/login"}
response = requests.post("https://zeb.security/api/v1/scan", headers=headers, json=payload)
print(response.json())`

  return (
    <div className="dev-portal-shell">
      {/* Top Bar with Back Button */}
      <div className="dev-portal-top-bar">
        <button
          type="button"
          className="mech-btn dev-back-btn"
          onClick={onBackToInspector}
        >
          <ArrowLeft size={14} weight="bold" />
          <span>Return to URL Inspector</span>
        </button>

        <span className="dev-portal-badge">
          <TerminalWindow size={14} weight="bold" />
          <span>DEVELOPER API PLATFORM</span>
        </span>
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

      {/* Quota & Usage Overview */}
      <div className="dev-metrics-grid">
        <div className="metric-tile">
          <span className="metric-tile-label">Daily Quota</span>
          <span className="metric-tile-value">
            {usageStats?.todayCount ?? 0} / 1,000 reqs
          </span>
          <span className="metric-tile-label" style={{ marginTop: 4 }}>Resets at 00:00 UTC</span>
        </div>

        <div className="metric-tile">
          <span className="metric-tile-label">Burst Limit</span>
          <span className="metric-tile-value">60 req / min</span>
          <span className="metric-tile-label" style={{ marginTop: 4 }}>High-Speed Window</span>
        </div>

        <div className="metric-tile">
          <span className="metric-tile-label">Active API Keys</span>
          <span className="metric-tile-value">{keys.length}</span>
          <span className="metric-tile-label" style={{ marginTop: 4 }}>Cryptographically Hashed</span>
        </div>

        <div className="metric-tile">
          <span className="metric-tile-label">Storage Retention</span>
          <span className="metric-tile-value">30 Days</span>
          <span className="metric-tile-label" style={{ marginTop: 4 }}>MongoDB Native TTL</span>
        </div>
      </div>

      {/* Key Generation & Key List */}
      <div className="dev-section-block">
        <div className="dev-section-header">
          <div className="dev-section-title">
            <Key size={16} weight="bold" />
            <h3>Your API Keys</h3>
          </div>

          <form className="create-key-form" onSubmit={handleCreateKey}>
            <input
              type="text"
              className="url-input-field key-input-field"
              placeholder="Key Name (e.g. Production CI/CD)"
              value={newKeyName}
              onChange={e => setNewKeyName(e.target.value)}
            />
            <button type="submit" className="mech-btn mech-btn-primary" disabled={!newKeyName.trim()}>
              <Plus size={14} weight="bold" />
              <span>Create Key</span>
            </button>
          </form>
        </div>

        {/* Keys Table */}
        {keys.length > 0 ? (
          <div className="dev-keys-table-wrap">
            <table className="dev-keys-table">
              <thead>
                <tr>
                  <th>NAME</th>
                  <th>KEY PREFIX</th>
                  <th>RATE LIMIT</th>
                  <th>DAILY QUOTA</th>
                  <th>CREATED</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {keys.map(k => (
                  <tr key={k._id} className={selectedKeyId === k._id ? 'selected-row' : ''}>
                    <td className="key-name-cell">
                      <button
                        type="button"
                        className="key-select-btn"
                        onClick={() => setSelectedKeyId(k._id)}
                      >
                        {k.name}
                      </button>
                    </td>
                    <td><code>{k.key_prefix}...</code></td>
                    <td>{k.rate_limit_per_minute || 60}/min</td>
                    <td>{k.daily_quota || 1000}/day</td>
                    <td>{new Date(k.created_at).toLocaleDateString()}</td>
                    <td>
                      <button
                        type="button"
                        className="mech-btn revoke-btn"
                        onClick={() => handleRevokeKey(k._id)}
                        title="Revoke API Key"
                      >
                        <Trash size={12} weight="bold" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="no-keys-lead">
            No active API keys found. Generate a key above to start scanning.
          </p>
        )}
      </div>

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
