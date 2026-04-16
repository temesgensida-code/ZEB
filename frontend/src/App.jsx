import { useState } from 'react'
import './App.css'
import { IoInformationCircleOutline } from "react-icons/io5";

function App() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [showInfo, setShowInfo] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    setResult(null)

    if (!url.trim()) {
      setError('Please enter a URL to check.')
      return
    }

    setLoading(true)

    try {
      const response = await fetch('/api/check-url/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      })

      const data = await response.json()

      if (!response.ok) {
        setError(data.error || 'Could not check URL safety.')
        return
      }

      setResult(data)
    } catch {
      setError('Network error while calling the backend API.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="page">
      <section className="card">
        <h1>ZEB</h1>
        <h3>URL Safety Checker</h3>
        <p className="subtitle">
          Enter a URL and the backend will check it via Google Safe Browsing.
        </p>

        <button
          type="button"
          className="info-toggle"
          onClick={() => setShowInfo((current) => !current)}
          aria-expanded={showInfo}
          aria-label={showInfo ? 'Hide checks info' : 'Show checks info'}
          title={showInfo ? 'Hide checks info' : 'Show checks info'}
        >
          <IoInformationCircleOutline />
        </button>

        {showInfo && (
          <div className="info-panel">
            <h2>What This Checker Tests</h2>
            <ul>
              <li>Google Safe Browsing threat matches (malware, phishing, unwanted software)</li>
              <li>URL structure risks (IP-based links, suspicious TLDs, typosquatting patterns)</li>
              <li>Domain age from WHOIS (newly registered domains are higher risk)</li>
              <li>Redirect chain risks (too many redirects or suspicious redirect hops)</li>
              <li>Sandbox HTML preview with no JavaScript execution</li>
              <li>Suspicious login form patterns and high-pressure phishing keywords</li>
              <li>Suspicious script sources and script obfuscation-like patterns</li>
            </ul>
            <p className="assurance-note">
              Important: We cannot guarantee 100% assurance for any URL. Malicious sites can
              constantly change strategy and evade automated checks.
            </p>
          </div>
        )}

        <form className="checker-form" onSubmit={handleSubmit}>
          <input
            type="text"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="example.com or https://example.com"
            aria-label="URL to check"
          />
          <button type="submit" disabled={loading}>
            {loading ? 'Checking...' : 'Check URL'}
          </button>
        </form>

        {error && <p className="message error">{error}</p>}

        {result && (
          <div className={`result ${result.unsafe ? 'unsafe' : 'unsure'}`}>
            <p>
              <strong>URL:</strong> {result.url}
            </p>
            <p>
              <strong>Status:</strong> {result.verdict || 'UNSURE'}
            </p>
            <p>{result.message}</p>
            {result.unsafe && result.threats?.length > 0 && (
              <ul>
                {result.threats.map((threat, index) => (
                  <li key={`${threat.threatType}-${index}`}>
                    {threat.threatType} ({threat.platformType})
                  </li>
                ))}
              </ul>
            )}

            {result.structureAnalysis && (
              <div className="analysis-block">
                <h2>URL Structure Analysis</h2>
                <p>
                  <strong>Host:</strong> {result.structureAnalysis.hostname || 'N/A'}
                </p>
                <p>
                  <strong>Registered Domain:</strong>{' '}
                  {result.structureAnalysis.registeredDomain || 'N/A'}
                </p>
                <p>
                  <strong>Domain (Full):</strong>{' '}
                  {result.structureAnalysis.registeredDomainFull || 'N/A'}
                </p>
                <p>
                  <strong>TLD:</strong> {result.structureAnalysis.tld || 'N/A'}
                </p>
                <p>
                  <strong>Domain Age:</strong>{' '}
                  {result.structureAnalysis.domainAge?.available
                    ? `${result.structureAnalysis.domainAge.domainAgeDays} days`
                    : 'Unavailable'}
                </p>
                <p>
                  <strong>New Domain Risk:</strong>{' '}
                  {result.structureAnalysis.domainAge?.isNewDomain
                    ? 'Yes (higher risk)'
                    : result.structureAnalysis.domainAge?.isNewDomain === false
                      ? 'No'
                      : 'Unknown'}
                </p>
                <ul>
                  {result.structureAnalysis.findings?.map((finding, index) => (
                    <li key={`${finding.type}-${index}`}>
                      <strong>{finding.flagged ? 'Suspicious:' : 'Note:'}</strong>{' '}
                      {finding.explanation}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </section>
    </main>
  )
}

export default App
