import { useState } from 'react'
import './App.css'

function App() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

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
        <h1>URL Safety Checker</h1>
        <p className="subtitle">
          Enter a URL and the backend will check it via Google Safe Browsing.
        </p>

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
          </div>
        )}
      </section>
    </main>
  )
}

export default App
