import React, { useState } from 'react'
import { ShareNetwork, Warning, ShieldCheck, ShieldWarning } from '@phosphor-icons/react'
import { parseAndClassifyTokens } from '../utils/urlTokenizer'

/**
 * Interactive Link Dissector (URL Anatomy Breakdown - Pillar 6.1)
 * Deconstructs raw URLs into typed semantic tokens with interactive threat popovers.
 */
export function LinkDissector({ url, structureAnalysis }) {
  const [activeTokenIdx, setActiveTokenIdx] = useState(null)
  const tokens = parseAndClassifyTokens(url, structureAnalysis)

  if (!tokens || tokens.length === 0) {
    return null
  }

  const hasDeceptiveToken = tokens.some(t => t.isDeceptive || t.riskLevel === 'danger')

  return (
    <div className="link-dissector-card">
      <div className="dissector-header-row">
        <div className="dissector-title-lockup">
          <ShareNetwork size={16} weight="bold" />
          <span className="dissector-heading">Interactive Link Dissector</span>
          <span className="dissector-tag">URL ANATOMY BREAKDOWN</span>
        </div>
        <div className="dissector-status-hint">
          {hasDeceptiveToken ? (
            <span className="hint-danger">
              <ShieldWarning size={14} weight="bold" /> Deceptive segments detected
            </span>
          ) : (
            <span className="hint-safe">
              <ShieldCheck size={14} weight="bold" /> Clean URL structure
            </span>
          )}
        </div>
      </div>

      <p className="dissector-subtext">
        Click or hover any segment to inspect why attackers structure each component and reveal hidden spoofing lures.
      </p>

      {/* Dissector Rail */}
      <div className="token-rail-container" role="region" aria-label="Deconstructed URL tokens">
        <div className="token-rail">
          {tokens.map((tok, idx) => {
            const isActive = activeTokenIdx === idx
            return (
              <div
                key={idx}
                className={`token-pill token-${tok.riskLevel} ${tok.isDeceptive ? 'pulse-deceptive' : ''} ${isActive ? 'token-active' : ''}`}
                onMouseEnter={() => setActiveTokenIdx(idx)}
                onMouseLeave={() => setActiveTokenIdx(null)}
                onClick={() => setActiveTokenIdx(isActive ? null : idx)}
                tabIndex={0}
                role="button"
                aria-expanded={isActive}
                aria-label={`${tok.label}: ${tok.rawText}`}
              >
                <span className="token-raw-text">{tok.rawText}</span>
                <span className="token-type-pill">{tok.label}</span>

                {/* Popover */}
                {isActive && (
                  <div className={`token-popover-flyout flyout-${tok.riskLevel}`} role="tooltip">
                    <div className="popover-header">
                      {tok.riskLevel === 'danger' && <Warning size={14} weight="bold" />}
                      <strong>{tok.label}</strong>
                    </div>
                    <p className="popover-body">{tok.explanation}</p>
                    {tok.isDeceptive && (
                      <div className="popover-warning-bar">
                        ATTACK VECTOR: Visual deception intended to masquerade as trusted entity.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
