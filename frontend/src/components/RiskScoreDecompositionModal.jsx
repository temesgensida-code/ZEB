import React, { useEffect, useMemo } from 'react'
import {
  X,
  ChartLineUp,
  ShieldCheck,
  ShieldWarning,
  ShieldSlash,
  Calculator,
  ArrowRight,
  Info,
  CheckCircle,
  WarningCircle,
} from '@phosphor-icons/react'
import { decomposeRiskScore } from '../utils/riskDecomposer'

export function RiskScoreDecompositionModal({
  isOpen = true,
  result,
  onClose,
  onOpenExplainer,
}) {
  useEffect(() => {
    if (!isOpen) return

    function handleKeyDown(e) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  const decomposition = useMemo(() => decomposeRiskScore(result), [result])
  const score = decomposition.compositeScore
  const isHigh = score >= 60
  const isMed = score >= 30 && score < 60
  const severityLabel = score >= 80 ? 'CRITICAL RISK' : isHigh ? 'HIGH RISK' : isMed ? 'MEDIUM RISK' : score > 0 ? 'LOW RISK' : 'CLEAN'
  const severityColor = isHigh ? 'var(--risk-danger-accent)' : isMed ? 'var(--risk-warn-accent)' : 'var(--risk-safe-accent)'

  if (!isOpen) return null

  return (
    <div
      className="modal-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="decomp-modal-title"
    >
      <div
        className="modal-dialog risk-decomposition-dialog"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="modal-header-section">
          <div className="modal-title-lockup">
            <Calculator size={20} weight="bold" />
            <div>
              <h2 id="decomp-modal-title" className="modal-heading-text">
                Risk Score Mathematical Decomposition
              </h2>
              <span className="sandbox-isolation-badge">
                HEURISTIC POINT ATTRIBUTION LEDGER V2.4
              </span>
            </div>
          </div>
          <button
            type="button"
            className="mech-btn modal-close-btn"
            onClick={onClose}
            aria-label="Close modal"
          >
            <X size={16} weight="bold" />
          </button>
        </div>

        <div className="modal-body-section">
          {/* Formula & Composite Score Banner */}
          <div className="decomp-formula-card">
            <div className="decomp-score-hero">
              <div className="decomp-score-number" style={{ color: severityColor }}>
                {score}
                <span className="decomp-score-denom">/100</span>
              </div>
              <span
                className="decomp-severity-pill"
                style={{
                  color: severityColor,
                  borderColor: severityColor,
                }}
              >
                {severityLabel}
              </span>
            </div>

            <div className="decomp-formula-details">
              <div className="formula-equation-row">
                <span className="formula-label">COMPUTATION FORMULA:</span>
                <code className="formula-code">
                  Score = Min(100, Base [0] + Σ Active Deductions [{decomposition.activePointsTotal} pts])
                </code>
              </div>
              <div className="formula-stats-row">
                <span className="formula-stat-item">
                  <strong>{decomposition.activeRuleCount}</strong> Active Violations
                </span>
                <span className="formula-stat-sep">|</span>
                <span className="formula-stat-item">
                  <strong>{decomposition.totalRulesAudited}</strong> Heuristic Rules Audited
                </span>
                <span className="formula-stat-sep">|</span>
                <span className="formula-stat-item">
                  Clamped Result: <strong>{score} / 100</strong>
                </span>
              </div>
            </div>
          </div>

          {/* Active Violations Ledger */}
          <div className="decomp-section-group">
            <div className="decomp-section-header">
              <WarningCircle size={15} weight="bold" />
              <span>Active Point Deductions Applied ({decomposition.activeRuleCount})</span>
            </div>

            {decomposition.activeDeductionsList.length > 0 ? (
              <div className="active-deductions-table">
                {decomposition.activeDeductionsList.map((ded, idx) => (
                  <div key={idx} className="active-deduction-row">
                    <div className="deduction-left-cell">
                      <div className="deduction-title-wrap">
                        <span className="deduction-name">{ded.label}</span>
                        <span className="deduction-cat-tag">{ded.categoryTitle}</span>
                      </div>
                      <p className="deduction-detail-desc">{ded.detail}</p>
                    </div>

                    <div className="deduction-right-cell">
                      <span className="deduction-points-badge">
                        +{ded.points} PTS
                      </span>
                      {ded.explainerTopic && (
                        <button
                          type="button"
                          className="explain-mini-pill"
                          onClick={() => {
                            onClose()
                            if (onOpenExplainer) {
                              onOpenExplainer(ded.explainerTopic)
                            }
                          }}
                          title={`Learn more about ${ded.label}`}
                        >
                          (?) Explain
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="decomp-clean-state-box">
                <CheckCircle size={32} weight="bold" style={{ color: 'var(--risk-safe-accent)' }} />
                <p className="clean-state-title">Zero Active Heuristic Deductions</p>
                <p className="clean-state-desc">
                  Passive inspection audited all 17 multi-layer threat heuristics and found zero point-deduction violations. The destination retains baseline zero-hour security hygiene.
                </p>
              </div>
            )}
          </div>

          {/* Full Category Heuristic Breakdown Matrix */}
          <div className="decomp-section-group">
            <div className="decomp-section-header">
              <ChartLineUp size={15} weight="bold" />
              <span>Full Heuristic Rule Matrix by Category</span>
            </div>

            <div className="matrix-categories-stack">
              {decomposition.categories.map(cat => (
                <div key={cat.id} className="matrix-category-card">
                  <div className="category-card-header">
                    <div className="cat-header-title-wrap">
                      <span className="cat-header-title">{cat.title}</span>
                      <span className="cat-header-desc">{cat.description}</span>
                    </div>
                    <div className="cat-points-tally">
                      <span className={`cat-points-badge ${cat.activePoints > 0 ? 'points-has-active' : 'points-clean'}`}>
                        {cat.activePoints > 0 ? `+${cat.activePoints} pts applied` : '0 pts (Clean)'}
                      </span>
                    </div>
                  </div>

                  <div className="category-rules-list">
                    {cat.rules.map(rule => (
                      <div
                        key={rule.id}
                        className={`category-rule-item ${rule.isActive ? 'rule-active' : 'rule-inactive'}`}
                      >
                        <div className="rule-status-marker">
                          {rule.isActive ? (
                            <span className="rule-marker-active">
                              <WarningCircle size={13} weight="bold" />
                            </span>
                          ) : (
                            <span className="rule-marker-clean">
                              <CheckCircle size={13} weight="bold" />
                            </span>
                          )}
                        </div>

                        <div className="rule-info-col">
                          <span className="rule-label-text">{rule.label}</span>
                          <span className="rule-detail-text">{rule.detail}</span>
                        </div>

                        <div className="rule-actions-col">
                          <span className={`rule-weight-badge ${rule.isActive ? 'badge-weight-applied' : 'badge-weight-dormant'}`}>
                            {rule.isActive ? `+${rule.points} PTS` : `${rule.points} PTS MAX`}
                          </span>
                          {rule.explainerTopic && (
                            <button
                              type="button"
                              className="explain-mini-pill"
                              onClick={() => {
                                onClose()
                                if (onOpenExplainer) {
                                  onOpenExplainer(rule.explainerTopic)
                                }
                              }}
                              title={`Learn how ${rule.label} works`}
                            >
                              (?)
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
