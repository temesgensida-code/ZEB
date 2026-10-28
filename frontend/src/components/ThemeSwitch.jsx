import React from 'react'
import { Sun, Moon } from '@phosphor-icons/react'

/**
 * Rectangular Sliding Theme Switcher
 * Dual-segment module [ Sun LIGHT | Moon DARK ] with mechanical rectangular slide block.
 */
export function ThemeSwitch({ theme, onToggle }) {
  const isDark = theme === 'dark'

  return (
    <div
      className="theme-switch-shell"
      role="radiogroup"
      aria-label="Color Theme Selection"
    >
      <div className={`theme-switch-slider ${isDark ? 'slide-dark' : 'slide-light'}`} />

      <button
        type="button"
        role="radio"
        aria-checked={!isDark}
        className={`theme-segment-btn ${!isDark ? 'active' : ''}`}
        onClick={() => isDark && onToggle()}
        title="Switch to pure white light mode"
      >
        <Sun size={14} weight="bold" />
        <span className="segment-label">LIGHT</span>
      </button>

      <button
        type="button"
        role="radio"
        aria-checked={isDark}
        className={`theme-segment-btn ${isDark ? 'active' : ''}`}
        onClick={() => !isDark && onToggle()}
        title="Switch to pure black cyber-terminal mode"
      >
        <Moon size={14} weight="bold" />
        <span className="segment-label">DARK</span>
      </button>
    </div>
  )
}
