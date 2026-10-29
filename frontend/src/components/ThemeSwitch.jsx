import React from 'react'
import { Sun, Monitor, Moon } from '@phosphor-icons/react'

/**
 * Cubic 3-Way Theme Switcher with System Adaptation
 * Segmented cubic controller [ Sun | Monitor | Moon ] with mechanical sliding block.
 */
export function ThemeSwitch({ themePreference = 'system', onSelectTheme, theme, onToggle }) {
  // Support either modern preference ('light' | 'system' | 'dark') or legacy (theme + onToggle)
  const currentPref = themePreference || (theme === 'dark' ? 'dark' : 'light')

  function handleSelect(newPref) {
    if (onSelectTheme) {
      onSelectTheme(newPref)
    } else if (onToggle) {
      if ((newPref === 'dark' && theme !== 'dark') || (newPref === 'light' && theme !== 'light')) {
        onToggle()
      }
    }
  }

  return (
    <div
      className="theme-switch-cubic-shell"
      role="radiogroup"
      aria-label="Color Theme Selection"
    >
      <div className={`theme-switch-cubic-slider pos-${currentPref}`} aria-hidden="true" />

      <button
        type="button"
        role="radio"
        aria-checked={currentPref === 'light'}
        className={`theme-cube-btn ${currentPref === 'light' ? 'active' : ''}`}
        onClick={() => handleSelect('light')}
        title="Light mode (pure white)"
        aria-label="Light mode"
      >
        <Sun size={15} weight="bold" />
      </button>

      <button
        type="button"
        role="radio"
        aria-checked={currentPref === 'system'}
        className={`theme-cube-btn ${currentPref === 'system' ? 'active' : ''}`}
        onClick={() => handleSelect('system')}
        title="System theme (syncs with OS mode)"
        aria-label="System theme"
      >
        <Monitor size={15} weight="bold" />
      </button>

      <button
        type="button"
        role="radio"
        aria-checked={currentPref === 'dark'}
        className={`theme-cube-btn ${currentPref === 'dark' ? 'active' : ''}`}
        onClick={() => handleSelect('dark')}
        title="Dark mode (cyber-terminal)"
        aria-label="Dark mode"
      >
        <Moon size={15} weight="bold" />
      </button>
    </div>
  )
}
