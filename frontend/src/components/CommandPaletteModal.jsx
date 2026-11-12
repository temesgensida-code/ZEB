import React, { useState, useEffect, useRef, useMemo } from 'react'
import {
  MagnifyingGlass,
  X,
  ClipboardText,
  Link as LinkIcon,
  Copy,
  Eye,
  DownloadSimple,
  Calculator,
  ShieldCheck,
  Code,
  Sun,
  Moon,
  Desktop,
  ShareNetwork,
  ArrowRight,
  TerminalWindow,
} from '@phosphor-icons/react'

export function CommandPaletteModal({
  isOpen,
  onClose,
  hasResult,
  onFocusInput,
  onPasteAndInspect,
  onCopyDefanged,
  onCopyIncidentBrief,
  onOpenSafePreview,
  onOpenExport,
  onOpenRiskDecomposition,
  onOpenHowItWorks,
  onSelectPreset,
  onNavigate,
  currentView,
  onCycleTheme,
}) {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef(null)
  const listRef = useRef(null)

  // Focus input on open
  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setSelectedIndex(0)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [isOpen])

  // Build command list based on app state
  const commands = useMemo(() => {
    const list = [
      {
        id: 'paste-inspect',
        category: 'Action',
        title: 'Inspect URL from Clipboard',
        desc: 'Reads clipboard text and immediately executes heuristic scan',
        shortcut: 'Ctrl+V',
        icon: <ClipboardText size={16} weight="bold" />,
        action: onPasteAndInspect,
        available: true,
      },
      {
        id: 'focus-input',
        category: 'Action',
        title: 'Focus URL Search Bar',
        desc: 'Jumps cursor directly to the primary URL inspection input',
        shortcut: '/',
        icon: <LinkIcon size={16} weight="bold" />,
        action: onFocusInput,
        available: true,
      },
      {
        id: 'copy-defanged',
        category: 'Inspection',
        title: 'Copy Defanged URL',
        desc: 'Copies hxxp[.] notation safe for Slack, Teams, and email exchange',
        shortcut: 'D',
        icon: <Copy size={16} weight="bold" />,
        action: onCopyDefanged,
        available: hasResult,
      },
      {
        id: 'copy-incident-brief',
        category: 'Inspection',
        title: 'Copy Incident Brief (Slack/Teams)',
        desc: 'Copies authoritative zero-emoji ASCII incident dossier to clipboard',
        shortcut: 'B',
        icon: <ShareNetwork size={16} weight="bold" />,
        action: onCopyIncidentBrief,
        available: hasResult,
      },
      {
        id: 'open-preview',
        category: 'Inspection',
        title: 'Open Safe Cloud Sandbox Preview',
        desc: 'Launches isolated dual-engine visual preview and de-scripted DOM reader',
        shortcut: 'P',
        icon: <Eye size={16} weight="bold" />,
        action: onOpenSafePreview,
        available: hasResult,
      },
      {
        id: 'open-export',
        category: 'Inspection',
        title: 'Export Security Dossier (STIX / Markdown)',
        desc: 'Generates STIX 2.1 JSON bundle, IOC defanged list, and markdown report',
        shortcut: 'E',
        icon: <DownloadSimple size={16} weight="bold" />,
        action: onOpenExport,
        available: hasResult,
      },
      {
        id: 'open-risk-decomp',
        category: 'Inspection',
        title: 'Decompose Risk Score Mathematics',
        desc: 'Examine exact heuristic point attributions and scoring formulas',
        shortcut: 'R',
        icon: <Calculator size={16} weight="bold" />,
        action: onOpenRiskDecomposition,
        available: hasResult,
      },
      {
        id: 'preset-clean',
        category: 'Sample Presets',
        title: 'Load Clean Preset (github.com)',
        desc: 'Standard HTTPS repository host with mature domain history',
        shortcut: null,
        icon: <ShieldCheck size={16} weight="bold" />,
        action: () => onSelectPreset('https://github.com'),
        available: true,
      },
      {
        id: 'preset-shortener',
        category: 'Sample Presets',
        title: 'Load Shortener Preset (bit.ly/3xSecurityDemo)',
        desc: 'Obfuscated multi-hop redirect gateway with cloaked destination',
        shortcut: null,
        icon: <ShareNetwork size={16} weight="bold" />,
        action: () => onSelectPreset('https://bit.ly/3xSecurityDemo'),
        available: true,
      },
      {
        id: 'preset-ip',
        category: 'Sample Presets',
        title: 'Load Raw IP Preset (192.168.1.1/login)',
        desc: 'Direct IP host routing bypassing canonical named DNS',
        shortcut: null,
        icon: <TerminalWindow size={16} weight="bold" />,
        action: () => onSelectPreset('http://192.168.1.1/login'),
        available: true,
      },
      {
        id: 'nav-view',
        category: 'Navigation',
        title: currentView === 'developer' ? 'Switch to URL Inspector' : 'Switch to Developer API Portal',
        desc: currentView === 'developer' ? 'Return to real-time URL heuristic checker' : 'Manage API keys, webhooks, and sandbox quotas',
        shortcut: null,
        icon: <Code size={16} weight="bold" />,
        action: () => onNavigate(currentView === 'developer' ? 'inspector' : 'developer'),
        available: true,
      },
      {
        id: 'how-it-works',
        category: 'Documentation',
        title: 'How ZEB Inspects Links (Technical FAQ)',
        desc: 'Review 6-stage heuristic matrix and passive isolation guarantees',
        shortcut: '?',
        icon: <ShieldCheck size={16} weight="bold" />,
        action: onOpenHowItWorks,
        available: true,
      },
      {
        id: 'cycle-theme',
        category: 'Preferences',
        title: 'Toggle Display Theme',
        desc: 'Cycles between Dark, Light, and System OS preference modes',
        shortcut: null,
        icon: <Sun size={16} weight="bold" />,
        action: onCycleTheme,
        available: true,
      },
    ]

    return list.filter(c => c.available)
  }, [
    hasResult,
    onPasteAndInspect,
    onFocusInput,
    onCopyDefanged,
    onCopyIncidentBrief,
    onOpenSafePreview,
    onOpenExport,
    onOpenRiskDecomposition,
    onOpenHowItWorks,
    onSelectPreset,
    onNavigate,
    currentView,
    onCycleTheme,
  ])

  // Filter commands by search query
  const filteredCommands = useMemo(() => {
    if (!query.trim()) return commands
    const q = query.toLowerCase()
    return commands.filter(
      c =>
        c.title.toLowerCase().includes(q) ||
        c.desc.toLowerCase().includes(q) ||
        c.category.toLowerCase().includes(q) ||
        (c.shortcut && c.shortcut.toLowerCase().includes(q))
    )
  }, [commands, query])

  // Handle keyboard navigation
  useEffect(() => {
    function handleKeyDown(e) {
      if (!isOpen) return

      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIndex(prev => (filteredCommands.length > 0 ? (prev + 1) % filteredCommands.length : 0))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIndex(prev => (filteredCommands.length > 0 ? (prev - 1 + filteredCommands.length) % filteredCommands.length : 0))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        const selected = filteredCommands[selectedIndex]
        if (selected && selected.action) {
          onClose()
          selected.action()
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, filteredCommands, selectedIndex, onClose])

  // Scroll active item into view
  useEffect(() => {
    if (listRef.current) {
      const activeEl = listRef.current.querySelector('.palette-item.is-selected')
      if (activeEl) {
        activeEl.scrollIntoView({ block: 'nearest' })
      }
    }
  }, [selectedIndex])

  if (!isOpen) return null

  return (
    <div
      className="modal-overlay command-palette-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Command Palette"
    >
      <div
        className="command-palette-dialog"
        onClick={e => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div className="palette-input-shell">
          <span className="palette-reticle reticle-tl" aria-hidden="true" />
          <span className="palette-reticle reticle-tr" aria-hidden="true" />
          <span className="palette-search-icon">
            <MagnifyingGlass size={18} weight="bold" />
          </span>
          <input
            ref={inputRef}
            type="text"
            className="palette-search-input"
            value={query}
            onChange={e => {
              setQuery(e.target.value)
              setSelectedIndex(0)
            }}
            placeholder="Type an action, command, or sample preset..."
            spellCheck={false}
            autoComplete="off"
            aria-label="Search actions"
          />
          <button
            type="button"
            className="palette-close-btn"
            onClick={onClose}
            aria-label="Close command palette"
          >
            <span className="palette-kbd-badge">ESC</span>
          </button>
        </div>

        {/* Results List */}
        <div className="palette-results-list" ref={listRef} role="listbox">
          {filteredCommands.length > 0 ? (
            filteredCommands.map((cmd, idx) => {
              const isSelected = idx === selectedIndex
              return (
                <div
                  key={cmd.id}
                  className={`palette-item ${isSelected ? 'is-selected' : ''}`}
                  onClick={() => {
                    onClose()
                    cmd.action()
                  }}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  role="option"
                  aria-selected={isSelected}
                >
                  <span className="palette-item-icon">{cmd.icon}</span>
                  <div className="palette-item-content">
                    <div className="palette-item-header">
                      <span className="palette-item-title">{cmd.title}</span>
                      <span className="palette-item-category">{cmd.category}</span>
                    </div>
                    <span className="palette-item-desc">{cmd.desc}</span>
                  </div>

                  {cmd.shortcut ? (
                    <span className="palette-kbd-badge">{cmd.shortcut}</span>
                  ) : (
                    <ArrowRight size={14} weight="bold" className="palette-item-arrow" />
                  )}
                </div>
              )
            })
          ) : (
            <div className="palette-empty-state">
              <p>No matching commands found for "{query}"</p>
            </div>
          )}
        </div>

        {/* Bottom Keybinding Legend */}
        <div className="palette-footer-legend">
          <span className="legend-item">
            <kbd className="legend-kbd">↑</kbd>
            <kbd className="legend-kbd">↓</kbd> Navigate
          </span>
          <span className="legend-sep">·</span>
          <span className="legend-item">
            <kbd className="legend-kbd">↵</kbd> Select
          </span>
          <span className="legend-sep">·</span>
          <span className="legend-item">
            <kbd className="legend-kbd">esc</kbd> Dismiss
          </span>
          <span className="legend-sep">·</span>
          <span className="legend-item">
            <kbd className="legend-kbd">⌘K</kbd> Toggle Omnibar
          </span>
        </div>
      </div>
    </div>
  )
}
