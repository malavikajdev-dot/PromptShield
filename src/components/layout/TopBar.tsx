import React, { useState } from 'react';
import {
  Menu,
  ShieldAlert,
  Activity,
  Terminal,
  Bell,
  User,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  ChevronDown,
} from 'lucide-react';
import { NavSection } from './Sidebar.tsx';
import { SystemHealthStatus } from '../../types/security.ts';

interface TopBarProps {
  currentSection: NavSection;
  onOpenMobile: () => void;
  onNavigate: (section: NavSection) => void;
  health: SystemHealthStatus | null;
}

export function TopBar({ currentSection, onOpenMobile, onNavigate, health }: TopBarProps) {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  const notifications = [
    {
      id: 1,
      title: 'Prompt Injection Intercepted',
      desc: 'Gateway blocked unauthorized file read on restricted vault',
      time: 'Just now',
      type: 'block',
    },
    {
      id: 2,
      title: 'Audit Chain Verified',
      desc: 'All SHA-256 blocks cryptographically intact',
      time: '5m ago',
      type: 'allow',
    },
    {
      id: 3,
      title: 'Approval Gate Triggered',
      desc: 'External email dispatch pending administrative approval',
      time: '12m ago',
      type: 'approval',
    },
  ];

  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#080d1a]/95 backdrop-blur-md sticky top-0 z-30 px-4 sm:px-6 lg:px-8 flex items-center justify-between">
      {/* Left: Mobile Toggle & Brand / Breadcrumb */}
      <div className="flex items-center gap-3 sm:gap-4">
        <button
          onClick={onOpenMobile}
          className="p-2 -ml-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 lg:hidden cursor-pointer"
          aria-label="Open navigation menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Brand identity on top bar */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-sky-400 to-blue-600 p-0.5 shadow-[0_0_15px_rgba(56,189,248,0.35)] shrink-0">
            <div className="w-full h-full bg-[#0a0f1d] rounded-[10px] flex items-center justify-center text-sky-400">
              <ShieldAlert className="w-5 h-5 text-sky-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-white text-base sm:text-lg tracking-tight">
                PromptShield
              </span>
              <span className="hidden sm:inline-block text-[10px] font-mono uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-sky-500/15 text-sky-300 border border-sky-400/30">
                PRO
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-medium hidden sm:block">
              AI Agent Security &amp; Trust Platform
            </p>
          </div>
        </div>
      </div>

      {/* Right Controls: System Status, Launch Test, Notifications & User */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* System Status Chip */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-800 bg-[#0c1322] text-xs font-mono shadow-inner">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-slate-400">System:</span>
          <span className="text-emerald-400 font-semibold">Active &amp; Protected</span>
        </div>

        {/* AI Threat Model Chip */}
        <div className="hidden xl:flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-800 bg-[#0c1322] text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-sky-400" />
          <span className="text-slate-400">Threat Engine:</span>
          <span className="text-sky-300 font-medium">
            {health?.geminiApi.status === 'CONFIGURED' ? 'Gemini 3.8 Flash' : 'Deterministic Fallback'}
          </span>
        </div>

        {/* Action Button: Quick Launch */}
        <button
          onClick={() => onNavigate('playground')}
          className="flex items-center gap-1.5 px-3 sm:px-3.5 py-1.5 rounded-lg text-xs font-bold bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-slate-950 shadow-[0_0_15px_rgba(56,189,248,0.35)] transition-all cursor-pointer shrink-0"
        >
          <Terminal className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Run Attack Test</span>
          <span className="sm:hidden">Test</span>
        </button>

        {/* Notification Bell Dropdown */}
        <div className="relative">
          <button
            onClick={() => {
              setShowNotifications(!showNotifications);
              setShowUserMenu(false);
            }}
            className="w-8 h-8 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white flex items-center justify-center relative cursor-pointer transition-colors border border-slate-700/60"
            aria-label="Notifications"
          >
            <Bell className="w-4 h-4" />
            <span className="w-2 h-2 rounded-full bg-sky-400 absolute top-1.5 right-1.5 ring-2 ring-[#080d1a]" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 sm:w-88 bg-[#0c1322] border border-slate-800 rounded-xl shadow-2xl p-3 z-50 animate-in fade-in slide-in-from-top-2">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 px-1">
                <span className="text-xs font-bold text-white uppercase tracking-wider">
                  Security Alerts
                </span>
                <span className="text-[10px] font-mono text-sky-400 font-semibold">
                  3 New
                </span>
              </div>
              <div className="space-y-1.5">
                {notifications.map((n) => (
                  <div
                    key={n.id}
                    className="p-2.5 rounded-lg bg-[#080d1a] border border-slate-800/80 hover:border-slate-700 transition-colors text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-white">{n.title}</span>
                      <span className="text-[10px] text-slate-500 font-mono">{n.time}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5">{n.desc}</p>
                  </div>
                ))}
              </div>
              <button
                onClick={() => {
                  setShowNotifications(false);
                  onNavigate('audit');
                }}
                className="w-full mt-2 py-1.5 text-center text-xs text-sky-400 hover:text-sky-300 font-medium block"
              >
                View Full Audit Logs &rarr;
              </button>
            </div>
          )}
        </div>

        {/* User Profile Menu */}
        <div className="relative">
          <button
            onClick={() => {
              setShowUserMenu(!showUserMenu);
              setShowNotifications(false);
            }}
            className="flex items-center gap-2 pl-1 pr-2 py-1 rounded-lg bg-slate-800/60 hover:bg-slate-700/80 border border-slate-700/60 cursor-pointer transition-colors"
          >
            <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-sky-500 to-cyan-400 flex items-center justify-center text-slate-950 font-bold text-xs shadow-[0_0_8px_rgba(56,189,248,0.4)]">
              AV
            </div>
            <span className="text-xs font-medium text-slate-200 hidden md:block">
              Alex Vance
            </span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {showUserMenu && (
            <div className="absolute right-0 mt-2 w-64 bg-[#0c1322] border border-slate-800 rounded-xl shadow-2xl p-3 z-50 animate-in fade-in slide-in-from-top-2">
              <div className="pb-3 border-b border-slate-800 px-1">
                <div className="font-bold text-white text-xs">Alex Vance</div>
                <div className="text-[11px] text-slate-400 truncate">
                  alex.vance@promptshield.io
                </div>
                <div className="mt-1 text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30 inline-block font-semibold">
                  Role: Lead Security Architect
                </div>
              </div>
              <div className="pt-2 space-y-1 text-xs">
                <button
                  onClick={() => {
                    setShowUserMenu(false);
                    onNavigate('policies');
                  }}
                  className="w-full text-left px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800/60 cursor-pointer transition-colors"
                >
                  Security Policies
                </button>
                <button
                  onClick={() => {
                    setShowUserMenu(false);
                    onNavigate('settings');
                  }}
                  className="w-full text-left px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800/60 cursor-pointer transition-colors"
                >
                  Platform Settings
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
