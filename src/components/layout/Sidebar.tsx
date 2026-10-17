import React from 'react';
import {
  LayoutDashboard,
  Swords,
  GitCompare,
  FileCheck2,
  ShieldCheck,
  FileText,
  Activity,
  Settings,
  ShieldAlert,
  ChevronRight,
} from 'lucide-react';

export type NavSection =
  | 'dashboard'
  | 'playground'
  | 'comparison'
  | 'testcases'
  | 'policies'
  | 'audit'
  | 'settings';

interface SidebarProps {
  currentSection: NavSection;
  onSelectSection: (section: NavSection) => void;
  isOpenMobile: boolean;
  onCloseMobile: () => void;
}

export function Sidebar({
  currentSection,
  onSelectSection,
  isOpenMobile,
  onCloseMobile,
}: SidebarProps) {
  const navItems: {
    id: NavSection;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string;
  }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'playground', label: 'Attack Playground', icon: Swords, badge: 'Live' },
    { id: 'comparison', label: 'Protected vs. Unprotected', icon: GitCompare },
    { id: 'testcases', label: 'Test Cases', icon: FileCheck2 },
    { id: 'policies', label: 'Security Policies', icon: ShieldCheck },
    { id: 'audit', label: 'Audit Logs', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpenMobile && (
        <div
          className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm lg:hidden"
          onClick={onCloseMobile}
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 w-64 bg-[#070b14] border-r border-slate-800/80 flex flex-col transition-transform duration-200 ease-in-out lg:translate-x-0 ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 px-5 border-b border-slate-800/80 flex items-center gap-3 bg-[#0a0f1d]">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-sky-400 to-blue-600 p-0.5 shadow-[0_0_15px_rgba(56,189,248,0.4)] shrink-0">
            <div className="w-full h-full bg-[#0a0f1d] rounded-[10px] flex items-center justify-center text-sky-400">
              <ShieldAlert className="w-5 h-5 text-sky-400" />
            </div>
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-1.5">
              <span className="font-extrabold text-white text-base tracking-tight">
                PromptShield
              </span>
              <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-400/40">
                PRO
              </span>
            </div>
            <span className="text-[10px] text-slate-400 font-mono">Agent Trust Gateway</span>
          </div>
        </div>

        {/* Navigation Section */}
        <div className="px-3 pt-4 pb-2 text-[10px] font-bold text-slate-500 uppercase tracking-wider font-mono">
          Main Navigation
        </div>

        <nav className="flex-1 px-3 space-y-1.5 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentSection === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  onSelectSection(item.id);
                  onCloseMobile();
                }}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs sm:text-sm font-medium transition-all group cursor-pointer ${
                  isActive
                    ? 'bg-gradient-to-r from-sky-500 to-blue-600 text-slate-950 font-bold shadow-[0_0_20px_rgba(56,189,248,0.45)]'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/50 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    className={`w-4 h-4 transition-colors ${
                      isActive ? 'text-slate-950' : 'text-slate-400 group-hover:text-sky-400'
                    }`}
                  />
                  <span>{item.label}</span>
                </div>

                {item.badge ? (
                  <span
                    className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                      isActive
                        ? 'bg-slate-950/30 text-slate-950 border border-slate-950/20'
                        : 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                    }`}
                  >
                    {item.badge}
                  </span>
                ) : (
                  isActive && <ChevronRight className="w-3.5 h-3.5 text-slate-950" />
                )}
              </button>
            );
          })}
        </nav>

        {/* Security Posture Summary Card in Sidebar Footer */}
        <div className="p-3.5 m-3 rounded-xl border border-sky-500/20 bg-gradient-to-b from-[#0e1628] to-[#0a0f1d] shadow-[0_0_15px_rgba(56,189,248,0.1)]">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[11px] font-bold text-slate-200">Gateway Posture</span>
            <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Zero-Trust
            </span>
          </div>
          <p className="text-[10px] text-slate-400 leading-relaxed">
            All agent proposals evaluated independently. Default-deny active.
          </p>
        </div>
      </aside>
    </>
  );
}
