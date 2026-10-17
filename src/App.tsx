/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { NavSection, Sidebar } from './components/layout/Sidebar.tsx';
import { TopBar } from './components/layout/TopBar.tsx';
import { DashboardView } from './components/dashboard/DashboardView.tsx';
import { PlaygroundView } from './components/playground/PlaygroundView.tsx';
import { ComparisonView } from './components/comparison/ComparisonView.tsx';
import { TestCasesView } from './components/testcases/TestCasesView.tsx';
import { PoliciesView } from './components/policies/PoliciesView.tsx';
import { AuditLogsView } from './components/audit/AuditLogsView.tsx';
import { SettingsView } from './components/settings/SettingsView.tsx';
import { SystemHealthStatus } from './types/security.ts';
import { fetchHealth } from './services/api.ts';

export default function App() {
  const [currentSection, setCurrentSection] = useState<NavSection>('dashboard');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [health, setHealth] = useState<SystemHealthStatus | null>(null);

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch((err) => console.warn('Could not poll health on app start:', err));
  }, []);

  const renderSection = () => {
    switch (currentSection) {
      case 'dashboard':
        return <DashboardView onNavigate={setCurrentSection} />;
      case 'playground':
        return <PlaygroundView />;
      case 'comparison':
        return <ComparisonView />;
      case 'testcases':
        return <TestCasesView />;
      case 'policies':
        return <PoliciesView />;
      case 'audit':
        return <AuditLogsView />;
      case 'settings':
        return <SettingsView />;
      default:
        return <DashboardView onNavigate={setCurrentSection} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans selection:bg-sky-500/30 selection:text-sky-200">
      {/* Sidebar Navigation */}
      <Sidebar
        currentSection={currentSection}
        onSelectSection={setCurrentSection}
        isOpenMobile={isMobileMenuOpen}
        onCloseMobile={() => setIsMobileMenuOpen(false)}
      />

      {/* Main Content Area (Offset by Sidebar on desktop) */}
      <div className="lg:pl-64 flex flex-col min-h-screen">
        {/* Top Bar Header */}
        <TopBar
          currentSection={currentSection}
          onOpenMobile={() => setIsMobileMenuOpen(true)}
          onNavigate={setCurrentSection}
          health={health}
        />

        {/* Page Container */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          {renderSection()}
        </main>

        {/* Footer */}
        <footer className="border-t border-slate-800/80 bg-[#0a0f1d] py-4 px-6 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span>PromptShield AI Agent Security & Trust Platform</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
            <span>Zero-Trust Gateway v1.4</span>
            <span>•</span>
            <span>RFC 6234 SHA-256 Ledger</span>
          </div>
        </footer>
      </div>
    </div>
  );
}
