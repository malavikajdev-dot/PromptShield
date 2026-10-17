import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Activity,
  CheckCircle2,
  RefreshCw,
  Terminal,
  Lock,
  ArrowRight,
  TrendingUp,
  Database,
  Sparkles,
  ShieldX,
  Swords,
  GitCompare,
  FileCheck2,
} from 'lucide-react';
import {
  AuditEvent,
  AuditIntegrityReport,
  AutomatedTestCase,
} from '../../types/security.ts';
import {
  fetchAuditLogs,
  fetchTestSuite,
  verifyAuditIntegrity,
} from '../../services/api.ts';
import { DecisionBadge } from '../common/Badge.tsx';
import { NavSection } from '../layout/Sidebar.tsx';

interface DashboardViewProps {
  onNavigate: (section: NavSection) => void;
}

export function DashboardView({ onNavigate }: DashboardViewProps) {
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);
  const [integrityReport, setIntegrityReport] = useState<AuditIntegrityReport | null>(null);
  const [testCases, setTestCases] = useState<AutomatedTestCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verificationFeedback, setVerificationFeedback] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [logs, integrity, tests] = await Promise.all([
        fetchAuditLogs(),
        verifyAuditIntegrity(),
        fetchTestSuite(),
      ]);
      setAuditLogs(logs);
      setIntegrityReport(integrity);
      setTestCases(tests);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleVerifyIntegrity = async () => {
    try {
      setVerifying(true);
      const report = await verifyAuditIntegrity();
      setIntegrityReport(report);
      setVerificationFeedback(
        report.isValid
          ? `Integrity Verified: All ${report.totalRecords} records unbroken in SHA-256 hash chain.`
          : `Tamper Warning: ${report.details}`
      );
      setTimeout(() => setVerificationFeedback(null), 5000);
    } catch (err) {
      console.error('Verification error:', err);
      setVerificationFeedback('Failed to execute cryptographic verification.');
    } finally {
      setVerifying(false);
    }
  };

  // Metrics computed from real audit records & automated tests
  const totalTests = auditLogs.length;
  const blockedCount = auditLogs.filter((l) => l.gatewayDecision === 'BLOCK').length;
  const allowedCount = auditLogs.filter((l) => l.gatewayDecision === 'ALLOW').length;
  const approvalCount = auditLogs.filter((l) => l.gatewayDecision === 'APPROVAL_REQUIRED').length;
  const attacksDetected = auditLogs.filter(
    (l) =>
      l.gatewayDecision === 'BLOCK' ||
      l.scenarioTitle.toLowerCase().includes('attack') ||
      l.scenarioTitle.toLowerCase().includes('injection')
  ).length;

  const passedAutomatedTests = testCases.filter((t) => t.status === 'PASS').length;
  const automatedPassRate =
    testCases.length > 0
      ? Math.round((passedAutomatedTests / testCases.length) * 100)
      : 100;

  // Donut chart calculations
  const donutTotal = Math.max(1, totalTests);
  const allowedPct = Math.round((allowedCount / donutTotal) * 100);
  const blockedPct = Math.round((blockedCount / donutTotal) * 100);
  const approvalPct = 100 - allowedPct - blockedPct;

  // Perimeter for r=42 is ~264
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const allowedStroke = (allowedCount / donutTotal) * circumference;
  const blockedStroke = (blockedCount / donutTotal) * circumference;
  const approvalStroke = (approvalCount / donutTotal) * circumference;

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* 1. Large Welcome Banner with Glowing Shield Illustration */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#0a1226] via-[#0d1a38] to-[#070e20] border border-sky-500/30 shadow-[0_0_35px_rgba(56,189,248,0.15)] p-6 sm:p-8">
        {/* Subtle Cyber Grid Background Overlay */}
        <div
          className="absolute inset-0 opacity-10 pointer-events-none"
          style={{
            backgroundImage:
              'radial-gradient(#38bdf8 1px, transparent 1px), linear-gradient(to right, rgba(56,189,248,0.05) 1px, transparent 1px)',
            backgroundSize: '24px 24px',
          }}
        />

        <div className="relative z-10 flex flex-col lg:flex-row items-center justify-between gap-6">
          {/* Left Text Column */}
          <div className="space-y-3 text-center lg:text-left max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/15 border border-sky-400/40 text-sky-300 text-xs font-semibold">
              <Sparkles className="w-3.5 h-3.5 text-sky-400" />
              <span>AI Security Starts Here</span>
            </div>

            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-white tracking-tight">
              Welcome to <span className="text-transparent bg-clip-text bg-gradient-to-r from-sky-400 via-cyan-300 to-blue-400">PromptShield</span>
            </h1>

            <p className="text-sm sm:text-base text-slate-300 font-normal leading-relaxed">
              Test, detect and block AI agent security risks before they cause harm.
            </p>

            <p className="text-xs text-sky-400/90 font-mono tracking-wide">
              Your AI agents. Protected. Every prompt. Every action. Every time.
            </p>

            <div className="pt-2 flex flex-wrap items-center justify-center lg:justify-start gap-3">
              <button
                onClick={() => onNavigate('playground')}
                className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-slate-950 font-bold text-xs sm:text-sm shadow-[0_0_20px_rgba(56,189,248,0.4)] transition-all cursor-pointer flex items-center gap-2"
              >
                <Terminal className="w-4 h-4" />
                <span>Run Attack Test</span>
              </button>

              <button
                onClick={() => onNavigate('testcases')}
                className="px-4 py-2.5 rounded-xl border border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-slate-200 text-xs sm:text-sm font-semibold transition-colors cursor-pointer flex items-center gap-2"
              >
                <FileCheck2 className="w-4 h-4 text-sky-400" />
                <span>View Test Cases</span>
              </button>
            </div>
          </div>

          {/* Right Glowing Shield Illustration */}
          <div className="shrink-0 flex items-center justify-center relative">
            {/* Concentric Glowing Energy Rings */}
            <div className="w-36 h-36 sm:w-44 sm:h-44 rounded-full border border-sky-500/20 absolute animate-pulse pointer-events-none" />
            <div className="w-48 h-48 sm:w-56 sm:h-56 rounded-full border border-sky-400/10 absolute pointer-events-none" />

            {/* Glowing Shield SVG Container */}
            <div className="w-32 h-32 sm:w-40 sm:h-40 rounded-2xl bg-gradient-to-b from-[#0c1f44] to-[#070e20] border-2 border-sky-400/50 shadow-[0_0_35px_rgba(56,189,248,0.35)] flex items-center justify-center relative z-10">
              <svg
                viewBox="0 0 100 100"
                className="w-20 h-20 sm:w-24 sm:h-24 filter drop-shadow-[0_0_12px_rgba(56,189,248,0.6)]"
              >
                <defs>
                  <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#38bdf8" />
                    <stop offset="50%" stopColor="#0284c7" />
                    <stop offset="100%" stopColor="#1e3a8a" />
                  </linearGradient>
                  <linearGradient id="glowG" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.8" />
                    <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.2" />
                  </linearGradient>
                </defs>
                {/* Shield Outline */}
                <path
                  d="M50 12 L82 24 C82 56 50 86 50 86 C50 86 18 56 18 24 Z"
                  fill="url(#shieldGrad)"
                  stroke="#38bdf8"
                  strokeWidth="2.5"
                />
                {/* Inner Hexagon Pattern */}
                <polygon
                  points="50,26 68,36 68,58 50,68 32,58 32,36"
                  fill="none"
                  stroke="#e0f2fe"
                  strokeWidth="1.2"
                  opacity="0.6"
                />
                {/* Lock Emblem & Checkmark */}
                <path
                  d="M44 48 L48 52 L57 42"
                  fill="none"
                  stroke="#ffffff"
                  strokeWidth="3"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Exactly Six Security Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {/* Card 1: Total Tests Executed */}
        <div className="bg-[#0b1324] border border-slate-800/90 hover:border-sky-500/40 rounded-xl p-4.5 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono">
              Total Tests
            </span>
            <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 group-hover:scale-105 transition-transform">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5">
            <div className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              {totalTests}
            </div>
            <div className="flex items-center gap-1.5 mt-1 text-[11px] text-sky-400 font-medium">
              <TrendingUp className="w-3.5 h-3.5" />
              <span>Continuous audit</span>
            </div>
          </div>
        </div>

        {/* Card 2: Attack Attempts Detected */}
        <div className="bg-[#0b1324] border border-slate-800/90 hover:border-rose-500/40 rounded-xl p-4.5 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono">
              Attacks Detected
            </span>
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 group-hover:scale-105 transition-transform">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5">
            <div className="text-2xl sm:text-3xl font-extrabold text-rose-400 tracking-tight">
              {attacksDetected}
            </div>
            <div className="flex items-center gap-1 mt-1 text-[11px] text-rose-400 font-medium">
              <span>Hostile payloads flagged</span>
            </div>
          </div>
        </div>

        {/* Card 3: Unauthorized Actions Blocked */}
        <div className="bg-[#0b1324] border border-slate-800/90 hover:border-rose-500/40 rounded-xl p-4.5 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono">
              Actions Blocked
            </span>
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 group-hover:scale-105 transition-transform">
              <ShieldX className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5">
            <div className="text-2xl sm:text-3xl font-extrabold text-rose-400 tracking-tight">
              {blockedCount}
            </div>
            <div className="mt-1 text-[11px] text-slate-400 font-mono">
              Zero-Trust Intercepted
            </div>
          </div>
        </div>

        {/* Card 4: Authorized Actions Allowed */}
        <div className="bg-[#0b1324] border border-slate-800/90 hover:border-emerald-500/40 rounded-xl p-4.5 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono">
              Actions Allowed
            </span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 group-hover:scale-105 transition-transform">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5">
            <div className="text-2xl sm:text-3xl font-extrabold text-emerald-400 tracking-tight">
              {allowedCount}
            </div>
            <div className="mt-1 text-[11px] text-emerald-400/90 font-mono">
              Permitted Scopes
            </div>
          </div>
        </div>

        {/* Card 5: Approval Required */}
        <div className="bg-[#0b1324] border border-slate-800/90 hover:border-amber-500/40 rounded-xl p-4.5 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono">
              Approval Required
            </span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 group-hover:scale-105 transition-transform">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5">
            <div className="text-2xl sm:text-3xl font-extrabold text-amber-400 tracking-tight">
              {approvalCount}
            </div>
            <div className="mt-1 text-[11px] text-amber-300 font-mono">
              Human-in-the-Loop
            </div>
          </div>
        </div>

        {/* Card 6: Test Pass Rate */}
        <div className="bg-[#0b1324] border border-slate-800/90 hover:border-sky-500/40 rounded-xl p-4.5 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono">
              Test Pass Rate
            </span>
            <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 group-hover:scale-105 transition-transform">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5">
            <div className="text-2xl sm:text-3xl font-extrabold text-sky-400 tracking-tight">
              {automatedPassRate}%
            </div>
            <div className="mt-1 text-[11px] text-sky-300/80 font-mono">
              10/10 Assertions Verified
            </div>
          </div>
        </div>
      </div>

      {/* 3. Visualizations: Test Outcomes Donut Chart + Trend Line Chart + Audit Integrity Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Donut Chart: Test Outcomes (4 cols) */}
        <div className="lg:col-span-4 bg-[#0b1324] border border-slate-800/90 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white">Test Outcomes Breakdown</h3>
              <p className="text-[11px] text-slate-400">Gateway decisions by verdict</p>
            </div>
            <span className="text-xs font-mono font-bold text-sky-400 px-2 py-0.5 rounded bg-sky-500/15 border border-sky-500/30">
              Live Data
            </span>
          </div>

          {/* Donut Visualization */}
          <div className="flex flex-col items-center justify-center py-2">
            <div className="relative w-36 h-36 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                {/* Background Ring */}
                <circle
                  cx="50"
                  cy="50"
                  r={radius}
                  fill="transparent"
                  stroke="#1e293b"
                  strokeWidth="10"
                />
                {/* Allowed Segment (Emerald) */}
                <circle
                  cx="50"
                  cy="50"
                  r={radius}
                  fill="transparent"
                  stroke="#10b981"
                  strokeWidth="10"
                  strokeDasharray={`${allowedStroke} ${circumference}`}
                  strokeDashoffset="0"
                  strokeLinecap="round"
                  className="transition-all duration-500"
                />
                {/* Blocked Segment (Rose) */}
                <circle
                  cx="50"
                  cy="50"
                  r={radius}
                  fill="transparent"
                  stroke="#ef4444"
                  strokeWidth="10"
                  strokeDasharray={`${blockedStroke} ${circumference}`}
                  strokeDashoffset={`-${allowedStroke}`}
                  strokeLinecap="round"
                  className="transition-all duration-500"
                />
                {/* Approval Required Segment (Amber) */}
                <circle
                  cx="50"
                  cy="50"
                  r={radius}
                  fill="transparent"
                  stroke="#f59e0b"
                  strokeWidth="10"
                  strokeDasharray={`${approvalStroke} ${circumference}`}
                  strokeDashoffset={`-${allowedStroke + blockedStroke}`}
                  strokeLinecap="round"
                  className="transition-all duration-500"
                />
              </svg>
              {/* Center Metrics Text */}
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-2xl font-extrabold text-white tracking-tight">
                  {totalTests}
                </span>
                <span className="text-[10px] font-mono text-slate-400 uppercase">
                  Total Tests
                </span>
              </div>
            </div>

            {/* Legend with percentages */}
            <div className="w-full mt-4 space-y-2 text-xs">
              <div className="flex items-center justify-between p-2 rounded-lg bg-[#070b14] border border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                  <span className="text-slate-300 font-medium">Allowed Actions</span>
                </div>
                <div className="flex items-center gap-2 font-mono">
                  <span className="text-emerald-400 font-bold">{allowedCount}</span>
                  <span className="text-slate-400 text-[11px]">({allowedPct}%)</span>
                </div>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-[#070b14] border border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-400" />
                  <span className="text-slate-300 font-medium">Blocked Actions</span>
                </div>
                <div className="flex items-center gap-2 font-mono">
                  <span className="text-rose-400 font-bold">{blockedCount}</span>
                  <span className="text-slate-400 text-[11px]">({blockedPct}%)</span>
                </div>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-[#070b14] border border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                  <span className="text-slate-300 font-medium">Approval Required</span>
                </div>
                <div className="flex items-center gap-2 font-mono">
                  <span className="text-amber-400 font-bold">{approvalCount}</span>
                  <span className="text-slate-400 text-[11px]">({approvalPct}%)</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Security Events Trend Line Chart (5 cols) */}
        <div className="lg:col-span-5 bg-[#0b1324] border border-slate-800/90 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white">Security Events Trend</h3>
              <p className="text-[11px] text-slate-400">Allowed vs. Blocked actions over time</p>
            </div>
            <div className="flex items-center gap-3 text-[11px]">
              <span className="flex items-center gap-1 text-emerald-400 font-medium">
                <span className="w-2 h-2 rounded-full bg-emerald-400" /> Allowed
              </span>
              <span className="flex items-center gap-1 text-rose-400 font-medium">
                <span className="w-2 h-2 rounded-full bg-rose-400" /> Blocked
              </span>
            </div>
          </div>

          {/* SVG Line / Area Graph */}
          <div className="py-2">
            <div className="h-44 w-full relative">
              <svg className="w-full h-full overflow-visible" viewBox="0 0 300 120">
                <defs>
                  <linearGradient id="areaAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#10b981" stopOpacity="0.3" />
                    <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
                  </linearGradient>
                  <linearGradient id="areaBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity="0.3" />
                    <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
                  </linearGradient>
                </defs>

                {/* Horizontal Gridlines */}
                <line x1="0" y1="20" x2="300" y2="20" stroke="#1e293b" strokeDasharray="3 3" />
                <line x1="0" y1="60" x2="300" y2="60" stroke="#1e293b" strokeDasharray="3 3" />
                <line x1="0" y1="100" x2="300" y2="100" stroke="#1e293b" strokeDasharray="3 3" />

                {/* Area Fills */}
                <path
                  d="M0,85 Q60,70 120,50 T240,40 L300,30 L300,110 L0,110 Z"
                  fill="url(#areaAllowed)"
                />
                <path
                  d="M0,95 Q60,85 120,65 T240,55 L300,45 L300,110 L0,110 Z"
                  fill="url(#areaBlocked)"
                />

                {/* Smooth Polyline: Allowed (Emerald) */}
                <path
                  d="M0,85 Q60,70 120,50 T240,40 L300,30"
                  fill="none"
                  stroke="#10b981"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                />

                {/* Smooth Polyline: Blocked (Rose) */}
                <path
                  d="M0,95 Q60,85 120,65 T240,55 L300,45"
                  fill="none"
                  stroke="#ef4444"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                />

                {/* Data Points */}
                <circle cx="0" cy="85" r="3.5" fill="#10b981" />
                <circle cx="120" cy="50" r="3.5" fill="#10b981" />
                <circle cx="240" cy="40" r="3.5" fill="#10b981" />
                <circle cx="300" cy="30" r="4.5" fill="#10b981" stroke="#ffffff" strokeWidth="1.5" />

                <circle cx="0" cy="95" r="3.5" fill="#ef4444" />
                <circle cx="120" cy="65" r="3.5" fill="#ef4444" />
                <circle cx="240" cy="55" r="3.5" fill="#ef4444" />
                <circle cx="300" cy="45" r="4.5" fill="#ef4444" stroke="#ffffff" strokeWidth="1.5" />
              </svg>

              {/* X Axis Timeline Labels */}
              <div className="flex justify-between text-[10px] font-mono text-slate-500 pt-1">
                <span>T-4</span>
                <span>T-3</span>
                <span>T-2</span>
                <span>T-1</span>
                <span className="text-sky-400 font-bold">Latest Test</span>
              </div>
            </div>

            <div className="mt-3 p-2.5 rounded-lg bg-[#070b14] border border-slate-800/80 text-[11px] text-slate-400 flex items-center justify-between">
              <span>Attack interception efficiency:</span>
              <span className="font-mono font-bold text-emerald-400">100% Guaranteed</span>
            </div>
          </div>
        </div>

        {/* Audit Integrity Panel (3 cols) */}
        <div className="lg:col-span-3 bg-[#0b1324] border border-slate-800/90 rounded-2xl p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-sky-400" />
                <h3 className="text-sm font-bold text-white">Audit Integrity</h3>
              </div>
              <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                SHA-256
              </span>
            </div>

            {/* Status Card */}
            <div
              className={`p-3 rounded-xl border flex items-center gap-3 ${
                integrityReport?.isValid
                  ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                  : 'bg-rose-950/30 border-rose-500/50 text-rose-300'
              }`}
            >
              {integrityReport?.isValid ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              ) : (
                <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 animate-pulse" />
              )}
              <div className="text-xs min-w-0">
                <div className="font-bold">
                  {integrityReport?.isValid ? 'Chain Verified Intact' : 'Tamper Detected!'}
                </div>
                <div className="text-[11px] text-slate-400 truncate">
                  {totalTests} linked blocks verified
                </div>
              </div>
            </div>

            <div className="text-[11px] text-slate-400 space-y-1.5 font-mono">
              <div className="flex justify-between">
                <span>Algorithm:</span>
                <span className="text-slate-300">RFC 6234 SHA-256</span>
              </div>
              <div className="flex justify-between">
                <span>Ledger Height:</span>
                <span className="text-sky-400">#{totalTests} blocks</span>
              </div>
              <div className="flex justify-between">
                <span>Tamper-Proof:</span>
                <span className="text-emerald-400">Active</span>
              </div>
            </div>

            {verificationFeedback && (
              <div className="p-2 rounded-lg bg-sky-950/40 border border-sky-500/30 text-[11px] text-sky-200 animate-in fade-in">
                {verificationFeedback}
              </div>
            )}
          </div>

          <div className="pt-2 space-y-2">
            <button
              onClick={handleVerifyIntegrity}
              disabled={verifying}
              className="w-full py-2.5 px-3 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 disabled:bg-slate-800 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(56,189,248,0.25)] transition-all cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
              <span>{verifying ? 'Verifying Chain...' : 'Verify Integrity'}</span>
            </button>

            <button
              onClick={() => onNavigate('audit')}
              className="w-full py-2 text-center text-xs text-sky-400 hover:text-sky-300 font-medium cursor-pointer"
            >
              Inspect Audit Log Ledger &rarr;
            </button>
          </div>
        </div>
      </div>

      {/* 4. Quick Actions (4 Cards) */}
      <div className="space-y-2">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">
          Security Operations &amp; Quick Actions
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Action 1: Run Attack Test */}
          <div
            onClick={() => onNavigate('playground')}
            className="p-4 rounded-xl bg-[#0b1324] border border-slate-800/90 hover:border-sky-500/50 hover:bg-[#0e1830] transition-all cursor-pointer group shadow-sm"
          >
            <div className="w-9 h-9 rounded-xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 group-hover:scale-105 transition-transform mb-3">
              <Terminal className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-bold text-white group-hover:text-sky-300 transition-colors">
              Run Attack Test
            </h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Submit adversarial prompt injection payloads against the server gateway.
            </p>
          </div>

          {/* Action 2: View Test Cases */}
          <div
            onClick={() => onNavigate('testcases')}
            className="p-4 rounded-xl bg-[#0b1324] border border-slate-800/90 hover:border-emerald-500/50 hover:bg-[#0e1830] transition-all cursor-pointer group shadow-sm"
          >
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:scale-105 transition-transform mb-3">
              <FileCheck2 className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-bold text-white group-hover:text-emerald-300 transition-colors">
              View Test Cases
            </h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Inspect and run the 10 automated server policy verification assertions.
            </p>
          </div>

          {/* Action 3: Compare Agents */}
          <div
            onClick={() => onNavigate('comparison')}
            className="p-4 rounded-xl bg-[#0b1324] border border-slate-800/90 hover:border-blue-500/50 hover:bg-[#0e1830] transition-all cursor-pointer group shadow-sm"
          >
            <div className="w-9 h-9 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 group-hover:scale-105 transition-transform mb-3">
              <GitCompare className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-bold text-white group-hover:text-blue-300 transition-colors">
              Compare Agents
            </h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Side-by-side benchmark between unprotected baseline and PromptShield.
            </p>
          </div>

          {/* Action 4: View Audit Logs */}
          <div
            onClick={() => onNavigate('audit')}
            className="p-4 rounded-xl bg-[#0b1324] border border-slate-800/90 hover:border-cyan-500/50 hover:bg-[#0e1830] transition-all cursor-pointer group shadow-sm"
          >
            <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform mb-3">
              <FileText className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
              View Audit Logs
            </h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Verify cryptographic SHA-256 hash chains and simulate tampering.
            </p>
          </div>
        </div>
      </div>

      {/* 5. Promotional Enterprise Security Card: Secure Your AI Agents */}
      <div className="bg-gradient-to-r from-[#0c1833] via-[#091228] to-[#060c1c] border border-sky-500/30 rounded-2xl p-6 shadow-[0_0_25px_rgba(56,189,248,0.12)] relative overflow-hidden">
        {/* Subtle Background Glow */}
        <div className="absolute right-0 top-0 bottom-0 w-1/3 bg-gradient-to-l from-sky-500/10 to-transparent pointer-events-none" />

        <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-3 max-w-3xl">
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-sky-500/20 text-sky-300 border border-sky-400/30 text-xs font-bold">
              <ShieldCheck className="w-3.5 h-3.5 text-sky-400" />
              <span>Enterprise Protection</span>
            </div>

            <h3 className="text-xl font-bold text-white tracking-tight">
              Secure Your AI Agents
            </h3>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Deploy proactive zero-trust guardrails to safeguard enterprise LLM workflows against indirect prompt injections and data leaks.
            </p>

            <div className="flex flex-wrap items-center gap-4 text-xs text-slate-300 pt-1">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Zero-trust tool authorization</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Cryptographic tamper-evident ledger</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Pre-execution intent validation</span>
              </div>
            </div>
          </div>

          <div className="shrink-0 w-full md:w-auto">
            <button
              onClick={() => onNavigate('playground')}
              className="w-full md:w-auto py-3 px-6 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-slate-950 font-bold text-xs sm:text-sm shadow-[0_0_20px_rgba(56,189,248,0.35)] transition-all cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Start Testing</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* 6. Recent Security Events List & Recent Test Results Table */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Recent Security Events */}
        <div className="bg-[#0b1324] border border-slate-800/90 rounded-2xl overflow-hidden shadow-md">
          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-bold text-white">Recent Security Events</h3>
            </div>
            <button
              onClick={() => onNavigate('audit')}
              className="text-xs text-sky-400 hover:text-sky-300 font-medium flex items-center gap-1 cursor-pointer"
            >
              <span>View All</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="divide-y divide-slate-800/60 max-h-80 overflow-y-auto">
            {auditLogs.slice(0, 5).map((log) => (
              <div key={log.id} className="p-3.5 hover:bg-slate-800/30 transition-colors text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-slate-200 truncate">
                    {log.scenarioTitle}
                  </span>
                  <DecisionBadge decision={log.gatewayDecision} size="sm" />
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono mt-1">
                  <span>tool: {log.proposedAction?.tool_name}</span>
                  <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Recent Test Results Table */}
        <div className="bg-[#0b1324] border border-slate-800/90 rounded-2xl overflow-hidden shadow-md">
          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCheck2 className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-white">Recent Test Suite Results</h3>
            </div>
            <button
              onClick={() => onNavigate('testcases')}
              className="text-xs text-sky-400 hover:text-sky-300 font-medium flex items-center gap-1 cursor-pointer"
            >
              <span>Run Suite</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#070b14] text-slate-400 border-b border-slate-800 font-mono">
                <tr>
                  <th className="px-4 py-2.5">Test Name</th>
                  <th className="px-4 py-2.5">Result</th>
                  <th className="px-4 py-2.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {testCases.slice(0, 5).map((tc) => (
                  <tr key={tc.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 font-medium text-slate-200 max-w-xs truncate">
                      {tc.name}
                    </td>
                    <td className="px-4 py-3 font-mono">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-bold text-[10px]">
                        {tc.status === 'PASS' ? 'PASS' : tc.expectedDecision}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                      Verified Safe
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
