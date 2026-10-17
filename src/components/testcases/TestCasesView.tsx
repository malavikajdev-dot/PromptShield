import React, { useEffect, useState } from 'react';
import {
  FileCheck2,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Terminal,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Copy,
  Check,
} from 'lucide-react';
import { AutomatedTestCase } from '../../types/security.ts';
import { fetchTestSuite, runTestSuite } from '../../services/api.ts';
import { DecisionBadge } from '../common/Badge.tsx';

export function TestCasesView() {
  const [tests, setTests] = useState<AutomatedTestCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [runningSuite, setRunningSuite] = useState(false);
  const [expandedTestId, setExpandedTestId] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [copiedCmd, setCopiedCmd] = useState(false);

  const loadTests = async () => {
    try {
      setLoading(true);
      const data = await fetchTestSuite();
      setTests(data);
    } catch (err) {
      console.error('Failed to load test suite:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTests();
  }, []);

  const handleRunAllTests = async () => {
    try {
      setRunningSuite(true);
      const data = await runTestSuite();
      setTests(data.tests);
    } catch (err) {
      console.error('Failed to run test suite:', err);
    } finally {
      setRunningSuite(false);
    }
  };

  const categories = [
    'ALL',
    'Benign Requests',
    'Prompt Injection',
    'Indirect Injection',
    'Privilege Escalation',
    'Data Exfiltration',
    'Parameter Tampering',
    'Audit Integrity',
  ];

  const filteredTests =
    selectedCategory === 'ALL'
      ? tests
      : tests.filter((t) => t.category === selectedCategory);

  const passedCount = tests.filter((t) => t.status === 'PASS').length;
  const failedCount = tests.filter((t) => t.status === 'FAIL').length;
  const idleCount = tests.filter((t) => t.status === 'IDLE').length;
  const passRate =
    tests.length > 0 && passedCount + failedCount > 0
      ? Math.round((passedCount / (passedCount + failedCount)) * 100)
      : 100;

  const copyCliCommand = () => {
    navigator.clipboard.writeText('npm run test');
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Test Suite Control Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 border border-sky-400/30">
                Automated Verification Suite
              </span>
              <span className="text-xs text-slate-400">10 Server-Side Policy Checks</span>
            </div>
            <h2 className="text-lg font-bold text-white mt-1">AI Agent Security Test Suite</h2>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
              Executes live tests verifying that benign requests pass, injections are stopped, 
              privilege escalations fail closed, and the cryptographic hash chain retains integrity.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleRunAllTests}
              disabled={runningSuite}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:bg-slate-800 text-slate-950 font-bold text-xs sm:text-sm transition-all shadow-[0_0_15px_rgba(56,189,248,0.3)] cursor-pointer"
            >
              {runningSuite ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Executing 10 Security Assertions...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Run Full Test Suite</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Live Scorecard */}
        <div className="mt-5 grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 border-t border-slate-800/80 text-xs">
          <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Total Assertions:</span>
            <span className="text-lg font-bold text-white">{tests.length}</span>
          </div>
          <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Passed:</span>
            <span className="text-lg font-bold text-emerald-400">{passedCount}</span>
          </div>
          <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Failed:</span>
            <span className="text-lg font-bold text-rose-400">{failedCount}</span>
          </div>
          <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Suite Pass Rate:</span>
            <span className="text-lg font-bold text-sky-400">
              {idleCount === tests.length ? 'Ready' : `${passRate}%`}
            </span>
          </div>
        </div>
      </div>

      {/* CLI Instruction Box */}
      <div className="p-4 rounded-xl bg-[#0a0f1d] border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 text-slate-300">
          <Terminal className="w-4 h-4 text-sky-400 shrink-0" />
          <span>You can also run automated verification directly in your terminal:</span>
          <code className="font-mono text-sky-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-700">
            npx tsx src/server/testRunner.ts
          </code>
        </div>
        <button
          onClick={copyCliCommand}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white px-2.5 py-1 rounded bg-slate-800 border border-slate-700 cursor-pointer transition-colors"
        >
          {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
        </button>
      </div>

      {/* Category Filter Pills */}
      <div className="flex flex-wrap gap-2">
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors cursor-pointer ${
              selectedCategory === cat
                ? 'bg-sky-500/20 border-sky-500/50 text-sky-300'
                : 'bg-[#0f172a] border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Test Cases Table / Cards */}
      <div className="space-y-3">
        {filteredTests.map((tc) => {
          const isExpanded = expandedTestId === tc.id;
          return (
            <div
              key={tc.id}
              className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition-colors"
            >
              <div
                onClick={() => setExpandedTestId(isExpanded ? null : tc.id)}
                className="p-4 flex items-center justify-between gap-4 cursor-pointer select-none"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="shrink-0">
                    {tc.status === 'PASS' ? (
                      <span className="flex items-center gap-1 text-xs font-mono font-bold px-2 py-1 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        PASS
                      </span>
                    ) : tc.status === 'FAIL' ? (
                      <span className="flex items-center gap-1 text-xs font-mono font-bold px-2 py-1 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
                        <XCircle className="w-3.5 h-3.5 text-rose-400" />
                        FAIL
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-xs font-mono font-medium px-2 py-1 rounded bg-slate-800 text-slate-400 border border-slate-700">
                        <Clock className="w-3.5 h-3.5" />
                        READY
                      </span>
                    )}
                  </div>

                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-sky-400">{tc.id}</span>
                      <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                        {tc.category}
                      </span>
                    </div>
                    <h4 className="text-xs sm:text-sm font-semibold text-white mt-0.5 truncate">
                      {tc.name}
                    </h4>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="hidden md:flex items-center gap-2 text-xs">
                    <span className="text-slate-400">Expected:</span>
                    <DecisionBadge decision={tc.expectedDecision} size="sm" />
                  </div>
                  {tc.latencyMs !== undefined && (
                    <span className="text-[11px] font-mono text-slate-400 hidden sm:inline">
                      {tc.latencyMs}ms
                    </span>
                  )}
                  {isExpanded ? (
                    <ChevronUp className="w-4 h-4 text-slate-400" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-slate-400" />
                  )}
                </div>
              </div>

              {/* Collapsible Details */}
              {isExpanded && (
                <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 bg-[#0a0f1d]/60 space-y-3 text-xs">
                  <p className="text-slate-300 leading-relaxed">{tc.description}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                    <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800">
                      <span className="text-slate-400 block text-[10px] font-sans">Input Prompt:</span>
                      <span className="text-slate-200 mt-1 block">"{tc.inputPrompt}"</span>
                    </div>

                    <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800 space-y-1">
                      <div className="flex justify-between">
                        <span className="text-slate-400 font-sans text-[10px]">Expected Decision:</span>
                        <DecisionBadge decision={tc.expectedDecision} size="sm" />
                      </div>
                      <div className="flex justify-between pt-1">
                        <span className="text-slate-400 font-sans text-[10px]">Actual Gateway Decision:</span>
                        {tc.actualDecision ? (
                          <DecisionBadge decision={tc.actualDecision} size="sm" />
                        ) : (
                          <span className="text-slate-500">Not yet executed</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {tc.actualReason && (
                    <div className="p-3 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-200 text-xs">
                      <strong className="text-sky-100">Observed Gateway Rationale: </strong>
                      {tc.actualReason}
                    </div>
                  )}

                  {tc.timestamp && (
                    <div className="text-[11px] text-slate-500 font-mono">
                      Last Executed: {new Date(tc.timestamp).toLocaleString()} ({tc.latencyMs}ms)
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
