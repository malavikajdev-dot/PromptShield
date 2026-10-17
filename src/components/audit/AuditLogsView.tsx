import React, { useEffect, useState } from 'react';
import {
  FileText,
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Search,
  Hash,
  ChevronDown,
  ChevronUp,
  Cpu,
  RotateCcw,
  Info,
  Bug,
} from 'lucide-react';
import { AuditEvent, AuditIntegrityReport } from '../../types/security.ts';
import {
  fetchAuditLogs,
  restoreAuditChain,
  simulateAuditTamper,
  verifyAuditIntegrity,
} from '../../services/api.ts';
import { DecisionBadge, StatusBadge } from '../common/Badge.tsx';

export function AuditLogsView() {
  const [logs, setLogs] = useState<AuditEvent[]>([]);
  const [integrityReport, setIntegrityReport] = useState<AuditIntegrityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [tampering, setTampering] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterDecision, setFilterDecision] = useState<string>('ALL');
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
  const [bannerNotice, setBannerNotice] = useState<{ type: 'success' | 'warn'; text: string } | null>(null);

  const loadLogs = async () => {
    try {
      setLoading(true);
      const [data, report] = await Promise.all([fetchAuditLogs(), verifyAuditIntegrity()]);
      setLogs(data);
      setIntegrityReport(report);
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, []);

  const handleVerifyIntegrity = async () => {
    try {
      setVerifying(true);
      const report = await verifyAuditIntegrity();
      setIntegrityReport(report);
      setBannerNotice({
        type: report.isValid ? 'success' : 'warn',
        text: report.isValid
          ? `Cryptographic integrity verification passed! All ${report.totalRecords} records linked by valid SHA-256 digests.`
          : `Integrity check failed: ${report.details}`,
      });
    } catch (err: any) {
      console.error('Verification error:', err);
    } finally {
      setVerifying(false);
    }
  };

  const handleSimulateTampering = async () => {
    if (logs.length === 0) return;
    try {
      setTampering(true);
      // Tamper with the most recent or selected record
      const targetId = logs[0].id;
      const res = await simulateAuditTamper(targetId);
      // Reload logs and verify to show the broken chain
      const [updatedLogs, report] = await Promise.all([fetchAuditLogs(), verifyAuditIntegrity()]);
      setLogs(updatedLogs);
      setIntegrityReport(report);
      setBannerNotice({
        type: 'warn',
        text: `Tamper simulation triggered! Record '${res.tamperedRecordId}' payload was altered without re-signing the cryptographic chain. Click "Verify Integrity" to inspect detection!`,
      });
    } catch (err: any) {
      console.error('Tampering simulation failed:', err);
    } finally {
      setTampering(false);
    }
  };

  const handleRestoreChain = async () => {
    try {
      setRestoring(true);
      await restoreAuditChain();
      const [updatedLogs, report] = await Promise.all([fetchAuditLogs(), verifyAuditIntegrity()]);
      setLogs(updatedLogs);
      setIntegrityReport(report);
      setBannerNotice({
        type: 'success',
        text: 'Audit chain successfully restored and cryptographically re-signed.',
      });
    } catch (err: any) {
      console.error('Chain restoration failed:', err);
    } finally {
      setRestoring(false);
    }
  };

  const filteredLogs = logs.filter((log) => {
    const matchesQuery =
      log.inputPrompt.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.scenarioTitle.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.proposedAction.tool_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.hash.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesDecision =
      filterDecision === 'ALL' || log.gatewayDecision === filterDecision;
    return matchesQuery && matchesDecision;
  });

  return (
    <div className="space-y-6">
      {/* Integrity & Actions Banner */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 border border-sky-400/30">
                Cryptographic Ledger
              </span>
              <span className="text-xs text-slate-400 font-mono">Algorithm: SHA-256 Blockchain</span>
            </div>
            <h2 className="text-lg font-bold text-white mt-1">Tamper-Evident Audit Trail</h2>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
              Every evaluation and tool invocation is recorded with previous-hash linkage. Any unauthorized
              payload modification severs the downstream chain.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={handleVerifyIntegrity}
              disabled={verifying}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:bg-slate-800 text-slate-950 font-bold text-xs cursor-pointer shadow-[0_0_12px_rgba(56,189,248,0.25)] transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
              <span>Verify Integrity</span>
            </button>

            <button
              onClick={handleSimulateTampering}
              disabled={tampering || logs.length === 0}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-amber-500/40 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 text-xs font-semibold cursor-pointer transition-colors"
              title="Mutates a record without updating cryptographic hashes to prove detection"
            >
              <Bug className="w-3.5 h-3.5" />
              <span>Simulate Tamper</span>
            </button>

            {!integrityReport?.isValid && (
              <button
                onClick={handleRestoreChain}
                disabled={restoring}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 text-xs font-semibold cursor-pointer transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Restore Chain</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Integrity Card */}
        <div
          className={`mt-4 p-4 rounded-lg border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs ${
            integrityReport?.isValid
              ? 'bg-emerald-950/25 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/40 border-rose-500/50 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-3">
            {integrityReport?.isValid ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 animate-pulse" />
            )}
            <div>
              <div className="font-bold text-sm">
                Integrity Status: {integrityReport?.isValid ? 'VERIFIED INTACT' : 'CHAIN TAMPER DETECTED!'}
              </div>
              <p className="text-slate-300 mt-0.5 leading-relaxed">
                {integrityReport?.details}
              </p>
            </div>
          </div>
          <span className="font-mono text-[11px] text-slate-400 shrink-0">
            {logs.length} committed blocks
          </span>
        </div>

        {bannerNotice && (
          <div className="mt-3 p-3 rounded-lg bg-sky-950/40 border border-sky-500/30 text-xs text-sky-200">
            {bannerNotice.text}
          </div>
        )}
      </div>

      {/* Educational Callout on Cryptography */}
      <div className="p-4 rounded-xl bg-[#0a0f1d] border border-slate-800 flex items-start gap-3">
        <Info className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 leading-relaxed">
          <strong className="text-slate-100 block mb-0.5">Security Architecture Notice (RFC 6234):</strong>
          A tamper-evident hash chain mathematically detects unauthorized mutation or truncation between committed records. 
          However, as mandated by cybersecurity standards, a hash chain alone is not a digital signature and does not establish non-repudiation 
          unless paired with an external hardware security module (HSM) or public key infrastructure (PKI) timestamping service.
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search prompt, tool, or hash..."
            className="w-full bg-[#0f172a] border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          {['ALL', 'ALLOW', 'BLOCK', 'APPROVAL_REQUIRED'].map((dec) => (
            <button
              key={dec}
              onClick={() => setFilterDecision(dec)}
              className={`text-xs px-2.5 py-1.5 rounded-lg border transition-colors cursor-pointer ${
                filterDecision === dec
                  ? 'bg-sky-500/20 border-sky-500/40 text-sky-300 font-semibold'
                  : 'bg-[#0f172a] border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {dec}
            </button>
          ))}
        </div>
      </div>

      {/* Audit Log Entries List */}
      <div className="space-y-3">
        {filteredLogs.length === 0 ? (
          <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-10 text-center text-xs text-slate-400">
            No audit records matching your search or filters.
          </div>
        ) : (
          filteredLogs.map((log, index) => {
            const isExpanded = expandedLogId === log.id;
            return (
              <div
                key={log.id}
                className={`bg-[#0f172a] border rounded-xl overflow-hidden transition-all ${
                  log.isSimulatedTampered
                    ? 'border-rose-500/70 shadow-[0_0_15px_rgba(244,63,94,0.2)]'
                    : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                <div
                  onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                  className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer select-none"
                >
                  <div className="flex items-start md:items-center gap-3 min-w-0">
                    <div className="w-8 h-8 rounded-lg bg-[#0a0f1d] border border-slate-800 flex items-center justify-center text-slate-400 font-mono text-xs shrink-0">
                      #{logs.length - index}
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-white truncate">
                          {log.scenarioTitle}
                        </span>
                        {log.isSimulatedTampered && (
                          <span className="text-[10px] uppercase font-bold font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40">
                            TAMPER SIMULATED
                          </span>
                        )}
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400 font-mono mt-0.5">
                        <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                        <span>•</span>
                        <span className="text-sky-400">tool: {log.proposedAction.tool_name}</span>
                        <span>•</span>
                        <span className="truncate max-w-xs">{log.id}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                    <DecisionBadge decision={log.gatewayDecision} size="sm" />
                    <StatusBadge status={log.toolExecutionStatus} />
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Forensic Trace Panel */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-3 border-t border-slate-800/80 bg-[#0a0f1d]/70 space-y-4 text-xs font-mono">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Left: Decision Details */}
                      <div className="space-y-3">
                        <div>
                          <span className="text-slate-400 font-sans block mb-1">Original Test Input:</span>
                          <div className="p-2.5 rounded bg-[#0a0f1d] border border-slate-800 text-slate-200 font-sans">
                            "{log.inputPrompt}"
                          </div>
                        </div>

                        <div>
                          <span className="text-slate-400 font-sans block mb-1">Gateway Decision & Reason:</span>
                          <div className="p-2.5 rounded bg-[#0a0f1d] border border-slate-800 space-y-1">
                            <div className="flex justify-between items-center">
                              <span className="text-slate-400 font-sans">Policy ID: {log.policyId}</span>
                              <DecisionBadge decision={log.gatewayDecision} size="sm" />
                            </div>
                            <p className="text-slate-300 font-sans pt-1 leading-relaxed">
                              {log.decisionReason}
                            </p>
                          </div>
                        </div>

                        <div>
                          <span className="text-slate-400 font-sans block mb-1">AI Proposal:</span>
                          <pre className="p-2.5 rounded bg-[#0a0f1d] border border-slate-800 text-sky-300 text-[11px] overflow-x-auto">
                            {JSON.stringify(log.proposedAction, null, 2)}
                          </pre>
                        </div>
                      </div>

                      {/* Right: Cryptographic Hashes & Tool Output */}
                      <div className="space-y-3">
                        <div>
                          <span className="text-slate-400 font-sans block mb-1">Cryptographic Linkage (SHA-256):</span>
                          <div className="p-2.5 rounded bg-[#0a0f1d] border border-slate-800 space-y-2 text-[11px]">
                            <div>
                              <span className="text-slate-500 block">Previous Block Hash (prevHash):</span>
                              <span className="text-slate-300 break-all">{log.prevHash}</span>
                            </div>
                            <div className="pt-1 border-t border-slate-800">
                              <span className="text-slate-500 block">Committed Record Hash:</span>
                              <span className="text-sky-400 break-all">{log.hash}</span>
                            </div>
                          </div>
                        </div>

                        <div>
                          <span className="text-slate-400 font-sans block mb-1">Tool Execution Result:</span>
                          <pre className="p-2.5 rounded bg-[#0a0f1d] border border-slate-800 text-slate-300 text-[11px] overflow-x-auto max-h-40">
                            {JSON.stringify(log.toolResult, null, 2)}
                          </pre>
                        </div>

                        <div className="text-[11px] text-slate-500 font-sans">
                          Model Mode: {log.aiMode}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
