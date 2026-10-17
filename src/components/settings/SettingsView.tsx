import React, { useEffect, useState } from 'react';
import {
  Settings,
  Cpu,
  Shield,
  Database,
  Lock,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Info,
  BookOpen,
  Sparkles,
} from 'lucide-react';
import { restoreAuditChain, fetchArmorIQStatus } from '../../services/api.ts';

export function SettingsView() {
  const [resettingData, setResettingData] = useState(false);
  const [msg, setMsg] = useState<{ type: 'success' | 'warn'; text: string } | null>(null);
  const [armorStatus, setArmorStatus] = useState<any>(null);

  useEffect(() => {
    fetchArmorIQStatus()
      .then(setArmorStatus)
      .catch((err) => console.warn('Could not load ArmorIQ status:', err));
  }, []);

  const handleResetLedger = async () => {
    if (!confirm('Re-sign and clean the audit trail chain?')) return;
    try {
      setResettingData(true);
      await restoreAuditChain();
      setMsg({ type: 'success', text: 'Audit hash chain repaired and re-signed from genesis block.' });
    } catch (err: any) {
      setMsg({ type: 'warn', text: err.message || 'Operation failed' });
    } finally {
      setResettingData(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 border border-sky-400/30">
            Platform Configuration
          </span>
          <span className="text-xs text-slate-400">Settings & Governance</span>
        </div>
        <h2 className="text-lg font-bold text-white">Platform Settings & ArmorIQ Architecture Contract</h2>
        <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
          Configure security testing preferences, audit persistence parameters, and inspect the ArmorIQ integration specification.
        </p>

        {msg && (
          <div
            className={`mt-4 p-3 rounded-lg text-xs flex items-center gap-2 border ${
              msg.type === 'success'
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                : 'bg-amber-950/40 border-amber-500/40 text-amber-300'
            }`}
          >
            {msg.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            )}
            <span>{msg.text}</span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* AI Engine & Gateway Settings */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2.5 border-b border-slate-800 pb-3">
            <Cpu className="w-5 h-5 text-sky-400" />
            <h3 className="text-sm font-bold text-white">AI Engine & Threat Analysis</h3>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800 space-y-1">
              <span className="text-slate-400 block">Primary AI Model:</span>
              <span className="font-mono text-sky-300 font-semibold">gemini-3.8-flash</span>
              <p className="text-[11px] text-slate-400 pt-1">
                Utilizes the official @google/genai TypeScript SDK from the server runtime.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800 space-y-1">
              <span className="text-slate-400 block">Deterministic Fallback Engine:</span>
              <span className="font-mono text-emerald-400 font-semibold">ACTIVE & STANDBY</span>
              <p className="text-[11px] text-slate-400 pt-1">
                Automatically activates if the Gemini API key is unpopulated or if rate limits occur, providing 100% offline security evaluation capability.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800 space-y-1">
              <span className="text-slate-400 block">Model Authorization Boundary:</span>
              <span className="font-mono text-amber-400 font-semibold">STRICT PROPOSAL-ONLY</span>
              <p className="text-[11px] text-slate-400 pt-1">
                The model cannot invoke tools directly, cannot elevate its clearance, and cannot alter security policies.
              </p>
            </div>
          </div>
        </div>

        {/* Audit Trail & Storage Settings */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2.5 border-b border-slate-800 pb-3">
            <Database className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">Cryptographic Audit & Storage</h3>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800 space-y-1">
              <span className="text-slate-400 block">Storage Mechanism:</span>
              <span className="font-mono text-slate-200 font-semibold">DEVELOPMENT_LOCAL_PERSISTENT</span>
              <p className="text-[11px] text-slate-400 pt-1">
                Committed events are saved locally to <code className="text-sky-300">.audit_logs.json</code> to persist across dev server restarts.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800 space-y-1">
              <span className="text-slate-400 block">Hashing Algorithm:</span>
              <span className="font-mono text-sky-400 font-semibold">SHA-256 Block Chain (Genesis = 64x0)</span>
              <p className="text-[11px] text-slate-400 pt-1">
                Each block includes the SHA-256 digest of the previous block, creating an unbroken tamper-evident timeline.
              </p>
            </div>

            <button
              onClick={handleResetLedger}
              disabled={resettingData}
              className="w-full py-2.5 px-3 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>{resettingData ? 'Repairing...' : 'Cleanse & Re-sign Audit Chain'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* ArmorIQ Integration Architecture & Live Status */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <Sparkles className="w-5 h-5 text-sky-400" />
            <div>
              <h3 className="text-sm font-bold text-white">ArmorIQ Integration & Cryptographic Attestation</h3>
              <p className="text-xs text-slate-400">Live configuration status and official SDK workflow integration</p>
            </div>
          </div>
          <span
            className={`text-xs font-mono px-2.5 py-1 rounded-full font-bold border ${
              armorStatus?.isConfigured
                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
            }`}
          >
            {armorStatus?.isConfigured ? 'CONNECTED & OPERATIONAL' : 'CONFIGURATION PENDING'}
          </span>
        </div>

        <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800">
              <span className="text-slate-400 block text-[10px] font-mono">SDK Package:</span>
              <span className="font-semibold text-sky-300 font-mono">@armoriq/sdk v0.6.10</span>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800">
              <span className="text-slate-400 block text-[10px] font-mono">API Secret (ARMORIQ_API_KEY):</span>
              <span className="font-semibold text-emerald-400 font-mono">
                {armorStatus?.apiKeyConfigured ? 'Secured Server Secret Active' : 'Not Populated'}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800">
              <span className="text-slate-400 block text-[10px] font-mono">IAP Proxy Endpoint:</span>
              <span className="font-semibold text-slate-200 font-mono truncate block">
                {armorStatus?.proxyEndpoint || 'https://proxy.armoriq.ai'}
              </span>
            </div>
          </div>

          <p>
            PromptShield integrates the official ArmorIQ TypeScript SDK per the official documentation (https://docs.armoriq.ai/sdk).
            Every AI agent tool proposal captures its execution plan, requests a signed cryptographic intent token, and enforces authorization before any call reaches the MCP server:
          </p>

          <pre className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800 font-mono text-[11px] text-sky-300 overflow-x-auto">
{`// 1. Capture Plan with ArmorIQ SDK
const planCapture = client.capturePlan('gemini-3.8-flash', prompt, {
  goal: 'Safe Document Read',
  steps: [{ action: 'read_public_document', tool: 'read_public_document', mcp: 'promptshield-secure-mcp-server' }]
});

// 2. Request Genuine Signed Intent Token from ArmorIQ IAP
const intentToken = await client.getIntentToken(planCapture);

// 3. Gateway Zero-Trust Authorization Gating
if (gatewayEvaluation.decision === 'ALLOW') {
  // Execute via Real MCP Server with synthetic demo data
  return await mcpClient.callTool({ name: 'read_public_document', arguments: {} });
} else {
  // MCP tool call strictly PREVENTED
  throw new SecurityPolicyException('Execution blocked by authorization gateway');
}`}
          </pre>

          <div className="p-3 rounded-lg bg-[#0a0f1d] border border-slate-800 flex items-start gap-2.5">
            <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
            <div className="text-[11px] text-slate-400">
              <strong className="text-slate-200">Strict Non-Exposure & Integrity Guarantee: </strong>
              Neither <code className="text-sky-300">ARMORIQ_API_KEY</code> nor <code className="text-sky-300">GEMINI_API_KEY</code> are ever sent to client browsers or printed in telemetry. If the gateway blocks an action, the MCP server tool is never executed.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
